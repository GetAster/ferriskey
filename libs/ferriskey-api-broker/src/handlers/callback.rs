use axum::{
    Form,
    extract::{Path, Query, State},
    http::{
        HeaderValue, StatusCode,
        header::{LOCATION, SET_COOKIE},
    },
    response::IntoResponse,
};

use ferriskey_api_core::login_step::login_action_cookie;
use ferriskey_core::domain::abyss::identity_provider::broker::{
    BrokerCallbackInput, BrokerService,
};
use ferriskey_core::domain::authentication::ports::AuthService;
use ferriskey_core::domain::common::entities::app_errors::CoreError;
use ferriskey_core::domain::email_verification::ports::EmailVerificationService;
use ferriskey_core::domain::user::entities::RequiredAction;

use ferriskey_api_core::request_context::RequestContext;
use ferriskey_api_core::url::{FullUrl, WebappUrl};
use ferriskey_api_core::{
    api_entities::api_error::{ApiError, ApiErrorResponse},
    app_state::AppState,
};

use super::super::validators::BrokerCallbackQuery;

/// Handles the callback from the external identity provider
///
/// This endpoint validates the state parameter, exchanges the authorization code
/// for tokens, finds or creates the user, and redirects back to the client
/// with an authorization code.
#[utoipa::path(
    post,
    path = "/broker/{alias}/endpoint",
    tag = "broker",
    summary = "Handle SSO callback from identity provider",
    description = "Processes the IdP callback, exchanges code for tokens, and redirects to client",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
        ("alias" = String, Path, description = "Identity provider alias"),
        BrokerCallbackQuery
    ),
    responses(
        (status = 302, description = "Redirect to client with authorization code"),
        (status = 400, description = "Bad request - invalid state or expired session", body = ApiErrorResponse),
        (status = 401, description = "Authentication failed at identity provider", body = ApiErrorResponse),
        (status = 502, description = "Error communicating with identity provider", body = ApiErrorResponse),
    )
)]
pub async fn broker_callback(
    Path((realm_name, alias)): Path<(String, String)>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    WebappUrl(webapp_url): WebappUrl,
    context: RequestContext,
    Query(params): Query<BrokerCallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    finish_callback(
        realm_name, alias, state, base_url, webapp_url, context, params,
    )
    .await
}

/// Apple returns a form POST. State and the exchanged ID token remain the
/// authority; a form's email or id_token never replaces verified token claims.
pub async fn broker_callback_post(
    Path((realm_name, alias)): Path<(String, String)>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    WebappUrl(webapp_url): WebappUrl,
    context: RequestContext,
    Form(params): Form<BrokerCallbackQuery>,
) -> Result<impl IntoResponse, ApiError> {
    finish_callback(
        realm_name, alias, state, base_url, webapp_url, context, params,
    )
    .await
}

async fn finish_callback(
    realm_name: String,
    alias: String,
    state: AppState,
    base_url: String,
    webapp_url: String,
    context: RequestContext,
    params: BrokerCallbackQuery,
) -> Result<axum::response::Response, ApiError> {
    let root_scoped_base_url = format!("{base_url}{}", state.args.server.root_path);
    let result = match state
        .service
        .handle_callback(BrokerCallbackInput {
            user: params.user,
            realm_name: realm_name.clone(),
            alias,
            code: params.code,
            state: params.state,
            error: params.error,
            error_description: params.error_description,
            base_url: root_scoped_base_url.clone(),
            webapp_base_url: webapp_url.clone(),
            ip_address: context.ip_address,
            user_agent: context.user_agent.clone(),
        })
        .await
    {
        Ok(result) => result,
        Err(CoreError::UserDisabled) => {
            let frontend_origin = if state.args.webapp_url_from_request {
                webapp_url
            } else {
                state
                    .args
                    .server
                    .allowed_origins
                    .first()
                    .map(|s| s.trim_end_matches('/').to_string())
                    .unwrap_or_else(|| base_url.clone())
            };

            let login_url = format!(
                "{frontend_origin}/realms/{realm_name}/authentication/login?login_error=User+account+is+disabled"
            );
            return Ok((StatusCode::FOUND, [(LOCATION, login_url)]).into_response());
        }
        Err(e) => return Err(e.into()),
    };

    let action_token = if result.second_factor_pending || !result.required_actions.is_empty() {
        let session_id = result.browser_session_id.ok_or(CoreError::InvalidSession)?;
        let token = state
            .service
            .issue_primary_login_action_token(
                realm_name.clone(),
                session_id,
                result.user_id,
                root_scoped_base_url,
                !result.second_factor_pending,
            )
            .await?;
        if result
            .required_actions
            .contains(&RequiredAction::VerifyEmail)
        {
            if let Err(error) = state
                .service
                .email_verification_service
                .send_verification_email(
                    result.user_id,
                    realm_name.clone(),
                    webapp_url,
                    context.user_agent,
                )
                .await
            {
                tracing::warn!(%error, "Unable to deliver verification email after provider login");
            }
        }
        Some(token)
    } else {
        None
    };
    let mut response = (StatusCode::FOUND, [(LOCATION, result.redirect_url)]).into_response();
    if let Some(token) = action_token {
        response.headers_mut().append(
            SET_COOKIE,
            login_action_cookie(
                token,
                &state.args.server.root_path,
                &realm_name,
                base_url.starts_with("https://"),
            )?,
        );
    }

    if let Some(session_id) = result.browser_session_id {
        let secure = if base_url.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        let cookie =
            format!("FERRISKEY_SESSION={session_id}; Path=/; HttpOnly; SameSite=Lax{secure}");
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
    }

    Ok(response)
}
