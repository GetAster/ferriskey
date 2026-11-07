use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use axum_cookie::CookieManager;
use ferriskey_api_core::login_step::login_action_cookie;
use ferriskey_core::domain::authentication::ports::AuthService;
use ferriskey_core::domain::trident::ports::{
    MagicLinkInput, TridentService, VerifyMagicLinkInput,
};
use serde::{Deserialize, Serialize};
use tracing::debug;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use ferriskey_api_core::url::WebappUrl;
use ferriskey_api_core::{
    api_entities::{
        api_error::{ApiError, ValidateJson},
        response::Response,
    },
    app_state::AppState,
    authentication::{AuthenticateResponse, AuthenticationStatus},
    request_context::RequestContext,
    sso_cookie,
    url::FullUrl,
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SendMagicLinkRequest {
    #[validate(email)]
    pub email: String,
    /// Keep the SSO session past the browser closing once the link is used.
    /// Honoured only when the realm enables "remember me".
    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SendMagicLinkResponse {
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyMagicLinkQuery {
    pub token_id: Uuid,
    pub magic_token: String,
}

#[utoipa::path(
    post,
    path = "/login-actions/send-magic-link",
    tag = "auth",
    summary = "Send magic link for passwordless authentication",
    description = "Sends a magic link to the user's email for passwordless authentication. The link contains a unique token that can be used to verify the user's identity.",
    params(
        ("realm_name" = String, Path, description = "The realm name"),
    ),
    request_body = SendMagicLinkRequest,
    responses(
        (status = 200, body = SendMagicLinkResponse, description = "Magic link sent successfully"),
        (status = 400, description = "Bad Request"),
        (status = 500, description = "Internal Server Error")
    )
)]
pub async fn send_magic_link(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    WebappUrl(base_url): WebappUrl,
    context: RequestContext,
    cookie: CookieManager,
    ValidateJson(payload): ValidateJson<SendMagicLinkRequest>,
) -> Result<Response<SendMagicLinkResponse>, ApiError> {
    state
        .service
        .check_email_ip(
            &realm_name,
            context.ip_address.as_deref().and_then(|ip| ip.parse().ok()),
        )
        .await?;

    let session_code = cookie
        .get("FERRISKEY_SESSION")
        .map(|c| c.value().to_string());

    state
        .service
        .generate_magic_link(MagicLinkInput {
            realm_name,
            email: payload.email.clone(),
            base_url,
            session_code,
            remember_me: payload.remember_me,
            user_agent: context.user_agent,
        })
        .await?;

    debug!("Magic link request processed");

    Ok(Response::OK(SendMagicLinkResponse {
        message: "Magic link sent successfully. Check your email.".to_string(),
    }))
}

#[utoipa::path(
    get,
    path = "/login-actions/verify-magic-link",
    tag = "auth",
    summary = "Verify magic link and complete authentication",
    description = "Verifies the magic link token and completes the authentication flow. Returns authentication status and redirect URL with authorization code.",
    params(
        ("realm_name" = String, Path, description = "Name of the realm"),
        ("token_id" = String, Query, description = "The unique token identifier from the magic link"),
        ("magic_token" = String, Query, description = "The secret verification token from the magic link"),
    ),
    responses(
        (status = 200, body = AuthenticateResponse, description = "Magic link verified successfully"),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Not Found"),
        (status = 500, description = "Internal Server Error")
    )
)]
pub async fn verify_magic_link(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    WebappUrl(webapp_url): WebappUrl,
    cookie: CookieManager,
    Query(query): Query<VerifyMagicLinkQuery>,
) -> Result<impl IntoResponse, ApiError> {
    debug!("Verifying magic link for token_id: {}", query.token_id);

    let verified = state
        .service
        .verify_magic_link(VerifyMagicLinkInput {
            magic_token_id: query.token_id,
            magic_token: query.magic_token,
            webapp_base_url: webapp_url,
            browser_session: cookie
                .get("FERRISKEY_SESSION")
                .and_then(|cookie| Uuid::parse_str(cookie.value()).ok()),
        })
        .await?;

    debug!("Magic link verified");

    let pending = verified.login_url.is_empty();
    let mut headers = sso_cookie::headers(verified.sso_session, base_url.starts_with("https"))?;
    if pending {
        let token = state
            .service
            .issue_primary_login_action_token(
                realm_name.clone(),
                verified.session_code,
                verified.user_id,
                format!(
                    "{}{}",
                    base_url.trim_end_matches('/'),
                    state.args.server.root_path
                ),
                verified.second_factor_verified,
            )
            .await?;
        headers.append(
            header::SET_COOKIE,
            login_action_cookie(
                token,
                &state.args.server.root_path,
                &realm_name,
                base_url.starts_with("https"),
            )?,
        );
    }
    let response = AuthenticateResponse {
        status: if !pending {
            AuthenticationStatus::Success
        } else if verified.pending_actions.is_empty() {
            AuthenticationStatus::RequiresOtpChallenge
        } else {
            AuthenticationStatus::RequiresActions
        },
        url: (!pending).then_some(verified.login_url),
        required_actions: pending.then_some(verified.pending_actions),
        email: None,
        message: None,
    };

    Ok((
        StatusCode::OK,
        headers,
        [(header::REFERRER_POLICY, "no-referrer")],
        axum::Json(response),
    )
        .into_response())
}
