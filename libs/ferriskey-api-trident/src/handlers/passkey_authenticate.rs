use axum::{
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
};
use axum_cookie::CookieManager;
use ferriskey_api_core::login_step::login_action_cookie;
use ferriskey_core::domain::authentication::ports::AuthService;
use ferriskey_core::domain::trident::ports::{
    PasskeyAuthenticateInput, PublicKeyCredential, TridentService,
};
use ferriskey_core::domain::user::entities::RequiredAction;
use serde::{Deserialize, Serialize};
use utoipa::{
    PartialSchema, ToSchema,
    openapi::{ObjectBuilder, RefOr, Schema},
};
use validator::Validate;

use crate::validators::webauthn_rp_info_from_webapp_url;
use ferriskey_api_core::url::WebappUrl;
use ferriskey_api_core::{
    api_entities::{
        api_error::{ApiError, ApiErrorResponse, ValidateJson},
        response::Response,
    },
    app_state::AppState,
    sso_cookie,
    url::FullUrl,
};

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct PasskeyAuthenticateRequest(PublicKeyCredential);

impl Validate for PasskeyAuthenticateRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        Ok(())
    }
}

impl ToSchema for PasskeyAuthenticateRequest {
    fn name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("PasskeyPublicKeyCredential")
    }
}

impl PartialSchema for PasskeyAuthenticateRequest {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .description(Some("PublicKeyCredential assertion response for passkey authentication. See https://w3c.github.io/webauthn/#dictdef-publickeycredentialjson"))
                .build(),
        ))
    }
}

#[derive(Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct PasskeyAuthenticateResponse {
    login_url: String,
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_actions: Vec<RequiredAction>,
}

/// The body is the browser's assertion as is, so options travel in the query.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PasskeyAuthenticateQuery {
    /// Keep the SSO session past the browser closing. Honoured only when the
    /// realm enables "remember me".
    #[serde(default)]
    pub remember_me: bool,
}

#[utoipa::path(
    post,
    path = "/login-actions/passkey-authenticate",
    tag = "auth",
    summary = "Authenticate using a passkey",
    description = "Complete passkey authentication by submitting the browser's assertion response. On success, returns a login URL with an authorization code.",
    request_body = PasskeyAuthenticateRequest,
    params(
        ("realm_name" = String, Path, description = "Name of the realm"),
        PasskeyAuthenticateQuery,
    ),
    responses(
        (status = 200, description = "Passkey authentication successful", body = PasskeyAuthenticateResponse),
        (status = 400, description = "Invalid request payload", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid session cookie", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    )
)]
pub async fn passkey_authenticate(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    WebappUrl(webapp_url): WebappUrl,
    FullUrl(_, base_url): FullUrl,
    Query(query): Query<PasskeyAuthenticateQuery>,
    cookie: CookieManager,
    ValidateJson(payload): ValidateJson<PasskeyAuthenticateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let session_code = cookie
        .get("FERRISKEY_SESSION")
        .ok_or_else(|| ApiError::Unauthorized("Missing session cookie".into()))?
        .value()
        .to_string();

    let rp_info = webauthn_rp_info_from_webapp_url(&webapp_url);

    let output = state
        .service
        .passkey_authenticate(PasskeyAuthenticateInput {
            realm_name: realm_name.clone(),
            session_code,
            webapp_base_url: webapp_url.clone(),
            rp_info,
            credential: payload.0,
            remember_me: query.remember_me,
        })
        .await
        .map_err(ApiError::from)?;

    let pending = output.login_url.is_empty();
    let mut headers = sso_cookie::headers(output.sso_session, base_url.starts_with("https"))?;
    if pending {
        let token = state
            .service
            .issue_primary_login_action_token(
                realm_name.clone(),
                output.session_code,
                output.user_id,
                format!(
                    "{}{}",
                    base_url.trim_end_matches('/'),
                    state.args.server.root_path
                ),
                true,
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
    Ok((
        headers,
        Response::OK(PasskeyAuthenticateResponse {
            login_url: output.login_url,
            status: if pending {
                "RequiresActions"
            } else {
                "Success"
            }
            .to_string(),
            required_actions: output.pending_actions,
        }),
    ))
}
