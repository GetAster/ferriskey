use axum::{
    Extension,
    extract::{Path, State},
    response::IntoResponse,
};
use ferriskey_api_core::{
    api_entities::{api_error::ApiError, response::Response},
    app_state::AppState,
    login_step::{LoginActionStep, LoginStepReply},
    url::{FullUrl, WebappUrl},
};
use ferriskey_core::domain::{
    authentication::value_objects::Identity, trident::ports::TridentService,
    user::entities::RequiredAction,
};
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
pub struct ContinueLoginResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_actions: Vec<RequiredAction>,
}

/// Re-check the authenticated login after an out-of-band action such as email
/// verification. The email link itself never establishes a browser identity.
#[utoipa::path(
    post,
    path = "/login-actions/continue",
    tag = "auth",
    summary = "Continue a login after completing a required action",
    params(("realm_name" = String, Path, description = "Realm name")),
    responses(
        (status = 200, body = ContinueLoginResponse),
        (status = 401, description = "Missing, expired or invalid login-action cookie"),
        (status = 403, description = "Second factor is still required"),
    )
)]
pub async fn continue_login(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    WebappUrl(webapp_url): WebappUrl,
    Extension(identity): Extension<Identity>,
    Extension(step): Extension<LoginActionStep>,
) -> Result<impl IntoResponse, ApiError> {
    let progress = state
        .service
        .continue_login(
            identity,
            realm_name,
            step.auth_session_id.to_string(),
            webapp_url,
            step.second_factor_verified,
        )
        .await?;
    let reply = LoginStepReply::new(progress, base_url.starts_with("https"))?;
    Ok((
        reply.headers,
        reply.continues,
        Response::OK(ContinueLoginResponse {
            url: reply.url,
            required_actions: reply.required_actions,
        }),
    ))
}
