use super::continue_login::ContinueLoginResponse;
use axum::{
    Extension, Json,
    extract::{Path, State},
    response::IntoResponse,
};
use ferriskey_api_core::{
    api_entities::{
        api_error::{ApiError, ApiErrorBody},
        response::Response,
    },
    app_state::AppState,
    login_step::{LoginActionStep, LoginStepReply},
    url::{FullUrl, WebappUrl},
};
use ferriskey_core::domain::{
    authentication::value_objects::Identity, trident::ports::TridentService,
    user::entities::RequiredAction,
};
use serde::Deserialize;
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct SkipLoginActionRequest {
    pub action: RequiredAction,
}

#[utoipa::path(post, path = "/login-actions/skip", tag = "auth",
    summary = "Decline the optional passkey offer for this login",
    request_body = SkipLoginActionRequest,
    params(("realm_name" = String, Path, description = "Realm name")),
    responses((status = 200, body = ContinueLoginResponse),
        (status = 401, description = "Invalid or consumed login-action cookie"),
        (status = 403, description = "Action is mandatory or no optional offer is pending")))]
pub async fn skip_login_action(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    FullUrl(_, base_url): FullUrl,
    WebappUrl(webapp_url): WebappUrl,
    Extension(identity): Extension<Identity>,
    Extension(step): Extension<LoginActionStep>,
    Json(payload): Json<SkipLoginActionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.action == RequiredAction::ConfigurePasskey
        && matches!(&identity, Identity::User(user) if user.required_actions.contains(&RequiredAction::ConfigurePasskey))
    {
        return Err(ApiError::Forbidden(ApiErrorBody::new(
            "This account needs a passkey to continue",
            "action_required",
        )));
    }
    let progress = state
        .service
        .continue_login(
            identity,
            realm_name,
            step.auth_session_id.to_string(),
            webapp_url,
            step.second_factor_verified,
            Some(payload.action),
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
