use axum::{
    Extension,
    extract::{Path, State},
};
use ferriskey_core::domain::authentication::value_objects::Identity;
use ferriskey_core::domain::email_verification::ports::EmailVerificationService;
use serde::Serialize;
use utoipa::ToSchema;

use ferriskey_api_core::api_entities::{
    api_error::{ApiError, ApiErrorResponse},
    response::Response,
};
use ferriskey_api_core::app_state::AppState;
use ferriskey_api_core::request_context::RequestContext;
use ferriskey_api_core::url::WebappUrl;

#[derive(Debug, Serialize, ToSchema)]
pub struct ResendVerificationEmailResponse {
    pub message: String,
}

/// POST /realms/{realm_name}/login-actions/resend-verification-email
#[utoipa::path(
    post,
    path = "/login-actions/resend-verification-email",
    tag = "auth",
    summary = "Resend verification email",
    description = "Resend the email verification link to the user's email address. Requires the validated login-action cookie for the pending login.",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "Verification email sent", body = ResendVerificationEmailResponse),
        (status = 401, description = "Unauthorized - missing or invalid token", body = ApiErrorResponse),
        (status = 404, description = "User not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn resend_verification_email_handler(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    WebappUrl(verification_base_url): WebappUrl,
    context: RequestContext,
    Extension(identity): Extension<Identity>,
) -> Result<Response<ResendVerificationEmailResponse>, ApiError> {
    state
        .service
        .check_email_ip(
            &realm_name,
            context.ip_address.as_deref().and_then(|ip| ip.parse().ok()),
        )
        .await?;
    let user_id = identity.id();

    let delivery = state
        .service
        .email_verification_service
        .send_verification_email(
            user_id,
            realm_name,
            verification_base_url,
            context.user_agent,
        )
        .await;
    // Recipient/realm throttling must look exactly like a successful send.
    match delivery {
        Ok(())
        | Err(
            ferriskey_core::domain::common::entities::app_errors::CoreError::EmailRateLimited {
                ..
            },
        ) => {}
        Err(error) => return Err(error.into()),
    }

    Ok(Response::OK(ResendVerificationEmailResponse {
        message: "Verification email sent successfully".to_string(),
    }))
}
