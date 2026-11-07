use axum::{
    Extension,
    extract::{Path, State},
};
use axum_cookie::CookieManager;
use chrono::{DateTime, Utc};
use ferriskey_api_core::sso_cookie::SSO_SESSION_COOKIE;
use ferriskey_api_core::{
    api_entities::{
        api_error::{ApiError, ApiErrorBody, ApiErrorResponse, ValidateJson},
        response::Response,
    },
    app_state::AppState,
};
use ferriskey_core::domain::account_security::entities::{ElevationProof, RequestElevationInput};
use ferriskey_core::domain::account_security::ports::AccountSecurityService;
use ferriskey_core::domain::authentication::value_objects::Identity;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::validators::RequestElevationValidator;
use ferriskey_api_core::caller_session::CallerSession;

#[derive(Debug, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct ElevationResponse {
    pub elevation_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[utoipa::path(
    post,
    path = "/me/reauthenticate",
    tag = "account",
    summary = "Re-authenticate to unlock sensitive account operations",
    description = "Verifies a credential the caller already holds and returns a short-lived elevation bound to the caller's session. Every sensitive account operation requires one. Supply exactly one of `password`, `otp_code`, or `recent_authentication: true`. Passwordless realms accept recent authentication only for a verified email account whose same live session authenticated within five minutes and whose FERRISKEY_SSO browser cookie matches the access-token session. Reauthenticate through the normal login flow when stale. Refreshing a token does not renew this interval. Credential changes require a password or recent-authentication proof; OTP alone cannot rotate credentials.",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
    ),
    request_body(
        content = RequestElevationValidator,
        description = "The credential proving the caller is still who they claim",
        content_type = "application/json",
    ),
    responses(
        (status = 200, description = "Elevation granted", body = ElevationResponse),
        (status = 400, description = "Invalid request data, or not exactly one of password and otp_code", body = ApiErrorResponse),
        (status = 401, description = "The proof did not check out, the account is locked, or the token carries no session", body = ApiErrorResponse),
        (status = 403, description = "The caller is not a regular user", body = ApiErrorResponse),
        (status = 404, description = "No such realm", body = ApiErrorResponse),
        (status = 409, description = "The account signs in through an external directory and has no local password", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    )
)]
pub async fn request_elevation(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    CallerSession(session_id): CallerSession,
    cookies: CookieManager,
    ValidateJson(payload): ValidateJson<RequestElevationValidator>,
) -> Result<Response<ElevationResponse>, ApiError> {
    let proof = match (
        payload.password,
        payload.otp_code,
        payload.recent_authentication,
    ) {
        (Some(password), None, false) => ElevationProof::Password(password),
        (None, Some(code), false) => ElevationProof::Otp(code),
        (None, None, true) => ElevationProof::RecentAuthentication {
            sso_cookie: cookies
                .get(SSO_SESSION_COOKIE)
                .map(|cookie| cookie.value().to_string())
                .ok_or_else(|| {
                    ApiError::Forbidden(ApiErrorBody::new(
                        "Recent authentication requires the browser SSO cookie",
                        "elevation_required",
                    ))
                })?,
        },
        _ => {
            return Err(ApiError::BadRequest(ApiErrorBody::new(
                "Supply exactly one of password, otp_code or recent_authentication",
                "invalid_elevation_proof",
            )));
        }
    };

    let elevation = state
        .service
        .request_elevation(
            identity,
            RequestElevationInput {
                realm_name,
                session_id,
                proof,
            },
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Response::OK(ElevationResponse {
        elevation_id: elevation.elevation_id,
        expires_at: elevation.expires_at,
    }))
}
