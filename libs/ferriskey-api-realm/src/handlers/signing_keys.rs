use axum::{
    Extension,
    extract::{Path, State},
};
use ferriskey_api_core::api_entities::{
    api_error::{ApiError, ApiErrorResponse},
    response::Response,
};
use ferriskey_api_core::app_state::AppState;
use ferriskey_core::domain::authentication::value_objects::Identity;
use ferriskey_core::domain::jwt::ports::KeyRotation;

#[utoipa::path(
    post,
    path = "/{realm_name}/keys/next",
    tag = "realm",
    summary = "Stage the next signing key of a realm",
    description = "Generates the realm's next signing key, of the type its default_signing_algorithm setting asks for, unless one is already staged. The key is published in the JWKS but does not sign until the realm is rotated.",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "The realm's keys after staging", body = KeyRotation),
        (status = 403, description = "Insufficient permissions", body = ApiErrorResponse),
        (status = 404, description = "Realm not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn stage_signing_key(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> Result<Response<KeyRotation>, ApiError> {
    let outcome = state
        .service
        .stage_realm_signing_key(identity, realm_name)
        .await
        .map_err(ApiError::from)?;

    Ok(Response::OK(outcome))
}

#[utoipa::path(
    post,
    path = "/{realm_name}/keys/rotate",
    tag = "realm",
    summary = "Rotate the signing key of a realm",
    description = "Promotes the realm's next signing key to active, generating it first when none is staged, and retires the previous active key. Retired keys stay in the JWKS and keep verifying until every token they could have signed has expired.",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
    ),
    responses(
        (status = 200, description = "The realm's keys after rotation", body = KeyRotation),
        (status = 403, description = "Insufficient permissions", body = ApiErrorResponse),
        (status = 404, description = "Realm not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn rotate_signing_key(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> Result<Response<KeyRotation>, ApiError> {
    let outcome = state
        .service
        .rotate_realm_signing_key(identity, realm_name)
        .await
        .map_err(ApiError::from)?;

    Ok(Response::OK(outcome))
}
