use crate::validators::SetOrgRootValidator;
use axum::{
    Extension,
    extract::{Path, State},
};
use ferriskey_api_core::api_entities::{
    api_error::{ApiError, ApiErrorResponse, ValidateJson},
    response::Response,
};
use ferriskey_api_core::app_state::AppState;
use ferriskey_core::domain::authentication::value_objects::Identity;
use ferriskey_core::domain::realm::entities::Realm;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct SetOrgRootResponse {
    pub data: Realm,
}

#[utoipa::path(
    put,
    path = "/{realm_name}/org-root",
    tag = "realm",
    summary = "Set the organisation root public key of a realm",
    description = "Sets the organisation root's Ed25519 public key on the realm, as 64 lowercase hex characters. It is public material and is returned with the realm.",
    params(
        ("realm_name" = String, Path, description = "Realm name"),
    ),
    request_body = SetOrgRootValidator,
    responses(
        (status = 200, description = "Organisation root set", body = SetOrgRootResponse),
        (status = 400, description = "Invalid public key", body = ApiErrorResponse),
        (status = 401, description = "Realm not found", body = ApiErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn set_org_root(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    ValidateJson(payload): ValidateJson<SetOrgRootValidator>,
) -> Result<Response<SetOrgRootResponse>, ApiError> {
    state
        .service
        .set_realm_org_root(identity, realm_name, payload.org_root_pubkey)
        .await
        .map(|data| Response::OK(SetOrgRootResponse { data }))
        .map_err(ApiError::from)
}
