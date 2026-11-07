use axum::extract::{Path, State};
use ferriskey_api_core::app_state::AppState;
use ferriskey_core::domain::portal_theme::{
    entities::PortalPageType,
    validation::{REQUIRED_BLOCKS, required_blocks_for_settings},
};
use ferriskey_core::domain::realm::ports::RealmService;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use ferriskey_api_core::api_entities::{
    api_error::{ApiError, ApiErrorResponse},
    response::Response,
};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PageRequirement {
    pub page_type: PortalPageType,
    pub required_blocks: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PageRequirementsResponse {
    pub data: Vec<PageRequirement>,
}

#[utoipa::path(
    get,
    path = "/portal/page-requirements",
    tag = "portal-theme",
    summary = "Get portal page block requirements",
    description = "Returns the list of block types that must appear in each page's component tree to pass validation.",
    params(
        ("realm_name" = String, Path, description = "Name of the realm"),
    ),
    responses(
        (status = 200, description = "Requirements retrieved successfully", body = PageRequirementsResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
)]
pub async fn get_page_requirements(
    Path(realm_name): Path<String>,
    State(state): State<AppState>,
) -> Result<Response<PageRequirementsResponse>, ApiError> {
    let login = state
        .service
        .get_login_settings(realm_name)
        .await
        .map_err(ApiError::from)?;
    let mut settings =
        ferriskey_core::domain::realm::entities::RealmSetting::new(uuid::Uuid::nil().into(), None);
    settings.passwordless_enabled = login.passwordless_enabled;
    settings.user_registration_enabled = login.user_registration_enabled;
    settings.forgot_password_enabled = login.forgot_password_enabled;
    settings.magic_link_enabled = login.magic_link_enabled;
    let data = REQUIRED_BLOCKS
        .iter()
        .map(|(pt, _)| PageRequirement {
            page_type: *pt,
            required_blocks: required_blocks_for_settings(*pt, Some(&settings))
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        })
        .collect();

    Ok(Response::OK(PageRequirementsResponse { data }))
}
