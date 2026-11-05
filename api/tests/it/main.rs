//! Merged integration-test binary for ferriskey-api.
//!
//! Rust-dev house rule: one integration-test binary per crate, one module
//! per area. Each former test binary is a module below and still runs as
//! its own process (and its own Postgres schema) via `sh/rust-tests.sh`,
//! which filters this binary per top-level module. To run one area locally:
//!
//! ```text
//! cargo test -p ferriskey-api --test it <area>:: -- --include-ignored
//! ```
//!
//! The `oidc_bdd` cucumber suite stays its own binary (`harness = false`;
//! its runner exits the process), see `scripts/test-targets.allow`.

mod abyss_cross_realm_test;
mod account_lockout_test;
mod account_security_test;
mod auth_session_cross_realm_test;
mod authz_management_test;
mod authzen_test;
mod backchannel_logout_test;
mod broker_login_pkce_test;
mod client_credentials_profile_test;
mod client_credentials_roles_test;
mod client_credentials_test;
mod client_cross_realm_test;
mod client_scopes_listing_test;
mod clients_listing_test;
mod common;
mod compass_flows_listing_test;
mod consent_test;
mod credential_cross_realm_test;
mod device_flow_test;
mod email_templates_listing_test;
mod federation_providers_listing_test;
mod group_members_listing_test;
mod identity_providers_listing_test;
mod login_action_root_path_test;
mod login_aliases_test;
mod login_completion_gate_test;
mod login_statement_budget_test;
mod maintenance_cross_realm_test;
mod management_api_audience_test;
mod mcp_cimd_dcr_test;
mod mcp_protocol_test;
mod mcp_resource_owner_test;
mod me_profile_test;
mod mfa_bypass_test;
mod nonce_id_token_test;
mod observability_cross_realm_test;
mod oidc_conformance_test;
mod oidc_cross_realm_test;
mod oidc_findings_test;
mod opaque_refresh_token_test;
mod organization_cross_realm_test;
mod organization_groups_listing_test;
mod organization_members_listing_test;
mod organization_test;
mod organizations_listing_test;
mod password_import_test;
mod password_policy_test;
mod pkce_test;
mod portal_layouts_listing_test;
mod portal_theme_test;
mod portal_themes_listing_test;
mod realm_cross_realm_test;
mod realm_lifecycle_test;
mod realm_scope_ratchet_test;
mod realms_listing_test;
mod redirect_uri_validation_test;
mod refresh_in_place_rotation_test;
mod refresh_token_rotation_test;
mod registration_test;
mod required_action_flow_test;
mod role_cross_realm_test;
mod roles_listing_test;
mod saml_cross_realm_test;
mod saml_test;
mod scope_cross_realm_test;
mod sealed_secrets_test;
mod seawatch_test;
mod security_events_listing_test;
mod session_cross_realm_test;
mod session_management_test;
mod session_participants_test;
mod sso_session_test;
mod supplied_user_id_test;
mod token_basic_auth_test;
mod token_endpoint_throttle_test;
mod token_exchange_policy_test;
mod token_exchange_test;
mod token_resource_direct_grants_test;
mod token_revocation_test;
mod token_state_cache_test;
mod token_subject_cache_test;
mod trident_cross_realm_test;
mod user_cross_realm_test;
mod user_privilege_bound_test;
mod user_sessions_listing_test;
mod users_listing_test;
mod web_origin_test;
mod webapp_url_from_request_test;
mod webhook_deliveries_listing_test;
mod webhook_delivery_api_test;
mod webhooks_listing_test;
