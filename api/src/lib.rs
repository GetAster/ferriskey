pub mod application;
pub mod args;

pub mod embedded;
pub use embedded::{FerriskeyApp, HostOptions, SchemaMigrations, build};

pub use ferriskey_core::application::services::ApplicationService;
/// Authentication operations available through the embedded application service.
pub use ferriskey_core::domain::authentication::ports::AuthService;
/// Domain errors returned by the embedded application service.
pub use ferriskey_core::domain::common::entities::app_errors::CoreError;

pub use ferriskey_core::domain::authentication::issuance;
pub use issuance::{
    IssueAccessTokenError, IssueAccessTokenInput, IssueAccessTokenOutput, TokenConfirmation,
};

pub use ferriskey_core::domain::authentication::service_account;
pub use service_account::{
    EnsureServiceAccountError, EnsureServiceAccountInput, EnsureServiceAccountOutput,
};
