pub mod application;
pub mod args;

pub mod embedded;
pub use embedded::{FerriskeyApp, HostOptions, SchemaMigrations, build};

pub use ferriskey_core::application::services::ApplicationService;
