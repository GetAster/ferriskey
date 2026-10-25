use chrono::{TimeZone, Utc};

use crate::{domain::realm::entities::Realm, entity::realms::Model};

impl From<Model> for Realm {
    fn from(value: Model) -> Self {
        let created_at = Utc.from_utc_datetime(&value.created_at);
        let updated_at = Utc.from_utc_datetime(&value.updated_at);

        Realm {
            id: value.id.into(),
            name: value.name,
            display_name: value.display_name,
            org_root_pubkey: value.org_root_pubkey,
            settings: None,
            created_at,
            updated_at,
        }
    }
}

impl From<&Model> for Realm {
    fn from(model: &Model) -> Self {
        let created_at = Utc.from_utc_datetime(&model.created_at);
        let updated_at = Utc.from_utc_datetime(&model.updated_at);

        Realm {
            id: model.id.into(),
            name: model.name.clone(),
            display_name: model.display_name.clone(),
            org_root_pubkey: model.org_root_pubkey.clone(),
            settings: None,
            created_at,
            updated_at,
        }
    }
}
