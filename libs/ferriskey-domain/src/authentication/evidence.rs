//! Server-observed proof facts. Never populate these from request hints or protocol mappers.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationEvidence {
    pub authenticated_at: Option<i64>,
    #[serde(flatten)]
    pub method: AuthenticationProof,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub otp_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthenticationProof {
    Passkey {
        credential: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        aaguid: Option<String>,
        uv: bool,
    },
    EmailLink,
    Federated {
        provider: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upstream_sub: Option<String>,
    },
    Password,
    Otp,
}

impl AuthenticationEvidence {
    pub fn new(method: AuthenticationProof) -> Self {
        Self {
            authenticated_at: Some(chrono::Utc::now().timestamp()),
            method,
            otp_verified: false,
        }
    }
    pub fn phishing_resistant(&self) -> bool {
        matches!(self.method, AuthenticationProof::Passkey { .. })
    }
    pub fn claims(&self) -> HashMap<String, serde_json::Value> {
        use serde_json::json;
        let mut claims = HashMap::new();
        let mut amr = match &self.method {
            AuthenticationProof::Passkey { uv: true, .. } => vec!["pop", "user", "mfa"],
            AuthenticationProof::Passkey { uv: false, .. } => vec!["pop", "user"],
            AuthenticationProof::EmailLink | AuthenticationProof::Otp => vec!["otp"],
            AuthenticationProof::Password => vec!["pwd"],
            AuthenticationProof::Federated { .. } => vec![],
        };
        if self.otp_verified && !amr.contains(&"otp") {
            amr.push("otp");
        }
        if self.otp_verified && matches!(self.method, AuthenticationProof::Password) {
            amr.push("mfa");
        }
        if !amr.is_empty() {
            claims.insert("amr".into(), json!(amr));
        }
        if self.phishing_resistant() {
            claims.insert("acr".into(), json!("phr"));
        }
        claims.insert(
            "aster_auth".into(),
            serde_json::to_value(&self.method).expect("proof serializes"),
        );
        if let Some(authenticated_at) = self.authenticated_at {
            claims.insert("auth_time".into(), json!(authenticated_at));
        }
        claims
    }
}

/// Requirements remain attached to the authorization transaction through every continuation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticationRequirements {
    pub essential_acr: Option<Vec<String>>,
    pub preferred_acr: Vec<String>,
    pub max_age: Option<u64>,
    pub requested_at: i64,
}
impl AuthenticationRequirements {
    pub fn parse(
        claims: Option<&str>,
        acr_values: Option<&str>,
        max_age: Option<i64>,
        now: i64,
    ) -> Result<Self, &'static str> {
        let max_age = max_age
            .map(|n| u64::try_from(n).map_err(|_| "negative max_age"))
            .transpose()?;
        let mut result = Self {
            max_age,
            requested_at: now,
            preferred_acr: acr_values
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
            ..Self::default()
        };
        if let Some(claims) = claims {
            let claims: serde_json::Value =
                serde_json::from_str(claims).map_err(|_| "invalid claims JSON")?;
            if !claims.is_object() {
                return Err("claims must be an object");
            }
            if claims
                .get("id_token")
                .is_some_and(|v| !v.is_object() && !v.is_null())
            {
                return Err("id_token claims must be an object");
            }
            if let Some(acr) = claims.get("id_token").and_then(|v| v.get("acr")) {
                if !acr.is_object() && !acr.is_null() {
                    return Err("acr request must be an object");
                }
                if acr.get("essential").is_some_and(|v| !v.is_boolean()) {
                    return Err("essential must be a boolean");
                }
                if acr.get("value").is_some() && acr.get("values").is_some() {
                    return Err("acr cannot specify both value and values");
                }
                if acr.get("essential").and_then(|v| v.as_bool()) == Some(true) {
                    let values = if let Some(value) = acr.get("value") {
                        vec![
                            value
                                .as_str()
                                .ok_or("acr value must be a string")?
                                .to_owned(),
                        ]
                    } else if let Some(values) = acr.get("values") {
                        values
                            .as_array()
                            .ok_or("acr values must be an array")?
                            .iter()
                            .map(|v| {
                                v.as_str()
                                    .map(str::to_owned)
                                    .ok_or("acr value must be a string")
                            })
                            .collect::<Result<Vec<_>, _>>()?
                    } else {
                        vec!["phr".to_owned()]
                    };
                    result.essential_acr = Some(values);
                }
            }
        }
        Ok(result)
    }
    pub fn satisfied(&self, evidence: Option<&AuthenticationEvidence>, now: i64) -> bool {
        if let Some(values) = &self.essential_acr
            && (!values.iter().any(|v| v == "phr")
                || !evidence.is_some_and(AuthenticationEvidence::phishing_resistant))
        {
            return false;
        }
        if let Some(max_age) = self.max_age {
            let Some(evidence) = evidence else {
                return false;
            };
            let Some(authenticated_at) = evidence.authenticated_at else {
                return false;
            };
            if authenticated_at > now {
                return false;
            }
            if max_age == 0 {
                return authenticated_at >= self.requested_at;
            }
            if now.saturating_sub(authenticated_at) as u64 > max_age {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn passkey(uv: bool) -> AuthenticationEvidence {
        AuthenticationEvidence {
            authenticated_at: Some(100),
            method: AuthenticationProof::Passkey {
                credential: "hashed".into(),
                aaguid: None,
                uv,
            },
            otp_verified: false,
        }
    }
    #[test]
    fn passkey_claims_describe_presence_and_verification_separately() {
        assert_eq!(
            passkey(false).claims()["amr"],
            serde_json::json!(["pop", "user"])
        );
        assert_eq!(
            passkey(true).claims()["amr"],
            serde_json::json!(["pop", "user", "mfa"])
        );
        assert_eq!(passkey(false).claims()["acr"], "phr");
        assert!(passkey(true).claims()["aster_auth"].get("aaguid").is_none());
    }
    #[test]
    fn email_and_federation_cannot_claim_phishing_resistance() {
        let email = AuthenticationEvidence::new(AuthenticationProof::EmailLink).claims();
        assert_eq!(email["amr"], serde_json::json!(["otp"]));
        assert!(!email.contains_key("acr"));
        let social = AuthenticationEvidence::new(AuthenticationProof::Federated {
            provider: "google".into(),
            upstream_iss: None,
            upstream_sub: None,
        })
        .claims();
        assert!(!social.contains_key("amr"));
        assert!(!social.contains_key("acr"));
        assert!(social["aster_auth"].get("upstream_iss").is_none());
    }
    #[test]
    fn essential_claim_and_freshness_are_both_enforced() {
        let requirements = AuthenticationRequirements::parse(
            Some(r#"{"id_token":{"acr":{"essential":true,"values":["phr"]}}}"#),
            None,
            Some(300),
            101,
        )
        .unwrap();
        assert!(requirements.satisfied(Some(&passkey(true)), 400));
        assert!(!requirements.satisfied(Some(&passkey(true)), 401));
        assert!(!requirements.satisfied(None, 101));
        assert!(!requirements.satisfied(
            Some(&AuthenticationEvidence::new(AuthenticationProof::EmailLink)),
            101
        ));
    }
    #[test]
    fn preferences_are_not_essential_and_unknown_essential_values_fail() {
        assert!(
            AuthenticationRequirements::parse(None, Some("phr"), None, 0)
                .unwrap()
                .satisfied(None, 0)
        );
        let req = AuthenticationRequirements::parse(
            Some(r#"{"id_token":{"acr":{"essential":true,"value":"phrh"}}}"#),
            None,
            None,
            0,
        )
        .unwrap();
        assert!(!req.satisfied(Some(&passkey(true)), 100));
    }
    #[test]
    fn zero_max_age_means_authenticate_for_this_transaction() {
        let req = AuthenticationRequirements::parse(None, None, Some(0), 101).unwrap();
        assert!(!req.satisfied(Some(&passkey(true)), 102));
        let mut fresh = passkey(true);
        fresh.authenticated_at = Some(101);
        assert!(req.satisfied(Some(&fresh), 102));
        assert!(!req.satisfied(Some(&fresh), 100));
        assert!(AuthenticationRequirements::parse(None, None, Some(-1), 0).is_err());
    }
    #[test]
    fn serialization_roundtrip_preserves_time_and_proofs() {
        let evidence = passkey(true);
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            serde_json::from_value::<AuthenticationEvidence>(json).unwrap(),
            evidence
        );
    }
    #[test]
    fn federation_without_upstream_authentication_time_cannot_prove_freshness() {
        let evidence = AuthenticationEvidence {
            authenticated_at: None,
            method: AuthenticationProof::Federated {
                provider: "google".into(),
                upstream_iss: Some("https://accounts.google.com".into()),
                upstream_sub: Some("subject".into()),
            },
            otp_verified: false,
        };
        assert!(!evidence.claims().contains_key("auth_time"));
        let requirements = AuthenticationRequirements::parse(None, None, Some(300), 100).unwrap();
        assert!(!requirements.satisfied(Some(&evidence), 100));
    }

    #[test]
    fn malformed_essential_claim_is_not_silently_downgraded() {
        for request in [
            r#"{"id_token":{"acr":{"essential":"true","values":["phr"]}}}"#,
            r#"{"id_token":{"acr":{"essential":true,"value":"phr","values":["phr"]}}}"#,
        ] {
            assert!(AuthenticationRequirements::parse(Some(request), None, None, 0).is_err());
        }
    }
}
