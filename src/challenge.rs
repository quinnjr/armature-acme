/// ACME challenge types and handling
use serde::{Deserialize, Serialize};

/// ACME authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// Authorization identifier
    pub identifier: crate::order::Identifier,

    /// Authorization status
    pub status: AuthorizationStatus,

    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// List of challenges
    pub challenges: Vec<Challenge>,

    /// Wildcard indicator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard: Option<bool>,
}

/// Authorization status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    /// Authorization is pending
    Pending,
    /// Authorization is valid
    Valid,
    /// Authorization is invalid
    Invalid,
    /// Authorization is deactivated
    Deactivated,
    /// Authorization has expired
    Expired,
    /// Authorization is revoked
    Revoked,
}

/// ACME challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge type
    #[serde(rename = "type")]
    pub challenge_type: String,

    /// Challenge URL
    pub url: String,

    /// Challenge status
    pub status: ChallengeStatus,

    /// Challenge token.
    ///
    /// Defaults to empty when absent: some newer challenge types advertised by
    /// a CA (e.g. `dns-persist-01`) carry no token, and must not break parsing
    /// of the surrounding authorization.
    #[serde(default)]
    pub token: String,

    /// Validation record (for DNS challenges)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,

    /// Error details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

/// Challenge status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    /// Challenge is pending
    Pending,
    /// Challenge is processing
    Processing,
    /// Challenge is valid
    Valid,
    /// Challenge is invalid
    Invalid,
}

/// Validate an ACME challenge token received from the CA.
///
/// RFC 8555 §8.3 defines the token as base64url (`[A-Za-z0-9_-]`) with no
/// padding. Anything else — notably `/`, `.` or `..` — is rejected so a
/// hostile or compromised CA cannot make a caller that builds a webroot path
/// from the token (`webroot.join(".well-known/acme-challenge").join(token)`)
/// read or write outside the challenge directory.
///
/// # Example
///
/// ```
/// use armature_acme::validate_challenge_token;
///
/// assert!(validate_challenge_token("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA").is_ok());
/// assert!(validate_challenge_token("../../etc/passwd").is_err());
/// assert!(validate_challenge_token("").is_err());
/// ```
pub fn validate_challenge_token(token: &str) -> crate::error::Result<()> {
    if !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Ok(())
    } else {
        Err(crate::error::AcmeError::ChallengeFailed(format!(
            "CA returned a malformed challenge token ({} bytes); expected base64url",
            token.len()
        )))
    }
}

/// HTTP-01 challenge data
///
/// Challenges returned by [`AcmeClient::get_challenges`](crate::AcmeClient::get_challenges)
/// always carry a token that passed [`validate_challenge_token`]. If you build
/// one yourself, validate the token before using it in a filesystem path.
#[derive(Debug, Clone)]
pub struct Http01Challenge {
    /// Challenge token
    pub token: String,

    /// Key authorization
    pub key_authorization: String,

    /// Challenge URL
    pub url: String,
}

impl Http01Challenge {
    /// Get the path where the challenge should be served
    pub fn path(&self) -> String {
        format!("/.well-known/acme-challenge/{}", self.token)
    }

    /// Get the content that should be served at the challenge path
    pub fn content(&self) -> &str {
        &self.key_authorization
    }
}

/// DNS-01 challenge data
#[derive(Debug, Clone)]
pub struct Dns01Challenge {
    /// Challenge token
    pub token: String,

    /// DNS record value (base64url encoded SHA-256 hash)
    pub dns_value: String,

    /// Challenge URL
    pub url: String,
}

impl Dns01Challenge {
    /// Get the DNS record name
    pub fn record_name(&self, domain: &str) -> String {
        format!("_acme-challenge.{}", domain)
    }

    /// Get the DNS record value
    pub fn record_value(&self) -> &str {
        &self.dns_value
    }
}

/// TLS-ALPN-01 challenge data
#[derive(Debug, Clone)]
pub struct TlsAlpn01Challenge {
    /// Challenge token
    pub token: String,

    /// Key authorization
    pub key_authorization: String,

    /// Challenge URL
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http01_challenge_path() {
        let challenge = Http01Challenge {
            token: "test_token".to_string(),
            key_authorization: "test_key_auth".to_string(),
            url: "https://example.com/challenge".to_string(),
        };

        assert_eq!(challenge.path(), "/.well-known/acme-challenge/test_token");
        assert_eq!(challenge.content(), "test_key_auth");
    }

    #[test]
    fn challenge_token_rejects_path_traversal_and_non_base64url() {
        for bad in [
            "", "..", "../x", "a/b", "a\\b", "tok en", "tok.en", "tok%2Fen", "tok=", "tok\n",
            "t\u{e9}",
        ] {
            assert!(validate_challenge_token(bad).is_err(), "accepted {bad:?}");
        }
        for good in [
            "abc",
            "A-b_9",
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
        ] {
            assert!(validate_challenge_token(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn test_dns01_challenge_record() {
        let challenge = Dns01Challenge {
            token: "test_token".to_string(),
            dns_value: "test_dns_value".to_string(),
            url: "https://example.com/challenge".to_string(),
        };

        assert_eq!(
            challenge.record_name("example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(challenge.record_value(), "test_dns_value");
    }

    #[test]
    fn test_challenge_status_serialization() {
        let status = ChallengeStatus::Valid;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"valid\"");
    }
}
