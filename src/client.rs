//! ACME client implementation (RFC 8555).

use crate::{
    challenge::*,
    config::*,
    directory::*,
    error::*,
    jws::{self, AccountKey, KeyRef, Payload},
    order::{Order, OrderStatus},
};
use reqwest::Url;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use serde_json::{Value, json};
use std::path::Path;
use tokio::sync::Mutex;

/// Maximum time to poll a challenge/order for a terminal state.
const POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Delay between polls.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Captured pieces of an ACME HTTP response we care about.
struct AcmeResponse {
    location: Option<String>,
    body: Vec<u8>,
}

impl AcmeResponse {
    fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| {
            AcmeError::Internal(format!(
                "failed to parse ACME response as {}: {e}; body: {}",
                std::any::type_name::<T>(),
                String::from_utf8_lossy(&self.body)
            ))
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// ACME client for certificate management.
///
/// This client implements the RFC 8555 flow for obtaining and renewing
/// SSL/TLS certificates from providers like Let's Encrypt.
///
/// # Challenge validation
///
/// The client drives account registration, ordering, challenge notification,
/// finalization and certificate download. For **HTTP-01** (the default) the
/// caller is responsible for serving each challenge's `key_authorization` at
/// its `.well-known/acme-challenge/<token>` path *before* calling
/// [`AcmeClient::notify_challenge_ready`] / [`AcmeClient::order_certificate`];
/// for **DNS-01** the caller must publish the TXT record
/// ([`jws::dns01_txt_value`]). The client does not run a challenge web server.
///
/// # Example
///
/// ```no_run
/// use armature_acme::{AcmeClient, AcmeConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = AcmeConfig::lets_encrypt_staging(
///     vec!["admin@example.com".to_string()],
///     vec!["example.com".to_string()],
/// ).with_accept_tos(true);
///
/// let client = AcmeClient::new(config).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct AcmeClient {
    config: AcmeConfig,
    directory: Directory,
    /// Parsed directory URL; every URL the client sends a request to must
    /// share its origin.
    origin: Url,
    http_client: reqwest::Client,
    account_key: Option<AccountKey>,
    account_url: Option<String>,
    /// The most recently observed replay nonce (interior-mutable so that
    /// `&self` request methods can consume and refresh it).
    nonce: Mutex<Option<String>>,
}

impl AcmeClient {
    /// Create a new ACME client and fetch the ACME directory.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use armature_acme::{AcmeClient, AcmeConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = AcmeConfig::lets_encrypt_staging(
    ///     vec!["admin@example.com".to_string()],
    ///     vec!["example.com".to_string()],
    /// );
    ///
    /// let client = AcmeClient::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails with [`AcmeError::InvalidDirectory`] when `directory_url` is not
    /// an `https://` URL, or when the directory advertises an endpoint on a
    /// different origin than the directory itself.
    pub async fn new(config: AcmeConfig) -> Result<Self> {
        let origin = require_https(&config.directory_url)?;

        // `https_only` also stops a redirect from downgrading a request to
        // plain HTTP; the timeouts keep a slow or hostile CA from hanging the
        // renewal task forever.
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .user_agent(concat!("armature-acme/", env!("CARGO_PKG_VERSION")));

        if let Some(pem) = &config.ca_certificate {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| AcmeError::Internal(format!("invalid CA certificate: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }
        let http_client = builder
            .build()
            .map_err(|e| AcmeError::Internal(e.to_string()))?;

        let directory = Self::fetch_directory(&http_client, &config.directory_url).await?;

        Ok(Self {
            config,
            directory,
            origin,
            http_client,
            account_key: None,
            account_url: None,
            nonce: Mutex::new(None),
        })
    }

    /// Fetch the ACME directory and check that every endpoint it advertises is
    /// on the directory's own origin.
    async fn fetch_directory(client: &reqwest::Client, url: &str) -> Result<Directory> {
        let origin = require_https(url)?;
        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(AcmeError::InvalidDirectory(format!(
                "Failed to fetch directory: {}",
                response.status()
            )));
        }

        let directory: Directory = response.json().await?;
        validate_directory(&directory, &origin)?;
        Ok(directory)
    }

    /// Refuse to send a request (and, for signed requests, a JWS) to a URL
    /// that is not on the CA's origin. Order, authorization, challenge,
    /// finalize and certificate URLs all come from CA responses, so this keeps
    /// a tampered response from steering the client at another host.
    fn check_origin(&self, url: &str, what: &str) -> Result<()> {
        require_same_origin(&self.origin, url, what)
    }

    // ----- nonce management -------------------------------------------------

    fn nonce_from(response: &reqwest::Response) -> Option<String> {
        response
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Return a fresh nonce, reusing a stored one or fetching from `newNonce`.
    async fn take_nonce(&self) -> Result<String> {
        if let Some(n) = self.nonce.lock().await.take() {
            return Ok(n);
        }
        self.check_origin(&self.directory.new_nonce, "newNonce")?;
        let response = self
            .http_client
            .head(&self.directory.new_nonce)
            .send()
            .await?;
        Self::nonce_from(&response)
            .ok_or_else(|| AcmeError::Internal("newNonce returned no Replay-Nonce header".into()))
    }

    // ----- signed requests --------------------------------------------------

    /// POST a signed JWS request, managing nonces and retrying once on badNonce.
    async fn post_signed(
        &self,
        url: &str,
        key_ref: KeyRef<'_>,
        payload: Payload<'_>,
    ) -> Result<AcmeResponse> {
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| AcmeError::InvalidAccount("account key not initialized".into()))?;
        self.check_origin(url, "request")?;

        // Retry budget for the anti-replay nonce. A CA may reject a nonce
        // (Pebble deliberately rejects a fraction of good nonces); each retry
        // uses the fresh nonce captured from the rejecting response.
        const MAX_BADNONCE_RETRIES: u32 = 5;
        for attempt in 0..=MAX_BADNONCE_RETRIES {
            let nonce = self.take_nonce().await?;
            let body = jws::sign_jws(key, url, &nonce, key_ref, payload)?;

            let response = self
                .http_client
                .post(url)
                .header("content-type", "application/jose+json")
                .json(&body)
                .send()
                .await?;

            // Always capture the fresh nonce, even on error responses.
            let new_nonce = Self::nonce_from(&response);
            let status = response.status();
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let bytes = response.bytes().await?.to_vec();

            if let Some(n) = new_nonce {
                *self.nonce.lock().await = Some(n);
            }

            if status.is_success() {
                return Ok(AcmeResponse {
                    location,
                    body: bytes,
                });
            }

            // Parse the RFC 7807 problem document.
            let problem: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let problem_type = problem
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let detail = problem
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("(no detail)")
                .to_string();

            if problem_type.ends_with(":badNonce") && attempt < MAX_BADNONCE_RETRIES {
                // Retry with the refreshed nonce captured above.
                continue;
            }

            return Err(Self::problem_error(problem_type, detail, status));
        }
        Err(AcmeError::Internal(
            "signed request failed after nonce retry".into(),
        ))
    }

    fn problem_error(problem_type: &str, detail: String, status: reqwest::StatusCode) -> AcmeError {
        if problem_type.ends_with(":rateLimited") {
            AcmeError::RateLimitExceeded(detail)
        } else if problem_type.ends_with(":accountDoesNotExist")
            || problem_type.ends_with(":unauthorized")
        {
            AcmeError::InvalidAccount(format!("{detail} ({problem_type})"))
        } else {
            AcmeError::OrderFailed(format!(
                "ACME error {status}: {detail} ({})",
                if problem_type.is_empty() {
                    "unknown"
                } else {
                    problem_type
                }
            ))
        }
    }

    /// POST-as-GET a resource and deserialize its JSON body.
    async fn post_as_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let kid = self.kid()?;
        let resp = self
            .post_signed(url, KeyRef::Kid(&kid), Payload::Empty)
            .await?;
        resp.json()
    }

    /// The account URL used as the JWS `kid`.
    fn kid(&self) -> Result<String> {
        self.account_url
            .clone()
            .ok_or_else(|| AcmeError::InvalidAccount("account not registered".into()))
    }

    // ----- account persistence ---------------------------------------------

    fn account_key_path(&self) -> std::path::PathBuf {
        self.config.account_dir.join("account_key.pem")
    }

    fn account_url_path(&self) -> std::path::PathBuf {
        self.config.account_dir.join("account_url.txt")
    }

    fn load_or_generate_key(&self) -> Result<AccountKey> {
        let path = self.account_key_path();
        if path.exists() {
            let pem = std::fs::read_to_string(&path)?;
            let der = jws::pem_to_pkcs8(&pem)?;
            return AccountKey::from_pkcs8(der);
        }
        let key = AccountKey::generate()?;
        create_private_dir(&self.config.account_dir)?;
        set_dir_perms(&self.config.account_dir);
        write_file_atomic(&path, jws::pkcs8_to_pem(key.pkcs8_der()).as_bytes(), 0o600)?;
        Ok(key)
    }

    // ----- protocol flow ----------------------------------------------------

    /// Register a new ACME account, or reuse the persisted key/account.
    ///
    /// The account key is loaded from `account_dir/account_key.pem` if present,
    /// otherwise generated and persisted. Re-registering with the same key is
    /// idempotent — the CA returns the existing account URL.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use armature_acme::{AcmeClient, AcmeConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = AcmeConfig::lets_encrypt_staging(
    /// #     vec!["admin@example.com".to_string()],
    /// #     vec!["example.com".to_string()],
    /// # ).with_accept_tos(true);
    /// # let mut client = AcmeClient::new(config).await?;
    /// client.register_account().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_account(&mut self) -> Result<()> {
        // Fail closed: if the CA advertises Terms of Service and the caller has
        // not agreed, do not attempt registration.
        let tos_advertised = self
            .directory
            .meta
            .as_ref()
            .and_then(|m| m.terms_of_service.as_ref())
            .is_some();
        if !self.config.accept_tos && tos_advertised {
            return Err(AcmeError::InvalidAccount(
                "the CA requires agreeing to its Terms of Service; \
                 set AcmeConfig::with_accept_tos(true)"
                    .into(),
            ));
        }

        let key = self.load_or_generate_key()?;
        self.account_key = Some(key);

        // Build newAccount payload.
        let contact: Vec<String> = self
            .config
            .contact_email
            .iter()
            .filter(|e| !e.trim().is_empty())
            .map(|e| {
                if e.starts_with("mailto:") {
                    e.clone()
                } else {
                    format!("mailto:{e}")
                }
            })
            .collect();

        let mut payload = json!({ "termsOfServiceAgreed": self.config.accept_tos });
        if !contact.is_empty() {
            payload["contact"] = json!(contact);
        }

        // External Account Binding, if configured.
        if let (Some(kid), Some(hmac)) = (&self.config.eab_kid, &self.config.eab_hmac_key) {
            let jwk = self.account_key.as_ref().expect("key just set").jwk();
            let eab = jws::eab_jws(kid, hmac, &self.directory.new_account, &jwk)?;
            payload["externalAccountBinding"] = eab;
        }

        tracing::info!("Registering ACME account");
        let url = self.directory.new_account.clone();
        let resp = self
            .post_signed(&url, KeyRef::Jwk, Payload::Json(&payload))
            .await?;

        let account_url = resp.location.ok_or_else(|| {
            AcmeError::InvalidAccount("newAccount response had no Location header".into())
        })?;
        self.check_origin(&account_url, "account URL")?;
        self.account_url = Some(account_url.clone());

        // Persist the account URL (best effort).
        if create_private_dir(&self.config.account_dir).is_ok() {
            let _ = write_file_atomic(&self.account_url_path(), account_url.as_bytes(), 0o600);
        }

        Ok(())
    }

    /// Create a new certificate order for the configured domains.
    ///
    /// Returns the order URL.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use armature_acme::{AcmeClient, AcmeConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = AcmeConfig::lets_encrypt_staging(
    /// #     vec!["admin@example.com".to_string()],
    /// #     vec!["example.com".to_string()],
    /// # ).with_accept_tos(true);
    /// # let mut client = AcmeClient::new(config).await?;
    /// # client.register_account().await?;
    /// let order_url = client.create_order().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_order(&self) -> Result<String> {
        let kid = self.kid()?;

        if self.config.domains.is_empty() {
            return Err(AcmeError::OrderFailed("no domains configured".into()));
        }

        tracing::info!(
            "Creating certificate order for domains: {:?}",
            self.config.domains
        );

        let identifiers: Vec<Value> = self
            .config
            .domains
            .iter()
            .map(|d| json!({ "type": "dns", "value": d }))
            .collect();
        let payload = json!({ "identifiers": identifiers });

        let url = self.directory.new_order.clone();
        let resp = self
            .post_signed(&url, KeyRef::Kid(&kid), Payload::Json(&payload))
            .await?;
        resp.location.ok_or_else(|| {
            AcmeError::OrderFailed("newOrder response had no Location header".into())
        })
    }

    /// Fetch the challenges for an order, selecting the configured type.
    ///
    /// Returns one [`Http01Challenge`] per authorization. The returned
    /// `key_authorization` is the value to serve for HTTP-01; for DNS-01 pass it
    /// through [`jws::dns01_txt_value`] to derive the TXT record value.
    pub async fn get_challenges(&self, order_url: &str) -> Result<Vec<Http01Challenge>> {
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| AcmeError::InvalidAccount("account key not initialized".into()))?;

        tracing::info!("Fetching challenges for order {order_url}");
        let order: Order = self.post_as_get(order_url).await?;

        let wanted = challenge_type_id(self.config.challenge_type);
        let mut out = Vec::new();

        for auth_url in &order.authorizations {
            let auth: Authorization = self.post_as_get(auth_url).await?;
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.challenge_type == wanted)
                .ok_or_else(|| {
                    AcmeError::ChallengeFailed(format!(
                        "authorization {auth_url} has no {wanted} challenge"
                    ))
                })?;
            // The token ends up in URLs and, for HTTP-01 webroot setups, in
            // filesystem paths — reject anything that is not base64url.
            validate_challenge_token(&challenge.token)?;

            out.push(Http01Challenge {
                token: challenge.token.clone(),
                key_authorization: key.key_authorization(&challenge.token),
                url: challenge.url.clone(),
            });
        }

        Ok(out)
    }

    /// Tell the CA a challenge is ready, then poll it to a terminal state.
    ///
    /// Returns `Ok(())` when the challenge becomes `valid`, or an error carrying
    /// the CA's challenge error when it becomes `invalid` or the poll times out.
    pub async fn notify_challenge_ready(&self, challenge_url: &str) -> Result<()> {
        let kid = self.kid()?;

        tracing::info!("Notifying challenge ready: {challenge_url}");
        // An empty JSON object triggers validation (RFC 8555 §7.5.1).
        let empty = json!({});
        self.post_signed(challenge_url, KeyRef::Kid(&kid), Payload::Json(&empty))
            .await?;

        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        loop {
            let challenge: Challenge = self.post_as_get(challenge_url).await?;
            match challenge.status {
                ChallengeStatus::Valid => return Ok(()),
                ChallengeStatus::Invalid => {
                    let detail = challenge
                        .error
                        .as_ref()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "challenge failed".into());
                    return Err(AcmeError::ChallengeFailed(detail));
                }
                _ => {
                    if std::time::Instant::now() >= deadline {
                        return Err(AcmeError::ChallengeFailed(
                            "timed out waiting for challenge validation".into(),
                        ));
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
    }

    /// Finalize an order: generate a CSR, submit it, and download the cert.
    ///
    /// Returns `(certificate_pem_chain, certificate_private_key_pem)`. The
    /// private key is a freshly generated ECDSA P-256 key matching the CSR.
    /// Returns an error (never empty strings) if finalization fails.
    pub async fn finalize_order(&self, order_url: &str) -> Result<(String, String)> {
        let kid = self.kid()?;

        if self.config.domains.is_empty() {
            return Err(AcmeError::OrderFailed("no domains configured".into()));
        }

        tracing::info!("Finalizing order {order_url}");

        // Generate the certificate keypair + CSR with a SAN per domain.
        let params = rcgen::CertificateParams::new(self.config.domains.clone())
            .map_err(|e| AcmeError::CertificateError(format!("CSR params: {e}")))?;
        let cert_key = rcgen::KeyPair::generate()
            .map_err(|e| AcmeError::CertificateError(format!("keygen: {e}")))?;
        let csr = params
            .serialize_request(&cert_key)
            .map_err(|e| AcmeError::CertificateError(format!("serialize CSR: {e}")))?;
        let csr_der = csr.der();
        let cert_key_pem = cert_key.serialize_pem();

        // Look up the order's finalize URL.
        let order: Order = self.post_as_get(order_url).await?;
        let finalize_url = order.finalize.clone();

        let payload = json!({ "csr": jws::b64url(csr_der) });
        self.post_signed(&finalize_url, KeyRef::Kid(&kid), Payload::Json(&payload))
            .await?;

        // Poll the order until it is valid (certificate ready) or fails.
        let deadline = std::time::Instant::now() + POLL_TIMEOUT;
        let order = loop {
            let order: Order = self.post_as_get(order_url).await?;
            match order.status {
                OrderStatus::Valid => break order,
                OrderStatus::Invalid => {
                    return Err(AcmeError::OrderFailed(
                        "order became invalid during finalization".into(),
                    ));
                }
                _ => {
                    if std::time::Instant::now() >= deadline {
                        return Err(AcmeError::OrderFailed(
                            "timed out waiting for order finalization".into(),
                        ));
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        };

        let cert_url = order
            .certificate
            .ok_or_else(|| AcmeError::OrderFailed("valid order has no certificate URL".into()))?;

        // Download the PEM certificate chain (POST-as-GET returns raw PEM).
        let resp = self
            .post_signed(&cert_url, KeyRef::Kid(&kid), Payload::Empty)
            .await?;
        let cert_pem = resp.text();
        if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(AcmeError::CertificateError(
                "downloaded certificate chain was empty or not PEM".into(),
            ));
        }

        Ok((cert_pem, cert_key_pem))
    }

    /// Obtain a certificate end-to-end.
    ///
    /// Orchestrates register → order → challenges → notify → finalize and
    /// returns `(certificate_pem_chain, private_key_pem)`.
    ///
    /// **Challenge validation must be satisfied out-of-band.** For HTTP-01 the
    /// caller must be serving each challenge's `key_authorization` at its
    /// `.well-known/acme-challenge/<token>` path before this call reaches the
    /// notify step; for DNS-01 the TXT record must be published. To interleave
    /// serving with the flow, drive the steps manually instead:
    /// [`create_order`](Self::create_order) →
    /// [`get_challenges`](Self::get_challenges) → serve/publish →
    /// [`notify_challenge_ready`](Self::notify_challenge_ready) →
    /// [`finalize_order`](Self::finalize_order).
    ///
    /// Returns a real [`AcmeError`] on any failure — never empty strings.
    pub async fn order_certificate(&mut self) -> Result<(String, String)> {
        if self.account_url.is_none() {
            self.register_account().await?;
        }

        let order_url = self.create_order().await?;

        let challenges = self.get_challenges(&order_url).await?;
        for challenge in &challenges {
            self.notify_challenge_ready(&challenge.url).await?;
        }

        self.finalize_order(&order_url).await
    }

    /// Check whether the certificate at `cert_path` should be renewed.
    ///
    /// Returns `true` when the leaf certificate expires within
    /// `renew_before_days`, or when the file is missing/unparseable.
    pub async fn should_renew(&self, cert_path: impl AsRef<Path>) -> Result<bool> {
        let cert_path = cert_path.as_ref();
        if !cert_path.exists() {
            return Ok(true);
        }

        let pem = std::fs::read(cert_path)?;
        // A corrupt/truncated/empty cert file is treated the same as a
        // missing one: renew rather than silently skip (fail-open-to-outage
        // would leave a renewal daemon never renewing a damaged cert).
        let leaf = match CertificateDer::pem_slice_iter(&pem).next().transpose() {
            Ok(Some(leaf)) => leaf,
            Ok(None) | Err(_) => return Ok(true),
        };

        let cert = match x509_parser::parse_x509_certificate(leaf.as_ref()) {
            Ok((_, cert)) => cert,
            Err(_) => return Ok(true),
        };
        let not_after = cert.validity().not_after.timestamp();

        let renew_secs = i64::from(self.config.renew_before_days) * 86_400;
        let threshold = chrono::Utc::now().timestamp() + renew_secs;
        Ok(threshold >= not_after)
    }

    /// Validate and write a certificate chain and private key to `cert_dir`.
    ///
    /// Returns `(cert_path, key_path)`. Rejects empty/whitespace or non-PEM
    /// input with an [`AcmeError`] so an empty result can never be written as a
    /// valid certificate.
    pub async fn save_certificate(
        &self,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(String, String)> {
        if cert_pem.trim().is_empty() || !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(AcmeError::CertificateError(
                "refusing to save empty or non-PEM certificate".into(),
            ));
        }
        if key_pem.trim().is_empty() || !key_pem.contains("-----BEGIN") {
            return Err(AcmeError::CertificateError(
                "refusing to save empty or non-PEM private key".into(),
            ));
        }

        create_private_dir(&self.config.cert_dir)?;

        let cert_path = self.config.cert_dir.join("cert.pem");
        let key_path = self.config.cert_dir.join("key.pem");

        // Write the key first: a crash between the two renames then leaves a
        // new key with the old cert (detected as a mismatch) rather than a
        // world-readable window for the key. The chain is public material.
        write_file_atomic(&key_path, key_pem.as_bytes(), 0o600)?;
        write_file_atomic(&cert_path, cert_pem.as_bytes(), 0o644)?;

        Ok((
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
        ))
    }

    /// Get the ACME directory.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// Get the configuration.
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }

    /// The registered account URL, if `register_account` has succeeded.
    pub fn account_url(&self) -> Option<&str> {
        self.account_url.as_deref()
    }
}

/// The ACME challenge type identifier string (e.g. `http-01`).
fn challenge_type_id(challenge_type: ChallengeType) -> &'static str {
    match challenge_type {
        ChallengeType::Http01 => "http-01",
        ChallengeType::Dns01 => "dns-01",
        ChallengeType::TlsAlpn01 => "tls-alpn-01",
    }
}

/// Parse `url` and require the `https` scheme.
fn require_https(url: &str) -> Result<Url> {
    let parsed = Url::parse(url)
        .map_err(|e| AcmeError::InvalidDirectory(format!("invalid ACME directory URL: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(AcmeError::InvalidDirectory(format!(
            "ACME directory URL must use https, got scheme {:?}",
            parsed.scheme()
        )));
    }
    Ok(parsed)
}

/// Require `url` to parse and share `base`'s origin (scheme, host and port).
fn require_same_origin(base: &Url, url: &str, what: &str) -> Result<()> {
    let parsed = Url::parse(url)
        .map_err(|e| AcmeError::InvalidDirectory(format!("invalid {what} URL from CA: {e}")))?;
    if parsed.origin() != base.origin() {
        return Err(AcmeError::InvalidDirectory(format!(
            "{what} URL {parsed} is not on the ACME directory's origin {}",
            base.origin().ascii_serialization()
        )));
    }
    Ok(())
}

/// Check that every endpoint a directory advertises is on `origin`.
fn validate_directory(directory: &Directory, origin: &Url) -> Result<()> {
    require_same_origin(origin, &directory.new_account, "newAccount")?;
    require_same_origin(origin, &directory.new_order, "newOrder")?;
    require_same_origin(origin, &directory.new_nonce, "newNonce")?;
    require_same_origin(origin, &directory.revoke_cert, "revokeCert")?;
    if let Some(key_change) = &directory.key_change {
        require_same_origin(origin, key_change, "keyChange")?;
    }
    Ok(())
}

/// Create `dir` (and missing parents) with mode `0700` on Unix.
///
/// Directories that already exist keep their mode: they may be shared,
/// operator-managed locations. The atomic write below does not depend on the
/// directory being private.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Atomically replace `path` with `contents`.
///
/// The bytes go to a fresh sibling temp file created `0600` with
/// `O_CREAT | O_EXCL | O_NOFOLLOW` — so a pre-planted file or symlink at the
/// temp name makes the write fail instead of being followed — and are
/// `fsync`ed before the file is given its final `mode` and `rename`d over
/// `path`. `rename` replaces a symlink at `path` rather than writing through
/// it, and readers only ever see the old or the complete new file. The
/// directory is `fsync`ed afterwards so the rename survives a crash.
#[cfg(unix)]
fn write_file_atomic(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = dir.join(temp_name(path));

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let result = (|| {
        file.write_all(contents)?;
        // `mode` above is filtered through the umask; set it exactly.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(not(unix))]
fn write_file_atomic(path: &Path, contents: &[u8], _mode: u32) -> std::io::Result<()> {
    use std::io::Write;

    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = dir.join(temp_name(path));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// A hidden, unpredictable sibling temp-file name for `path`.
fn temp_name(path: &Path) -> String {
    use ring::rand::SecureRandom;

    let mut nonce = [0u8; 8];
    // `SystemRandom` failing is not recoverable in practice; fall back to a
    // fixed suffix, which `O_EXCL` still makes safe (the write just fails if
    // the name is taken).
    let _ = ring::rand::SystemRandom::new().fill(&mut nonce);
    let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let base = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(".{base}.{}.{suffix}.tmp", std::process::id())
}

#[cfg(unix)]
fn set_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_perms(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_directory_invalid_url() {
        let client = reqwest::Client::new();
        let result = AcmeClient::fetch_directory(&client, "https://invalid.example.com").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_access() {
        let config = AcmeConfig::lets_encrypt_staging(
            vec!["admin@example.com".to_string()],
            vec!["example.com".to_string()],
        );
        assert_eq!(config.domains, vec!["example.com"]);
    }

    #[test]
    fn challenge_type_ids() {
        assert_eq!(challenge_type_id(ChallengeType::Http01), "http-01");
        assert_eq!(challenge_type_id(ChallengeType::Dns01), "dns-01");
        assert_eq!(challenge_type_id(ChallengeType::TlsAlpn01), "tls-alpn-01");
    }

    /// A client without a real CA connection, for testing pure-local behavior.
    fn offline_client(config: AcmeConfig) -> AcmeClient {
        AcmeClient {
            config,
            directory: Directory {
                new_account: "https://ca.example/acme/new-acct".into(),
                new_order: "https://ca.example/acme/new-order".into(),
                new_nonce: "https://ca.example/acme/new-nonce".into(),
                revoke_cert: "https://ca.example/acme/revoke".into(),
                key_change: None,
                meta: None,
            },
            origin: Url::parse("https://ca.example/directory").unwrap(),
            http_client: reqwest::Client::new(),
            account_key: None,
            account_url: None,
            nonce: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn save_certificate_rejects_empty() {
        let dir = std::env::temp_dir().join(format!("acme-save-{}", std::process::id()));
        let config = AcmeConfig::default().with_cert_dir(dir.clone());
        let client = offline_client(config);

        assert!(client.save_certificate("", "key").await.is_err());
        assert!(client.save_certificate("   \n  ", "key").await.is_err());
        assert!(
            client
                .save_certificate("not a pem", "-----BEGIN PRIVATE KEY-----")
                .await
                .is_err()
        );
        assert!(
            client
                .save_certificate(
                    "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
                    ""
                )
                .await
                .is_err()
        );

        // A valid-looking pair writes files.
        let ok = client
            .save_certificate(
                "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n",
            )
            .await;
        assert!(ok.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn csr_contains_configured_sans() {
        // Mirrors the CSR construction in `finalize_order`: a CSR built for the
        // configured domains must carry them as SubjectAltName DNS entries.
        let domains = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        let params = rcgen::CertificateParams::new(domains.clone()).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = params.serialize_request(&key).unwrap();
        let der = csr.der();

        use x509_parser::prelude::FromDer;
        let (_, parsed) =
            x509_parser::certification_request::X509CertificationRequest::from_der(der.as_ref())
                .unwrap();
        let exts = parsed
            .requested_extensions()
            .expect("CSR requested extensions");
        let mut found: Vec<String> = Vec::new();
        for ext in exts {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(n) = gn {
                        found.push(n.to_string());
                    }
                }
            }
        }
        for d in &domains {
            assert!(found.contains(d), "CSR SANs {found:?} must contain {d}");
        }
    }

    #[test]
    fn directory_url_must_be_https() {
        assert!(require_https("https://acme.example/dir").is_ok());
        for bad in [
            "http://acme.example/dir",
            "ftp://acme.example/dir",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(
                matches!(require_https(bad), Err(AcmeError::InvalidDirectory(_))),
                "accepted {bad}"
            );
        }
    }

    #[tokio::test]
    async fn new_rejects_plain_http_directory_without_network() {
        let config = AcmeConfig::new(
            "http://127.0.0.1:9/directory",
            vec![],
            vec!["example.com".into()],
        );
        let err = AcmeClient::new(config).await.unwrap_err();
        assert!(matches!(err, AcmeError::InvalidDirectory(_)), "{err}");
    }

    #[test]
    fn directory_endpoints_must_share_origin() {
        let origin = Url::parse("https://ca.example/directory").unwrap();
        let good = Directory {
            new_account: "https://ca.example/acme/new-acct".into(),
            new_order: "https://ca.example/acme/new-order".into(),
            new_nonce: "https://ca.example/acme/new-nonce".into(),
            revoke_cert: "https://ca.example/acme/revoke".into(),
            key_change: Some("https://ca.example/acme/key-change".into()),
            meta: None,
        };
        assert!(validate_directory(&good, &origin).is_ok());

        for (field, url) in [
            ("new_account", "https://evil.example/acme/new-acct"),
            ("new_order", "http://ca.example/acme/new-order"),
            ("new_nonce", "https://ca.example:8443/acme/new-nonce"),
            ("revoke_cert", "https://ca.example.evil.example/revoke"),
            ("key_change", "https://169.254.169.254/latest"),
        ] {
            let mut d = good.clone();
            match field {
                "new_account" => d.new_account = url.into(),
                "new_order" => d.new_order = url.into(),
                "new_nonce" => d.new_nonce = url.into(),
                "revoke_cert" => d.revoke_cert = url.into(),
                _ => d.key_change = Some(url.into()),
            }
            assert!(
                validate_directory(&d, &origin).is_err(),
                "accepted off-origin {field} = {url}"
            );
        }
    }

    #[tokio::test]
    async fn signed_requests_refuse_off_origin_urls() {
        let mut client = offline_client(AcmeConfig::default());
        client.account_key = Some(AccountKey::generate().unwrap());
        client.account_url = Some("https://ca.example/acme/acct/1".into());

        // Fails at the origin check, before any nonce fetch or network I/O.
        let err = client
            .post_as_get::<Value>("https://evil.example/acme/order/1")
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::InvalidDirectory(_)), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_mode_and_replaces_symlink_without_following() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("acme-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_private_dir(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );

        // A symlink planted at the key path must be replaced, not written through.
        let victim = dir.join("victim");
        std::fs::write(&victim, b"original").unwrap();
        let key = dir.join("key.pem");
        std::os::unix::fs::symlink(&victim, &key).unwrap();

        write_file_atomic(&key, b"secret", 0o600).unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        let meta = std::fs::symlink_metadata(&key).unwrap();
        assert!(meta.file_type().is_file(), "symlink was followed");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&key).unwrap(), b"secret");

        // Public material gets the requested mode; no temp files are left.
        let cert = dir.join("cert.pem");
        write_file_atomic(&cert, b"chain", 0o644).unwrap();
        assert_eq!(
            std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn save_certificate_creates_private_dir_and_key() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("acme-perms-{}/certs", std::process::id()));
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
        let client = offline_client(AcmeConfig::default().with_cert_dir(dir.clone()));
        let (_, key_path) = client
            .save_certificate(
                "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n",
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[tokio::test]
    async fn should_renew_missing_file_is_true() {
        let client = offline_client(AcmeConfig::default());
        assert!(
            client
                .should_renew("/nonexistent/path/cert.pem")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn should_renew_honors_boundary() {
        use rcgen::{CertificateParams, KeyPair};
        use time::{Duration, OffsetDateTime};

        // Build a self-signed cert expiring `days` from now, write it, return path.
        fn write_cert_expiring_in(days: i64, tag: &str) -> std::path::PathBuf {
            let mut params = CertificateParams::new(vec!["renew.example".to_string()]).unwrap();
            params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
            params.not_after = OffsetDateTime::now_utc() + Duration::days(days);
            let key = KeyPair::generate().unwrap();
            let pem = params.self_signed(&key).unwrap().pem();
            let path = std::env::temp_dir().join(format!(
                "acme-renew-{tag}-{}-{days}.pem",
                std::process::id()
            ));
            std::fs::write(&path, pem).unwrap();
            path
        }

        // Cert expiring in 40 days, renew window 30 days -> NOT due for renewal.
        let far = write_cert_expiring_in(40, "far");
        let config = AcmeConfig::default().with_renew_before_days(30);
        let client = offline_client(config);
        assert!(
            !client.should_renew(&far).await.unwrap(),
            "cert 40d out with 30d window should not renew"
        );

        // Cert expiring in 10 days, renew window 30 days -> due for renewal.
        let near = write_cert_expiring_in(10, "near");
        assert!(
            client.should_renew(&near).await.unwrap(),
            "cert 10d out with 30d window should renew"
        );

        let _ = std::fs::remove_file(&far);
        let _ = std::fs::remove_file(&near);
    }
}
