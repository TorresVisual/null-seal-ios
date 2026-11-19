//! The item types besides login (#61, #62, #63): secure note, Wi-Fi network, software license,
//! recovery codes, authenticator and SSH key. One flat DTO serves all four so a client needs one detail/edit path;
//! a field the type does not use stays empty and is not stored.

use super::*;
use core_vault::ItemType;

/// Full non-login item for the detail and edit views. The secret field per type, which a client
/// masks until asked: `notes` of a note, `password` of a Wi-Fi network, `license_key`, `codes`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemFields {
    pub item_type: ItemType,
    pub title: String,
    pub notes: String,
    pub ssid: String,
    pub security: String,
    pub password: String,
    pub license_key: String,
    pub licensed_to: String,
    /// One recovery code per element.
    pub codes: Vec<String>,
    /// Authenticator secret: an `otpauth://totp/...` URI or a bare base32 secret. The live code
    /// comes from [`Account::login_totp`], which reads this field of any item.
    pub totp: String,
    /// SSH key: the unencrypted OpenSSH private key. Paste or file-import it, or fill it from
    /// [`generate_ssh_key`]. Masked by clients like the other secrets.
    #[serde(default)]
    pub private_key: String,
    /// Derived from `private_key` on read; ignored on save.
    #[serde(default)]
    pub public_key: String,
    /// `SHA256:...` as `ssh-keygen -lf` prints it; derived on read, ignored on save.
    #[serde(default)]
    pub fingerprint: String,
}

impl core::fmt::Debug for ItemFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ItemFields")
            .field("item_type", &self.item_type)
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

impl ItemFields {
    pub fn new(item_type: ItemType) -> Self {
        Self {
            item_type,
            title: String::new(),
            notes: String::new(),
            ssid: String::new(),
            security: String::new(),
            password: String::new(),
            license_key: String::new(),
            licensed_to: String::new(),
            codes: Vec::new(),
            totp: String::new(),
            private_key: String::new(),
            public_key: String::new(),
            fingerprint: String::new(),
        }
    }
}

/// Make a new SSH private key: Ed25519, or RSA of `rsa_bits` (2048 to 8192) when given.
/// Nothing is stored; put the result in [`ItemFields::private_key`] and save.
pub fn generate_ssh_key(rsa_bits: Option<usize>) -> Result<Zeroizing<String>, AccountError> {
    let key = match rsa_bits {
        Some(bits) => core_ssh::generate_rsa(bits),
        None => core_ssh::generate_ed25519(),
    }
    .map_err(AccountError::Ssh)?;
    key.private_openssh().map_err(AccountError::Ssh)
}

/// Public key line and fingerprint of a private key, to preview an import before saving.
pub fn ssh_key_info(private_key: &str) -> Result<(String, String), AccountError> {
    let k = core_ssh::import(private_key).map_err(AccountError::Ssh)?;
    Ok((k.public_openssh(), k.fingerprint()))
}

/// What importing an authenticator export added.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OtpImport {
    pub imported: usize,
    /// Accounts that cannot make a time-based code here (HOTP, MD5).
    pub skipped: usize,
}

impl Account {
    /// Create one authenticator entry per account of a Google Authenticator export link
    /// (`otpauth-migration://`). Importing the same link twice makes the entries twice.
    pub fn import_otp_migration(
        &mut self,
        link: &str,
        now_ms: u64,
    ) -> Result<OtpImport, AccountError> {
        let m = core_otp::parse_migration(link).map_err(AccountError::Otp)?;
        let mut f = ItemFields::new(ItemType::Totp);
        for uri in &m.uris {
            let label = Otp::parse(uri).map_err(AccountError::Otp)?.label();
            f.title = if label.is_empty() {
                "Authenticator".into()
            } else {
                label
            };
            f.totp = uri.to_string();
            self.save_item(None, &f, now_ms)?;
        }
        Ok(OtpImport {
            imported: m.uris.len(),
            skipped: m.skipped,
        })
    }

    /// An item of any type except login (see [`Account::get_login`]).
    pub fn get_item(&self, id: &str) -> Result<ItemFields, AccountError> {
        let p = self.session.open_record(&self.live(id)?)?;
        let d = p.data;
        let private_key = d.private_key.unwrap_or_default();
        let (public_key, fingerprint) = ssh_key_info(&private_key).unwrap_or_default();
        Ok(ItemFields {
            item_type: p.item_type,
            title: d.title,
            notes: d.notes.unwrap_or_default(),
            ssid: d.ssid.unwrap_or_default(),
            security: d.wifi_security.unwrap_or_default(),
            password: d.password.unwrap_or_default(),
            license_key: d.license_key.unwrap_or_default(),
            licensed_to: d.licensed_to.unwrap_or_default(),
            codes: d.codes,
            totp: d.totp.unwrap_or_default(),
            private_key,
            public_key,
            fingerprint,
        })
    }

    /// Create (`id` = `None`) or update a non-login item; unknown fields of an existing item
    /// survive. The type of an existing item cannot change.
    pub fn save_item(
        &mut self,
        id: Option<&str>,
        f: &ItemFields,
        now_ms: u64,
    ) -> Result<String, AccountError> {
        if f.item_type == ItemType::Login {
            return Err(AccountError::Format);
        }
        // An authenticator must hold a time-based secret this build can show a code for.
        let is_totp = f.item_type == ItemType::Totp;
        let totp = if is_totp { f.totp.trim() } else { "" };
        if is_totp && totp_of(Some(totp)).is_none() {
            return Err(AccountError::Format);
        }
        // An SSH key must parse; it is stored re-encoded, so a pasted key is normalised.
        let private_key = if f.item_type == ItemType::SshKey {
            let k = core_ssh::import(&f.private_key).map_err(AccountError::Ssh)?;
            k.private_openssh().map_err(AccountError::Ssh)?
        } else {
            Zeroizing::default()
        };
        let (id, mut payload, old) = match id {
            Some(id) => {
                let p = self.session.open_record(&self.live(id)?)?;
                if p.item_type != f.item_type {
                    return Err(AccountError::Format);
                }
                (id.to_owned(), p.clone(), Some(p))
            }
            None => (
                random_id()?,
                Payload::new(
                    f.item_type,
                    Item {
                        created_at: now_ms,
                        ..Item::default()
                    },
                ),
                None,
            ),
        };
        let d = &mut payload.data;
        let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        d.title = f.title.clone();
        d.notes = opt(&f.notes);
        d.ssid = opt(&f.ssid);
        d.wifi_security = opt(&f.security);
        d.password = opt(&f.password);
        d.license_key = opt(&f.license_key);
        d.licensed_to = opt(&f.licensed_to);
        d.totp = opt(totp);
        d.private_key = opt(&private_key);
        d.codes = f
            .codes
            .iter()
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect();
        d.updated_at = now_ms;
        self.write(&id, old.as_ref(), Some(payload), now_ms)?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests;
