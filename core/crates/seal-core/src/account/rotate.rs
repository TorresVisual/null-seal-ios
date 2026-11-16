//! Device registry, revocation and key rotation (#44, SR-10).
//!
//! A revoked device still knows the Account Key (AK) and every Vault Key (VK), so removing it
//! from the relay is not enough: everything it could read must stop being what new data is
//! sealed under. Revocation therefore rotates (ADR 0001, "Operations"):
//!
//! ```text
//!  revoking device R                      relay                     remaining device B
//!   new AK', VK', master + recovery wrappers
//!   one sealed bundle per remaining device ---- POST /rotate ----> drops the revoked rows,
//!   (X25519 to the device + old AK binding)      (one atomic       keeps one bundle per device
//!   install own bundle, re-seal every record     step: the         <--- GET /rekey ---- (next sync)
//!   under VK' (fresh hlc), push                  commit point)     install, re-seal anything
//!                                                                  still under the old key, push
//! ```
//!
//! The relay is untrusted, so it is never asked who the remaining devices are: each device
//! publishes an attestation (its keys, sealed under the AK) and the revoking device only
//! delivers keys to devices whose attestation opens under the AK and matches the relay's key.
//! A device the relay invented opens nothing and gets nothing.
//!
//! Residual (threat model T1+T2): a revoked device that also controls the relay still holds
//! the old AK, so it could forge a bundle for a device that has not rotated yet. Rotation
//! protects against a stolen device or a compromised relay alone, not both together.

use super::*;
use core_keys::{open_from, seal_to};
use core_sync::devices::{self, RemoteDevice};

/// One row of the device list. The relay only stores what devices hand it, so `verified`
/// tells whether the device proved itself to the account (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: String,
    /// When the relay registered the device (relay clock, Unix ms).
    pub created_at: u64,
    /// When the relay last saw a request from it (relay clock, Unix ms); the relay rounds it.
    pub last_seen: Option<u64>,
    pub current: bool,
    pub verified: bool,
}

/// A revocation being prepared: the chosen devices, the confirmed master password and the new
/// recovery key, which must be retyped before [`Account::finish_revocation`] changes anything.
pub struct Revocation {
    revoke: Vec<String>,
    password: Zeroizing<String>,
    recovery: Key,
}

impl Revocation {
    /// Whether `typed` is the new recovery code, so a UI can let the user retry a typo instead of
    /// discarding the revocation ([`Account::finish_revocation`] consumes it either way).
    pub fn recovery_matches(&self, typed: &str) -> bool {
        verify_retyped(&self.recovery, typed)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RevocationReport {
    pub revoked: usize,
    /// Remaining devices (this one included) that were handed the new keys.
    pub rekeyed: usize,
    /// Records of this device re-sealed under the new key.
    pub reencrypted: usize,
    /// `false`: the rotation is done but pushing the re-sealed records was cut short; the rest
    /// stays queued and the next sync finishes it.
    pub synced: bool,
}

/// A relay device row plus the X25519 key it has proven to the account, if any.
struct Peer {
    dev: RemoteDevice,
    x_pub: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct Attest {
    pubkey: String,
    x_pub: String,
    /// The vaults this device holds (#130), so devices that missed a `create_vault` learn of it
    /// at their next sync. Sealed under the Account Key like the rest: the relay can neither
    /// read nor forge a grant, and a revoked device's copy stops opening at the next rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    vaults: Vec<VaultMeta>,
}

fn attest_ctx(device_id: &str) -> Vec<u8> {
    context(&[b"device-attest", device_id.as_bytes()])
}

fn rekey_ctx(device_id: &str, ak_gen: u32) -> Vec<u8> {
    context(&[b"rekey", device_id.as_bytes(), &ak_gen.to_be_bytes()])
}

/// A device's attestation, if it opens under `ak` and agrees with the signing key the relay
/// lists for the device.
fn open_attest(ak: &Key, d: &RemoteDevice) -> Option<Attest> {
    let (_, pt) = open(ak, &attest_ctx(&d.id), d.attest.as_deref()?).ok()?;
    let a: Attest = serde_json::from_slice(&pt).ok()?;
    (key32(&a.pubkey)? == d.pubkey).then_some(a)
}

fn key32(s: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(unb64(s).ok()?).ok()
}

/// The X25519 key a device vouched for, if its attestation checks out.
fn attested_x_pub(ak: &Key, d: &RemoteDevice) -> Option<[u8; 32]> {
    key32(&open_attest(ak, d)?.x_pub)
}

/// A vault grant is only taken whole: sane id, every wrapped key opens under `ak` (so it is ours,
/// not noise) and the name opens too (a bad one would break the vault list).
fn grant_is_valid(ak: &Key, v: &VaultMeta) -> bool {
    let wraps = |g: u32, w: &str| {
        unb64(w).is_ok_and(|b| core_keys::unwrap_vault_key(ak, v.id.as_bytes(), g, &b).is_ok())
    };
    (1..=80).contains(&v.id.len())
        && wraps(v.key_gen, &v.wrapped_key)
        && v.old.iter().all(|o| wraps(o.key_gen, &o.wrapped_key))
        && vaults::open_name(ak, v).is_ok()
}

impl Account {
    fn registry(&self, t: &dyn Transport, now_ms: u64) -> Result<Vec<Peer>, AccountError> {
        let (ak, me) = (self.session.account_key()?, self.device()?);
        Ok(devices::list(t, me, now_ms)?
            .into_iter()
            .map(|d| {
                let x_pub = if d.id == me.id {
                    me.x_public().ok()
                } else {
                    attested_x_pub(ak, &d)
                };
                Peer { dev: d, x_pub }
            })
            .collect())
    }

    /// The relay's device list, checked against the account. Needs the vault unlocked.
    pub fn list_devices(
        &self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<Vec<DeviceInfo>, AccountError> {
        let me = self.device()?.id.clone();
        Ok(self
            .registry(transport, now_ms)?
            .into_iter()
            .map(|Peer { dev, x_pub }| DeviceInfo {
                current: dev.id == me,
                verified: x_pub.is_some(),
                id: dev.id,
                created_at: dev.created_at,
                last_seen: dev.last_seen,
            })
            .collect())
    }

    /// Publish this device's attestation once per Account Key generation, and again whenever its
    /// vault list has grown (#130).
    pub(super) fn publish_attest(
        &mut self,
        t: &dyn Transport,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let gen_now = self.meta.shared.ak_gen;
        let n_vaults = self.meta.shared.vaults.len();
        if self.meta.attested == Some(gen_now) && self.meta.attested_vaults == n_vaults {
            return Ok(());
        }
        let device = self.device()?;
        let body = serde_json::to_vec(&Attest {
            pubkey: b64(&device.public_key()),
            x_pub: b64(&device.x_public()?),
            vaults: self.meta.shared.vaults.clone(),
        })
        .map_err(|_| AccountError::Format)?;
        let blob = seal(
            self.session.account_key()?,
            gen_now,
            &attest_ctx(&device.id),
            &body,
        )?;
        devices::publish_attest(t, device, now_ms, &blob)?;
        self.meta.attested = Some(gen_now);
        self.meta.attested_vaults = n_vaults;
        save_meta(&self.store, &self.meta)
    }

    /// Adopt vaults other devices created (#130): read the attestations on the relay, keep every
    /// vault we do not have whose grant opens under our Account Key, and open it. Returns how
    /// many were added. Must run before pulling, so the vault's records can be verified.
    pub(super) fn receive_vaults(
        &mut self,
        t: &dyn Transport,
        now_ms: u64,
    ) -> Result<usize, AccountError> {
        let mut new: Vec<VaultMeta> = Vec::new();
        {
            let (ak, me) = (self.session.account_key()?, self.device()?);
            let known = &self.meta.shared.vaults;
            for d in devices::list(t, me, now_ms)? {
                let Some(a) = open_attest(ak, &d).filter(|_| d.id != me.id) else {
                    continue;
                };
                for v in a.vaults {
                    let seen = known.iter().chain(&new).any(|k| k.id == v.id);
                    if !seen && grant_is_valid(ak, &v) {
                        new.push(v);
                    }
                }
            }
        }
        if new.is_empty() {
            return Ok(0);
        }
        let first = self.meta.shared.vaults.len();
        let mut meta = self.meta.clone();
        meta.shared.vaults.extend(new);
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        let entries = vault_entries(&self.meta.shared)?;
        for e in &entries[first..] {
            if let Err(err) = self.session.add_vault(&self.store, e) {
                // disk has the vault, memory does not: lock so the next unlock reads the disk
                self.lock();
                return Err(err.into());
            }
        }
        Ok(entries.len() - first)
    }

    /// First step of revoking `revoke` (and rotating the keys): checks the master password and
    /// makes the new recovery code to show once. Nothing changes until
    /// [`finish_revocation`](Self::finish_revocation). An empty list is a plain rotation.
    pub fn begin_revocation(
        &self,
        password: &str,
        revoke: Vec<String>,
    ) -> Result<(Revocation, Zeroizing<String>), AccountError> {
        self.session.account_key()?;
        if revoke.contains(&self.meta.device_id) {
            return Err(AccountError::RevokeSelf);
        }
        // The password is about to wrap the new Account Key; a typo would lock everyone out.
        self.check_master_password(password)?;
        let recovery = new_recovery_key()?;
        let code = encode_recovery_key(&recovery);
        Ok((
            Revocation {
                revoke,
                password: Zeroizing::new(password.to_owned()),
                recovery,
            },
            code,
        ))
    }

    /// Revoke the devices and rotate every key, if `typed` is the new recovery code. The relay
    /// step is atomic; if it fails nothing changed. Once it succeeded the rotation is final and
    /// this method only reports trouble in the re-sealing that follows through
    /// [`RevocationReport::synced`].
    pub fn finish_revocation(
        &mut self,
        rev: Revocation,
        typed: &str,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<RevocationReport, AccountError> {
        if !verify_retyped(&rev.recovery, typed) {
            return Err(AccountError::RecoveryMismatch);
        }
        // Re-seal what is current, not what we last happened to pull.
        self.sync(transport, now_ms)?;

        let registry = self.registry(transport, now_ms)?;
        if rev
            .revoke
            .iter()
            .any(|id| !registry.iter().any(|p| &p.dev.id == id))
        {
            return Err(AccountError::UnknownDevice);
        }
        let keep: Vec<_> = registry
            .iter()
            .filter(|p| !rev.revoke.contains(&p.dev.id))
            .collect();
        let unverified: Vec<String> = keep
            .iter()
            .filter(|p| p.x_pub.is_none())
            .map(|p| p.dev.id.clone())
            .collect();
        if !unverified.is_empty() {
            return Err(AccountError::UnverifiedDevices(unverified));
        }

        let (bundle, targets, auth) = {
            let s = &self.meta.shared;
            let header = header_of(s)?;
            let ak = new_account_key()?;
            let ak_gen = s.ak_gen + 1;
            let mut vaults = Vec::with_capacity(s.vaults.len());
            for v in &s.vaults {
                let wrap = |g: u32, k: &Key| {
                    wrap_vault_key(&ak, ak_gen, v.id.as_bytes(), g, k).map(|b| b64(&b))
                };
                let key_gen = self.session.key_gen(&v.id)? + 1;
                let name = vaults::open_name(self.session.account_key()?, v)?;
                vaults.push(VaultMeta {
                    name: vaults::seal_name(&ak, ak_gen, &v.id, &name)?,
                    id: v.id.clone(),
                    key_gen,
                    wrapped_key: wrap(key_gen, &new_vault_key()?)?,
                    old: self
                        .session
                        .keyring(&v.id)?
                        .into_iter()
                        .map(|(g, k)| {
                            Ok(OldKey {
                                key_gen: g,
                                wrapped_key: wrap(g, k)?,
                            })
                        })
                        .collect::<Result<_, AccountError>>()?,
                });
            }
            let master = Wrapper::Master {
                password: &rev.password,
                header: &header,
            };
            let bundle = Bundle {
                shared: Shared {
                    master_wrapper: b64(&wrap_account_key(&ak, &master)?),
                    recovery_wrapper: b64(&wrap_account_key(
                        &ak,
                        &Wrapper::Recovery(&rev.recovery),
                    )?),
                    ak_gen,
                    vaults,
                    ..s.clone()
                },
                ak: b64(ak.expose()),
            };
            let plain =
                Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| AccountError::Format)?);
            let old_ak = self.session.account_key()?;
            let targets = keep
                .iter()
                .map(|p| {
                    let x_pub = p.x_pub.ok_or(AccountError::Format)?;
                    let ctx = rekey_ctx(&p.dev.id, ak_gen);
                    let sealed = seal_to(&x_pub, old_ak.expose(), &ctx, &plain)?;
                    Ok((
                        p.dev.id.clone(),
                        [ak_gen.to_be_bytes().as_slice(), &sealed].concat(),
                    ))
                })
                .collect::<Result<Vec<_>, AccountError>>()?;
            (bundle, targets, devices::account_auth(&ak)?)
        };

        // The commit point: from here the revoked devices are out and the keys have moved.
        let device = self.device()?;
        devices::rotate(transport, device, now_ms, &rev.revoke, &targets, &auth)?;
        // Ours comes from memory; if this fails the same bundle waits on the relay for next sync.
        self.install_bundle(bundle)?;
        let _ = devices::clear_rekey(transport, self.device()?, now_ms);

        let reencrypted = self.reencrypt_stale(now_ms)?;
        Ok(RevocationReport {
            revoked: rev.revoke.len(),
            rekeyed: targets.len(),
            reencrypted,
            synced: self.sync(transport, now_ms).is_ok(),
        })
    }

    /// Adopt a rotated key set: validate it fully, persist, then swap the live keys.
    fn install_bundle(&mut self, bundle: Bundle) -> Result<(), AccountError> {
        let s = &bundle.shared;
        header_of(s)?;
        if s.account_id != self.meta.shared.account_id
            || s.ak_gen <= self.meta.shared.ak_gen
            || self
                .meta
                .shared
                .vaults
                .iter()
                .any(|v| !s.vaults.iter().any(|n| n.id == v.id))
        {
            return Err(AccountError::Format);
        }
        let ak = Key::from_bytes(
            unb64(&bundle.ak)?
                .try_into()
                .map_err(|_| AccountError::Format)?,
        );
        let entries = vault_entries(s)?;
        for e in &entries {
            // fails unless the new Account Key really opens the new Vault Keys
            core_keys::unwrap_vault_key(&ak, e.id.as_bytes(), e.key_gen, &e.wrapped_key)
                .map_err(|_| AccountError::Crypto)?;
        }
        let seed = &self.device()?.seed;
        let device_seed = b64(&seal(
            &ak,
            s.ak_gen,
            &seed_ctx(&self.meta.device_id),
            seed.expose(),
        )?);
        let mut meta = self.meta.clone();
        meta.shared = bundle.shared;
        meta.device_seed = device_seed;
        meta.attested = None;
        meta.acct_published = None;
        // wraps the retired Account Key; the user turns it on again to wrap the new one
        meta.device_wrapper = None;
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        if let Err(e) = self
            .session
            .rekey(&self.store, ak, &vault_entries(&self.meta.shared)?)
        {
            // disk holds the new keys, memory the old: lock so the next unlock reads the disk
            self.lock();
            return Err(e.into());
        }
        Ok(())
    }

    /// Pick up and install the key bundle the relay holds for this device, if any.
    pub(super) fn receive_rekey(
        &mut self,
        t: &dyn Transport,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let Some(blob) = devices::fetch_rekey(t, self.device()?, now_ms)? else {
            return Ok(());
        };
        let Some((gen_bytes, sealed)) = blob.split_first_chunk::<4>() else {
            return Ok(());
        };
        let ak_gen = u32::from_be_bytes(*gen_bytes);
        if ak_gen > self.meta.shared.ak_gen {
            let plain = {
                let (x, ak) = (self.device()?.x_secret()?, self.session.account_key()?);
                open_from(
                    &x,
                    ak.expose(),
                    &rekey_ctx(&self.meta.device_id, ak_gen),
                    sealed,
                )
            };
            // A bundle that does not open is not ours (or the relay is playing games): leave
            // it, keep working with the keys we have. Newer records then surface as `Deferred`.
            let Ok(plain) = plain else {
                return Ok(());
            };
            let bundle: Bundle =
                serde_json::from_slice(&plain).map_err(|_| AccountError::Format)?;
            self.install_bundle(bundle)?;
        }
        // applied, or stale (an older rotation or our own, already installed): drop the copy
        devices::clear_rekey(t, self.device()?, now_ms)?;
        Ok(())
    }

    /// Re-seal every record still under an older key generation with a fresh hlc and queue it
    /// for push. Idempotent, so an interrupted rotation just resumes. Records this build cannot
    /// read (newer schema) stay as they are. ponytail: they keep the old key readable to a
    /// revoked device until a build that understands them re-seals them.
    pub(super) fn reencrypt_stale(&mut self, now_ms: u64) -> Result<usize, AccountError> {
        let mut n = 0;
        let vaults: Vec<String> = self
            .meta
            .shared
            .vaults
            .iter()
            .map(|v| v.id.clone())
            .collect();
        for vault in vaults {
            let current = self.session.key_gen(&vault)?;
            for rec in self.store.list(&vault)? {
                if blob_key_gen(&rec.blob).is_ok_and(|g| g >= current) {
                    continue;
                }
                let Ok(payload) = self.session.open_record(&rec) else {
                    continue;
                };
                let hlc = self.clock.tick(&self.store, now_ms)?;
                let new =
                    self.session
                        .seal_record(&vault, &rec.id, &hlc, rec.tombstone, &payload)?;
                self.store.put_local(&new)?;
                n += 1;
            }
            self.session.refresh_index(&self.store, &vault)?;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests;
