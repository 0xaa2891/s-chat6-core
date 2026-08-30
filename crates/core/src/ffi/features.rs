//! Feature surface at the boundary: attachments, profiles, policy,
//! contact close, and stickers.

use crate::store::profiles::ProfilesRepository;
use crate::{attach, media, policy, profile, stickers, store, util, wire_types};

use super::{hex_id16, hex_id32, CoreError, SchatCore};

/// Everything needed to send one attachment (see
/// [`attach::AttachmentSpec`]).
#[derive(uniffi::Record, Clone, Debug)]
pub struct AttachmentSpecFfi {
    pub media_class: u8,
    pub mime_hint: String,
    pub orig_ext: String,
    pub bytes: Vec<u8>,
    pub caption: String,
    pub view_once: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ProfilePairFfi {
    pub local_name: String,
    pub local_jpeg: Vec<u8>,
    pub peer_name: Option<String>,
    pub peer_jpeg: Option<Vec<u8>>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PolicyFfi {
    pub ttl_sec: u32,
    pub screenshot: bool,
    pub attach_download: bool,
    pub local_want: u32,
    pub peer_want: u32,
    pub pending: bool,
    pub pending_inbound: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PackInfoFfi {
    pub pack_id: String,
    pub pack_pk: String,
    pub title: String,
    pub kind: u8,
    pub visibility: u8,
    pub item_count: u32,
    pub icon_item_id: u16,
    pub ours: bool,
    pub cached: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PackCreatedFfi {
    pub pack_id: String,
    pub pack_pk: String,
}

#[uniffi::export]
impl SchatCore {
    /// Send media: one inline head, or head + chunk envelopes. Returns
    /// the transfer's hex head id.
    pub fn send_attachment(
        &self,
        rel_id: String,
        spec: AttachmentSpecFfi,
    ) -> Result<String, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let id = self.rt.block_on(eng.send_attachment(
            &rel_id,
            &attach::AttachmentSpec {
                media_class: spec.media_class,
                mime_hint: spec.mime_hint,
                orig_ext: spec.orig_ext,
                bytes: spec.bytes,
                caption: spec.caption,
                view_once: spec.view_once,
            },
        ))?;
        Ok(store::hex_encode(&id))
    }

    /// Reassembled attachment bytes (`None` until complete). View-once
    /// attachments return `None` after `attachment_viewed`.
    pub fn attachment_bytes(&self, head_id: String) -> Result<Option<Vec<u8>>, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let head = hex_id16(&head_id)?;
        Ok(eng.attachment_bytes(&head)?)
    }

    /// Mark a view-once attachment viewed: the bytes are burned.
    pub fn attachment_viewed(&self, head_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let head = hex_id16(&head_id)?;
        Ok(eng.attachment_viewed(&head)?)
    }

    /// Set our profile (name + media-prepared JPEG, possibly empty).
    pub fn profile_set(&self, name: String, jpeg: Vec<u8>) -> Result<(), CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(profile::set_our_profile(&eng.db, &name, &jpeg)?)
    }

    /// Push our profile to every active relationship.
    pub fn profile_broadcast(&self) -> Result<u32, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.broadcast_profile())?)
    }

    /// Ask a peer for their current profile.
    pub fn profile_request(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.send_profile_req(&rel_id))?)
    }

    /// Local + peer profile for a relationship.
    pub fn profile_show(&self, rel_id: String) -> Result<ProfilePairFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let local = profile::our_profile(&eng.db)?;
        let peer = eng.db.profile(&rel_id)?;
        Ok(ProfilePairFfi {
            local_name: local.name,
            local_jpeg: local.jpeg,
            peer_name: peer.as_ref().map(|p| p.name.clone()),
            peer_jpeg: peer.map(|p| p.jpeg),
        })
    }

    /// Propose rule changes (None keeps the currently agreed value).
    pub fn policy_propose(
        &self,
        rel_id: String,
        ttl_sec: Option<u32>,
        screenshot: Option<bool>,
        attach_download: Option<bool>,
    ) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let cur = policy::load_policy(eng.db.conn(), &rel_id)?;
        self.rt.block_on(eng.propose_rules(
            &rel_id,
            ttl_sec.unwrap_or(cur.ttl_sec),
            screenshot.unwrap_or(cur.screenshot),
            attach_download.unwrap_or(cur.attach_download),
        ))?;
        Ok(())
    }

    pub fn policy_accept(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        self.rt.block_on(eng.accept_rules(&rel_id))?;
        Ok(())
    }

    pub fn policy_decline(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(eng.decline_rules(&rel_id)?)
    }

    /// Our want for one capability (CAP_ATTACH/EMOJI/PRESENCE/TYPING/
    /// RECEIPTS ids live in `policy`).
    pub fn policy_set_cap(&self, rel_id: String, cap_id: u8, on: bool) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        self.rt.block_on(eng.set_capability(&rel_id, cap_id, on))?;
        Ok(())
    }

    pub fn policy_show(&self, rel_id: String) -> Result<PolicyFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let s = policy::load_policy(eng.db.conn(), &rel_id)?;
        Ok(PolicyFfi {
            ttl_sec: s.ttl_sec,
            screenshot: s.screenshot,
            attach_download: s.attach_download,
            local_want: s.local_want,
            peer_want: s.peer_want,
            pending: s.pending.is_some(),
            pending_inbound: s.pending.as_ref().is_some_and(|p| p.inbound),
        })
    }

    /// The contact-close flow: DELETE_ALL + CONTACT_CLOSE go out, the
    /// local burn completes once they settle (see `sweep`).
    pub fn close_contact(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.close_contact(&rel_id))?)
    }

    /// Send a sticker from an installed pack.
    pub fn sticker_send(
        &self,
        rel_id: String,
        pack_id: String,
        item_id: u16,
    ) -> Result<String, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let pack = hex_id16(&pack_id)?;
        let id = self
            .rt
            .block_on(eng.send_sticker(&rel_id, &pack, item_id))?;
        Ok(store::hex_encode(&id))
    }

    /// All installed (and auto-cached) packs.
    pub fn sticker_list(&self) -> Result<Vec<PackInfoFfi>, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(stickers::packs::list_packs(&eng.db)?
            .into_iter()
            .map(|p| PackInfoFfi {
                pack_id: store::hex_encode(&p.pack_id),
                pack_pk: store::hex_encode(&p.pack_pk),
                title: p.title,
                kind: p.kind,
                visibility: p.visibility,
                item_count: p.item_count,
                icon_item_id: p.icon_item_id,
                ours: p.ours,
                cached: p.cached,
            })
            .collect())
    }

    /// Create a pack we sign. `items` are raw image bytes — each is
    /// media-prepared (strip, bound, re-encode) before install.
    /// Returns (pack_id, pack_pk) hex.
    pub fn sticker_create(
        &self,
        title: String,
        kind: u8,
        visibility: u8,
        items: Vec<Vec<u8>>,
    ) -> Result<PackCreatedFfi, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let mut prepared = Vec::with_capacity(items.len());
        for bytes in &items {
            let p =
                media::prepare_sticker(bytes, kind).map_err(|e| CoreError::Other(e.to_string()))?;
            prepared.push(wire_types::sticker::PackDocItem {
                item_id: (prepared.len() + 1) as u16,
                w: p.width as u16,
                h: p.height as u16,
                sha256: util::sha256(&p.bytes),
                bytes: p.bytes,
            });
        }
        let (pack_id, pack_pk) = eng.create_pack(&title, kind, visibility, 1, prepared)?;
        Ok(PackCreatedFfi {
            pack_id: store::hex_encode(&pack_id),
            pack_pk: store::hex_encode(&pack_pk),
        })
    }

    /// Uninstall a pack (returns false if unknown).
    pub fn sticker_remove(&self, pack_id: String) -> Result<bool, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let pack = hex_id16(&pack_id)?;
        Ok(eng.remove_pack(&pack)?)
    }

    /// Ask a peer for a pack (user-driven clone).
    pub fn sticker_fetch(
        &self,
        rel_id: String,
        pack_id: String,
        pack_pk: String,
    ) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let pack = hex_id16(&pack_id)?;
        let pk = hex_id32(&pack_pk)?;
        Ok(self.rt.block_on(eng.fetch_pack(&rel_id, &pack, &pk))?)
    }
}
