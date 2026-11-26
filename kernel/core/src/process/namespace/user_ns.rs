// SPDX-License-Identifier: MPL-2.0

use spin::Once;

use crate::{
    fs::pseudofs::{NsCommonOps, NsType, StashedDentry},
    prelude::*,
    process::{Gid, Uid},
};

/// The maximum number of extents in a single UID or GID map.
///
/// Reference: `UID_GID_MAP_MAX_EXTENTS`
/// <https://elixir.bootlin.com/linux/v6.16.9/source/include/linux/uidgid.h#L32>.
const MAX_MAP_EXTENTS: usize = 5;

/// The maximum allowed nesting level of user namespaces.
///
/// Reference: `MAX_USER_NS_LEVEL`
/// <https://elixir.bootlin.com/linux/v6.16.9/source/include/linux/user_namespace.h#L14>.
const MAX_USER_NS_LEVEL: u32 = 32;

/// The user namespace.
pub struct UserNamespace {
    stashed_dentry: StashedDentry,
    parent: Option<Arc<UserNamespace>>,
    level: u32,
    owner: Uid,
    state: Mutex<UserNsState>,
}

struct UserNsState {
    uid_map: Vec<IdMapExtent>,
    gid_map: Vec<IdMapExtent>,
    setgroups: SetgroupsState,
}

/// A single line of a UID or GID map: IDs in `[first, first + count)`
/// are mapped to IDs in `[lower_first, lower_first + count)`
/// of the parent user namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdMapExtent {
    first: u32,
    lower_first: u32,
    count: u32,
}

/// Whether `setgroups(2)` is allowed for processes in the user namespace.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/kernel/user_namespace.c#L40>.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetgroupsState {
    Allow,
    Deny,
}

/// The credentials of the writer for a UID/GID map write.
pub(crate) struct MapWriter {
    /// The effective UID of the writer (a global kernel ID).
    pub(crate) euid: Uid,
    /// The effective GID of the writer (a global kernel ID).
    pub(crate) egid: Gid,
    /// The supplementary GIDs of the writer (global kernel IDs).
    pub(crate) groups: BTreeSet<Gid>,
    /// Whether the writer has `CAP_SETUID` (for UID maps)
    /// or `CAP_SETGID` (for GID maps) in the parent user namespace.
    pub(crate) privileged: bool,
}

impl UserNamespace {
    /// Returns a reference to the singleton initial user namespace.
    pub fn get_init_singleton() -> &'static Arc<UserNamespace> {
        static INIT: Once<Arc<UserNamespace>> = Once::new();

        INIT.call_once(|| {
            // The initial user namespace maps every ID onto itself.
            let full_range = IdMapExtent {
                first: 0,
                lower_first: 0,
                count: u32::MAX,
            };
            Arc::new(Self {
                stashed_dentry: StashedDentry::new(),
                parent: None,
                level: 0,
                owner: Uid::new_root(),
                state: Mutex::new(UserNsState {
                    uid_map: vec![full_range],
                    gid_map: vec![full_range],
                    setgroups: SetgroupsState::Allow,
                }),
            })
        })
    }

    /// Creates a new child user namespace owned by `owner`.
    ///
    /// The owner is the creator's global kernel UID.
    /// The new namespace starts out with empty ID maps and
    /// with `setgroups(2)` allowed, mirroring Linux.
    pub(crate) fn new_child(parent: &Arc<UserNamespace>, owner: Uid) -> Result<Arc<UserNamespace>> {
        if parent.level > MAX_USER_NS_LEVEL {
            return Err(errno!(EUSERS, "too many nested user namespaces"));
        }

        Ok(Arc::new(Self {
            stashed_dentry: StashedDentry::new(),
            parent: Some(parent.clone()),
            level: parent.level + 1,
            owner,
            state: Mutex::new(UserNsState {
                uid_map: Vec::new(),
                gid_map: Vec::new(),
                setgroups: SetgroupsState::Allow,
            }),
        }))
    }

    /// Returns the parent user namespace, or `None` for the initial namespace.
    pub(crate) fn parent_ns(&self) -> Option<Arc<UserNamespace>> {
        self.parent.clone()
    }

    /// Returns the owner UID of the user namespace.
    pub(crate) fn owner_uid(&self) -> Result<Uid> {
        Ok(self.owner)
    }

    /// Returns whether this namespace is the same as, or an ancestor of, the other namespace.
    pub(crate) fn is_same_or_ancestor_of(self: &Arc<Self>, other: &UserNamespace) -> bool {
        let mut current = Some(other);
        while let Some(namespace) = current {
            if core::ptr::eq(Arc::as_ptr(self), namespace) {
                return true;
            }
            current = namespace.parent.as_deref();
        }
        false
    }

    /// Translates a global kernel UID into an ID in this namespace.
    ///
    /// Unmapped IDs are translated to the overflow UID, mirroring
    /// `from_kuid_munged` in Linux.
    pub(crate) fn kuid_to_uid(&self, kuid: Uid) -> Uid {
        self.try_kuid_to_uid(kuid)
            .map(Uid::new)
            .unwrap_or_else(Uid::new_overflow)
    }

    /// Translates a global kernel GID into an ID in this namespace.
    ///
    /// Unmapped IDs are translated to the overflow GID, mirroring
    /// `from_kgid_munged` in Linux.
    pub(crate) fn kgid_to_gid(&self, kgid: Gid) -> Gid {
        self.try_kgid_to_gid(kgid)
            .map(Gid::new)
            .unwrap_or_else(Gid::new_overflow)
    }

    /// Translates a global kernel UID into an ID in this namespace,
    /// or returns `None` if the ID is not mapped.
    fn try_kuid_to_uid(&self, kuid: Uid) -> Option<u32> {
        let Some(parent) = self.parent.as_ref() else {
            // The initial user namespace maps every ID onto itself.
            return Some(u32::from(kuid));
        };
        let id_in_parent = parent.try_kuid_to_uid(kuid)?;
        self.state
            .lock()
            .uid_map
            .iter()
            .find_map(|extent| extent.translate_from_parent(id_in_parent))
    }

    /// Translates a global kernel GID into an ID in this namespace,
    /// or returns `None` if the ID is not mapped.
    fn try_kgid_to_gid(&self, kgid: Gid) -> Option<u32> {
        let Some(parent) = self.parent.as_ref() else {
            // The initial user namespace maps every ID onto itself.
            return Some(u32::from(kgid));
        };
        let id_in_parent = parent.try_kgid_to_gid(kgid)?;
        self.state
            .lock()
            .gid_map
            .iter()
            .find_map(|extent| extent.translate_from_parent(id_in_parent))
    }

    /// Returns the writer's effective UID expressed in the parent namespace,
    /// or `None` if it is not mapped there.
    fn euid_in_parent(&self, euid: Uid) -> Option<u32> {
        match self.parent.as_ref() {
            Some(parent) => parent.try_kuid_to_uid(euid),
            None => Some(u32::from(euid)),
        }
    }

    /// Returns whether `gid` matches the writer's effective or supplementary
    /// GIDs when expressed in the parent namespace.
    fn gid_matches_writer_in_parent(&self, gid: u32, writer: &MapWriter) -> bool {
        let Some(parent) = self.parent.as_ref() else {
            return u32::from(writer.egid) == gid || writer.groups.contains(&Gid::new(gid));
        };
        if parent.try_kgid_to_gid(writer.egid) == Some(gid) {
            return true;
        }
        writer
            .groups
            .iter()
            .any(|group| parent.try_kgid_to_gid(*group) == Some(gid))
    }

    /// Returns a copy of the UID map extents.
    pub(crate) fn uid_map_extents(&self) -> Vec<(u32, u32, u32)> {
        self.state
            .lock()
            .uid_map
            .iter()
            .map(|extent| (extent.first, extent.lower_first, extent.count))
            .collect()
    }

    /// Returns a copy of the GID map extents.
    pub(crate) fn gid_map_extents(&self) -> Vec<(u32, u32, u32)> {
        self.state
            .lock()
            .gid_map
            .iter()
            .map(|extent| (extent.first, extent.lower_first, extent.count))
            .collect()
    }

    /// Returns the current `setgroups` state.
    pub(crate) fn setgroups_state(&self) -> SetgroupsState {
        self.state.lock().setgroups
    }

    /// Writes the UID map from the given file content.
    ///
    /// This enforces Linux's write rules: maps can only be written once,
    /// unprivileged writers (those without `CAP_SETUID` in the parent
    /// namespace) are restricted to a single extent that maps their own UID,
    /// and malformed content is rejected with `EINVAL`.
    pub(crate) fn write_uid_map(&self, text: &str, writer: &MapWriter) -> Result<()> {
        let extents = parse_id_map(text)?;

        let mut state = self.state.lock();
        if !state.uid_map.is_empty() {
            return Err(errno!(EPERM, "the UID map can only be written once"));
        }

        if !writer.privileged {
            if extents.len() != 1 {
                return Err(errno!(
                    EINVAL,
                    "unprivileged UID maps must contain exactly one extent"
                ));
            }
            if self.euid_in_parent(writer.euid) != Some(extents[0].lower_first) {
                return Err(errno!(
                    EPERM,
                    "unprivileged UID maps must map the writer's own UID"
                ));
            }
        }

        state.uid_map = extents;
        Ok(())
    }

    /// Writes the GID map from the given file content.
    ///
    /// In addition to the UID map rules, writing the GID map as an
    /// unprivileged writer (one without `CAP_SETGID` in the parent namespace)
    /// requires `setgroups` to have been set to "deny" first.
    pub(crate) fn write_gid_map(&self, text: &str, writer: &MapWriter) -> Result<()> {
        let extents = parse_id_map(text)?;

        let mut state = self.state.lock();
        if !state.gid_map.is_empty() {
            return Err(errno!(EPERM, "the GID map can only be written once"));
        }

        if !writer.privileged {
            if state.setgroups != SetgroupsState::Deny {
                return Err(errno!(
                    EPERM,
                    "unprivileged GID map writes require setgroups to be denied first"
                ));
            }
            if extents.len() != 1 {
                return Err(errno!(
                    EINVAL,
                    "unprivileged GID maps must contain exactly one extent"
                ));
            }
            if !self.gid_matches_writer_in_parent(extents[0].lower_first, writer) {
                return Err(errno!(
                    EPERM,
                    "unprivileged GID maps must map the writer's own GID"
                ));
            }
        }

        state.gid_map = extents;
        Ok(())
    }

    /// Writes the `setgroups` state from the given file content.
    pub(crate) fn write_setgroups(&self, text: &str) -> Result<()> {
        let decision = match text.trim() {
            "deny" => SetgroupsState::Deny,
            "allow" => SetgroupsState::Allow,
            _ => {
                return Err(errno!(
                    EINVAL,
                    "setgroups only accepts \"deny\" or \"allow\""
                ));
            }
        };

        let mut state = self.state.lock();
        if state.setgroups == SetgroupsState::Deny {
            return Err(errno!(EPERM, "setgroups cannot be allowed once denied"));
        }
        match decision {
            SetgroupsState::Deny => {
                if !state.gid_map.is_empty() {
                    return Err(errno!(
                        EPERM,
                        "setgroups cannot be denied after the GID map is written"
                    ));
                }
                state.setgroups = SetgroupsState::Deny;
                Ok(())
            }
            SetgroupsState::Allow => Ok(()),
        }
    }
}

impl IdMapExtent {
    /// Maps an ID in the parent namespace to an ID in this namespace.
    fn translate_from_parent(&self, id_in_parent: u32) -> Option<u32> {
        if self.lower_first <= id_in_parent && id_in_parent - self.lower_first < self.count {
            Some(self.first + (id_in_parent - self.lower_first))
        } else {
            None
        }
    }
}

/// Parses the content of a UID or GID map file.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.16.9/source/kernel/user_namespace.c>, `map_write`.
fn parse_id_map(text: &str) -> Result<Vec<IdMapExtent>> {
    let mut extents = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 3 {
            return Err(errno!(
                EINVAL,
                "each ID map line needs exactly three numbers"
            ));
        }
        let parse = |field: &str| {
            field
                .parse::<u32>()
                .map_err(|_| errno!(EINVAL, "ID map entries must be unsigned 32-bit integers"))
        };
        let (first, lower_first, count) = (parse(fields[0])?, parse(fields[1])?, parse(fields[2])?);
        if count == 0 {
            return Err(errno!(EINVAL, "ID map entries must have a non-zero count"));
        }
        // Reject ranges that would wrap around.
        first
            .checked_add(count)
            .ok_or_else(|| errno!(EINVAL, "ID map entries must not overflow the ID range"))?;
        lower_first
            .checked_add(count)
            .ok_or_else(|| errno!(EINVAL, "ID map entries must not overflow the ID range"))?;
        extents.push(IdMapExtent {
            first,
            lower_first,
            count,
        });
    }

    if extents.is_empty() || extents.len() > MAX_MAP_EXTENTS {
        return Err(errno!(
            EINVAL,
            "ID maps must contain between one and five extents"
        ));
    }

    // Extents must be sorted in ascending order and must not overlap.
    for pair in extents.windows(2) {
        let (prev, next) = (pair[0], pair[1]);
        if next.first < prev.first + prev.count {
            return Err(errno!(EINVAL, "ID map extents must not overlap"));
        }
        if next.lower_first < prev.lower_first + prev.count {
            return Err(errno!(EINVAL, "ID map extents must not overlap"));
        }
    }

    Ok(extents)
}

impl NsCommonOps for UserNamespace {
    const TYPE: NsType = NsType::User;

    fn owner_user_ns(&self) -> Option<&Arc<UserNamespace>> {
        // For user namespaces, `NS_GET_USERNS` returns the parent user namespace
        // rather than an "owner". The initial user namespace has no parent.
        // Reference: <https://elixir.bootlin.com/linux/v6.19/source/kernel/user_namespace.c#L1406>
        self.parent.as_ref()
    }

    fn parent(&self) -> Result<&Arc<Self>> {
        // User namespaces do not support `NS_GET_PARENT`.
        // Reference: <https://elixir.bootlin.com/linux/v6.19/source/kernel/user_namespace.c#L1407>
        Err(errno!(
            EPERM,
            "user namespaces do not support NS_GET_PARENT"
        ))
    }

    fn stashed_dentry(&self) -> &StashedDentry {
        &self.stashed_dentry
    }
}
