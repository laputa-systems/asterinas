// SPDX-License-Identifier: MPL-2.0

//! Handle link-related requests.

use aster_bigtcp::{
    iface::{InterfaceFlags, InterfaceType},
    wire::EthernetAddress,
};

use super::util::{self, ResponseMode};
use crate::{
    net::{
        iface::{DEFAULT_TX_QUEUE_LEN, Iface, config, iter_all_ifaces},
        socket::{
            netlink::{
                message::{
                    CMsgSegHdr, CSegmentType, GetRequestFlags, NewRequestFlags, SegHdrCommonFlags,
                },
                route::message::{
                    CIfinfoMsg, CLinkStats64, LinkAttr, LinkAttrClass, LinkSegment, OperState,
                    RtExtFilter, RtnlSegment,
                },
            },
            util::options::check_current_privileged,
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

/// The unspecified link-layer address.
const UNSPECIFIED_LINK_ADDR: EthernetAddress = EthernetAddress([0; 6]);

pub(super) fn do_get_link(
    request_segment: &LinkSegment,
    strict_check: bool,
) -> Result<Vec<RtnlSegment>> {
    validate_getlink_request(request_segment, strict_check)?;

    let filter_by = FilterBy::from_request(request_segment)?;
    let stats = if skips_stats(request_segment) {
        LinkStats::Skipped
    } else {
        LinkStats::Included
    };

    let mut response_segments: Vec<RtnlSegment> = iter_all_ifaces()
        // Filter to include only requested links.
        .filter(|iface| match &filter_by {
            FilterBy::Index(index) => *index == iface.index(),
            FilterBy::Name(name) => *name == iface.name().as_cstr(),
            FilterBy::Dump => true,
        })
        .map(|iface| iface_to_new_link(request_segment.header(), iface, 0, stats))
        .map(RtnlSegment::NewLink)
        .collect();

    let response_mode = match filter_by {
        FilterBy::Dump => ResponseMode::Dump,
        FilterBy::Index(_) | FilterBy::Name(_) => ResponseMode::Single,
    };

    if response_mode == ResponseMode::Single && response_segments.is_empty() {
        return Err(errno!(ENODEV, "no link found"));
    }

    util::finish_response(
        request_segment.header(),
        response_mode,
        &mut response_segments,
    );

    Ok(response_segments)
}

/// Changes an existing link, as `do_setlink` does for `RTM_NEWLINK`.
///
/// Only bringing a link up or down applies. A request to change the name, the hardware address,
/// the MTU, the queue length or the link mode fails before anything changes.
///
/// Reference: `rtnl_newlink` in <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c>.
pub(super) fn do_new_link(request_segment: &LinkSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    let attrs = request_segment.attrs();
    let name = attrs.iter().find_map(|attr| match attr {
        LinkAttr::Name(name) => Some(name),
        _ => None,
    });
    let index = body
        .index
        .filter(|index| i32::try_from(index.get()).is_ok());
    let iface = match (index, name) {
        (Some(index), _) => iter_all_ifaces().find(|iface| iface.index() == index.get()),
        (None, Some(name)) => iter_all_ifaces().find(|iface| iface.name().as_cstr() == name.as_cstr()),
        (None, None) => None,
    };

    let request_flags = NewRequestFlags::from_bits_truncate(request_segment.header().flags);
    let Some(iface) = iface else {
        if request_flags.contains(NewRequestFlags::CREATE) {
            return_errno_with_message!(Errno::EOPNOTSUPP, "creating a link is not supported");
        }
        return_errno_with_message!(Errno::ENODEV, "no link found");
    };
    if request_flags.contains(NewRequestFlags::EXCL) {
        return_errno_with_message!(Errno::EEXIST, "the link already exists");
    }
    if request_flags.contains(NewRequestFlags::REPLACE) {
        return_errno_with_message!(Errno::EOPNOTSUPP, "replacing a link is not supported");
    }

    for attr in attrs {
        let unchanged = match attr {
            LinkAttr::Name(name) => name.as_cstr() == iface.name().as_cstr(),
            LinkAttr::Address(address) => {
                *address == iface.ethernet_addr().unwrap_or(UNSPECIFIED_LINK_ADDR)
            }
            LinkAttr::Mtu(mtu) => *mtu as usize == iface.mtu(),
            LinkAttr::TxqLen(len) => *len == DEFAULT_TX_QUEUE_LEN,
            LinkAttr::LinkMode(mode) => *mode == 0,
            _ => true,
        };
        if !unchanged {
            return_errno_with_message!(
                Errno::EOPNOTSUPP,
                "only the up flag of a link can be changed"
            );
        }
    }

    if body.flags.is_empty() && body.change == 0 {
        return Ok(());
    }
    let requested = if body.change == 0 {
        body.flags
    } else {
        let change = InterfaceFlags::from_bits_truncate(body.change);
        (body.flags & change) | (iface.flags() - change)
    };
    config::change_flags(iface, requested)
}

/// Whether a link message carries the link's counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LinkStats {
    Included,
    Skipped,
}

fn skips_stats(request_segment: &LinkSegment) -> bool {
    request_segment.attrs().iter().any(|attr| {
        matches!(attr, LinkAttr::ExtMask(filter) if filter.contains(RtExtFilter::SKIP_STATS))
    })
}

enum FilterBy<'a> {
    Index(u32),
    Name(&'a CStr),
    Dump,
}

impl<'a> FilterBy<'a> {
    fn from_request(request_segment: &'a LinkSegment) -> Result<Self> {
        let dump_all = {
            let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
            flags.contains(GetRequestFlags::DUMP)
        };
        if dump_all {
            return Ok(Self::Dump);
        }

        // `index` takes precedence over `required_name`.

        let required_index = request_segment.body().index;
        if required_index != 0 {
            return Ok(Self::Index(required_index));
        }

        let required_name = request_segment.attrs().iter().find_map(|attr| {
            if let LinkAttr::Name(name) = attr {
                Some(name.as_cstr())
            } else {
                None
            }
        });
        if let Some(required_name) = required_name {
            return Ok(Self::Name(required_name));
        }

        Err(errno!(
            EINVAL,
            "either interface name or index should be specified for non-dump mode"
        ))
    }
}

fn validate_getlink_request(request_segment: &LinkSegment, strict_check: bool) -> Result<()> {
    if !strict_check {
        return Ok(());
    }

    let body = request_segment.body();
    // GETLINK reserves these fields.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L4141>.
    if body._pad != 0 || body.type_ != 0 || body.flags != 0 || body.change != 0 {
        return Err(errno!(
            EINVAL,
            "the link request header contains nonzero padding, type, flags, or change"
        ));
    }

    // Linux accepts different attributes for link dumps and single-link queries
    // when strict checking is enabled.
    let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
    let allowed = if flags.contains(GetRequestFlags::DUMP) {
        if body.index != 0 {
            return Err(errno!(
                EINVAL,
                "filtering by interface index is not supported for link dumps"
            ));
        }
        // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L2495>.
        [
            LinkAttrClass::MASTER,
            LinkAttrClass::LINKINFO,
            LinkAttrClass::EXT_MASK,
            LinkAttrClass::IF_NETNSID,
        ]
        .as_slice()
    } else {
        // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L4152>.
        [
            LinkAttrClass::IFNAME,
            LinkAttrClass::EXT_MASK,
            LinkAttrClass::IF_NETNSID,
        ]
        .as_slice()
    };
    for attr in request_segment.attrs() {
        if !allowed.contains(&attr.class()) {
            return Err(errno!(
                EINVAL,
                "the attribute is not allowed in this link request"
            ));
        }
    }
    Ok(())
}

/// Linux reports a loopback interface as `UNKNOWN` while it is up, as it has no carrier to track.
fn oper_state(iface: &Arc<Iface>) -> OperState {
    if !iface.flags().contains(InterfaceFlags::UP) {
        OperState::Down
    } else if iface.type_() == InterfaceType::LOOPBACK {
        OperState::Unknown
    } else {
        OperState::Up
    }
}

pub(super) fn iface_to_new_link(
    request_header: &CMsgSegHdr,
    iface: &Arc<Iface>,
    change: u32,
    stats: LinkStats,
) -> LinkSegment {
    let header = CMsgSegHdr {
        len: 0,
        type_: CSegmentType::NEWLINK as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    };

    let link_message = CIfinfoMsg {
        family: CSocketAddrFamily::AF_UNSPEC as u8,
        _pad: 0,
        type_: iface.type_() as u16,
        index: iface.index(),
        flags: iface.flags().bits(),
        change,
    };

    // Linux may report dozens of attributes in a fixed order.
    // See the reference below for the complete attribute list and ordering.
    // TODO: Asterinas currently reports only a subset of these attributes.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/core/rtnetlink.c#L2050>.
    let carrier = iface.carrier();
    let mut attrs = Vec::with_capacity(12);
    attrs.extend([
        LinkAttr::Name(*iface.name()),
        LinkAttr::TxqLen(DEFAULT_TX_QUEUE_LEN),
        LinkAttr::OperState(oper_state(iface)),
        LinkAttr::Mtu(iface.mtu() as u32),
        LinkAttr::Carrier(u8::from(carrier.on)),
        LinkAttr::CarrierChanges(carrier.changes()),
        LinkAttr::CarrierUpCount(carrier.up_count),
        LinkAttr::CarrierDownCount(carrier.down_count),
    ]);

    let (link_addr, link_broadcast_addr) = match iface.ethernet_addr() {
        Some(ethernet_addr) => (ethernet_addr, EthernetAddress::BROADCAST),
        None => (UNSPECIFIED_LINK_ADDR, UNSPECIFIED_LINK_ADDR),
    };
    attrs.extend([
        LinkAttr::Address(link_addr),
        LinkAttr::Broadcast(link_broadcast_addr),
    ]);

    if stats == LinkStats::Included {
        let counters = iface.link_counters();
        let stats = CLinkStats64 {
            rx_packets: counters.rx_packets,
            tx_packets: counters.tx_packets,
            rx_bytes: counters.rx_bytes,
            tx_bytes: counters.tx_bytes,
            ..CLinkStats64::default()
        };
        attrs.extend([LinkAttr::Stats64(stats), LinkAttr::Stats(stats.truncated())]);
    }

    LinkSegment::new(header, link_message, attrs)
}
