// SPDX-License-Identifier: MPL-2.0

//! Handle address-related requests.

use alloc::borrow::ToOwned;
use core::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
};

use aster_bigtcp::{
    iface::InterfaceName,
    wire::{Ipv4Cidr, Ipv6Cidr},
};

use super::{
    notify::RequestOrigin,
    util::{self, ResponseMode},
};
use crate::{
    net::{
        iface::{
            Iface,
            config::{self, AddressSelector, InterfaceAddress, NewAddress, ipv4_addresses},
            iter_all_ifaces,
        },
        socket::{
            netlink::{
                message::{
                    CMsgSegHdr, CSegmentType, GetRequestFlags, NewRequestFlags, SegHdrCommonFlags,
                },
                route::message::{
                    AddrAttr, AddrAttrClass, AddrCacheInfo, AddrMessageFlags, AddrProtocol,
                    AddrSegment, CIfaddrMsg, INFINITE_LIFETIME, RtScope, RtnlSegment,
                },
            },
            util::options::check_current_privileged,
        },
    },
    prelude::*,
    util::net::CSocketAddrFamily,
};

pub(super) fn do_get_addr(
    request_segment: &AddrSegment,
    strict_check: bool,
) -> Result<Vec<RtnlSegment>> {
    let dump_all = {
        let flags = GetRequestFlags::from_bits_truncate(request_segment.header().flags);
        flags.contains(GetRequestFlags::DUMP)
    };
    if !dump_all {
        return Err(errno!(EOPNOTSUPP, "GETADDR only supports dump requests"));
    }

    validate_getaddr_request(request_segment, strict_check)?;

    let requested_family = request_segment.body().family;
    // Linux filters address dumps by a nonzero interface index only in strict mode.
    // References:
    // - <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/devinet.c#L1950>
    // - <https://elixir.bootlin.com/linux/v7.1/source/net/ipv6/addrconf.c#L5430>
    let requested_index = strict_check
        .then(|| NonZeroU32::new(request_segment.body().index))
        .flatten();
    let mut ifaces = iter_all_ifaces()
        .filter(|iface| requested_index.is_none_or(|index| index.get() == iface.index()))
        .peekable();
    if requested_index.is_some() && ifaces.peek().is_none() {
        return Err(errno!(ENODEV, "the interface does not exist"));
    }

    let mut addr_segments: Vec<AddrSegment> = ifaces
        .flat_map(|iface| iface_to_new_addrs(request_segment.header(), requested_family, iface))
        .collect();

    // Linux dumps IPv4 addresses before IPv6 addresses
    // while preserving interface order within each family.
    addr_segments.sort_by_key(|segment| segment.body().family);

    let mut response_segments: Vec<RtnlSegment> = addr_segments
        .into_iter()
        .map(RtnlSegment::NewAddr)
        .collect();

    let response_mode = if requested_index.is_some() {
        ResponseMode::FilteredDump
    } else {
        ResponseMode::Dump
    };
    util::finish_response(
        request_segment.header(),
        response_mode,
        &mut response_segments,
    );

    Ok(response_segments)
}

fn validate_getaddr_request(request_segment: &AddrSegment, strict_check: bool) -> Result<()> {
    if !strict_check {
        return Ok(());
    }

    let body = request_segment.body();
    // These fields are reserved in GETADDR dumps.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/devinet.c#L1800>.
    if body.prefix_len != 0 || body.flags != 0 || body.scope != 0 {
        return Err(errno!(
            EINVAL,
            "the address request header contains nonzero prefix length, flags, or scope"
        ));
    }

    // Linux permits only `IFA_TARGET_NETNSID` in strict address dumps.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/devinet.c#L1811>.
    const ALLOWED: AddrAttrClass = AddrAttrClass::TARGET_NETNSID;
    if request_segment
        .attrs()
        .iter()
        .any(|attr| attr.class() != ALLOWED)
    {
        return Err(errno!(
            EINVAL,
            "the attribute is not allowed in an address dump request"
        ));
    }
    Ok(())
}

pub(super) fn do_new_addr(request_segment: &AddrSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    require_ipv4(body)?;

    let request_flags = NewRequestFlags::from_bits_truncate(request_segment.header().flags);
    if request_flags.contains(NewRequestFlags::REPLACE) {
        return Err(errno!(
            EOPNOTSUPP,
            "replacing an address is not supported"
        ));
    }

    let attrs = request_segment.attrs();
    let local = attrs
        .iter()
        .find_map(|attr| match attr {
            AddrAttr::Local(address) => Some(address),
            _ => None,
        })
        .or_else(|| {
            attrs.iter().find_map(|attr| match attr {
                AddrAttr::Address(address) => Some(address),
                _ => None,
            })
        });
    let Some(IpAddr::V4(local)) = local.copied() else {
        return Err(errno!(EINVAL, "the request has no IPv4 address"));
    };
    if body.prefix_len > 32 {
        return Err(errno!(EINVAL, "the prefix length is invalid"));
    }

    let iface = iface_by_index(body.index)?;

    let peer = attrs.iter().find_map(|attr| match attr {
        AddrAttr::Address(address) => Some(*address),
        _ => None,
    });
    if peer.is_some_and(|peer| peer != IpAddr::V4(local)) {
        return Err(errno!(EOPNOTSUPP, "peer addresses are not supported"));
    }

    let broadcast = attrs.iter().find_map(|attr| match attr {
        AddrAttr::Broadcast(address) => Some(*address),
        _ => None,
    });

    let flags = attrs
        .iter()
        .find_map(|attr| match attr {
            AddrAttr::Flags(flags) => Some(*flags),
            _ => None,
        })
        .unwrap_or_else(|| AddrMessageFlags::from_bits_truncate(body.flags as u32));
    if !(flags - AddrMessageFlags::PERMANENT).is_empty() {
        return Err(errno!(EOPNOTSUPP, "the address flags are not supported"));
    }

    let lifetimes = attrs.iter().find_map(|attr| match attr {
        AddrAttr::CacheInfo(info) => Some(*info),
        _ => None,
    });
    let lifetimes = match lifetimes {
        Some(info) => config::Ipv4AddressLifetimes::new(info.preferred, info.valid)?,
        None => config::Ipv4AddressLifetimes::PERMANENT,
    };

    let label = attrs.iter().find_map(|attr| match attr {
        AddrAttr::Label(label) => Some(InterfaceName::from_bytes_until_nul(
            label.as_bytes_with_nul(),
        )),
        _ => None,
    });

    config::add_ipv4_address(
        iface,
        NewAddress {
            cidr: Ipv4Cidr::new(local, body.prefix_len),
            broadcast,
            label,
            scope: body.scope,
            lifetimes,
        },
        RequestOrigin::request(request_segment.header()),
    )
}

pub(super) fn do_del_addr(request_segment: &AddrSegment) -> Result<()> {
    check_current_privileged()?;

    let body = request_segment.body();
    require_ipv4(body)?;

    let iface = iface_by_index(body.index)?;

    let attrs = request_segment.attrs();
    let ipv4 = |wanted: fn(&AddrAttr) -> Option<IpAddr>| -> Result<Option<Ipv4Addr>> {
        match attrs.iter().find_map(wanted) {
            None => Ok(None),
            Some(IpAddr::V4(address)) => Ok(Some(address)),
            Some(IpAddr::V6(_)) => Err(errno!(EINVAL, "the address is not an IPv4 address")),
        }
    };

    let selector = AddressSelector {
        local: ipv4(|attr| match attr {
            AddrAttr::Local(address) => Some(*address),
            _ => None,
        })?,
        network_member: ipv4(|attr| match attr {
            AddrAttr::Address(address) => Some(*address),
            _ => None,
        })?
        .map(|address| (address, body.prefix_len)),
        label: attrs.iter().find_map(|attr| match attr {
            AddrAttr::Label(label) => Some(InterfaceName::from_bytes_until_nul(
                label.as_bytes_with_nul(),
            )),
            _ => None,
        }),
    };

    config::remove_ipv4_address(
        iface,
        &selector,
        RequestOrigin::request(request_segment.header()),
    )
}

fn require_ipv4(body: &CIfaddrMsg) -> Result<()> {
    if body.family != CSocketAddrFamily::AF_INET as u8 {
        return Err(errno!(
            EOPNOTSUPP,
            "only IPv4 addresses can be changed"
        ));
    }
    Ok(())
}

fn iface_by_index(index: u32) -> Result<&'static Arc<Iface>> {
    iter_all_ifaces()
        .find(|iface| iface.index() == index)
        .ok_or_else(|| errno!(ENODEV, "no interface found"))
}

fn iface_to_new_addrs(
    request_header: &CMsgSegHdr,
    requested_family: u8,
    iface: &Arc<Iface>,
) -> impl IntoIterator<Item = AddrSegment> {
    let mut addr_segments = Vec::new();

    // Linux dumps addresses for all families
    // when the requested family is neither AF_INET nor AF_INET6.
    let dump_ipv4 = requested_family != CSocketAddrFamily::AF_INET6 as u8;
    let dump_ipv6 = requested_family != CSocketAddrFamily::AF_INET as u8;

    if dump_ipv4 {
        addr_segments.extend(
            ipv4_addresses(iface)
                .iter()
                .map(|address| ipv4_to_addr(request_header, CSegmentType::NEWADDR, address)),
        );
    }

    if dump_ipv6 && let Some(cidr) = iface.ipv6_cidr() {
        addr_segments.push(ipv6_to_new_addr(request_header, iface, cidr));
    }

    addr_segments
}

fn addr_header(request_header: &CMsgSegHdr, type_: CSegmentType) -> CMsgSegHdr {
    CMsgSegHdr {
        len: 0,
        type_: type_ as _,
        flags: SegHdrCommonFlags::empty().bits(),
        seq: request_header.seq,
        pid: request_header.pid,
    }
}

pub(super) fn ipv4_to_addr(
    request_header: &CMsgSegHdr,
    type_: CSegmentType,
    address: &InterfaceAddress,
) -> AddrSegment {
    let mut flags = AddrMessageFlags::empty();
    if address.valid_lifetime() == INFINITE_LIFETIME { flags |= AddrMessageFlags::PERMANENT; }
    if address.is_deprecated() { flags |= AddrMessageFlags::DEPRECATED; }
    if address.is_secondary() {
        flags |= AddrMessageFlags::SECONDARY;
    }

    let body = CIfaddrMsg {
        family: CSocketAddrFamily::AF_INET as _,
        prefix_len: address.cidr().prefix_len(),
        flags: flags.bits() as u8,
        scope: RtScope::try_from(address.scope()).expect("the scope was validated") as u8,
        index: address.iface().index(),
    };

    // Linux reports the following IPv4 address attributes, in order:
    // `IFA_ADDRESS`, `IFA_LOCAL`, `IFA_BROADCAST` when assigned, `IFA_LABEL`, `IFA_FLAGS`,
    // and `IFA_CACHEINFO`.
    // TODO: Support `IFA_PROTO` and `IFA_RT_PRIORITY`.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv4/devinet.c>.
    let local = IpAddr::V4(address.address());
    let mut attrs = vec![
        // Peer addresses are not supported, so `IFA_ADDRESS` equals `IFA_LOCAL`.
        AddrAttr::Address(local),
        AddrAttr::Local(local),
    ];
    if let Some(broadcast) = address.broadcast() {
        attrs.push(AddrAttr::Broadcast(broadcast));
    }
    attrs.extend([
        AddrAttr::Label(address.label().as_cstr().to_owned()),
        AddrAttr::Flags(flags),
        AddrAttr::CacheInfo(AddrCacheInfo {
            preferred: address.preferred_lifetime(),
            valid: address.valid_lifetime(),
            created: address.created_centiseconds(),
            updated: address.created_centiseconds(),
        }),
    ]);

    AddrSegment::new(addr_header(request_header, type_), body, attrs)
}

fn ipv6_to_new_addr(request_header: &CMsgSegHdr, iface: &Arc<Iface>, cidr: Ipv6Cidr) -> AddrSegment {
    let address = cidr.address();
    let scope = if address.is_loopback() {
        RtScope::HOST
    } else if address.is_unicast_link_local() {
        RtScope::LINK
    } else {
        RtScope::UNIVERSE
    };

    let body = CIfaddrMsg {
        family: CSocketAddrFamily::AF_INET6 as _,
        prefix_len: cidr.prefix_len(),
        flags: AddrMessageFlags::PERMANENT.bits() as u8,
        scope: scope as u8,
        index: iface.index(),
    };

    // Linux may report the following IPv6 address attributes, in order:
    // `IFA_LOCAL`, `IFA_ADDRESS`, `IFA_RT_PRIORITY`, `IFA_CACHEINFO`,
    // `IFA_FLAGS`, and `IFA_PROTO`.
    // TODO: Support `IFA_RT_PRIORITY` and `IFA_CACHEINFO`.
    // TODO: Support `IFA_PROTO` for non-loopback addresses.
    // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv6/addrconf.c>.
    let mut attrs = vec![
        // When a peer address is configured,
        // `IFA_ADDRESS` is the peer address,
        // and `IFA_LOCAL` is the local address.
        // Otherwise, `IFA_ADDRESS` is the local address,
        // and `IFA_LOCAL` is omitted.
        // Since `Iface` does not support peer addresses,
        // report only `IFA_ADDRESS` with the local address.
        AddrAttr::Address(IpAddr::V6(address)),
        AddrAttr::Flags(AddrMessageFlags::PERMANENT),
    ];
    if address.is_loopback() {
        // Linux marks an IPv6 loopback address with `IFAPROT_KERNEL_LO`.
        // Reference: <https://elixir.bootlin.com/linux/v7.1/source/net/ipv6/addrconf.c#L3289>.
        attrs.push(AddrAttr::Protocol(AddrProtocol::KernelLoopback));
    }

    AddrSegment::new(addr_header(request_header, CSegmentType::NEWADDR), body, attrs)
}
