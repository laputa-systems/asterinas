// SPDX-License-Identifier: MPL-2.0

use super::legacy::CRtGenMsg;
use crate::{
    net::socket::netlink::{
        message::{SegmentBody, SegmentCommon},
        route::message::attr::route::RouteAttr,
    },
    prelude::*,
};

pub(crate) type RouteSegment = SegmentCommon<CRtMsg, RouteAttr>;

impl SegmentBody for CRtMsg {
    type CLegacyType = CRtGenMsg;
}

/// `rtmsg` in Linux.
///
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/include/uapi/linux/rtnetlink.h>.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct CRtMsg {
    pub family: u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos: u8,
    pub table: u8,
    pub protocol: u8,
    pub scope: u8,
    pub type_: u8,
    pub flags: u32,
}

impl From<CRtGenMsg> for CRtMsg {
    fn from(value: CRtGenMsg) -> Self {
        Self {
            family: value.family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: 0,
            protocol: 0,
            scope: 0,
            type_: 0,
            flags: 0,
        }
    }
}
