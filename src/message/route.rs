// Copyright (c) 2025 Rafael Zalamena
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use byteorder::{NativeEndian, ReadBytesExt};
use std::io::Cursor;

use super::{NetlinkParseError, NetlinkParseResult};

//
// Constants definitions
//
pub mod family {
    pub const UNSPEC: u8 = libc::AF_UNSPEC as u8;
    pub const INET: u8 = libc::AF_INET as u8;
    pub const INET6: u8 = libc::AF_INET6 as u8;
}

pub mod route_type {
    pub const UNSPEC: u8 = libc::RTN_UNSPEC;
    pub const UNICAST: u8 = libc::RTN_UNICAST;
    pub const LOCAL: u8 = libc::RTN_LOCAL;
    pub const BROADCAST: u8 = libc::RTN_BROADCAST;
    pub const ANYCAST: u8 = libc::RTN_ANYCAST;
    pub const MULTICAST: u8 = libc::RTN_MULTICAST;
    pub const BLACKHOLE: u8 = libc::RTN_BLACKHOLE;
    pub const UNREACHEABLE: u8 = libc::RTN_UNREACHABLE;
    pub const PROHIBIT: u8 = libc::RTN_PROHIBIT;
    pub const THROW: u8 = libc::RTN_THROW;
    pub const NAT: u8 = libc::RTN_NAT;
    pub const XRESOLVE: u8 = libc::RTN_XRESOLVE;
}

pub mod protocol {
    pub const UNSPEC: u8 = libc::RTPROT_UNSPEC;
    pub const REDIRECT: u8 = libc::RTPROT_REDIRECT;
    pub const KERNEL: u8 = libc::RTPROT_KERNEL;
    pub const BOOT: u8 = libc::RTPROT_BOOT;
    pub const STATIC: u8 = libc::RTPROT_STATIC;
}

pub mod scope {
    pub const UNIVERSE: u8 = libc::RT_SCOPE_UNIVERSE;
    pub const SITE: u8 = libc::RT_SCOPE_SITE;
    pub const LINK: u8 = libc::RT_SCOPE_LINK;
    pub const HOST: u8 = libc::RT_SCOPE_HOST;
    pub const NOWHERE: u8 = libc::RT_SCOPE_NOWHERE;
}

pub mod route_flags {
    pub const NOTIFY: u32 = libc::RTM_F_NOTIFY;
    pub const CLONED: u32 = libc::RTM_F_CLONED;
    pub const EQUALIZE: u32 = libc::RTM_F_EQUALIZE;
}

pub mod link_attribute {
    pub const ADDRESS: u16 = libc::IFLA_ADDRESS;
    pub const IFNAME: u16 = libc::IFLA_IFNAME;
    pub const MTU: u16 = libc::IFLA_MTU;
}

//
// Struct definitions
//
pub struct LinkMessage {
    /// See [`family`] constants.
    pub family: u8,
    pub kind: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

impl LinkMessage {
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<(LinkMessage, usize)> {
        if bytes.len() < 16 {
            return Err(NetlinkParseError::MessageTooSmall);
        }

        let mut cursor = Cursor::new(bytes);

        let family = cursor.read_u8().unwrap();
        let kind = cursor.read_u16::<NativeEndian>().unwrap();
        let index = cursor.read_i32::<NativeEndian>().unwrap();
        let flags = cursor.read_u32::<NativeEndian>().unwrap();
        let change = cursor.read_u32::<NativeEndian>().unwrap();
        let link = LinkMessage {
            family,
            kind,
            index,
            flags,
            change,
        };

        Ok((link, cursor.position() as usize))
    }
}

#[repr(C)]
pub struct AddressMessage {
    /// See [`family`] constants.
    pub family: u8,
    pub prefix_length: u8,
    pub flags: u8,
    pub scope: u8,
    pub index: u32,
}

impl AddressMessage {
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<(AddressMessage, usize)> {
        if bytes.len() < 8 {
            return Err(NetlinkParseError::MessageTooSmall);
        }

        let mut cursor = Cursor::new(bytes);

        let family = cursor.read_u8().unwrap();
        let prefix_length = cursor.read_u8().unwrap();
        let flags = cursor.read_u8().unwrap();
        let scope = cursor.read_u8().unwrap();
        let index = cursor.read_u32::<NativeEndian>().unwrap();
        let address = AddressMessage {
            family,
            prefix_length,
            flags,
            scope,
            index,
        };

        Ok((address, cursor.position() as usize))
    }
}

pub struct RouteMessage {
    /// See [`family`] constants.
    pub family: u8,
    pub destination_prefix_length: u8,
    pub source_prefix_length: u8,
    pub type_of_service: u8,
    pub table: u8,
    /// See [`protocol`] constants.
    pub protocol: u8,
    /// See [`scope`] constants.
    pub scope: u8,
    pub kind: u8,
    /// See [`route_flags`] for available flags.
    pub flags: u32,
}

impl RouteMessage {
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<(RouteMessage, usize)> {
        if bytes.len() < 12 {
            return Err(NetlinkParseError::MessageTooSmall);
        }

        let mut cursor = Cursor::new(bytes);

        let family = cursor.read_u8().unwrap();
        let destination_prefix_length = cursor.read_u8().unwrap();
        let source_prefix_length = cursor.read_u8().unwrap();
        let type_of_service = cursor.read_u8().unwrap();
        let table = cursor.read_u8().unwrap();
        let protocol = cursor.read_u8().unwrap();
        let scope = cursor.read_u8().unwrap();
        let kind = cursor.read_u8().unwrap();
        let flags = cursor.read_u32::<NativeEndian>().unwrap();
        let route = RouteMessage {
            family,
            destination_prefix_length,
            source_prefix_length,
            type_of_service,
            table,
            protocol,
            scope,
            kind,
            flags,
        };

        Ok((route, cursor.position() as usize))
    }
}
