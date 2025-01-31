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

use crate::message::{NetlinkParseError, NetlinkParseResult};
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use std::{
    io::{Cursor, Error},
    mem,
};

/// Netlink header message types (use in `kind` field).
pub mod netlink_types {
    pub const DONE: u16 = libc::NLMSG_DONE as u16;
    pub const ERROR: u16 = libc::NLMSG_ERROR as u16;
    pub const NOOP: u16 = libc::NLMSG_NOOP as u16;
    pub const OVERRUN: u16 = libc::NLMSG_OVERRUN as u16;

    pub const NEWLINK: u16 = libc::RTM_NEWLINK;
    pub const DELLINK: u16 = libc::RTM_DELLINK;
    pub const GETLINK: u16 = libc::RTM_GETLINK;
    pub const SETLINK: u16 = libc::RTM_SETLINK;
    pub const NEWADDR: u16 = libc::RTM_NEWADDR;
    pub const DELADDR: u16 = libc::RTM_DELADDR;
    pub const GETADDR: u16 = libc::RTM_GETADDR;
    pub const NEWROUTE: u16 = libc::RTM_NEWROUTE;
    pub const DELROUTE: u16 = libc::RTM_DELROUTE;
    pub const GETROUTE: u16 = libc::RTM_GETROUTE;
}

pub mod netlink_flags {
    pub const ACK: u16 = libc::NLM_F_ACK as u16;
    pub const APPEND: u16 = libc::NLM_F_APPEND as u16;
    pub const ATOMIC: u16 = libc::NLM_F_ATOMIC as u16;
    pub const CREATE: u16 = libc::NLM_F_CREATE as u16;
    pub const DUMP: u16 = libc::NLM_F_DUMP as u16;
    pub const ECHO: u16 = libc::NLM_F_ECHO as u16;
    pub const EXCL: u16 = libc::NLM_F_EXCL as u16;
    pub const MATCH: u16 = libc::NLM_F_MATCH as u16;
    pub const MULTI: u16 = libc::NLM_F_MULTI as u16;
    pub const REPLACE: u16 = libc::NLM_F_REPLACE as u16;
    pub const REQUEST: u16 = libc::NLM_F_REQUEST as u16;
    pub const ROOT: u16 = libc::NLM_F_ROOT as u16;
    pub const DUMP_FILTERED: u16 = libc::NLM_F_DUMP_FILTERED as u16;
    pub const DUMP_INTR: u16 = libc::NLM_F_DUMP_INTR as u16;
}

/// Netlink header rust version.
pub struct NetlinkHeader {
    /// Netlink message length (including this header).
    pub length: u32,
    /// Netlink message type.
    pub kind: u16,
    /// Netlink flags.
    pub flags: u16,
    /// Netlink message sequence (for matching request/reply).
    pub sequence: u32,
    /// Netlink port identification (to identify the messenger).
    pub port_id: u32,
}

impl NetlinkHeader {
    /// Read bytes from `AF_NETLINK` or custom interfaces and turn into netlink
    /// header.
    ///
    /// Returns NetlinkHeader and offset to payload.
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<(NetlinkHeader, usize)> {
        if bytes.len() < mem::size_of::<NetlinkHeader>() {
            return Err(NetlinkParseError::MessageIncomplete);
        }

        let mut cursor = Cursor::new(bytes);
        let length = cursor.read_u32::<NativeEndian>().unwrap();
        if (length as usize) > bytes.len() {
            return Err(NetlinkParseError::MessageIncomplete);
        }
        if (length as usize) < mem::size_of::<NetlinkHeader>() {
            return Err(NetlinkParseError::MessageTooSmall);
        }

        let kind = cursor.read_u16::<NativeEndian>().unwrap();
        let flags = cursor.read_u16::<NativeEndian>().unwrap();
        let sequence = cursor.read_u32::<NativeEndian>().unwrap();
        let port_id = cursor.read_u32::<NativeEndian>().unwrap();

        Ok((
            NetlinkHeader {
                length,
                kind,
                flags,
                sequence,
                port_id,
            },
            cursor.position() as usize,
        ))
    }

    /// Transform netlink data structures into binaries for interfaces.
    pub fn to_bytes(self, bytes: &mut [u8]) -> Result<usize, Error> {
        let mut cursor = Cursor::new(bytes);

        cursor.write_u32::<NativeEndian>(self.length)?;
        cursor.write_u16::<NativeEndian>(self.kind)?;
        cursor.write_u16::<NativeEndian>(self.flags)?;
        cursor.write_u32::<NativeEndian>(self.sequence)?;
        cursor.write_u32::<NativeEndian>(self.port_id)?;
        Ok(cursor.position() as usize)
    }
}
