// Copyright (c) 2024 Rafael Zalamena
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

use super::{
    packet_writer::PacketWriter, route_attribute::*, NetlinkParseError, NetlinkParseResult,
    PacketParser,
};

pub enum MessageType {
    Link(Link),
    Address(AddressMessage),
    Route(RouteMessage),
}

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

//
// Struct definitions
//
#[repr(C)]
pub struct LinkMessage {
    /// See [`family`] constants.
    pub family: u8,
    pub kind: u16,
    pub index: i32,
    pub flags: u32,
    pub change: u32,
}

pub struct Link<'a> {
    pub message: LinkMessage,
    pub attributes: Vec<Attribute<'a>>,
}

impl<'a> Link<'a> {
    pub fn from(parser: &mut PacketParser) -> NetlinkParseResult<Link<'a>> {
        if (parser.remaining() as usize) < std::mem::size_of::<LinkMessage>() {
            return Err(NetlinkParseError::MessageIncomplete);
        }

        let family = parser.read_u8();
        let kind = parser.read_u16();
        let index = parser.read_i32();
        let flags = parser.read_u32();
        let change = parser.read_u32();
        let mut attributes = vec![];

        while parser.remaining() > 0 {
            let length = parser.read_u16();
            let kind = parser.read_u16();

            match kind {
                libc::IFLA_ADDRESS => attributes.push(Attribute::Mac(AttributeValue::<Mac>::from(
                    parser, length, kind,
                )?)),
                _ => attributes.push(Attribute::Unknown(AttributeValue::<&[u8]>::from(
                    parser, length, kind,
                )?)),
            }
        }

        Ok(Link {
            message: LinkMessage {
                family,
                kind,
                index,
                flags,
                change,
            },
            attributes: attributes,
        })
    }

    pub fn to_array(self, writter: &mut PacketWriter) {
        writter.write_u8(self.message.family);
        writter.write_u16(self.message.kind);
        writter.write_i32(self.message.index);
        writter.write_u32(self.message.flags);
        writter.write_u32(self.message.change);
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

#[repr(C)]
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
