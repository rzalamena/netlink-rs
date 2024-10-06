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

pub mod packet_parser;
pub mod packet_writer;
pub mod route;
pub mod route_attribute;

use packet_parser::PacketParser;
use packet_writer::PacketWriter;
use route::MessageType;
use std::mem;

/// Netlink maximum message size
/// ([source](https://github.com/torvalds/linux/blob/v6.11/include/linux/netlink.h#L273)).
pub const NETLINK_MESSAGE_MAXIMUM_SIZE: usize = 8192;

/// All possible netlink parse errors.
#[derive(Debug)]
pub enum NetlinkParseError {
    /// Buffer is smaller than a netlink header.
    MessageTooSmall,
    /// Buffer is truncated (smaller than the header length).
    MessageIncomplete,
}

/// Netlink header rust version.
#[repr(C)]
pub struct NetlinkHeader {
    /// Netlink message length (including this header).
    length: u32,
    /// Netlink message type.
    kind: u16,
    /// Netlink flags.
    flags: u16,
    /// Netlink message sequence (for matching request/reply).
    sequence: u32,
    /// Netlink port identification (to identify the messenger).
    port_id: u32,
}

/// Netlink possible payload types.
pub enum NetlinkPayload<'a> {
    None,
    Route(route::MessageType),
    Unknown(&'a [u8]),
}

/// Netlink rust representation.
pub struct NetlinkMessage<'a> {
    /// Netlink header.
    pub header: NetlinkHeader,
    /// Netlink payload.
    pub payload: NetlinkPayload<'a>,
}

type NetlinkParseResult<T> = Result<T, NetlinkParseError>;

impl NetlinkMessage<'_> {
    /// Read bytes from `AF_NETLINK` or custom interfaces and turn into netlink
    /// data structures.
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<NetlinkMessage> {
        if bytes.len() < mem::size_of::<NetlinkHeader>() {
            return Err(NetlinkParseError::MessageIncomplete);
        }

        let mut parser = PacketParser::new(bytes);
        let length = parser.read_u32();
        if (length as usize) > bytes.len() {
            return Err(NetlinkParseError::MessageIncomplete);
        }
        if (length as usize) < mem::size_of::<NetlinkHeader>() {
            return Err(NetlinkParseError::MessageTooSmall);
        }

        parser.set_netlink_length(length);
        let kind = parser.read_u16();
        let flags = parser.read_u16();
        let sequence = parser.read_u32();
        let port_id = parser.read_u32();
        let netlink_header = NetlinkHeader {
            length,
            kind,
            flags,
            sequence,
            port_id,
        };

        match kind {
            libc::RTM_GETLINK | libc::RTM_NEWLINK | libc::RTM_DELLINK | libc::RTM_SETLINK => {
                match route::Link::from(&mut parser) {
                    Ok(link) => Ok(NetlinkMessage {
                        header: netlink_header,
                        payload: NetlinkPayload::Route(MessageType::Link(link)),
                    }),
                    Err(_) => Ok(NetlinkMessage {
                        header: netlink_header,
                        payload: NetlinkPayload::Unknown(&bytes[16..]),
                    }),
                }
            }
            _ => Ok(NetlinkMessage {
                header: netlink_header,
                payload: NetlinkPayload::Unknown(&bytes[16..]),
            }),
        }
    }

    /// Transform netlink data structures into binaries for interfaces.
    pub fn to_array(self, bytes: &mut [u8]) -> usize {
        let mut writer = PacketWriter::new(bytes);

        writer.write_u32(self.header.length);
        writer.write_u16(self.header.kind);
        writer.write_u16(self.header.flags);
        writer.write_u32(self.header.sequence);
        writer.write_u32(self.header.port_id);
        writer.written_total()
    }
}

#[cfg(test)]
mod message_test {
    use crate::message::*;

    #[test]
    fn short_message() {
        let message: [u8; 15] = [
            0x00, 0x00, 0x00, 0x00, // Length
            0x00, 0x00, // Type
            0x00, 0x00, // Flags
            0x00, 0x00, 0x00, 0x00, // Sequence
            0x00, 0x00, 0x00, // Port ID (missing 1 byte)
        ];
        match NetlinkMessage::from(&message) {
            Err(NetlinkParseError::MessageIncomplete) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn wrong_message_length() {
        let message = NetlinkMessage {
            header: NetlinkHeader {
                length: 15,
                kind: 0,
                flags: 0,
                sequence: 0,
                port_id: 0,
            },
            payload: NetlinkPayload::None,
        };
        let mut bytes = [0u8; NETLINK_MESSAGE_MAXIMUM_SIZE];
        message.to_array(&mut bytes);

        match NetlinkMessage::from(&bytes) {
            Err(NetlinkParseError::MessageTooSmall) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn message_incomplete() {
        let message = NetlinkMessage {
            header: NetlinkHeader {
                length: 17,
                kind: 0,
                flags: 0,
                sequence: 0,
                port_id: 0,
            },
            payload: NetlinkPayload::None,
        };
        let mut bytes = [0u8; 16];
        let written = message.to_array(&mut bytes);

        // Assert that we only wrote 16 bytes, but header says its 17.
        assert_eq!(written, 16);
        match NetlinkMessage::from(&bytes) {
            Err(NetlinkParseError::MessageIncomplete) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn valid_netlink_message() {
        let message = NetlinkMessage {
            header: NetlinkHeader {
                length: 16,
                kind: libc::NLMSG_ERROR as u16,
                flags: libc::NLM_F_CREATE as u16,
                sequence: 1,
                port_id: 123,
            },
            payload: NetlinkPayload::None,
        };
        let mut bytes = [0u8; NETLINK_MESSAGE_MAXIMUM_SIZE];
        message.to_array(&mut bytes);

        match NetlinkMessage::from(&bytes) {
            Ok(message) => {
                assert_eq!(message.header.length, 16);
                assert_eq!(message.header.kind, libc::NLMSG_ERROR as u16);
                assert_eq!(message.header.flags, libc::NLM_F_CREATE as u16);
                assert_eq!(message.header.sequence, 1);
                assert_eq!(message.header.port_id, 123);
            }
            _ => assert!(false),
        }
    }
}
