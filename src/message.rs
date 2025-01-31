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

pub mod attribute;
pub mod header;
pub mod route;

/// Netlink maximum message size
/// ([source](https://github.com/torvalds/linux/blob/v6.11/include/linux/netlink.h#L273)).
pub const NETLINK_MESSAGE_MAXIMUM_SIZE: usize = 8192;

/// All possible netlink parse errors.
#[derive(Debug)]
pub enum NetlinkParseError {
    /// Buffer is smaller than a netlink header (unrecoverable).
    MessageTooSmall,
    /// Buffer is truncated (smaller than the header length, needs more reading).
    MessageIncomplete,
    /// Error parsing the attributes (unrecoverable).
    AttributeTooSmall,
}

/// Netlink possible payload types.
pub enum NetlinkPayload {
    /// Unloaded: initial payload value when it wasn't read yet.
    Unloaded,
    /// No payload.
    None,
    /// Link types: RTM_{NEW,DEL,GET,SET}LINK
    Link(route::LinkMessage),
    /// Address message: RTM_{NEW,DEL,GET}ADDR
    Address(route::AddressMessage),
    /// Route message: RTM_{NEW,DEL,GET}ROUTE
    Route(route::RouteMessage),
    /// Unknown payload type.
    Unknown(Vec<u8>),
}

/// Netlink rust representation.
pub struct NetlinkMessage {
    /// Netlink header.
    pub header: header::NetlinkHeader,
    /// Netlink payload.
    pub payload: NetlinkPayload,
    /// Netlink attributes.
    pub attributes: Vec<attribute::NetlinkAttribute>,
}

type NetlinkParseResult<T> = Result<T, NetlinkParseError>;

impl NetlinkMessage {
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<NetlinkMessage> {
        let (header, payload_position) = header::NetlinkHeader::from(bytes)?;
        let total_length = header.length as usize;
        let payload_slice = &bytes[payload_position..total_length];

        let (payload, attributes_position) = match header.kind {
            header::netlink_types::NEWLINK
            | header::netlink_types::DELLINK
            | header::netlink_types::GETLINK
            | header::netlink_types::SETLINK => {
                let (payload, position) = route::LinkMessage::from(&payload_slice)?;
                (NetlinkPayload::Link(payload), position)
            }

            header::netlink_types::NEWADDR
            | header::netlink_types::DELADDR
            | header::netlink_types::GETADDR => {
                let (payload, position) = route::AddressMessage::from(&payload_slice)?;
                (NetlinkPayload::Address(payload), position)
            }

            header::netlink_types::NEWROUTE
            | header::netlink_types::DELROUTE
            | header::netlink_types::GETROUTE => {
                let (payload, position) = route::RouteMessage::from(&payload_slice)?;
                (NetlinkPayload::Route(payload), position)
            }

            header::netlink_types::DONE
            | header::netlink_types::ERROR
            | header::netlink_types::NOOP
            | header::netlink_types::OVERRUN => (NetlinkPayload::None, total_length),

            _ => (NetlinkPayload::Unknown(Vec::from(payload_slice)), total_length),
        };

        if attributes_position != total_length {
            let attributes_slice = &bytes[attributes_position..total_length];
            let (attributes, _next_header_position) =
                attribute::NetlinkAttribute::from(&attributes_slice)?;

            Ok(NetlinkMessage {
                header,
                payload,
                attributes,
            })
        } else {
            Ok(NetlinkMessage {
                header,
                payload,
                attributes: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod message_test {
    use crate::message::header::netlink_flags;
    use crate::message::header::netlink_types;
    use crate::message::header::NetlinkHeader;
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
        match NetlinkHeader::from(&message) {
            Err(NetlinkParseError::MessageIncomplete) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn wrong_message_length() {
        let header = NetlinkHeader {
            length: 15,
            kind: 0,
            flags: 0,
            sequence: 0,
            port_id: 0,
        };
        let mut bytes = [0u8; NETLINK_MESSAGE_MAXIMUM_SIZE];
        header.to_bytes(&mut bytes).unwrap();

        match NetlinkHeader::from(&bytes) {
            Err(NetlinkParseError::MessageTooSmall) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn message_incomplete() {
        let header = NetlinkHeader {
            length: 17,
            kind: 0,
            flags: 0,
            sequence: 0,
            port_id: 0,
        };
        let mut bytes = [0u8; 16];
        let written = header.to_bytes(&mut bytes).unwrap();

        // Assert that we only wrote 16 bytes, but header says its 17.
        assert_eq!(written, 16);
        match NetlinkHeader::from(&bytes) {
            Err(NetlinkParseError::MessageIncomplete) => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn valid_netlink_message() {
        let header = NetlinkHeader {
            length: 16,
            kind: netlink_types::NOOP,
            flags: netlink_flags::CREATE,
            sequence: 1,
            port_id: 123,
        };
        let mut bytes = [0u8; NETLINK_MESSAGE_MAXIMUM_SIZE];
        header.to_bytes(&mut bytes).unwrap();

        match NetlinkHeader::from(&bytes) {
            Ok((header, _)) => {
                assert_eq!(header.length, 16);
                assert_eq!(header.kind, netlink_types::NOOP as u16);
                assert_eq!(header.flags, netlink_flags::CREATE as u16);
                assert_eq!(header.sequence, 1);
                assert_eq!(header.port_id, 123);
            }
            _ => assert!(false),
        }
    }

    #[test]
    fn buffer_too_small() {
        let header = NetlinkHeader {
            length: 16,
            kind: netlink_types::NOOP,
            flags: netlink_flags::CREATE,
            sequence: 1,
            port_id: 123,
        };
        let mut bytes = [0u8; 15];
        match header.to_bytes(&mut bytes) {
            Ok(_) => assert!(false),
            Err(_) => assert!(true),
        }
    }
}
