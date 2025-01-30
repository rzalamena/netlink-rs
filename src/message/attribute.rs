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

use std::{io::Read, vec};

use byteorder::{NativeEndian, ReadBytesExt};

use crate::message::NetlinkParseError;
use crate::message::NetlinkParseResult;

pub struct NetlinkAttribute {
    /// Netlink attribute type
    pub kind: u16,
    /// Attribute length
    pub length: u16,
    /// Value in binary
    pub value: Vec<u8>,
    /// Nested attributes
    pub nested: Vec<NetlinkAttribute>,
}

pub enum NetlinkAttributeParseError {
    /// Attribute size is smaller than header (fatal error).
    AttributeTooSmall,
    /// Bad attribute size (fatal error).
    AttributeIncomplete,
}

type Mac = [u8; 6];

impl NetlinkAttribute {
    pub fn from(bytes: &[u8]) -> NetlinkParseResult<(Vec<NetlinkAttribute>, usize)> {
        let total_length = bytes.len();
        if total_length < 4 {
            return Err(NetlinkParseError::AttributeTooSmall);
        }

        let mut attributes = vec![];
        let mut cursor = std::io::Cursor::new(bytes);
        let remaining = total_length;

        while cursor.position() < total_length as u64 {
            let kind = cursor.read_u16::<NativeEndian>().unwrap();
            let length = cursor.read_u16::<NativeEndian>().unwrap();

            if length as usize > remaining {
                return Err(NetlinkParseError::AttributeTooSmall);
            }

            let mut data = vec![0; length as usize];
            cursor.read_exact(&mut data).unwrap();

            if kind & libc::NLA_F_NESTED as u16 == libc::NLA_F_NESTED as u16 {
                let (nested_attributes, _) = NetlinkAttribute::from(&data)?;

                attributes.push(NetlinkAttribute {
                    kind,
                    length,
                    value: data,
                    nested: nested_attributes,
                });
            } else {
                attributes.push(NetlinkAttribute {
                    kind,
                    length,
                    value: data,
                    nested: Default::default(),
                });
            }
        }

        Ok((attributes, cursor.position() as usize))
    }

    pub fn mac(self) -> Option<Mac> {
        if self.value.len() < 6 {
            return None;
        }

        Some(self.value[0..5].try_into().unwrap())
    }

    pub fn ipv4(self) -> Option<std::net::Ipv4Addr> {
        if self.value.len() < 4 {
            return None;
        }

        Some(u32::from_ne_bytes(self.value[0..3].try_into().unwrap()).into())
    }
}
