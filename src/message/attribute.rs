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

use std::io::Write;
use std::io::{Error, Read};

use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};

use crate::message::NetlinkParseError;
use crate::message::NetlinkParseResult;

pub mod attribute_types {
    /// This value is used ORed with attribute types to signal
    /// nested attributes.
    pub const NESTED: u16 = libc::NLA_F_NESTED as u16;
}

#[derive(Default)]
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
        let mut remaining = total_length;

        while cursor.position() < remaining as u64 {
            let kind = cursor.read_u16::<NativeEndian>().unwrap();
            let mut length = cursor.read_u16::<NativeEndian>().unwrap();

            if length < 4 {
                return Err(NetlinkParseError::AttributeTooSmall);
            }

            length -= 4;

            if length as usize > remaining {
                return Err(NetlinkParseError::AttributeTooSmall);
            }

            let mut data = vec![0; length as usize];
            cursor.read_exact(&mut data).unwrap();

            if kind & attribute_types::NESTED == attribute_types::NESTED {
                let (nested_attributes, _) = NetlinkAttribute::from(&data)?;

                attributes.push(NetlinkAttribute {
                    kind: kind & !(attribute_types::NESTED),
                    length,
                    value: data,
                    nested: nested_attributes,
                });
            } else {
                attributes.push(NetlinkAttribute {
                    kind,
                    length,
                    value: data,
                    ..Default::default()
                });
            }

            remaining -= length as usize;
        }

        Ok((attributes, cursor.position() as usize))
    }

    pub fn message_size(&self) -> usize {
        return self.length as usize;
    }

    pub fn to_bytes(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        let mut cursor = std::io::Cursor::new(bytes);

        cursor.write_u16::<NativeEndian>(self.kind)?;
        cursor.write_u16::<NativeEndian>(self.length)?;
        // Value already contains all nested attributes, so no need to
        // recurse on nested attributes.
        cursor.write_all(&self.value)?;

        Ok(cursor.position() as usize)
    }

    pub fn mac(&self) -> Option<Mac> {
        if self.value.len() < 6 {
            return None;
        }

        Some(self.value[0..5].try_into().unwrap())
    }

    pub fn ipv4(&self) -> Option<std::net::Ipv4Addr> {
        if self.value.len() < 4 {
            return None;
        }

        Some(u32::from_ne_bytes(self.value[0..3].try_into().unwrap()).into())
    }

    pub fn ipv6(&self) -> Option<std::net::Ipv6Addr> {
        if self.value.len() < 16 {
            return None;
        }

        Some(u128::from_ne_bytes(self.value[0..15].try_into().unwrap()).into())
    }
}
