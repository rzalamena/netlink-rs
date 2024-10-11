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

use super::{packet_parser::PacketParser, NetlinkParseResult};

pub type IPv4 = u32;
pub type IPv6 = [u32; 4];
pub type Mac = [u8; 6];

pub struct AttributeValue<T> {
    pub length: u16,
    pub kind: u16,
    pub value: T,
}

impl AttributeValue<IPv4> {
    pub fn from(
        parser: &mut PacketParser,
        length: u16,
        kind: u16,
    ) -> NetlinkParseResult<AttributeValue<IPv4>> {
        Ok(AttributeValue::<IPv4> {
            length: length,
            kind: kind,
            value: parser.read_u32(),
        })
    }
}

impl AttributeValue<IPv6> {
    pub fn from(
        parser: &mut PacketParser,
        length: u16,
        kind: u16,
    ) -> NetlinkParseResult<AttributeValue<IPv6>> {
        Ok(AttributeValue::<IPv6> {
            length: length,
            kind: kind,
            value: [
                parser.read_u32(),
                parser.read_u32(),
                parser.read_u32(),
                parser.read_u32(),
            ],
        })
    }
}

impl AttributeValue<Mac> {
    pub fn from(
        parser: &mut PacketParser,
        length: u16,
        kind: u16,
    ) -> NetlinkParseResult<AttributeValue<Mac>> {
        Ok(AttributeValue::<Mac> {
            length: length,
            kind: kind,
            value: [
                parser.read_u8(),
                parser.read_u8(),
                parser.read_u8(),
                parser.read_u8(),
                parser.read_u8(),
                parser.read_u8(),
            ],
        })
    }
}

impl AttributeValue<&[u8]> {
    pub fn from<'a>(
        parser: &'a mut PacketParser<'a>,
        length: u16,
        kind: u16,
    ) -> NetlinkParseResult<AttributeValue<&'a [u8]>> {
        Ok(AttributeValue::<&[u8]> {
            length,
            kind,
            value: parser.get_slice(length as usize),
        })
    }
}

pub enum Attribute<'a> {
    IPv4(AttributeValue<IPv4>),
    IPv6(AttributeValue<IPv6>),
    Mac(AttributeValue<Mac>),
    Unknown(AttributeValue<&'a [u8]>),
}
