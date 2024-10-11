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

use std::io::{BufRead, Cursor, Read};

pub struct PacketParser<'a> {
    bytes: &'a [u8],
    cursor: Cursor<&'a [u8]>,
    total: u64,
    netlink_length: u32,
}

impl PacketParser<'_> {
    pub fn new(input_buffer: &[u8]) -> PacketParser {
        PacketParser {
            bytes: input_buffer,
            cursor: Cursor::new(input_buffer),
            total: input_buffer.len() as u64,
            netlink_length: 0,
        }
    }

    pub fn remaining(&self) -> u64 {
        self.total - self.cursor.position()
    }

    pub fn position(&self) -> u64 {
        self.cursor.position()
    }

    pub fn set_netlink_length(&mut self, length: u32) {
        self.netlink_length = length
    }

    pub fn get_netlink_length(&self) -> u32 {
        self.netlink_length
    }

    pub fn read_u8(&mut self) -> u8 {
        let mut buffer = [0u8; 1];
        self.cursor.read(&mut buffer).unwrap();
        buffer[0]
    }

    pub fn read_u16(&mut self) -> u16 {
        let mut buffer = [0u8; 2];
        self.cursor.read(&mut buffer).unwrap();
        u16::from_ne_bytes(buffer)
    }

    pub fn read_i32(&mut self) -> i32 {
        let mut buffer = [0u8; 4];
        self.cursor.read(&mut buffer).unwrap();
        i32::from_ne_bytes(buffer)
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut buffer = [0u8; 4];
        self.cursor.read(&mut buffer).unwrap();
        u32::from_ne_bytes(buffer)
    }

    pub fn read_mac(&mut self) -> [u8; 6] {
        let mut buffer = [0u8; 6];
        self.cursor.read(&mut buffer).unwrap();
        buffer
    }

    pub fn read_vec(&mut self, amount: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; amount];
        self.cursor.read(&mut bytes).unwrap();
        bytes
    }

    pub fn get_slice(&mut self, amount: usize) -> &[u8] {
        let slice =
            &self.bytes[self.cursor.position() as usize..self.cursor.position() as usize + amount];
        self.cursor.consume(amount);
        slice
    }
}
