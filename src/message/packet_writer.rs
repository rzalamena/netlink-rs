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

use std::io::Write;

pub struct PacketWriter<'a> {
    input_buffer: &'a mut [u8],
    total: usize,
}

impl PacketWriter<'_> {
    pub fn new(input_buffer: &mut [u8]) -> PacketWriter {
        PacketWriter {
            input_buffer,
            total: 0,
        }
    }

    pub fn written_total(&self) -> usize {
        self.total
    }

    pub fn write_u8(&mut self, value: u8) {
        match self.input_buffer.write(&value.to_ne_bytes()) {
            Ok(amount) => self.total += amount,
            Err(_) => (),
        }
    }

    pub fn write_u16(&mut self, value: u16) {
        match self.input_buffer.write(&value.to_ne_bytes()) {
            Ok(amount) => self.total += amount,
            Err(_) => (),
        }
    }

    pub fn write_i32(&mut self, value: i32) {
        match self.input_buffer.write(&value.to_ne_bytes()) {
            Ok(amount) => self.total += amount,
            Err(_) => (),
        }
    }

    pub fn write_u32(&mut self, value: u32) {
        match self.input_buffer.write(&value.to_ne_bytes()) {
            Ok(amount) => self.total += amount,
            Err(_) => (),
        }
    }
}
