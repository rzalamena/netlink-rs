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

use std::io::Error;
use std::io::Result;
use std::mem;

/// Netlink socket structure.
///
/// Wrapper on the file descriptor created by `socket()` system call.
pub struct NetlinkSocket {
    descriptor: i32,
}

/// Netlink protocols enumeration.
pub enum NetlinkProtocol {
    /// Netlink routing messages: interfaces, addresses, routes etc...
    Route = libc::NETLINK_ROUTE as isize,
}

pub mod netlink_groups {
    pub const LINK: u32 = (1 << (libc::RTNLGRP_LINK - 1)) as u32;
    pub const NOTIFY: u32 = (1 << (libc::RTNLGRP_NOTIFY - 1)) as u32;
    pub const NEIGHBOR: u32 = (1 << (libc::RTNLGRP_NEIGH - 1)) as u32;
    pub const TC: u32 = (1 << (libc::RTNLGRP_TC - 1)) as u32;
    pub const IPV4_INTERFACE_ADDRESS: u32 = (1 << (libc::RTNLGRP_IPV4_IFADDR - 1)) as u32;
    pub const IPV4_MULTICAST_ROUTE: u32 = (1 << (libc::RTNLGRP_IPV4_MROUTE - 1)) as u32;
    pub const IPV4_ROUTE: u32 = (1 << (libc::RTNLGRP_IPV4_ROUTE - 1)) as u32;
    pub const IPV4_RULE: u32 = (1 << (libc::RTNLGRP_IPV4_RULE - 1)) as u32;
    pub const IPV6_INTERFACE_ADDRESS: u32 = (1 << (libc::RTNLGRP_IPV6_IFADDR - 1)) as u32;
    pub const IPV6_MULTICAST_ROUTE: u32 = (1 << (libc::RTNLGRP_IPV6_MROUTE - 1)) as u32;
    pub const IPV6_ROUTE: u32 = (1 << (libc::RTNLGRP_IPV6_ROUTE - 1)) as u32;
    pub const IPV6_INTERFACE_INFO: u32 = (1 << (libc::RTNLGRP_IPV6_IFINFO - 1)) as u32;
    pub const IPV6_PREFIX: u32 = (1 << (libc::RTNLGRP_IPV6_PREFIX - 1)) as u32;
    pub const IPV6_RULE: u32 = (1 << (libc::RTNLGRP_IPV6_RULE - 1)) as u32;
    pub const IPV4_NETCONF: u32 = (1 << (libc::RTNLGRP_IPV4_NETCONF - 1)) as u32;
    pub const IPV6_NETCONF: u32 = (1 << (libc::RTNLGRP_IPV6_NETCONF - 1)) as u32;
    pub const MPLS_ROUTE: u32 = (1 << (libc::RTNLGRP_MPLS_ROUTE - 1)) as u32;
    pub const NSID: u32 = (1 << (libc::RTNLGRP_NSID - 1)) as u32;
    pub const MPLS_NETCONF: u32 = (1 << (libc::RTNLGRP_MPLS_NETCONF - 1)) as u32;
    pub const IPV4_MROUTE_R: u32 = (1 << (libc::RTNLGRP_IPV4_MROUTE_R - 1)) as u32;
    pub const IPV6_MROUTE_R: u32 = (1 << (libc::RTNLGRP_IPV6_MROUTE_R - 1)) as u32;
    pub const NEXTHOP: u32 = (1 << (libc::RTNLGRP_NEXTHOP - 1)) as u32;
}

impl NetlinkSocket {
    /// Create a new socket for protocol `protocol`, bind it to the
    /// port ID ``pid`` and subscribe to notifications groups `groups`.
    ///
    /// `pid` is usually the process PID or something of common knowledge
    /// between other software.
    ///
    /// `groups` is defined per `protocol` and is a bitfield.
    ///
    /// Example:
    /// ```
    /// use netlink_rs::socket::NetlinkProtocol;
    /// use netlink_rs::socket::NetlinkSocket;
    /// use netlink_rs::socket::netlink_groups;
    ///
    /// match NetlinkSocket::bind(
    ///     NetlinkProtocol::Route,
    ///     0,
    ///     netlink_groups::LINK | netlink_groups::NEIGHBOR,
    /// ) {
    ///     Ok(_socket) => assert!(true),
    ///     Err(_error) => assert!(false),
    /// }
    /// ```
    pub fn bind(protocol: NetlinkProtocol, pid: u32, groups: u32) -> Result<NetlinkSocket> {
        let descriptor = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                protocol as i32,
            )
        };
        if descriptor == -1 {
            return Err(Error::last_os_error());
        }

        let mut socket_address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        socket_address.nl_family = libc::AF_NETLINK as u16;
        socket_address.nl_pid = pid;
        socket_address.nl_groups = groups;

        let result = unsafe {
            libc::bind(
                descriptor,
                &mut socket_address as *mut libc::sockaddr_nl as *mut libc::sockaddr,
                mem::size_of_val(&socket_address) as libc::socklen_t,
            )
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }

        Ok(NetlinkSocket { descriptor })
    }

    /// Read data from the netlink socket into array.
    ///
    /// To avoid message truncation use the constant
    /// [`crate::message::NETLINK_MESSAGE_MAXIMUM_SIZE`] for the array size.
    pub fn recv(self, buffer: &mut [u8], flags: i32) -> Result<isize> {
        let bytes_read = unsafe {
            libc::recv(
                self.descriptor,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                flags,
            )
        };
        if bytes_read == -1 {
            return Err(Error::last_os_error());
        }
        if bytes_read == 0 {
            return Err(Error::other("connection closed or buffer length zero"));
        }

        Ok(bytes_read)
    }
}

#[cfg(test)]
mod socket_test {
    use super::*;

    #[test]
    fn bind() {
        match NetlinkSocket::bind(
            NetlinkProtocol::Route,
            0,
            netlink_groups::IPV4_INTERFACE_ADDRESS | netlink_groups::IPV4_ROUTE,
        ) {
            Ok(_socket) => assert!(true),
            Err(_error) => assert!(false),
        }
    }
}
