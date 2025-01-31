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
    /// between other software (`0` means use process PID).
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
    pub fn recv(&self, buffer: &mut [u8], flags: i32) -> Result<isize> {
        let mut iovec = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
            iov_len: buffer.len(),
        };
        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let bytes_read = unsafe { libc::recvmsg(self.descriptor, &mut msghdr, flags) };
        if bytes_read == -1 {
            return Err(Error::last_os_error());
        }
        if bytes_read == 0 {
            return Err(Error::other("connection closed or buffer length zero"));
        }
        if (msghdr.msg_flags & libc::MSG_TRUNC) == libc::MSG_TRUNC {
            return Err(Error::other("datagram truncated, incomplete message"));
        }

        Ok(bytes_read)
    }

    /// Send data to the netlink socket.
    pub fn send(&self, buffer: &[u8], flags: i32) -> Result<isize> {
        let bytes_sent = unsafe {
            libc::send(
                self.descriptor,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                flags,
            )
        };
        if bytes_sent == -1 {
            return Err(Error::last_os_error());
        }
        if bytes_sent == 0 {
            return Err(Error::other("connection closed or buffer length zero"));
        }

        Ok(bytes_sent)
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
