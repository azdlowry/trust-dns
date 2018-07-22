// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! MDNS based DNS client connection for Client impls

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use futures::Future;
use trust_dns_proto::DnsStreamHandle;
use trust_dns_proto::error::ProtoError;
use trust_dns_proto::multicast::{MDNS_IPV4, MDNS_IPV6, MdnsClientStream, MdnsQueryType};
use trust_dns_proto::xfer::{DnsRequestSender, DnsExchange, DnsExchangeConnect, DnsMultiplexer, DnsRequestStreamHandle, DnsMultiplexerConnect};

use rr::dnssec::Signer;
use client::ClientConnection;
use error::*;

/// MDNS based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct MdnsClientConnection {
    multicast_addr: SocketAddr,
    packet_ttl: Option<u32>,
    ipv4_if: Option<Ipv4Addr>,
    ipv6_if: Option<u32>,
}

impl MdnsClientConnection {
    /// associates the socket to the well-known ipv4 multicast addess
    pub fn new_ipv4(packet_ttl: Option<u32>, ipv4_if: Option<Ipv4Addr>) -> Self {
        MdnsClientConnection {
            multicast_addr: *MDNS_IPV4,
            packet_ttl,
            ipv4_if,
            ipv6_if: None,
        }
    }

    /// associates the socket to the well-known ipv6 multicast addess
    pub fn new_ipv6(packet_ttl: Option<u32>, ipv6_if: Option<u32>) -> Self {
        MdnsClientConnection {
            multicast_addr: *MDNS_IPV6,
            packet_ttl,
            ipv4_if: None,
            ipv6_if,
        }
    }
}

impl ClientConnection for MdnsClientConnection {
    type Sender = DnsMultiplexer<MdnsClientStream, Signer>;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = DnsMultiplexerConnect<MdnsClientStream, Signer>;

    fn new_stream(
        &self,
    ) -> (
        DnsExchangeConnect<Self::SenderFuture, Self::Sender, Self::Response>,
        DnsRequestStreamHandle<Self::Response>,
    ) {
        let (mdns_client_stream, handle) = MdnsClientStream::new(
            self.multicast_addr,
            MdnsQueryType::OneShot,
            self.packet_ttl,
            self.ipv4_if,
            self.ipv6_if,
        );

        // FIXME: what is the Signer here?
        let mp = DnsMultiplexer::new(Box::new(mdns_client_stream), handle, None::<Arc<Signer>>);
        DnsExchange::connect(mp)
    }
}
