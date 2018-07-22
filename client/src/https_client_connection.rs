// Copyright (C) 2015 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! UDP based DNS client connection for Client impls

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::Future;
use rustls::{Certificate, ClientConfig, ClientSession};
use trust_dns_https::{HttpsClientConnect, HttpsClientStream, HttpsClientStreamBuilder};
use trust_dns_proto::xfer::{DnsExchange, DnsExchangeConnect, DnsRequestSender, DnsRequestStreamHandle};
use trust_dns_proto::DnsStreamHandle;
use webpki::DNSNameRef;

use client::ClientConnection;
use error::*;

/// UDP based DNS Client connection
///
/// Use with `trust_dns::client::Client` impls
#[derive(Clone)]
pub struct HttpsClientConnection {
    name_server: SocketAddr,
    dns_name: String,
    client_config: ClientConfig,
}

impl HttpsClientConnection {
    /// Creates a new client connection.
    ///
    /// *Note* this has side affects of binding the socket to 0.0.0.0 and starting the listening
    ///        event_loop. Expect this to change in the future.
    ///
    /// # Arguments
    ///
    /// * `name_server` - address of the name server to use for queries
    pub fn new() -> HttpsClientConnectionBuilder {
        HttpsClientConnectionBuilder::new()
    }
}

impl ClientConnection for HttpsClientConnection {
    type Sender = HttpsClientStream;
    type Response = <Self::Sender as DnsRequestSender>::DnsResponseFuture;
    type SenderFuture = HttpsClientConnect;

    fn new_stream(
        &self,
    ) -> (
        DnsExchangeConnect<Self::SenderFuture, Self::Sender, Self::Response>,
        DnsRequestStreamHandle<Self::Response>,
    ) {
        let https_builder = HttpsClientStreamBuilder::with_client_config(self.client_config.clone());
        let https_connect = https_builder.build(self.name_server, self.dns_name.clone());

        DnsExchange::connect(https_connect)
    }
}

struct HttpsClientConnectionBuilder {
    client_config: ClientConfig,
}

impl HttpsClientConnectionBuilder {
    /// Return a new builder for DNS-over-HTTPS
    pub fn new() -> HttpsClientConnectionBuilder {
        HttpsClientConnectionBuilder {
            client_config: ClientConfig::new(),
        }
    }

    /// Constructs a new TlsStreamBuilder with the associated ClientConfig
    pub fn with_client_config(client_config: ClientConfig) -> Self {
        HttpsClientConnectionBuilder { client_config }
    }

    /// Add a custom trusted peer certificate or certificate auhtority.
    ///
    /// If this is the 'client' then the 'server' must have it associated as it's `identity`, or have had the `identity` signed by this certificate.
    pub fn add_ca(&mut self, ca: Certificate) {
        self.client_config
            .root_store
            .add(&ca)
            .expect("bad certificate!");
    }

    /// Creates a new HttpsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name, Subject Public Key Info (SPKI) name, as associated to a certificate
    pub fn build(self, name_server: SocketAddr, dns_name: String) -> HttpsClientConnection {
        HttpsClientConnection {
            name_server,
            dns_name,
            client_config: self.client_config,
        }
    }
}
