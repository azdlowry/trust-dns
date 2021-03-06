#![cfg(feature = "mdns")]

extern crate chrono;
extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate openssl;
extern crate tokio;
extern crate tokio_timer;
extern crate trust_dns;
extern crate trust_dns_integration;
extern crate trust_dns_proto;
extern crate trust_dns_server;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures::future::Either;
use futures::{Future, Stream};
use tokio::runtime::current_thread::Runtime;
use tokio_timer::Delay;

use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::multicast::MdnsQueryType;
use trust_dns::multicast::{MdnsClientStream, MdnsStream};
use trust_dns::op::Message;
use trust_dns::rr::{DNSClass, Name, RecordType};
use trust_dns::serialize::binary::BinDecodable;
use trust_dns_proto::xfer::SerialMessage;

const MDNS_PORT: u16 = 5363;

lazy_static! {
    /// 250 appears to be unused/unregistered
    static ref TEST_MDNS_IPV4: IpAddr = Ipv4Addr::new(224,0,0,249).into();
    /// FA appears to be unused/unregistered
    static ref TEST_MDNS_IPV6: IpAddr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0x00F9).into();
}

fn mdns_responsder(
    test_name: &'static str,
    client_done: Arc<AtomicBool>,
    mdns_addr: SocketAddr,
) -> JoinHandle<()> {
    let server = Arc::new(Barrier::new(2));
    let client = Arc::clone(&server);

    let join_handle = std::thread::Builder::new()
        .name(format!("{}:server", test_name))
        .spawn(move || {
            let mut io_loop = Runtime::new().unwrap();

            // a max time for the test to run
            let mut timeout = Delay::new(Instant::now() + Duration::from_millis(100));

            // FIXME: ipv6 if is hardcoded, need a different strategy
            let (mdns_stream, mdns_handle) = MdnsStream::new(
                mdns_addr,
                MdnsQueryType::OneShotJoin,
                Some(1),
                None,
                Some(5),
            );

            let mut stream = io_loop
                .block_on(mdns_stream)
                .ok()
                .expect("failed to create server stream")
                .into_future();

            server.wait();

            while !client_done.load(std::sync::atomic::Ordering::Relaxed) {
                match io_loop
                    .block_on(stream.select2(timeout))
                    .ok()
                    .expect("server stream closed")
                {
                    Either::A((data_src_stream_tmp, timeout_tmp)) => {
                        let (data_src, stream_tmp) = data_src_stream_tmp;
                        let (data, src) = data_src.expect("no buffer received").unwrap();

                        stream = stream_tmp.into_future();
                        timeout = timeout_tmp;

                        let message = Message::from_bytes(&data).expect("message decode failed");

                        // we're just going to bounce this message back

                        mdns_handle
                            .unbounded_send(SerialMessage::new(
                                message.to_vec().expect("message encode failed"),
                                src,
                            ))
                            .unwrap();
                    }
                    Either::B(((), data_src_stream_tmp)) => {
                        stream = data_src_stream_tmp;
                        timeout = Delay::new(Instant::now() + Duration::from_millis(100));
                    }
                }
            }
        })
        .unwrap();

    client.wait();
    println!("server started");

    join_handle
}

#[test]
fn test_query_mdns_ipv4() {
    let addr = SocketAddr::new(*TEST_MDNS_IPV4, MDNS_PORT + 1);
    let client_done = Arc::new(AtomicBool::new(false));
    let _server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone(), addr);

    // Check that the server is ready before sending...
    let mut io_loop = Runtime::new().unwrap();
    //let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = MdnsClientStream::new(addr, MdnsQueryType::OneShot, None, None, None);
    let client = ClientFuture::new(stream, sender, None);
    let mut client = io_loop.block_on(client).unwrap();

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);

    let message = io_loop.block_on(future).expect("mdns query failed");

    client_done.store(true, Ordering::Relaxed);

    println!("client message: {:#?}", message);
}

#[test]
#[ignore]
fn test_query_mdns_ipv6() {
    let addr = SocketAddr::new(*TEST_MDNS_IPV6, MDNS_PORT + 2);
    let client_done = Arc::new(AtomicBool::new(false));
    let _server_thread = mdns_responsder("test_query_mdns_ipv4", client_done.clone(), addr);
    let mut io_loop = Runtime::new().unwrap();

    // FIXME: ipv6 if is hardcoded...
    let (stream, sender) = MdnsClientStream::new(addr, MdnsQueryType::OneShot, None, None, Some(5));
    let client = ClientFuture::new(stream, sender, None);
    let mut client = io_loop.block_on(client).unwrap();

    // A PTR request is the DNS-SD method for doing a directory listing...
    let name = Name::from_ascii("_dns._udp.local.").unwrap();
    let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);

    let message = io_loop.block_on(future).expect("mdns query failed");

    client_done.store(true, Ordering::Relaxed);

    println!("client message: {:#?}", message);
}
