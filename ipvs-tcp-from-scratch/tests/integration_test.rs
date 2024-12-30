use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ipvs::{self, AddressFamily, Destination, Flags, ForwardTypeFull, Netmask};
use ipvs_tcp_from_scratch::ConnectionWatcher;
use ipvs_tcp_from_scratch_common::{Event, TcpSocketEvent, TcpState};
use tokio::net::{TcpListener, TcpSocket};
use tokio::spawn;
use tokio::time::timeout;

struct IpvsConfig {
    accept_port: u16,
    refuse_port: u16,
    drop_port: u16,

    /// forward to
    accept_port_dest: u16,
    /// forward to
    refuse_port_dest: u16,
    /// forward to
    drop_port_dest: u16,
}

/// Sets up IPVS services which forward data
/// accept_port -> accept_port_dest
/// refuse_port -> refuse_port_dest
/// drop_port -> drop_port_dest
fn setup_ipvs() -> IpvsConfig {
    let conf = IpvsConfig {
        accept_port: 33,
        refuse_port: 44,
        drop_port: 55,

        accept_port_dest: 1234,
        refuse_port_dest: 2345,
        drop_port_dest: 3456,
    };
    let c = ipvs::IpvsClient::new().unwrap();
    let accepted = ipvs::Service {
        address: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        netmask: Netmask::new(32, AddressFamily::IPv4),
        scheduler: ipvs::Scheduler::RoundRobin,
        flags: Flags(0),
        port: Some(conf.accept_port),
        fw_mark: None,
        persistence_timeout: None,
        family: AddressFamily::IPv4,
        protocol: ipvs::Protocol::TCP,
    };
    let refused = ipvs::Service {
        port: Some(conf.refuse_port),
        ..accepted
    };
    let dropped = ipvs::Service {
        port: Some(conf.drop_port),
        ..accepted
    };

    let _ = c.delete_service(&accepted);
    let _ = c.delete_service(&refused);
    let _ = c.delete_service(&dropped);

    c.create_service(&accepted).unwrap();
    c.create_service(&refused).unwrap();
    c.create_service(&dropped).unwrap();

    let accept_dest = Destination {
        address: std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        fwd_method: ForwardTypeFull::Masquerade,
        weight: 1,
        upper_threshold: None,
        lower_threshold: None,
        port: conf.accept_port_dest,
        family: AddressFamily::IPv4,
    };
    let refused_dest = ipvs::Destination {
        port: conf.refuse_port_dest,
        ..accept_dest
    };
    // unroutable address, TEST-NET-3
    let dropped_dest = ipvs::Destination {
        address: std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        port: conf.drop_port_dest,
        ..accept_dest
    };

    let _ = c.delete_destination(&accepted, &accept_dest);
    let _ = c.delete_destination(&refused, &refused_dest);
    let _ = c.delete_destination(&dropped, &dropped_dest);

    let _ = c.create_destination(&accepted, &accept_dest).unwrap();
    let _ = c.create_destination(&refused, &refused_dest).unwrap();
    let _ = c.create_destination(&dropped, &dropped_dest).unwrap();

    conf
}

/// Sets up a TCP connection with optional port rewrites for IPVS testing
async fn setup_tcp_test<F, Fut>(
    listen_port: Option<u16>,  // Port server listens on
    connect_port: Option<u16>, // Optional different port to connect to (for IPVS tests)
    callback: F,               // Callback that receives the events receiver
) -> std::io::Result<()>
where
    F: FnOnce(tokio::sync::mpsc::Receiver<TcpSocketEvent>, SocketAddr) -> Fut,
    Fut: Future<Output = ()>,
{
    // Setup connection watcher
    let mut watcher = ConnectionWatcher::new().unwrap();
    let rx = watcher.get_events().await.unwrap();

    // If no port is passed, listen on a random port, which we won't use
    let server = TcpListener::bind(format!("127.0.0.1:{}", listen_port.unwrap_or(0)))
        .await
        .expect("Could not bind to localhost. is loopback interface up?");
    let server_addr = server.local_addr().unwrap();
    // println!("Listening on {server_addr:?}");

    tokio::time::sleep(Duration::from_millis(1)).await;
    spawn(async move {
        spawn(async move {
            let client = TcpSocket::new_v4().unwrap();
            let connect_addr = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                connect_port.unwrap_or(server_addr.port()),
            ));
            println!("Connecting to {connect_addr:?}");

            let fut = client.connect(connect_addr);
            // Linux sends a retransmission on the first 1s interval
            let wrapped = tokio::time::timeout(Duration::from_millis(1500), fut);
            let _c = match wrapped.await {
                Ok(r) => match r {
                    Ok(_) => println!("client connected"),
                    Err(e) => println!("client failed to connect {e:?}"),
                },
                Err(_) => println!("client timed out"),
            };
        });

        loop {
            let (_, _) = server.accept().await.unwrap();
        }
    });

    // Run the callback with the events receiver
    callback(rx, server_addr).await;

    Ok(())
}
#[tokio::test]
#[ignore]
async fn trace_direct_connection() {
    let _conf = setup_ipvs();
    setup_tcp_test(None, None, |mut rx, server_addr| async move {
        let event = rx.recv().await.unwrap();
        match event.event {
            Event::StateChange { old, new } => {
                assert_eq!(old, TcpState::Close);
                assert_eq!(new, TcpState::SynSent);
            }
            _ => panic!("Unexpected state"),
        };
        assert_eq!(event.key.dst.port(), server_addr.port());
        // On TCP Open we don't know what service it will map to yet
        assert_eq!(event.ipvs_dest, None);
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_accepted() {
    let conf = setup_ipvs();
    setup_tcp_test(
        Some(conf.accept_port_dest),
        Some(conf.accept_port),
        |mut rx, server_addr| async move {
            let event = rx.recv().await.unwrap();
            // Expect the connection to open
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::Close);
                assert_eq!(new, TcpState::SynSent);
            } else {
                panic!("Unexpected state")
            };
            assert_eq!(event.key.dst.port(), conf.accept_port);
            // We should have source-port on open
            assert_ne!(event.key.src.port(), 0);
            // No IPVS info available on this transition
            assert_eq!(event.ipvs_dest, None);

            // Expect connection to establish
            let event = rx.recv().await.unwrap();
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::SynSent);
                assert_eq!(new, TcpState::Established);
            } else {
                panic!("Unexpected state")
            };
            assert_eq!(event.key.dst.port(), conf.accept_port);
            // Now we have IPVS info
            assert!(event.ipvs_dest.is_some());
            let svc = event.ipvs_dest.unwrap();
            assert_eq!(svc.port(), conf.accept_port_dest);
            assert_eq!(svc.port(), server_addr.port());

            // Server closes connection
            let event = rx.recv().await.unwrap();
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::Established);
                assert_eq!(new, TcpState::CloseWait);
            } else {
                panic!("Unexpected state")
            };
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_refused() {
    let conf = setup_ipvs();
    // Nothing listens on the port, should get refused
    setup_tcp_test(
        None,
        Some(conf.accept_port),
        |mut rx, _server_addr| async move {
            let event = rx.recv().await.unwrap();
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::Close);
                assert_eq!(new, TcpState::SynSent);
            } else {
                panic!("Unexpected state");
            };
            assert_eq!(event.key.dst.port(), conf.accept_port); // Destination port, as seen by the client

            // On TCP Open we don't know what service it will map to yet
            assert_eq!(event.ipvs_dest, None);

            let event = match timeout(Duration::from_millis(100), rx.recv()).await {
                Ok(ev) => ev.unwrap(),
                Err(_) => panic!("Timed out waiting"),
            };
            // refused vvv the important part of the test
            assert!(
                matches!(event.event, Event::ReceivedReset),
                "Unexpected state"
            );
            // ^^ the important part of the test
            assert_eq!(event.key.dst.port(), conf.accept_port); // Destination port, as seen by the client

            assert!(event.ipvs_dest.is_some());
            let svc = event.ipvs_dest.unwrap();
            assert_eq!(svc.port(), conf.accept_port_dest);
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn trace_ipvs_connection_not_responding() {
    let conf = setup_ipvs();
    setup_tcp_test(
        None,
        Some(conf.drop_port),
        |mut rx, _server_addr| async move {
            let event = rx.recv().await.unwrap();
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::Close);
                assert_eq!(new, TcpState::SynSent);
            } else {
                panic!("Unexpected state");
            }
            assert_eq!(event.key.dst.port(), conf.drop_port); // Destination port, as seen by the client

            // On TCP Open we don't know what service it will map to yet
            assert_eq!(event.ipvs_dest, None);

            let event = rx.recv().await.unwrap();
            assert!(matches!(event.event, Event::ConnectRetrans));
            assert_eq!(event.key.dst.port(), conf.drop_port); // Destination port, as seen by the client
            assert!(event.ipvs_dest.is_some());
            let svc = event.ipvs_dest.unwrap();
            assert_eq!(svc.port(), conf.drop_port_dest);

            let event = rx.recv().await.unwrap();
            // client gave up, not RST
            // vvvv important part of the test
            if let Event::StateChange { old, new } = event.event {
                assert_eq!(old, TcpState::SynSent);
                assert_eq!(new, TcpState::Close);
            } else {
                panic!("Unexpected state");
            }
            // ^^^^ important part of the test
            assert!(event.ipvs_dest.is_some());
            let svc = event.ipvs_dest.unwrap();
            assert_eq!(svc.port(), conf.drop_port_dest);
        },
    )
    .await
    .unwrap();
}
