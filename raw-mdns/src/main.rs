use std::net::{Ipv4Addr, SocketAddr};

use net2::unix::UnixUdpBuilderExt;

const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;
const INADDR_ANY: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const MY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 71);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let udp_socket = net2::UdpBuilder::new_v4()
        .unwrap()
        .reuse_address(true)
        .unwrap()
        .reuse_port(true)
        .unwrap()
        .bind((INADDR_ANY, MULTICAST_PORT))
        .unwrap();

    udp_socket.set_multicast_loop_v4(false).unwrap();
    udp_socket
        .join_multicast_v4(&MULTICAST_ADDR, &MY_IP)
        .unwrap();

    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_hue._tcp.local",
        false,
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );

    let data = builder.build().unwrap();

    udp_socket
        .send_to(
            &data,
            SocketAddr::new(MULTICAST_ADDR.into(), MULTICAST_PORT),
        )
        .unwrap();

    let mut buf = [0; 4096];
    let (bytes_read, responder_addr) = udp_socket.recv_from(&mut buf).unwrap();

    let packet = dns_parser::Packet::parse(&buf[..bytes_read])?;

    println!(
        "Received Packet [{:#x?}] from {:?}",
        &packet, &responder_addr
    );

    Ok(())
}
