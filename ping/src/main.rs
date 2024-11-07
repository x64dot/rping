use std::env; // For command line stuff and other STUFF
use iptools; //  To access validate_ip function to validate a IP address(Ipv4/Ipv6)

mod parser {
    use std::net::{IpAddr};

    pub fn count_args(args: &Vec<String>) -> i32 {
        let mut count:i32 = 0;

        for arg in args.iter(){
            if !arg.is_empty() {
                count += 1;
            }

        }
        return count;
    }

    pub fn check_ipv6(ip: &String, program_path: &String) -> bool {

        // Convert IP to IpAddr Enum
        let new_ip: IpAddr = match ip.parse() {
            Ok(new_ip) => new_ip,
            Err(_) => {
                eprintln!("{}: {}: Name or service not known.", program_path, ip);
                return true;
            },
        };
    
        // Ipv6 isn't supported yet, cause im lazy
        if new_ip.is_ipv6() {
            println!("{}: Ipv6 isn't supported at this moment.", program_path);
            return true;
        }
        return false;
    }
}

mod networking {
    use std::net::{ToSocketAddrs, SocketAddr, IpAddr};
    use pnet_packet::icmp::{echo_request, IcmpTypes, IcmpCode};
    use pnet_packet::{util, MutablePacket};
    use pnet::transport;
    use pnet::packet::ip;
    use std::process;
    use std::{thread, time}; 
    use std::str::FromStr;

    pub fn resolve_domain(ip: &String, program_path: &String) -> Option<String> {

        // Make the IP formatted for further use
        let formatted = format!("{}:0", ip);

        // This is where the magic happens
        let mut addrs_iter = match formatted.to_socket_addrs() {
            Ok(addrs_iter) => addrs_iter,
            Err(e) => {
                eprintln!("{}: {}: {}", program_path, ip, e);
                return None;
            },
        };

        if let Some(mut ipv4) = addrs_iter.next() {
            // Some nice messy string manipulation
            let ipv4_str = ipv4.to_string();

            let idk: Vec<_> = ipv4_str.split(':').collect();
            let stripped_ipv4 = idk[0].to_string();

            return Some(stripped_ipv4);
        } 

        return None;    
    }

    pub fn ping(ip: &String) {
        // Get process UID for ICMP identifer 
        let process_id: u32 = process::id();

        let destination = IpAddr::from_str(ip).unwrap();

        let mut seq: u16 = 0; // The sequence counter

        let (mut sender, mut receiver) = transport::transport_channel(1024, transport::TransportChannelType::Layer3(pnet_packet::ip::IpNextHeaderProtocol(1))).unwrap();
        //let (mut sender, mut receiver) = transport::transport_channel(1024, transport::TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv6(pnet_packet::ip::IpNextHeaderProtocol(1)))).unwrap();

        loop {
            seq += 1;
            let mut buffer = vec![0u8; 64];

            let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();

            // Set the ICMP type which is 8, for echo request
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);

            // Set the ICMP code which is 0, which is the only ICMP code for echo request
            icmp_packet.set_icmp_code(IcmpCode::new(0));

            // Set the ICMP identifer which will be the UID of the process
            icmp_packet.set_identifier(process_id as u16);

            // Set the ICMP sequence, which always starts at 1 
            icmp_packet.set_sequence_number(seq);

            // Set the ICMP checksum to 0, before doing anything else
            icmp_packet.set_checksum(0);


            // Set a dummy payload 
            let payload = b"abc";
            icmp_packet.set_payload(payload);

            // Calculate the Checksum, and then set the checksum
            let checksum_value = pnet::util::checksum(&icmp_packet.packet_mut(), 0);
            icmp_packet.set_checksum(checksum_value);
            println!("ICMP Packet: {:?}", icmp_packet);

            

            sender.set_ttl(64).unwrap();
            sender.send_to(icmp_packet, destination).unwrap();

            println!("Sent ICMP Packet!");

            // Sleep for one second
            thread::sleep(time::Duration::new(1,0));

        }
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let mut ipv4: String = String::new();

    // If no additional arguments are supplied, we abort.
    if parser::count_args(&args) == 1 {
        println!("{}: usage error: Destination address required", &args[0]);
        return;
    }
    ipv4 = args[1].clone();

    // If the IP address supplied, is invalid, we will do a further check to see if its a domain, If not we abort.
    if iptools::ipv4::validate_ip(&args[1]) == false && iptools::ipv6::validate_ip(&args[1]) == false {
        if let Some(resolved_ipv4) = networking::resolve_domain(&args[1], &args[0]) {
            ipv4 = resolved_ipv4;
        } else {
            println!("{}: {}: Name or service not known.", &args[0], &args[1]);
            return;
        }
    }
    
    // If ipv4 variable is empty, we abort.
    if ipv4.is_empty(){
        if parser::check_ipv6(&args[1], &args[0]) == true {
            return;
        }
    }

    println!("{}", ipv4);
    networking::ping(&ipv4);

}
