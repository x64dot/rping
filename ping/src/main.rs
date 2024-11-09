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
    use std::net::{ToSocketAddrs, IpAddr};
    use pnet_packet::icmp::{echo_request, IcmpTypes, IcmpCode};
    use pnet_packet::{MutablePacket};
    use pnet::transport;
    use pnet::packet::{Packet};
    use std::process;
    use std::{thread, time}; 
    use std::str::FromStr;
    use std::io::{self, Write};

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

        if let Some(ipv4) = addrs_iter.next() {
            // Some nice messy string manipulation
            let ipv4_str = ipv4.to_string();

            let idk: Vec<_> = ipv4_str.split(':').collect();
            let stripped_ipv4 = idk[0].to_string();

            return Some(stripped_ipv4);
        } 

        return None;    
    }

    pub fn ping(ip: &String, domain_or_not: &bool, domain: &String) {
        // Get process UID for ICMP identifer 
        let process_id: u32 = process::id();

        let mut track: bool = true;

        let destination = IpAddr::from_str(ip).unwrap();

        let timeout = std::time::Duration::from_secs(1);
        let mut packets_transmitted: i32 = 0;

        let mut seq: u16 = 0; // The sequence counter

        let (mut sender, mut receiver) = transport::transport_channel(1024, transport::TransportChannelType::Layer4(pnet::transport::TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocol(1)))).unwrap();

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
            let payload = b"abcdefghijklmnopqrstuvwxyz";
            icmp_packet.set_payload(payload);

            // Get payload size in bytes 
            let payload_size = payload.len() * std::mem::size_of::<u8>();

            // Calculate the Checksum, and then set the checksum
            let checksum_value = pnet::util::checksum(&icmp_packet.packet_mut(), 0);
            icmp_packet.set_checksum(checksum_value);

            // Set TTL(Time to live) to 64
            let ttl: u8 = 64;
            sender.set_ttl(ttl).unwrap();

            // Get packet size
            let packet_size = payload_size + 8;

            if track {
                if *domain_or_not {
                    print!("PING {} ({})", domain, ip);
                    print!(" {}({}) bytes of data\n", payload_size,  packet_size);

                    io::stdout().flush().unwrap();
                    track = false;
                } else {
                    print!("PING {} ({})", ip, ip);
                    print!(" {}({}) bytes of data\n", payload_size, packet_size);
            
                    io::stdout().flush().unwrap();
                    track = false;
                }
            }

            sender.send_to(icmp_packet, destination).unwrap();

            packets_transmitted += 1;
            
            let mut packet_iter = transport::icmp_packet_iter(&mut receiver);

            match packet_iter.next_with_timeout(timeout) {
                // If nothing was received within the time frame
                Ok(None) => println!("Request timed out."), 

                // How fun, something came back
                Ok(Some(packet)) => {
                    // Unpacking the tuple
                    let (ret_packet_struct, ret_packet_addr) = packet;

                    if ret_packet_struct.get_icmp_code() == pnet_packet::icmp::IcmpCode(0) && ret_packet_struct.get_icmp_type() == pnet_packet::icmp::IcmpType(0) {
                        let ret_packet = ret_packet_struct.packet();
                        let ret_packet_size = ret_packet.len() * std::mem::size_of::<u8>();
                        


                        println!("{} bytes from {}: icmp_seq={} ttl={} " , ret_packet_size, ret_packet_addr, seq, ttl);
                    }                   

                },

                Err(e) => println!("Error: {}", e),
            }

            // Sleep for one second before sending new ICMP echo request 
            thread::sleep(time::Duration::new(1,0));

        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut ipv4: String = String::new();
    let mut domain_bool: bool = false;
    let mut domain: String = String::new();

    // If no additional arguments are supplied, we abort.
    if parser::count_args(&args) == 1 {
        println!("{}: usage error: Destination address required", &args[0]);
        return;
    }
    ipv4 = args[1].clone();

    // If the IP address supplied, is invalid, we will do a further check to see if its a domain, If not we abort.
    if iptools::ipv4::validate_ip(&args[1]) == false && iptools::ipv6::validate_ip(&args[1]) == false {
        if let Some(resolved_ipv4) = networking::resolve_domain(&args[1], &args[0]) {
            domain = ipv4;
            ipv4 = resolved_ipv4;
            domain_bool = true;
        } else {
            println!("{}: {}: Name or service not known.", &args[0], &args[1]);
            return;
        }
    }
    
    // If ipv4 variable is empty, we abort.
    if ipv4.is_empty() {
        if parser::check_ipv6(&args[1], &args[0]) == true {
            return;
        }
    }

    if domain_bool {
        networking::ping(&ipv4, &domain_bool, &domain);
    } else {
        networking::ping(&ipv4, &domain_bool, &domain);
    }
}
