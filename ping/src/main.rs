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

        //Convert IP to IpAddr Enum
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
    use std::net::{ToSocketAddrs, SocketAddr};
    use pnet_packet::icmp;

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

        if let Some(mut ipv4) = addrs_iter.next(){
            
            return Some(ipv4.to_string().split(':').collect());
        } 

        return None;    
    }

    pub fn ping(ip: &String) {
        
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

}
