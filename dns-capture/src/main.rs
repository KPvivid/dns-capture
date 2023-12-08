use pcap;
use dns_parser::{Packet, RData};

fn parse_dns_packet(dns_payload: &[u8]) {
    match Packet::parse(dns_payload) {
        Ok(dns_packet) => {
            println!("DNS Packet:");
            println!("  Questions:");
            for question in dns_packet.questions {
                println!("    Name: {}", question.qname);
                println!("    Type: {:?}", question.qtype);
                println!("    Class: {:?}", question.qclass);
            }

            println!("  Answers:");
            for answer in dns_packet.answers {
                print_dns_record("    ", &answer);
            }

            println!("  Nameservers:");
            for authority in dns_packet.nameservers {
                print_dns_record("    ", &authority);
            }

            println!("  Additionals:");
            for additional in dns_packet.additional {
                print_dns_record("    ", &additional);
            }
        }
        Err(err) => {
            eprintln!("Error parsing DNS packet: {:?}", err);
        }
    }
}

fn print_dns_record(prefix: &str, record: &dns_parser::ResourceRecord) {
    println!("{}Name: {}", prefix, record.name);
    println!("{}TTL: {}", prefix, record.ttl);
    match &record.data {
        RData::A(ip) => println!("{}IP: {:#?}", prefix, ip),
        RData::AAAA(ip) => println!("{}IPv6: {:#?}", prefix, ip),
        RData::CNAME(cname) => println!("{}CNAME: {:#?}", prefix, cname),
        RData::TXT(txt) => println!("{}TXT: {:?}", prefix, txt),
        // Add more cases for other record types as needed
        _ => println!("{}Unsupported Record Type", prefix),
    }
}

fn main() {
    let device = pcap::Device::lookup().unwrap_or_else(|_| {
        panic!("Unable to find device");
    }).unwrap();
    println!("{:?}", device);

    let mut cap = pcap::Capture::from_device(device) // use the device
        .unwrap()
        .promisc(true) // set promiscuous mode
        .snaplen(5000) // set the snaplen
        .open().unwrap(); // open the capture

    cap.filter("udp and port 53", true).unwrap(); // filter DNS packets

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
        let header_size = 20;
        let dns_payload = &packet.data[header_size..];
        parse_dns_packet(&dns_payload);
    }
}
