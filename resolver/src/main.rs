use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

mod dns;

const MAX_WORKERS: usize = 16;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:33053")?;
    println!("DNS resolver running at 0.0.0.0:33053");

    let mut records = HashMap::new();
    records.insert("internal.test".to_string(), Ipv4Addr::new(10, 0, 100, 1));
    records.insert(
        "api.internal.test".to_string(),
        Ipv4Addr::new(10, 0, 100, 2),
    );

    let records = Arc::new(records);

    let (tx, rx) = mpsc::sync_channel::<()>(MAX_WORKERS);

    let rx = Arc::new(Mutex::new(rx));

    loop {
        let mut buf = [0u8; 512];
        let (size, source) = socket.recv_from(&mut buf)?;

        let request = buf[..size].to_vec();
        let socket = socket.try_clone()?;
        let tx = tx.clone();
        let rx = Arc::clone(&rx);

        let records = Arc::clone(&records);

        thread::spawn(move || {
            tx.send(()).unwrap();

            match dns::parser::parse_dns_request(&request) {
                Some(parsed) => {
                    println!("parsed request: {:?}", parsed);
                    let response = dns::builder::build_response(&parsed, &records);
                    socket.send_to(&response, source).unwrap();
                }
                None => {
                    println!("failed to parse dns request");
                }
            }

            rx.lock().unwrap().recv().unwrap();
        });
    }
}
