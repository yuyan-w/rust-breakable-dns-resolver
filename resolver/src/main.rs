use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

mod dns;

const MAX_WORKERS: usize = 16;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:33053")?;
    println!("DNS resolver running at 0.0.0.0:33053");

    let auth_internal_addr =
        std::env::var("AUTH_INTERNAL_ADDR").unwrap_or_else(|_| "auth-internal:33053".to_string());

    println!("auth internal addr: {}", auth_internal_addr);

    let (tx, rx) = mpsc::sync_channel::<()>(MAX_WORKERS);
    let rx = Arc::new(Mutex::new(rx));

    loop {
        let mut buf = [0u8; 512];
        let (size, source) = socket.recv_from(&mut buf)?;

        let request = buf[..size].to_vec();
        let socket = socket.try_clone()?;
        let tx = tx.clone();
        let rx = Arc::clone(&rx);
        let auth_internal_addr = auth_internal_addr.clone();

        thread::spawn(move || {
            tx.send(()).unwrap();

            match dns::parser::parse_dns_request(&request) {
                Some(parsed) => {
                    println!("parsed request: {:?}", parsed);

                    match forward_to_auth(&auth_internal_addr, &request) {
                        Ok(response) => {
                            socket.send_to(&response, source).unwrap();
                        }
                        Err(error) => {
                            println!("failed to forward request: {}", error);
                        }
                    }
                }
                None => {
                    println!("failed to parse dns request");
                }
            }

            rx.lock().unwrap().recv().unwrap();
        });
    }
}

fn forward_to_auth(auth_addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;

    upstream_socket.send_to(request, auth_addr)?;

    let mut buf = [0u8; 512];
    let (size, _) = upstream_socket.recv_from(&mut buf)?;

    Ok(buf[..size].to_vec())
}
