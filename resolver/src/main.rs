use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

mod dns;

const MAX_WORKERS: usize = 16;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
}

type Cache = Arc<Mutex<HashMap<CacheKey, Vec<u8>>>>;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:33053")?;
    println!("DNS resolver running at 0.0.0.0:33053");

    let auth_internal_addr =
        std::env::var("AUTH_INTERNAL_ADDR").unwrap_or_else(|_| "auth-internal:33053".to_string());

    println!("auth internal addr: {}", auth_internal_addr);

    let cache: Cache = Arc::new(Mutex::new(HashMap::new()));

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
        let cache = Arc::clone(&cache);

        thread::spawn(move || {
            tx.send(()).unwrap();

            match dns::parser::parse_dns_request(&request) {
                Some(parsed) => {
                    println!("parsed request: {:?}", parsed);

                    let cache_key = build_cache_key(&parsed);

                    if let Some(cached_response) = cache.lock().unwrap().get(&cache_key).cloned() {
                        println!("cache hit");

                        let response = replace_response_id(cached_response, &request);
                        socket.send_to(&response, source).unwrap();

                        rx.lock().unwrap().recv().unwrap();
                        return;
                    }

                    println!("cache miss");

                    match forward_to_auth(&auth_internal_addr, &request) {
                        Ok(response) => {
                            cache.lock().unwrap().insert(cache_key, response.clone());

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

fn build_cache_key(parsed: &dns::parser::DnsRequest) -> CacheKey {
    CacheKey {
        qname: parsed.question.qname.clone(),
        qtype: parsed.question.qtype,
        qclass: parsed.question.qclass,
    }
}

fn replace_response_id(mut response: Vec<u8>, request: &[u8]) -> Vec<u8> {
    response[0] = request[0];
    response[1] = request[1];

    response
}
