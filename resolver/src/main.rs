use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

mod cache;
mod dns;
mod dns_packet;
mod resolver;

const MAX_WORKERS: usize = 4;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:33053")?;
    println!("DNS resolver running at 0.0.0.0:33053");

    let auth_internal_addr =
        std::env::var("AUTH_INTERNAL_ADDR").unwrap_or_else(|_| "auth-internal:33053".to_string());

    println!("auth internal addr: {}", auth_internal_addr);

    let cache: cache::Cache = Arc::new(Mutex::new(HashMap::new()));

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

                    let cache_key = cache::build_cache_key(&parsed);
                    let cached_entry = { cache.lock().unwrap().get(&cache_key).cloned() };

                    if let Some(cached_entry) = cached_entry {
                        if !cache::is_expired(&cached_entry) {
                            println!("cache hit");

                            let remaining_ttl = cache::remaining_ttl(&cached_entry);
                            let response =
                                dns_packet::replace_response_id(cached_entry.response, &request);
                            let response = dns_packet::replace_answer_ttl(response, remaining_ttl);

                            socket.send_to(&response, source).unwrap();

                            rx.lock().unwrap().recv().unwrap();
                            return;
                        }

                        println!("cache expired");
                        cache.lock().unwrap().remove(&cache_key);
                    }

                    println!("cache miss");

                    match resolver::resolve_with_delegation(&auth_internal_addr, &request) {
                        Ok(response) => {
                            cache::store_if_cacheable(&cache, cache_key, &response);
                            socket.send_to(&response, source).unwrap();
                        }
                        Err(error) => {
                            println!("failed to resolve request: {}", error);
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
