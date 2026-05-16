use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

mod cache;
mod dns;
mod dns_packet;
mod resolver;

const MAX_IN_FLIGHT_REQUESTS: usize = 100;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:33053").await?);
    println!("DNS resolver running at 0.0.0.0:33053");

    let auth_internal_addr =
        std::env::var("AUTH_INTERNAL_ADDR").unwrap_or_else(|_| "auth-internal:33053".to_string());

    println!("auth internal addr: {}", auth_internal_addr);

    let cache: cache::Cache = Arc::new(Mutex::new(HashMap::new()));
    let semaphore = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS));

    loop {
        let mut buf = [0u8; 512];
        let (size, source) = socket.recv_from(&mut buf).await?;

        let request = buf[..size].to_vec();
        let socket = Arc::clone(&socket);
        let auth_internal_addr = auth_internal_addr.clone();
        let cache = Arc::clone(&cache);
        let semaphore = Arc::clone(&semaphore);

        tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

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

                            socket.send_to(&response, source).await.unwrap();
                            return;
                        }

                        println!("cache expired");
                        cache.lock().unwrap().remove(&cache_key);
                    }

                    println!("cache miss");

                    match resolver::resolve_with_delegation(&auth_internal_addr, &request).await {
                        Ok(response) => {
                            cache::store_if_cacheable(&cache, cache_key, &response);
                            socket.send_to(&response, source).await.unwrap();
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
        });
    }
}
