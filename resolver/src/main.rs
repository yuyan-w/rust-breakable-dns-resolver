use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

mod dns;

const MAX_WORKERS: usize = 16;
const NEGATIVE_CACHE_TTL: u32 = 10;

type Cache = Arc<Mutex<HashMap<CacheKey, CacheEntry>>>;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    ttl: u32,
}

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

                    let cached_entry = { cache.lock().unwrap().get(&cache_key).cloned() };

                    if let Some(cached_entry) = cached_entry {
                        if !is_expired(&cached_entry) {
                            println!("cache hit");

                            let remaining_ttl = remaining_ttl(&cached_entry);
                            let response = replace_response_id(cached_entry.response, &request);
                            let response = replace_answer_ttl(response, remaining_ttl);

                            socket.send_to(&response, source).unwrap();

                            rx.lock().unwrap().recv().unwrap();
                            return;
                        }

                        println!("cache expired");
                        cache.lock().unwrap().remove(&cache_key);
                    }

                    println!("cache miss");

                    match forward_to_auth(&auth_internal_addr, &request) {
                        Ok(response) => {
                            if let Some(ttl) = extract_answer_ttl(&response) {
                                println!("cache store: ttl={} sec", ttl);

                                cache.lock().unwrap().insert(
                                    cache_key,
                                    CacheEntry {
                                        response: response.clone(),
                                        stored_at: Instant::now(),
                                        ttl,
                                    },
                                );
                            } else if is_nxdomain_response(&response) {
                                println!("negative cache store: nxdomain ttl={} sec", NEGATIVE_CACHE_TTL);

                                cache.lock().unwrap().insert(
                                    cache_key,
                                    CacheEntry {
                                        response: response.clone(),
                                        stored_at: Instant::now(),
                                        ttl: NEGATIVE_CACHE_TTL,
                                    },
                                );
                            } else if is_nodata_response(&response) {
                                println!(
                                    "negative cache store: nodata ttl={} sec",
                                    NEGATIVE_CACHE_TTL
                                );

                                cache.lock().unwrap().insert(
                                    cache_key,
                                    CacheEntry {
                                        response: response.clone(),
                                        stored_at: Instant::now(),
                                        ttl: NEGATIVE_CACHE_TTL,
                                    },
                                );
                            }

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

/// 権威DNSへ問い合わせを行い、レスポンスを取得する
fn forward_to_auth(auth_addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;

    upstream_socket.send_to(request, auth_addr)?;

    let mut buf = [0u8; 512];
    let (size, _) = upstream_socket.recv_from(&mut buf)?;

    Ok(buf[..size].to_vec())
}

/// DNSリクエストからキャッシュキーを生成する
fn build_cache_key(parsed: &dns::parser::DnsRequest) -> CacheKey {
    CacheKey {
        qname: parsed.question.qname.to_lowercase(),
        qtype: parsed.question.qtype,
        qclass: parsed.question.qclass,
    }
}

/// キャッシュしたレスポンスのIDを現在のリクエストIDへ差し替える
fn replace_response_id(mut response: Vec<u8>, request: &[u8]) -> Vec<u8> {
    response[0] = request[0];
    response[1] = request[1];

    response
}

/// キャッシュがTTL切れか確認する
fn is_expired(entry: &CacheEntry) -> bool {
    entry.stored_at.elapsed() >= Duration::from_secs(entry.ttl as u64)
}

/// キャッシュの残りTTLを計算する
fn remaining_ttl(entry: &CacheEntry) -> u32 {
    let elapsed = entry.stored_at.elapsed().as_secs() as u32;

    entry.ttl.saturating_sub(elapsed)
}

/// DNSレスポンスがNXDOMAINか確認する
fn is_nxdomain_response(response: &[u8]) -> bool {
    if response.len() < 4 {
        return false;
    }

    let rcode = response[3] & 0x0f;

    rcode == 3
}

/// DNSレスポンスがNODATAか確認する
fn is_nodata_response(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }

    let rcode = response[3] & 0x0f;
    let ancount = u16::from_be_bytes([response[6], response[7]]);

    rcode == 0 && ancount == 0
}

/// DNSレスポンスからTTLを取得する
fn extract_answer_ttl(response: &[u8]) -> Option<u32> {
    let answer_offset = find_answer_offset(response)?;

    if answer_offset + 10 > response.len() {
        return None;
    }

    Some(u32::from_be_bytes([
        response[answer_offset + 6],
        response[answer_offset + 7],
        response[answer_offset + 8],
        response[answer_offset + 9],
    ]))
}

/// DNSレスポンス内のTTLを書き換える
fn replace_answer_ttl(mut response: Vec<u8>, ttl: u32) -> Vec<u8> {
    if let Some(answer_offset) = find_answer_offset(&response) {
        if answer_offset + 10 <= response.len() {
            let ttl_bytes = ttl.to_be_bytes();

            response[answer_offset + 6] = ttl_bytes[0];
            response[answer_offset + 7] = ttl_bytes[1];
            response[answer_offset + 8] = ttl_bytes[2];
            response[answer_offset + 9] = ttl_bytes[3];
        }
    }

    response
}

/// DNSパケット内のAnswerセクション開始位置を取得する
fn find_answer_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([packet[6], packet[7]]);

    if ancount == 0 {
        return None;
    }

    let mut offset = 12;

    loop {
        if offset >= packet.len() {
            return None;
        }

        let label_len = packet[offset] as usize;
        offset += 1;

        if label_len == 0 {
            break;
        }

        if offset + label_len > packet.len() {
            return None;
        }

        offset += label_len;
    }

    if offset + 4 > packet.len() {
        return None;
    }

    offset += 4;

    Some(offset)
}
