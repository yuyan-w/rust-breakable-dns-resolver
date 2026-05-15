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

                    match resolve_with_delegation(&auth_internal_addr, &request) {
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
                                println!(
                                    "negative cache store: nxdomain ttl={} sec",
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

/// auth-internalへ問い合わせし、
/// 委任先NSと一致するGlueレコードがあれば問い合わせを続行する
fn resolve_with_delegation(auth_internal_addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let response = resolve_once_with_delegation(auth_internal_addr, request)?;

    if let Some(response) = resolve_cname_if_needed(auth_internal_addr, request, &response)? {
        return Ok(response);
    }

    Ok(response)
}

/// auth-internalへ問い合わせし、
/// 委任先NSと一致するGlueレコードがあれば問い合わせを続行する
fn resolve_once_with_delegation(
    auth_internal_addr: &str,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    let response = forward_to_auth(auth_internal_addr, request)?;

    if !is_referral_response(&response) {
        return Ok(response);
    }

    println!("referral response found");

    let Some(glue_addr) = extract_trusted_glue_address(&response) else {
        println!("trusted glue record not found");
        return Ok(response);
    };

    println!("trusted glue address found: {}", glue_addr);

    forward_to_auth(&glue_addr, request)
}

/// A問い合わせがNODATAだった場合、同じ名前のCNAMEを探し、
/// CNAME先のAレコードまで問い合わせる
fn resolve_cname_if_needed(
    auth_internal_addr: &str,
    request: &[u8],
    response: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if !is_a_query(request) || !is_nodata_response(response) {
        return Ok(None);
    }

    let Some((qname, qclass)) = extract_question_name_and_class(request) else {
        return Ok(None);
    };

    println!("nodata response found. try cname lookup: {}", qname);

    let cname_request = build_query_request(request, &qname, 5, qclass)?;
    let cname_response = resolve_once_with_delegation(auth_internal_addr, &cname_request)?;

    let Some(cname_answer) = extract_cname_answer(&cname_response) else {
        println!("cname not found: {}", qname);
        return Ok(None);
    };

    println!(
        "cname found: {} -> {}",
        qname, cname_answer.target_name
    );

    let a_request = build_query_request(request, &cname_answer.target_name, 1, qclass)?;
    let a_response = resolve_once_with_delegation(auth_internal_addr, &a_request)?;

    let Some(a_answer) = extract_a_answer(&a_response) else {
        println!("cname target a record not found: {}", cname_answer.target_name);
        return Ok(None);
    };

    println!(
        "cname target a found: {} -> {}.{}.{}.{}",
        a_answer.name,
        a_answer.ip[0],
        a_answer.ip[1],
        a_answer.ip[2],
        a_answer.ip[3]
    );

    let response = build_cname_a_response(request, &qname, qclass, &cname_answer, &a_answer)?;

    Ok(Some(response))
}

#[derive(Debug)]
struct CnameAnswer {
    target_name: String,
    ttl: u32,
}

#[derive(Debug)]
struct AAnswer {
    name: String,
    ip: [u8; 4],
    ttl: u32,
}

fn is_a_query(request: &[u8]) -> bool {
    let Some((_qname, offset)) = read_dns_name(request, 12) else {
        return false;
    };

    if offset + 4 > request.len() {
        return false;
    }

    let qtype = u16::from_be_bytes([request[offset], request[offset + 1]]);

    qtype == 1
}

fn extract_question_name_and_class(request: &[u8]) -> Option<(String, u16)> {
    let (qname, offset) = read_dns_name(request, 12)?;

    if offset + 4 > request.len() {
        return None;
    }

    let qclass = u16::from_be_bytes([request[offset + 2], request[offset + 3]]);

    Some((qname, qclass))
}

fn build_query_request(
    original_request: &[u8],
    qname: &str,
    qtype: u16,
    qclass: u16,
) -> std::io::Result<Vec<u8>> {
    if original_request.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid dns request",
        ));
    }

    let mut request = Vec::new();

    request.extend_from_slice(&original_request[0..2]);
    request.push(original_request[2] & 0x01);
    request.push(0);
    request.extend_from_slice(&1u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());

    write_dns_name(&mut request, qname)?;
    request.extend_from_slice(&qtype.to_be_bytes());
    request.extend_from_slice(&qclass.to_be_bytes());

    Ok(request)
}

fn build_cname_a_response(
    original_request: &[u8],
    original_qname: &str,
    qclass: u16,
    cname_answer: &CnameAnswer,
    a_answer: &AAnswer,
) -> std::io::Result<Vec<u8>> {
    let question_end = skip_question(original_request).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid dns question")
    })?;

    let mut response = Vec::new();

    response.extend_from_slice(&original_request[0..2]);

    // QR=1, AA=1, RDは元リクエストから引き継ぐ。RAは立てない。
    response.push(0x84 | (original_request[2] & 0x01));
    response.push(0x00);

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&2u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&original_request[12..question_end]);

    write_dns_name(&mut response, original_qname)?;
    response.extend_from_slice(&5u16.to_be_bytes());
    response.extend_from_slice(&qclass.to_be_bytes());
    response.extend_from_slice(&cname_answer.ttl.to_be_bytes());

    let mut cname_rdata = Vec::new();
    write_dns_name(&mut cname_rdata, &cname_answer.target_name)?;
    response.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
    response.extend_from_slice(&cname_rdata);

    write_dns_name(&mut response, &a_answer.name)?;
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&qclass.to_be_bytes());
    response.extend_from_slice(&a_answer.ttl.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&a_answer.ip);

    Ok(response)
}

fn extract_cname_answer(packet: &[u8]) -> Option<CnameAnswer> {
    let mut offset = skip_question(packet)?;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    for _ in 0..ancount {
        let (_name, next_offset) = read_dns_name(packet, offset)?;
        offset = next_offset;

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        let rdata_offset = offset + 10;

        if rdata_offset + rdlength > packet.len() {
            return None;
        }

        if rr_type == 5 {
            let (target_name, _) = read_dns_name(packet, rdata_offset)?;

            return Some(CnameAnswer { target_name, ttl });
        }

        offset = rdata_offset + rdlength;
    }

    None
}

fn extract_a_answer(packet: &[u8]) -> Option<AAnswer> {
    let mut offset = skip_question(packet)?;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    for _ in 0..ancount {
        let (name, next_offset) = read_dns_name(packet, offset)?;
        offset = next_offset;

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        let rdata_offset = offset + 10;

        if rdata_offset + rdlength > packet.len() {
            return None;
        }

        if rr_type == 1 && rr_class == 1 && rdlength == 4 {
            return Some(AAnswer {
                name,
                ip: [
                    packet[rdata_offset],
                    packet[rdata_offset + 1],
                    packet[rdata_offset + 2],
                    packet[rdata_offset + 3],
                ],
                ttl,
            });
        }

        offset = rdata_offset + rdlength;
    }

    None
}

fn write_dns_name(buffer: &mut Vec<u8>, name: &str) -> std::io::Result<()> {
    for label in name.trim_end_matches('.').split('.') {
        if label.len() > 63 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "dns label too long",
            ));
        }

        buffer.push(label.len() as u8);
        buffer.extend_from_slice(label.as_bytes());
    }

    buffer.push(0);

    Ok(())
}

/// AUTHORITY section のNS名と一致するAdditionalのAレコードだけをGlueとして利用する
fn extract_trusted_glue_address(response: &[u8]) -> Option<String> {
    let ns_name = extract_authority_ns_name(response)?;
    let (glue_name, glue_ip) = extract_additional_a_record(response)?;

    if ns_name != glue_name {
        println!(
            "untrusted glue ignored: ns={} additional={}",
            ns_name, glue_name
        );
        return None;
    }

    Some(format!(
        "{}.{}.{}.{}:33053",
        glue_ip[0], glue_ip[1], glue_ip[2], glue_ip[3]
    ))
}

fn extract_authority_ns_name(packet: &[u8]) -> Option<String> {
    let mut offset = skip_question(packet)?;

    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;

    for _ in 0..ancount {
        offset = skip_rr(packet, offset)?;
    }

    for _ in 0..nscount {
        let (_owner_name, next_offset) = read_dns_name(packet, offset)?;
        offset = next_offset;

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        let rdata_offset = offset + 10;

        if rdata_offset + rdlength > packet.len() {
            return None;
        }

        if rr_type == 2 {
            let (ns_name, _) = read_dns_name(packet, rdata_offset)?;
            return Some(ns_name);
        }

        offset = rdata_offset + rdlength;
    }

    None
}

fn extract_additional_a_record(packet: &[u8]) -> Option<(String, [u8; 4])> {
    let mut offset = skip_question(packet)?;

    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    for _ in 0..ancount {
        offset = skip_rr(packet, offset)?;
    }

    for _ in 0..nscount {
        offset = skip_rr(packet, offset)?;
    }

    for _ in 0..arcount {
        let (name, next_offset) = read_dns_name(packet, offset)?;
        offset = next_offset;

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        let rdata_offset = offset + 10;

        if rdata_offset + rdlength > packet.len() {
            return None;
        }

        if rr_type == 1 && rr_class == 1 && rdlength == 4 {
            return Some((
                name,
                [
                    packet[rdata_offset],
                    packet[rdata_offset + 1],
                    packet[rdata_offset + 2],
                    packet[rdata_offset + 3],
                ],
            ));
        }

        offset = rdata_offset + rdlength;
    }

    None
}

fn skip_question(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }

    let (_qname, offset) = read_dns_name(packet, 12)?;

    if offset + 4 > packet.len() {
        return None;
    }

    Some(offset + 4)
}

fn skip_rr(packet: &[u8], offset: usize) -> Option<usize> {
    let (_name, mut offset) = read_dns_name(packet, offset)?;

    if offset + 10 > packet.len() {
        return None;
    }

    let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > packet.len() {
        return None;
    }

    Some(offset + rdlength)
}

fn read_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let original_offset = offset;

    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset];

        if len & 0b1100_0000 == 0b1100_0000 {
            if offset + 1 >= packet.len() {
                return None;
            }

            let pointer = (((len & 0b0011_1111) as usize) << 8) | packet[offset + 1] as usize;

            offset = pointer;
            jumped = true;
            continue;
        }

        offset += 1;

        if len == 0 {
            break;
        }

        let label_len = len as usize;

        if offset + label_len > packet.len() {
            return None;
        }

        labels.push(String::from_utf8_lossy(&packet[offset..offset + label_len]).to_string());
        offset += label_len;
    }

    let next_offset = if jumped { original_offset + 2 } else { offset };

    Some((labels.join(".").to_lowercase(), next_offset))
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

/// DNSレスポンスがreferral応答か確認する
fn is_referral_response(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }

    let rcode = response[3] & 0x0f;
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let nscount = u16::from_be_bytes([response[8], response[9]]);

    rcode == 0 && ancount == 0 && nscount > 0
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
    let nscount = u16::from_be_bytes([response[8], response[9]]);

    rcode == 0 && ancount == 0 && nscount == 0
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
