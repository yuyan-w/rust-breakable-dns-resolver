use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::dns;
use crate::dns_packet;

const NEGATIVE_CACHE_TTL: u32 = 10;

pub type Cache = Arc<Mutex<HashMap<CacheKey, CacheEntry>>>;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct CacheKey {
    qname: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Clone)]
pub struct CacheEntry {
    pub response: Vec<u8>,
    stored_at: Instant,
    ttl: u32,
}

/// DNSリクエストからキャッシュキーを生成する
pub fn build_cache_key(parsed: &dns::parser::DnsRequest) -> CacheKey {
    CacheKey {
        qname: parsed.question.qname.to_lowercase(),
        qtype: parsed.question.qtype,
        qclass: parsed.question.qclass,
    }
}

pub fn store_if_cacheable(cache: &Cache, cache_key: CacheKey, response: &[u8]) {
    if let Some(ttl) = dns_packet::extract_answer_ttl(response) {
        println!("cache store: ttl={} sec", ttl);

        cache.lock().unwrap().insert(
            cache_key,
            CacheEntry {
                response: response.to_vec(),
                stored_at: Instant::now(),
                ttl,
            },
        );
    } else if dns_packet::is_nxdomain_response(response) {
        println!(
            "negative cache store: nxdomain ttl={} sec",
            NEGATIVE_CACHE_TTL
        );

        cache.lock().unwrap().insert(
            cache_key,
            CacheEntry {
                response: response.to_vec(),
                stored_at: Instant::now(),
                ttl: NEGATIVE_CACHE_TTL,
            },
        );
    } else if dns_packet::is_nodata_response(response) {
        println!(
            "negative cache store: nodata ttl={} sec",
            NEGATIVE_CACHE_TTL
        );

        cache.lock().unwrap().insert(
            cache_key,
            CacheEntry {
                response: response.to_vec(),
                stored_at: Instant::now(),
                ttl: NEGATIVE_CACHE_TTL,
            },
        );
    }
}

/// キャッシュがTTL切れか確認する
pub fn is_expired(entry: &CacheEntry) -> bool {
    entry.stored_at.elapsed() >= Duration::from_secs(entry.ttl as u64)
}

/// キャッシュの残りTTLを計算する
pub fn remaining_ttl(entry: &CacheEntry) -> u32 {
    let elapsed = entry.stored_at.elapsed().as_secs() as u32;

    entry.ttl.saturating_sub(elapsed)
}
