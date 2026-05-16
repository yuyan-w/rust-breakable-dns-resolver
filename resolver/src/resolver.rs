use std::net::UdpSocket;
use std::time::Duration;

use crate::dns_packet;

const MAX_CNAME_DEPTH: usize = 5;
const UPSTREAM_TIMEOUT_SECONDS: u64 = 2;
const MAX_RETRIES: usize = 3;

/// auth-internalへ問い合わせし、
/// 委任先NSと一致するGlueレコードがあれば問い合わせを続行する
pub fn resolve_with_delegation(
    auth_internal_addr: &str,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
    match resolve_with_delegation_inner(auth_internal_addr, request) {
        Ok(response) => Ok(response),
        Err(error) => {
            println!("resolve failed. return SERVFAIL: {}", error);
            dns_packet::build_servfail_response(request)
        }
    }
}

fn resolve_with_delegation_inner(
    auth_internal_addr: &str,
    request: &[u8],
) -> std::io::Result<Vec<u8>> {
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

    if !dns_packet::is_referral_response(&response) {
        return Ok(response);
    }

    println!("referral response found");

    let Some(glue_addr) = dns_packet::extract_trusted_glue_address(&response) else {
        println!("trusted glue record not found");
        return Ok(response);
    };

    println!("trusted glue address found: {}", glue_addr);

    forward_to_auth(&glue_addr, request)
}

/// A問い合わせがNODATAだった場合、同じ名前のCNAMEを探し、
/// CNAME chainを再帰的に追跡する
fn resolve_cname_if_needed(
    auth_internal_addr: &str,
    request: &[u8],
    response: &[u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if !dns_packet::is_a_query(request) || !dns_packet::is_nodata_response(response) {
        return Ok(None);
    }

    let Some((qname, qclass)) = dns_packet::extract_question_name_and_class(request) else {
        return Ok(None);
    };

    println!("nodata response found. try cname lookup: {}", qname);

    match resolve_cname_chain(auth_internal_addr, request, &qname, qclass)? {
        CnameChainResult::Resolved {
            cname_answers,
            a_answer,
        } => {
            let response = dns_packet::build_cname_chain_a_response(
                request,
                qclass,
                &cname_answers,
                &a_answer,
            )?;
            Ok(Some(response))
        }
        CnameChainResult::NotFound => Ok(None),
        CnameChainResult::TooDeep { last_name } => {
            println!(
                "cname chain too deep: max_depth={} last_name={}",
                MAX_CNAME_DEPTH, last_name
            );

            let response = dns_packet::build_servfail_response(request)?;
            Ok(Some(response))
        }
    }
}

#[derive(Debug)]
enum CnameChainResult {
    Resolved {
        cname_answers: Vec<dns_packet::CnameAnswer>,
        a_answer: dns_packet::AAnswer,
    },
    NotFound,
    TooDeep {
        last_name: String,
    },
}

/// CNAMEの追跡先もCNAMEだった場合、さらに追跡する。
/// ただし無制限に追跡するとloopで終わらないため、最大追跡回数を設ける。
fn resolve_cname_chain(
    auth_internal_addr: &str,
    original_request: &[u8],
    start_name: &str,
    qclass: u16,
) -> std::io::Result<CnameChainResult> {
    let mut current_name = start_name.to_string();
    let mut cname_answers = Vec::new();

    for depth in 0..MAX_CNAME_DEPTH {
        let cname_request =
            dns_packet::build_query_request(original_request, &current_name, 5, qclass)?;
        let cname_response = resolve_once_with_delegation(auth_internal_addr, &cname_request)?;

        let Some(cname_answer) = dns_packet::extract_cname_answer(&cname_response) else {
            println!("cname not found: {}", current_name);
            return Ok(CnameChainResult::NotFound);
        };

        println!(
            "cname found: depth={} {} -> {}",
            depth + 1,
            cname_answer.name,
            cname_answer.target_name
        );

        let a_request = dns_packet::build_query_request(
            original_request,
            &cname_answer.target_name,
            1,
            qclass,
        )?;
        let a_response = resolve_once_with_delegation(auth_internal_addr, &a_request)?;

        if let Some(a_answer) = dns_packet::extract_a_answer(&a_response) {
            println!(
                "cname target a found: {} -> {}.{}.{}.{}",
                a_answer.name, a_answer.ip[0], a_answer.ip[1], a_answer.ip[2], a_answer.ip[3]
            );

            cname_answers.push(cname_answer);
            return Ok(CnameChainResult::Resolved {
                cname_answers,
                a_answer,
            });
        }

        println!(
            "cname target a record not found: {}",
            cname_answer.target_name
        );

        current_name = cname_answer.target_name.clone();
        cname_answers.push(cname_answer);
    }

    Ok(CnameChainResult::TooDeep {
        last_name: current_name,
    })
}

/// 権威DNSへ問い合わせを行い、レスポンスを取得する
pub fn forward_to_auth(auth_addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    for attempt in 1..=MAX_RETRIES {
        println!("upstream request attempt={}", attempt);

        let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;

        upstream_socket.set_read_timeout(Some(Duration::from_secs(UPSTREAM_TIMEOUT_SECONDS)))?;

        upstream_socket.send_to(request, auth_addr)?;

        let mut buf = [0u8; 512];

        match upstream_socket.recv_from(&mut buf) {
            Ok((size, _)) => {
                println!("upstream response received");
                return Ok(buf[..size].to_vec());
            }
            Err(error) => {
                println!(
                    "upstream request timeout attempt={} error={}",
                    attempt, error
                );
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "upstream request failed after retries",
    ))
}
