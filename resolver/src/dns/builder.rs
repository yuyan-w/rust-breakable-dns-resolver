use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::dns::parser::DnsRequest;

pub fn build_response(parsed: &DnsRequest, records: &HashMap<String, Ipv4Addr>) -> Vec<u8> {
    let ip = records
        .get(&parsed.question.qname)
        .copied()
        .unwrap_or(Ipv4Addr::new(10, 0, 100, 1));

    let mut response = Vec::new();

    // ------------------
    // Header 設定
    // ------------------
    // リクエストと同じIDを設定
    response.extend_from_slice(&parsed.header.id.to_be_bytes());

    // Flags
    response.extend_from_slice(&[0x81, 0x80]);

    // QDCOUNT / ANCOUNT / NSCOUNT / ARCOUNT
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00]);
    response.extend_from_slice(&[0x00, 0x00]);

    // ------------------
    // Question 設定（リクエストの内容をそのまま返す）
    // ------------------
    write_qname(&mut response, &parsed.question.qname);
    response.extend_from_slice(&parsed.question.qtype.to_be_bytes());
    response.extend_from_slice(&parsed.question.qclass.to_be_bytes());

    // ------------------
    // Answer 生成
    // ------------------
    response.extend_from_slice(&[0xc0, 0x0c]);

    response.extend_from_slice(&[0x00, 0x01]); // Type A
    response.extend_from_slice(&[0x00, 0x01]); // Class IN
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
    response.extend_from_slice(&[0x00, 0x04]);
    response.extend_from_slice(&ip.octets());

    response
}

//
fn write_qname(response: &mut Vec<u8>, qname: &str) {
    for label in qname.split('.') {
        response.push(label.len() as u8);
        response.extend_from_slice(label.as_bytes());
    }

    response.push(0x00);
}
