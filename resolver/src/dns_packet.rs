#[derive(Debug)]
pub struct CnameAnswer {
    pub name: String,
    pub target_name: String,
    pub ttl: u32,
}

#[derive(Debug)]
pub struct AAnswer {
    pub name: String,
    pub ip: [u8; 4],
    pub ttl: u32,
}

pub fn is_a_query(request: &[u8]) -> bool {
    let Some((_qname, offset)) = read_dns_name(request, 12) else {
        return false;
    };

    if offset + 4 > request.len() {
        return false;
    }

    let qtype = u16::from_be_bytes([request[offset], request[offset + 1]]);

    qtype == 1
}

pub fn extract_question_name_and_class(request: &[u8]) -> Option<(String, u16)> {
    let (qname, offset) = read_dns_name(request, 12)?;

    if offset + 4 > request.len() {
        return None;
    }

    let qclass = u16::from_be_bytes([request[offset + 2], request[offset + 3]]);

    Some((qname, qclass))
}

pub fn build_query_request(
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

pub fn build_cname_chain_a_response(
    original_request: &[u8],
    qclass: u16,
    cname_answers: &[CnameAnswer],
    a_answer: &AAnswer,
) -> std::io::Result<Vec<u8>> {
    let question_end = skip_question(original_request).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid dns question")
    })?;

    let answer_count = cname_answers.len() + 1;
    let mut response = Vec::new();

    response.extend_from_slice(&original_request[0..2]);

    // QR=1, AA=1, RDは元リクエストから引き継ぐ。RAは立てない。
    response.push(0x84 | (original_request[2] & 0x01));
    response.push(0x00);

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(answer_count as u16).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&original_request[12..question_end]);

    for cname_answer in cname_answers {
        write_dns_name(&mut response, &cname_answer.name)?;
        response.extend_from_slice(&5u16.to_be_bytes());
        response.extend_from_slice(&qclass.to_be_bytes());
        response.extend_from_slice(&cname_answer.ttl.to_be_bytes());

        let mut cname_rdata = Vec::new();
        write_dns_name(&mut cname_rdata, &cname_answer.target_name)?;
        response.extend_from_slice(&(cname_rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&cname_rdata);
    }

    write_dns_name(&mut response, &a_answer.name)?;
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&qclass.to_be_bytes());
    response.extend_from_slice(&a_answer.ttl.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&a_answer.ip);

    Ok(response)
}

pub fn build_servfail_response(original_request: &[u8]) -> std::io::Result<Vec<u8>> {
    let question_end = skip_question(original_request).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid dns question")
    })?;

    let mut response = Vec::new();

    response.extend_from_slice(&original_request[0..2]);

    // QR=1, AA=1, RDは元リクエストから引き継ぐ。RCODE=2(SERVFAIL)。
    response.push(0x84 | (original_request[2] & 0x01));
    response.push(0x02);

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    response.extend_from_slice(&original_request[12..question_end]);

    Ok(response)
}

pub fn extract_cname_answer(packet: &[u8]) -> Option<CnameAnswer> {
    let mut offset = skip_question(packet)?;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    for _ in 0..ancount {
        let (name, next_offset) = read_dns_name(packet, offset)?;
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

            return Some(CnameAnswer {
                name,
                target_name,
                ttl,
            });
        }

        offset = rdata_offset + rdlength;
    }

    None
}

pub fn extract_a_answer(packet: &[u8]) -> Option<AAnswer> {
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
pub fn extract_trusted_glue_address(response: &[u8]) -> Option<String> {
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

/// キャッシュしたレスポンスのIDを現在のリクエストIDへ差し替える
pub fn replace_response_id(mut response: Vec<u8>, request: &[u8]) -> Vec<u8> {
    response[0] = request[0];
    response[1] = request[1];

    response
}

/// DNSレスポンスがreferral応答か確認する
pub fn is_referral_response(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }

    let rcode = response[3] & 0x0f;
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let nscount = u16::from_be_bytes([response[8], response[9]]);

    rcode == 0 && ancount == 0 && nscount > 0
}

/// DNSレスポンスがNXDOMAINか確認する
pub fn is_nxdomain_response(response: &[u8]) -> bool {
    if response.len() < 4 {
        return false;
    }

    let rcode = response[3] & 0x0f;

    rcode == 3
}

/// DNSレスポンスがNODATAか確認する
pub fn is_nodata_response(response: &[u8]) -> bool {
    if response.len() < 12 {
        return false;
    }

    let rcode = response[3] & 0x0f;
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    let nscount = u16::from_be_bytes([response[8], response[9]]);

    rcode == 0 && ancount == 0 && nscount == 0
}

/// DNSレスポンスからTTLを取得する
pub fn extract_answer_ttl(response: &[u8]) -> Option<u32> {
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
pub fn replace_answer_ttl(mut response: Vec<u8>, ttl: u32) -> Vec<u8> {
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

pub fn is_truncated_response(response: &[u8]) -> bool {
    if response.len() < 4 {
        return false;
    }

    response[2] & 0b0000_0010 != 0
}
