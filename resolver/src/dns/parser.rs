#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub qdcount: u16,
}

#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug)]
pub struct DnsRequest {
    pub header: DnsHeader,
    pub question: DnsQuestion,
}

pub fn parse_dns_request(request: &[u8]) -> Option<DnsRequest> {
    if request.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([request[0], request[1]]);
    let qdcount = u16::from_be_bytes([request[4], request[5]]);

    let header = DnsHeader { id, qdcount };

    let mut offset = 12;
    let mut labels = Vec::new();

    loop {
        if offset >= request.len() {
            return None;
        }

        let label_len = request[offset] as usize;
        offset += 1;

        if label_len == 0 {
            break;
        }

        if offset + label_len > request.len() {
            return None;
        }

        let label = std::str::from_utf8(&request[offset..offset + label_len]).ok()?;
        labels.push(label.to_string());

        offset += label_len;
    }

    if offset + 4 > request.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([request[offset], request[offset + 1]]);
    let qclass = u16::from_be_bytes([request[offset + 2], request[offset + 3]]);

    let question = DnsQuestion {
        qname: labels.join("."),
        qtype,
        qclass,
    };

    Some(DnsRequest { header, question })
}
