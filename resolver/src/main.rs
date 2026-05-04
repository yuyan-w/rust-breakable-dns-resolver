use std::net::UdpSocket;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

const MAX_WORKERS: usize = 16;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:33053")?;
    println!("DNS resolver running at 0.0.0.0:33053");

    let (tx, rx) = mpsc::sync_channel::<()>(MAX_WORKERS);

    let rx = Arc::new(Mutex::new(rx));

    loop {
        let mut buf = [0u8; 512];
        let (size, source) = socket.recv_from(&mut buf)?;

        let request = buf[..size].to_vec();
        let socket = socket.try_clone()?;
        let tx = tx.clone();
        let rx = Arc::clone(&rx);

        thread::spawn(move || {
            tx.send(()).unwrap();

            let response = build_response(&request);
            socket.send_to(&response, source).unwrap();

            rx.lock().unwrap().recv().unwrap();
        });
    }
}

/// DNSリクエストに対する固定レスポンスを生成する
fn build_response(request: &[u8]) -> Vec<u8> {
    if request.len() < 2 {
        return Vec::new();
    }

    let mut response = Vec::new();

    // Transaction ID はリクエストと同じものを返す
    response.extend_from_slice(&request[0..2]);

    // Flags: response, recursion desired, recursion available, no error
    response.extend_from_slice(&[0x81, 0x80]);

    // QDCOUNT = 1
    response.extend_from_slice(&[0x00, 0x01]);

    // ANCOUNT = 1
    response.extend_from_slice(&[0x00, 0x01]);

    // NSCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]);

    // ARCOUNT = 0
    response.extend_from_slice(&[0x00, 0x00]);

    // Question: internal.test / Type A / Class IN
    response.extend_from_slice(&[
        0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x04, b't', b'e', b's', b't', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ]);

    // Answer name: Question のドメイン名を参照
    response.extend_from_slice(&[0xc0, 0x0c]);

    // Type A, Class IN
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);

    // TTL = 60
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);

    // RDLENGTH = 4
    response.extend_from_slice(&[0x00, 0x04]);

    // RDATA = 10.0.100.1
    response.extend_from_slice(&[10, 0, 100, 1]);

    response
}
