use std::net::UdpSocket;

pub fn forward_to_auth(auth_addr: &str, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;

    upstream_socket.send_to(request, auth_addr)?;

    let mut buf = [0u8; 512];
    let (size, _) = upstream_socket.recv_from(&mut buf)?;

    Ok(buf[..size].to_vec())
}
