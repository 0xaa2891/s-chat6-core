//! The SOCKS5 handshake: greeting, RFC 1929 user/pass auth (user == pass
//! == purpose token), CONNECT with ATYP=domain. `.onion` names are never
//! resolved locally.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::transport::error::TransportError;
use crate::transport::onion;

use super::{SOCKS_CONNECT_TIMEOUT, SOCKS_TCP_TIMEOUT};

/// One SOCKS5 CONNECT to `dest_host:dest_port` through the proxy at
/// `proxy`. Returns the connected stream. ATYP=domain always.
pub async fn socks_connect(
    proxy: SocketAddr,
    dest_host: &str,
    dest_port: u16,
    purpose: &str,
) -> Result<TcpStream, TransportError> {
    let stream = tokio::time::timeout(SOCKS_TCP_TIMEOUT, TcpStream::connect(proxy))
        .await
        .map_err(|_| TransportError::Timeout(format!("tcp connect to socks proxy {proxy}")))??;
    socks_handshake(stream, dest_host, dest_port, purpose).await
}

/// The handshake on an already-connected TCP stream (split out for tests).
pub async fn socks_handshake(
    mut stream: TcpStream,
    dest_host: &str,
    dest_port: u16,
    purpose: &str,
) -> Result<TcpStream, TransportError> {
    // Keep the `.onion` suffix: tor only routes a name to the HS subsystem
    // when it ends in `.onion`; a bare v3 name is treated as a regular DNS
    // name and stalls on networks without exits.
    let host = onion::normalize_hostname(dest_host)?;
    if host.len() > 255 {
        return Err(TransportError::Socks("destination name too long".into()));
    }
    let purpose = purpose.as_bytes();
    if purpose.len() > 255 {
        return Err(TransportError::Socks("purpose token too long".into()));
    }

    // Greeting: VER=5, NMETHODS=1, METHOD=user/pass(0x02).
    stream.write_all(&[0x05, 0x01, 0x02]).await?;
    let mut method = [0u8; 2];
    read_exact_timeout(&mut stream, &mut method).await?;
    if method != [0x05, 0x02] {
        return Err(TransportError::Socks(format!(
            "proxy refused user/pass auth: {method:02x?}"
        )));
    }

    // RFC 1929: VER=1, ULEN, USER, PLEN, PASS (user == pass == purpose).
    let mut auth = Vec::with_capacity(3 + 2 * purpose.len());
    auth.push(0x01);
    auth.push(purpose.len() as u8);
    auth.extend_from_slice(purpose);
    auth.push(purpose.len() as u8);
    auth.extend_from_slice(purpose);
    stream.write_all(&auth).await?;
    let mut auth_reply = [0u8; 2];
    read_exact_timeout(&mut stream, &mut auth_reply).await?;
    if auth_reply[1] != 0x00 {
        return Err(TransportError::Socks("proxy auth failed".into()));
    }

    // CONNECT, ATYP=domain. Never resolve .onion locally.
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut head = [0u8; 4];
    read_exact_timeout(&mut stream, &mut head).await?;
    if head[0] != 0x05 {
        return Err(TransportError::Socks("bad reply version".into()));
    }
    if head[1] != 0x00 {
        return Err(TransportError::Socks(format!(
            "connect failed with socks error 0x{:02x}",
            head[1]
        )));
    }
    // Skip BND.ADDR per ATYP.
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact_timeout(&mut stream, &mut len).await?;
            len[0] as usize
        }
        other => return Err(TransportError::Socks(format!("bad bnd atyp 0x{other:02x}"))),
    };
    let mut sink = vec![0u8; skip + 2];
    read_exact_timeout(&mut stream, &mut sink).await?;
    Ok(stream)
}

async fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), TransportError> {
    tokio::time::timeout(SOCKS_CONNECT_TIMEOUT, stream.read_exact(buf))
        .await
        .map_err(|_| TransportError::Timeout("socks handshake read".into()))??;
    Ok(())
}
