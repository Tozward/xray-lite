use anyhow::{anyhow, Result};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::BytesMut;

/// 从目标服务器获取 TLS 证书
pub async fn fetch_certificate(dest: &str, sni: &str) -> Result<Vec<u8>> {
    // 发送一个简单的 ClientHello 来触发 ServerHello + Certificate
    let client_hello = build_simple_client_hello(sni)?;
    // 读取响应并提取证书
    let mut buf = BytesMut::with_capacity(8192);

    #[cfg(unix)]
    if dest.starts_with('/') || dest.starts_with('@') {
        use tokio::net::UnixStream;
        let path = if dest.starts_with('@') {
            dest.replacen('@', "\0", 1)
        } else {
            dest.to_string()
        };
        
        let mut stream = UnixStream::connect(&path).await
            .map_err(|e| anyhow!("Failed to connect to UDS {}: {}", path, e))?;
        
        stream.write_all(&client_hello).await?;
        
        loop {
            let n = stream.read_buf(&mut buf).await?;
            if n == 0 || buf.len() > 8192 {
                break;
            }
        }
        return extract_certificate_from_response(&buf);
    }

    // 解析目标地址 (TCP 回退)
    let addr = if dest.contains(':') {
        dest.to_string()
    } else {
        format!("{}:443", dest)
    };
    
    // 连接到目标服务器
    let mut stream = tokio::net::TcpStream::connect(&addr).await
        .map_err(|e| anyhow!("Failed to connect to {}: {}", addr, e))?;
    
    stream.write_all(&client_hello).await?;
    
    loop {
        let n = stream.read_buf(&mut buf).await?;
        if n == 0 || buf.len() > 8192 {
            break;
        }
    }
    
    // 解析 TLS 记录，查找 Certificate 消息
    extract_certificate_from_response(&buf)
}

fn build_simple_client_hello(server_name: &str) -> Result<Vec<u8>> {
    use bytes::BufMut;
    
    let sni = server_name.split(':').next().unwrap_or(server_name);
    
    let mut hello = BytesMut::new();
    
    // TLS Record Header
    hello.put_u8(0x16); // ContentType: Handshake
    hello.put_u16(0x0303); // Version: TLS 1.2
    
    // 先占位长度
    let len_pos = hello.len();
    hello.put_u16(0);
    
    // Handshake Header
    hello.put_u8(0x01); // HandshakeType: ClientHello
    let hs_len_pos = hello.len();
    hello.put_u8(0); hello.put_u8(0); hello.put_u8(0);
    
    // ClientHello
    hello.put_u16(0x0303); // Version: TLS 1.2
    
    // Random (32 bytes)
    use rand::RngCore;
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    hello.put_slice(&random);
    
    // Session ID (empty)
    hello.put_u8(0);
    
    // Cipher Suites
    hello.put_u16(2); // Length
    hello.put_u16(0x1301); // TLS_AES_128_GCM_SHA256
    
    // Compression Methods
    hello.put_u8(1); // Length
    hello.put_u8(0); // null
    
    // Extensions
    let mut extensions = BytesMut::new();
    
    // SNI Extension
    extensions.put_u16(0x0000); // Type: server_name
    let mut sni_data = BytesMut::new();
    sni_data.put_u16((sni.len() + 3) as u16); // ServerNameList length
    sni_data.put_u8(0); // NameType: host_name
    sni_data.put_u16(sni.len() as u16);
    sni_data.put_slice(sni.as_bytes());
    extensions.put_u16(sni_data.len() as u16);
    extensions.put_slice(&sni_data);
    
    // Supported Versions (TLS 1.3)
    extensions.put_u16(0x002b);
    extensions.put_u16(3);
    extensions.put_u8(2);
    extensions.put_u16(0x0304);
    
    hello.put_u16(extensions.len() as u16);
    hello.put_slice(&extensions);
    
    // 回填长度
    let total_len = hello.len() - len_pos - 2;
    hello[len_pos..len_pos+2].copy_from_slice(&(total_len as u16).to_be_bytes());
    
    let hs_len = hello.len() - hs_len_pos - 3;
    let hs_len_bytes = (hs_len as u32).to_be_bytes();
    hello[hs_len_pos..hs_len_pos+3].copy_from_slice(&hs_len_bytes[1..4]);
    
    Ok(hello.to_vec())
}

fn extract_certificate_from_response(data: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    
    while pos + 5 < data.len() {
        let content_type = data[pos];
        let record_len = u16::from_be_bytes([data[pos+3], data[pos+4]]) as usize;
        
        if pos + 5 + record_len > data.len() {
            break;
        }
        
        // 查找 Handshake 记录
        if content_type == 0x16 {
            let payload = &data[pos+5..pos+5+record_len];
            
            // 查找 Certificate 消息 (type 11)
            if payload.len() > 0 && payload[0] == 11 {
                // 返回整个 Certificate 握手消息（包括 type + length）
                return Ok(payload.to_vec());
            }
        }
        
        pos += 5 + record_len;
    }
    
    Err(anyhow!("No certificate found in response"))
}
