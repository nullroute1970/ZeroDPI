//! Local DNS fixtures shared by resolver and consumer regression tests.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

pub struct TestDnsServer {
    pub addr: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl TestDnsServer {
    pub async fn start(rcode: u8, answer: Option<Ipv4Addr>, delay: Option<Duration>) -> Self {
        Self::start_many(rcode, answer.into_iter().collect(), delay).await
    }

    pub async fn start_many(rcode: u8, answers: Vec<Ipv4Addr>, delay: Option<Duration>) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (_len, peer) = socket.recv_from(&mut buf).await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let Some(delay) = delay else { continue };
                tokio::time::sleep(delay).await;
                let mut end = 12;
                while buf[end] != 0 {
                    end += usize::from(buf[end]) + 1;
                }
                end += 5;
                let mut response = Vec::from(&buf[..end]);
                response[2] = 0x81;
                response[3] = 0x80 | rcode;
                response[6..12].copy_from_slice(&[0, answers.len() as u8, 0, 0, 0, 0]);
                for ip in &answers {
                    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                    response.extend_from_slice(&ip.octets());
                }
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for TestDnsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
