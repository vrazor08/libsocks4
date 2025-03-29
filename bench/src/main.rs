use std::net::SocketAddrV4;
use std::process::exit;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROXY_ADDR: &str = "127.0.0.2:6969";
const TARGET_ADDR: &str = "127.0.0.2:5252";
const CONCURRENT_CON: usize = 400;
const SENDING_PACKETS_FOR_EACH_CON: usize = 5;
const PACKET_SIZE: usize = 10;

#[tokio::main]
async fn main() {
  println!("sending to {TARGET_ADDR} using socks4 proxy: {PROXY_ADDR}");
  let proxy: SocketAddrV4 = TARGET_ADDR.parse().unwrap();
  let target_ip = proxy.ip().octets();
  let target_port = proxy.port();
  let socks4_connect: [u8; 8] = [4, 1, (target_port >> 8) as u8, (target_port & 0xFF) as u8, target_ip[0], target_ip[1], target_ip[2], target_ip[3]];
  println!("socks4_connect: {:?}", socks4_connect);
  let mut handlers = Vec::with_capacity(CONCURRENT_CON);
  let total_send_pkts = Arc::new(AtomicU32::new(0));
  let mut cur_total_send_pkts;
  let total_erros = Arc::new(AtomicU32::new(0));
  let mut cur_total_erros;
  for i in 0..CONCURRENT_CON {
    cur_total_send_pkts = Arc::clone(&total_send_pkts);
    cur_total_erros = Arc::clone(&total_erros);
    let handler = tokio::spawn(async move {
      let mut read_buf = vec![0; 1024];
      let write_data: Vec<u8> = vec![1; i+PACKET_SIZE]; // TODO: maybe for debug build send some string
      let mut stream = TcpStream::connect(PROXY_ADDR).await.unwrap();
      stream.set_nodelay(true).unwrap();
      if cfg!(debug_assertions) {
        stream.write(&socks4_connect).await.unwrap();
        stream.read(read_buf.as_mut_slice()).await.unwrap();
      } else {
        cur_total_send_pkts.fetch_add(1, Ordering::SeqCst);
        if stream.write(&socks4_connect).await.ok().is_none() {
          cur_total_erros.fetch_add(1, Ordering::SeqCst);
          eprintln!("write socks4 connect error");
          return;
        }
        let n = stream.read(read_buf.as_mut_slice()).await.ok();
        if n.is_none() {
          cur_total_erros.fetch_add(1, Ordering::SeqCst);
          eprintln!("read socks4 connect error");
          return;
        }
        //assert_eq!(n.unwrap(), socks4_connect.len(), "socks4 connect reply != 8");
      }
      // TODO: check if we recv zero, close connection
      for _ in 0..SENDING_PACKETS_FOR_EACH_CON {
        if cfg!(debug_assertions) {
          stream.write(&write_data).await.unwrap();
          let n = stream.read(read_buf.as_mut_slice()).await.unwrap();
          println!("[{}] sending to client len: {:?}, recving from client len: {:?}", i, write_data.len(), n);
          assert_eq!(write_data.len(), n);
        } else {
          let _ = stream.write(&write_data).await.inspect_err(|e| {
            cur_total_erros.fetch_add(1, Ordering::SeqCst);
            eprintln!("{} write error: {}", write_data.len(), e);
          } );
          let _ = stream.read(read_buf.as_mut_slice()).await.inspect_err(|e| {
            cur_total_erros.fetch_add(1, Ordering::SeqCst);
            eprintln!("{} read error: {}", write_data.len(), e);
          } );
          cur_total_send_pkts.fetch_add(1, Ordering::SeqCst);
        }
      }
      if !cfg!(debug_assertions) {
        let _ = stream.shutdown().await.inspect_err(|_| { cur_total_erros.fetch_add(1, Ordering::SeqCst); } ); }
    });
    #[cfg(debug_assertions)] {println!("coroutine {} was spawned", i);}
    handlers.push(handler);

  }
  for handler in handlers {
    handler.await.unwrap();
  }
  if !cfg!(debug_assertions) { println!("{:?} packets were sent, {:?} errors were given", total_send_pkts, total_erros); }
  //total_erros.fetch_add(1, Ordering::SeqCst);
  if total_erros.load(Ordering::SeqCst) != 0 { exit(69); }
}
