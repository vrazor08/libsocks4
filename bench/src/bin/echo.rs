use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let addr = "127.0.0.2:5252".to_string();
  let listener = TcpListener::bind(&addr).await?;
  println!("Listening on: {addr}");

  loop {
    let (mut socket, client_addr) = listener.accept().await?;
    if cfg!(debug_assertions) { println!("Accepted connection from: {client_addr:?}"); }
    socket.set_nodelay(true).unwrap();
    tokio::spawn(async move {
      let mut buf = vec![0; 1024];
      loop {
        let n = socket.read(&mut buf).await.unwrap();
        if n == 0 {
          socket.shutdown().await.unwrap();
          return;
        }
        socket.write(&buf[0..n]).await.unwrap();
      }
    });
  }
}
