use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::net::tcp::{WriteHalf, ReadHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use structopt::StructOpt;

async fn safe_write<'a>(
  cur_total_send_pkts: Arc<AtomicU32>,
  cur_total_erros: Arc<AtomicU32>,
  mut write_stream: WriteHalf<'a>,
  src: &[u8]
) -> (WriteHalf<'a>, Option<usize>) {
  cur_total_send_pkts.fetch_add(1, Ordering::SeqCst);
  match write_stream.write(src).await {
    Ok(n) => (write_stream, Some(n)),
    Err(e) => {
      cur_total_erros.fetch_add(1, Ordering::SeqCst);
      if !src.is_empty() && src[0] == 4 {
        eprintln!("write socks4 connect error: {}", e);
      } else {
        eprintln!("write socks4 error: {}", e);
      }
      (write_stream, None)
    }
  }
}

async fn safe_read(
  cur_total_erros: Arc<AtomicU32>,
  mut read_stream: ReadHalf<'_>,
  mut buf: Vec<u8>
) -> (ReadHalf<'_>, Vec<u8>, Option<usize>) {
  match read_stream.read(buf.as_mut_slice()).await {
    Ok(n) => (read_stream, buf, Some(n)),
    Err(e) => {
      cur_total_erros.fetch_add(1, Ordering::SeqCst);
      eprintln!("read socks4 error: {}", e);
      (read_stream, buf, None)
    }
  }
}

pub mod libsocks_test {
  use std::cmp::Ordering;
  use std::sync::Arc;
  use std::mem::ManuallyDrop;
  use std::process::Command;
  use anyhow::Context;
  use tokio::net::TcpStream;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  #[allow(non_upper_case_globals)]
  static unsuccess_socks_ans: [u8; 8] = [0, 91, 0, 0, 0, 0, 0, 0];

  pub fn socks4_fds_count(socks_pid: usize) -> i32 {
    let output = Command::new("bash")
      .arg("-c")
      .arg(format!("ls -l /proc/{socks_pid}/fd | awk 'BEGIN {{ sum = -1 }}; {{sum+=1}}; END {{ print sum }}'"))
      .output()
      .expect("Failed to get fds number");
    assert!(output.status.success());
    let str_output = String::from_utf8(output.stdout).unwrap();
    str_output.trim().parse().expect("parse to i32")
  }

  async fn send_bad_socks4_connect_req(socks4_connect_command: &[u8], proxy_addr: Arc<String>, concurrent_con_for_each: usize, func_name: &str) -> Result<(), anyhow::Error> {
    let mut read_buf = vec![0u8; 100];
    for _ in 0..concurrent_con_for_each {
      let mut bad_command_stream = TcpStream::connect(proxy_addr.as_str()).await.context(format!("{func_name}:connect error"))?;
      bad_command_stream.write(socks4_connect_command).await.context(format!("{func_name}:write error"))?;
      let n = bad_command_stream.read(read_buf.as_mut_slice()).await.context(format!("{func_name}:read error"))?;
      if read_buf[..n].cmp(&unsuccess_socks_ans) != Ordering::Equal {
        anyhow::bail!("ans for socks4_connect_bad_command != unsuccess_socks_ans")
      }
    }
    Ok(())
  }

  pub async fn bad_socks4_connect(proxy_addr: Arc<String>, concurrent_con: usize) {
    let socks4_connect_bad_command: [u8; 8] = [4, 100, 0, 0, 0, 0, 0, 0];
    let socks4_connect_bad_small_len: [u8; 4] = [4, 1, 0, 0];
    let socks4_connect_bad_big_len: [u8; 9] = [4, 1, 0, 0, 0, 0, 0, 0, 0];
    let socks4_connect_bad_very_big_len = [socks4_connect_bad_big_len.as_slice(), &[0u8; 100]].concat();

    let mut handlers = Vec::with_capacity(4);
    let concurrent_con_for_each = concurrent_con / 4;
    let mut cur_proxy_addr;

    cur_proxy_addr = Arc::clone(&proxy_addr);
    handlers.push(tokio::spawn(async move {
      println!("sending socks4_connect_bad_command {concurrent_con_for_each} times");
      send_bad_socks4_connect_req(
        &socks4_connect_bad_command,
        cur_proxy_addr,
        concurrent_con_for_each,
        "bad_socks4_connect:socks4_connect_bad_small_len"
      ).await.unwrap();
    }));

    cur_proxy_addr = Arc::clone(&proxy_addr);
    handlers.push(tokio::spawn(async move {
      println!("sending socks4_connect_bad_small_len {concurrent_con_for_each} times");
      send_bad_socks4_connect_req(
        &socks4_connect_bad_small_len,
        cur_proxy_addr,
        concurrent_con_for_each,
        "bad_socks4_connect:socks4_connect_bad_command"
      ).await.unwrap();
    }));

    cur_proxy_addr = Arc::clone(&proxy_addr);
    handlers.push(tokio::spawn(async move {
      println!("sending socks4_connect_bad_big_len {concurrent_con_for_each} times");
      send_bad_socks4_connect_req(
        &socks4_connect_bad_big_len,
        cur_proxy_addr,
        concurrent_con_for_each,
        "bad_socks4_connect:socks4_connect_bad_big_len"
      ).await.unwrap();
    }));

    cur_proxy_addr = Arc::clone(&proxy_addr);
    handlers.push(tokio::spawn(async move {
      println!("sending socks4_connect_bad_very_big_len {concurrent_con_for_each} times");
      send_bad_socks4_connect_req(
        &socks4_connect_bad_very_big_len,
        cur_proxy_addr,
        concurrent_con_for_each,
        "bad_socks4_connect:socks4_connect_bad_very_big_len"
      ).await.unwrap();
    }));

    for handler in handlers {
      handler.await.unwrap();
    }
  }

  pub async fn socks4_connect_without_shutdown(proxy_addr: Arc<String>, socks4_connect: Arc<[u8]>, concurrent_con: usize) {
    let mut tmp_proxy_addr;
    let mut tmp_connect;
    let mut handlers = Vec::with_capacity(concurrent_con);
    println!("socks4_connect_without_shutdown: conecting without shutdown {concurrent_con} times");
    for _ in 0..concurrent_con {
      tmp_proxy_addr = Arc::clone(&proxy_addr);
      tmp_connect = Arc::clone(&socks4_connect);
      handlers.push(tokio::spawn(async move {
        let mut read_buf = vec![0; 100];
        let stream = TcpStream::connect(tmp_proxy_addr.as_str()).await.expect("socks4_connect_without_shutdown:TcpStream::connect error");
        stream.set_nodelay(true).unwrap();
        let mut unsafe_stream = ManuallyDrop::new(stream);
        unsafe_stream.write(&tmp_connect).await.expect("socks4_connect_without_shutdown:write(socks4_connect) error");
        let n = unsafe_stream.read(read_buf.as_mut_slice()).await.expect("socks4_connect_without_shutdown:read error");
        assert_eq!(n, 8, "socks4_connect_without_shutdown:read len != 8");
        assert_eq!(read_buf[1], 90, "socks4_connect_without_shutdown:socks4 reply != 90");
      }));
    }
    for handler in handlers { let _ = handler.await; }
  }
}

#[tokio::main]
async fn main() {
  let cmd = Cmd::from_args();
  println!("cmd: {cmd:#?}");
  let target_addr = cmd.target_addr;
  println!("sending to {target_addr} using socks4 proxy: {}", cmd.proxy_addr);
  let proxy_addr = Arc::new(cmd.proxy_addr);
  let mut tmp_proxy_addr = Arc::clone(&proxy_addr);
  let proxy: SocketAddrV4 = target_addr.parse().unwrap();
  let target_ip = proxy.ip().octets();
  let target_port = proxy.port();
  let socks4_connect: Arc<[u8; 8]> = Arc::new([4, 1, (target_port >> 8) as u8, (target_port & 0xFF) as u8, target_ip[0], target_ip[1], target_ip[2], target_ip[3]]);
  match cmd.mode {
    Subcommands::Test {socks_pid, recv_timeout} => {
      let fds_count_before = libsocks_test::socks4_fds_count(socks_pid);
      libsocks_test::bad_socks4_connect(tmp_proxy_addr.clone(), cmd.concurrent_con).await;
      tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
      assert_eq!(fds_count_before, libsocks_test::socks4_fds_count(socks_pid), "bad_socks4_connect: fds count != fds_count_before");
      libsocks_test::socks4_connect_without_shutdown(tmp_proxy_addr.clone(), socks4_connect, cmd.concurrent_con).await;
      tokio::time::sleep(tokio::time::Duration::from_millis(recv_timeout + 500)).await;
      assert_eq!(fds_count_before, libsocks_test::socks4_fds_count(socks_pid), "socks4_connect_without_shutdown: fds count != fds_count_before");
      println!("All tests was passed!");
    }
    Subcommands::Bench => {
      let mut handlers = Vec::with_capacity(cmd.concurrent_con);
      let total_send_pkts = Arc::new(AtomicU32::new(0));
      let mut cur_total_send_pkts;
      let total_erros = Arc::new(AtomicU32::new(0));
      let mut cur_total_erros;
      let mut tmp_connect;
      for i in 0..cmd.concurrent_con {
        cur_total_send_pkts = Arc::clone(&total_send_pkts);
        cur_total_erros = Arc::clone(&total_erros);
        tmp_proxy_addr = Arc::clone(&proxy_addr);
        tmp_connect = Arc::clone(&socks4_connect);
        let handler = tokio::spawn(async move {
          let mut read_buf = vec![0; 1024];
          let write_data: Vec<u8> = vec![1; i+cmd.packet_size]; // TODO: maybe for debug build send some string
          let mut stream = TcpStream::connect(tmp_proxy_addr.as_str()).await.unwrap();
          stream.set_nodelay(true).unwrap();
          let (mut read_stream, mut write_stream) = stream.split();
          let mut opt_n;
          let mut write_bytes;
          (write_stream, opt_n) = safe_write(cur_total_send_pkts.clone(), cur_total_erros.clone(), write_stream, tmp_connect.as_ref()).await;
          if opt_n.is_none() { return; }
          (read_stream, read_buf, opt_n) = safe_read(cur_total_erros.clone(), read_stream, read_buf).await;
          if let Some(n) = opt_n {
            if n == 0 {
              println!("shutdown with proxy because n = 0");
              return;
            }
            assert_eq!(n, tmp_connect.len(), "socks4 connect reply != {}", tmp_connect.len());
          } else { return; }
          for _ in 0..cmd.sending_packets_for_each_con {
            (write_stream, opt_n) = safe_write(cur_total_send_pkts.clone(), cur_total_erros.clone(), write_stream, &write_data).await;
            if let Some(n) = opt_n { write_bytes = n; }
            else { return; }
            (read_stream, read_buf, opt_n) = safe_read(cur_total_erros.clone(), read_stream, read_buf).await;
            if let Some(n) = opt_n {
              if n == 0 {
                println!("shutdown with proxy because n = 0");
                return;
              }
              assert_eq!(n, write_bytes, "socks4 connect reply != {}", write_bytes);
            } else { return; }
          }
        });
        handlers.push(handler);
      }
      for handler in handlers {
        handler.await.unwrap();
      }
      println!("{:?} packets were sent, {:?} errors were given", total_send_pkts, total_erros);
    }
  }
}

#[derive(Clone, Debug, StructOpt)]
enum Subcommands {
  #[structopt(name = "bench", about = "Benchmark mode")]
  /// Benchmark mode
  ///
  /// By default sends 10 packets in each of 450 connections
  Bench,

  #[structopt(name = "test", about = "Test mode")]
  /// Test mode
  ///
  /// For each test it uses concurrent 450 connections
  Test {
    /// Socks server pid
    #[structopt(short="p", long)]
    socks_pid: usize,

    /// Recv timeout in millis
    #[structopt(short, long, default_value="3000")]
    recv_timeout: u64
  },
}

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "libsocks4-bench-test")]
struct Cmd {
  #[structopt(subcommand)]
  mode: Subcommands,

  /// proxy server addr in ip:port format
  #[structopt(long)]
  proxy_addr: String,

  /// target server addr in ip:port format
  #[structopt(long)]
  target_addr: String,

  #[structopt(short="C", long, default_value="450")]
  concurrent_con: usize,

  #[structopt(short, long, default_value="10")]
  sending_packets_for_each_con: usize,

  /// One packet size
  #[structopt(short="P", long, default_value="10")]
  packet_size: usize,
}
