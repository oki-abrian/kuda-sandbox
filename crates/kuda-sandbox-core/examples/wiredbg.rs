use kuda_sandbox_core::wire::{recv_frame, send_frame, MsgType};
use std::time::Duration;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    println!("step1: bind");
    let p = std::path::PathBuf::from(format!("/tmp/kwdbg_{}.sock", Uuid::new_v4().simple()));
    let l = tokio::net::UnixListener::bind(&p).unwrap();
    println!("step2: connect");
    let mut c = tokio::net::UnixStream::connect(&p).await.unwrap();
    println!("step3: accept");
    let (s, _) = l.accept().await.unwrap();
    println!("step4: send");
    send_frame(&mut c, MsgType::StdoutChunk, b"ping", None).await.unwrap();
    println!("step5: recv");
    let mut s = s;
    let f = tokio::time::timeout(Duration::from_secs(5), recv_frame(&mut s)).await;
    println!("step6: {:?}", f.map(|r| r.map(|fr| (fr.msg_type, fr.payload))));
}
