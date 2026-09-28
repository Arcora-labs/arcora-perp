use std::{io::Read, net::{TcpListener,TcpStream}, thread, time::{Duration,Instant}};
fn main() {
 let listener=TcpListener::bind("127.0.0.1:0").unwrap();
 listener.set_nonblocking(true).unwrap();
 let addr=listener.local_addr().unwrap();
 let peer=thread::spawn(move||{let _s=TcpStream::connect(addr).unwrap();thread::sleep(Duration::from_millis(400));});
 let mut stream=loop{match listener.accept(){Ok((s,_))=>break s,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>thread::yield_now(),Err(e)=>panic!("{e}")}};
 stream.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
 let start=Instant::now();let result=stream.read(&mut [0]);println!("inherited read: {:?}, elapsed_ms={}",result,start.elapsed().as_millis());
 stream.set_nonblocking(false).unwrap();
 let start=Instant::now();let result=stream.read(&mut [0]);println!("explicit blocking read: {:?}, elapsed_ms={}",result,start.elapsed().as_millis());
 peer.join().unwrap();
}
