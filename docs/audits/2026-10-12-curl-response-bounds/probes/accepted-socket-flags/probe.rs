use std::{net::{TcpListener,TcpStream},os::fd::AsRawFd};
unsafe extern "C" {fn fcntl(fd:i32,cmd:i32,...)->i32;}
fn main(){let l=TcpListener::bind("127.0.0.1:0").unwrap();l.set_nonblocking(true).unwrap();let c=TcpStream::connect(l.local_addr().unwrap()).unwrap();let(s,_)=l.accept().unwrap();let before=unsafe{fcntl(s.as_raw_fd(),3)};s.set_nonblocking(false).unwrap();let after=unsafe{fcntl(s.as_raw_fd(),3)};println!("accepted_flags_before={} accepted_flags_after={} inherited_nonblocking={}",before,after,before&4!=0);assert!(before&4!=0);assert!(after&4==0);drop(c);}
