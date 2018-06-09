
use actix::prelude::*;
use futures::{Future, future};
use std::net::{SocketAddr};
// use pool::*;
use tokio_core::net::TcpStream;
use std::cell::RefCell;
use std::collections::HashMap;
use std;


pub struct ConnectionPool {
    max_per_peer: usize,
    max_peers: usize,
    lifetime: u64,
    objects: RefCell<HashMap<SocketAddr, Vec<(u64, TcpStream)>>>
}


#[derive(Message)]
pub enum PoolControlMessage {
    Checkout(SocketAddr), //, Recipient<PoolNotice>),
    Checkin(SocketAddr, TcpStream),
//    Drain
}

#[derive(Message)]
enum PoolNotice {
    Available(TcpStream),
    CheckoutFailed
}


impl ConnectionPool {

    pub fn new() -> ConnectionPool {
        ConnectionPool {
            max_per_peer: 100,
            max_peers: 100,
            lifetime: 120,
            objects: RefCell::new(HashMap::new())
        }
    }

    pub fn checkout(&mut self, s: SocketAddr) -> Box<Future<Item=TcpStream, Error=std::io::Error>> {
        let mut obj = self.objects.borrow_mut();
        let st = obj.entry(s)
            .or_insert_with(|| { Vec::new() })
            .pop();
        println!("Run checkout");
        match st {
            None => { 
                println!("New: {:?}", s);
                Box::new(TcpStream::connect2(&s))
            }
            Some((ts, tcp)) => {
                println!("Reuse");
                Box::new(future::ok(tcp)) 
            }
        }
    }

    fn checkin(&mut self, a: SocketAddr, s: TcpStream) {
        let mut obj = self.objects.borrow_mut();
        obj.entry(a).or_insert_with(|| Vec::new()).push((0 + self.lifetime, s))
    }
}

impl Actor for ConnectionPool {
    type Context = Context<Self>;


}



impl Handler<PoolControlMessage> for ConnectionPool {

    type Result = ();


    fn handle(&mut self, m: PoolControlMessage, ctx: &mut Context<Self>) {
        match m {
            PoolControlMessage::Checkout(s) => {
                self.checkout(s);
                    // .map_err(|e| result_to.do_send(PoolNotice::CheckoutFailed))
                    // .and_then(|t| result_to.do_send(PoolNotice::Available(t)));
           }
           PoolControlMessage::Checkin(a, s) => {
               self.checkin(a, s);
           }
        }
    }
}




















