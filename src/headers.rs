


use std::net::ToSocketAddrs;
use std::net::SocketAddr;
use std;


#[derive(Clone,Debug)]
pub enum Authority {
    HostPort(String, u16)
}


impl Authority {
    fn as_addr(&self) -> Result<SocketAddr, std::io::Error> {
        match self {
            &Authority::HostPort(ref h, ref p) => {
                let hp = format!("{}:{}", h, p);
                hp.to_socket_addrs()
                    .and_then(|mut v| { v.next().ok_or(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "No addresses found")) })

            }
        }
    }

    fn hostname(&self) -> &String {
        match self {
            &Authority::HostPort(ref h, ref p) => {
                h
            }
        }
    }
}




pub enum BodyLength {
    ContentLength(usize),
    Chunked,
    NoBody
}



