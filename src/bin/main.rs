// A tiny async server with tokio-core
extern crate futures;
extern crate tokio_core;
extern crate tokio_io;
extern crate openssl;
extern crate tokio_tls;
extern crate native_tls;
extern crate httparse;
extern crate bytes;
extern crate mproxy;
extern crate actix_web;
extern crate actix;
extern crate tokio_openssl;
extern crate env_logger;



use actix_web::{http, middleware, server, App, Path, pred, HttpRequest, HttpResponse, HttpMessage };
use std::rc::Rc;
use futures::{Future, Poll, Async, future, Stream};
use tokio_io::{io, AsyncRead, AsyncWrite};
use tokio_core::net::{TcpListener, TcpStream};
use tokio_core::reactor::{Core, Remote};
use bytes::{BytesMut, Bytes};
use std::str;
use std::mem;
use openssl::ssl;
use openssl::ssl::{SslConnector, SslAcceptor, SslMethod};
use tokio_io::codec::{Decoder, Encoder};
use tokio_openssl::{SslStream, SslConnectorExt, SslAcceptorExt};

use mproxy::ca;
use std::cell::RefCell;
use std::fmt;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use mproxy::messages::*;
use mproxy::client;
use std::io::Error;
use actix::Actor; 
use actix::prelude::*; 


struct HeaderParser<R: AsyncRead>{
    underlying: Option<R>,
    buf: BytesMut
}

impl<R: AsyncRead> HeaderParser<R> {
    fn new(reader: R) -> HeaderParser<R> {
        HeaderParser {
            underlying: Some(reader),
            buf: BytesMut::with_capacity(0),
        }
    }
}


//TODO(matt) - generalize
impl<R: AsyncRead> Future for HeaderParser<R> {
    type Item=(R, BytesMut, Http1Message<H1Request>);
    type Error=ParseError;
   
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        //TODO allocate from a slab
        let mut buf = BytesMut::with_capacity(4096);
        let result = { self.underlying.as_mut().map(|read| { read.read_buf(&mut buf) }) };

        match result.unwrap() {
            Err(e) => { Err(ParseError::from(e)) }
            Ok(Async::NotReady) => { Ok(Async::NotReady) }
            Ok(Async::Ready(count)) => {
                self.buf.extend(buf);
                 
                match parse_request_head(&mut self.buf)?  {
                    Async::Ready(head) => {
                        // For CONNECT self.buf should be empty, maybe track this....
                        return Ok(Async::Ready((self.underlying.take().unwrap(), self.buf.take(), head)));
                    }

                    Async::NotReady => {
                        // TODO length check
                        return Ok(Async::NotReady);
                    }
                }
            }
        }
    }
}


#[derive(Debug)]
enum MitmFlowError {
    LookupError(std::io::Error),
    UpstreamConnectError(std::io::Error),
    DownstreamError(std::io::Error),
    UpstreamSslError(ssl::Error),
    DownstreamSslError(ssl::Error),
    WrappedIo(std::io::Error),
}

impl From<MitmFlowError> for std::io::Error {

    fn from(m: MitmFlowError) -> std::io::Error {
        match m {
            MitmFlowError::LookupError(e) => e,
            MitmFlowError::UpstreamConnectError(e) => e,
            MitmFlowError::DownstreamError(e) => e,
            // TODO another error code
            MitmFlowError::UpstreamSslError(e) => e.into_io_error().unwrap_or(std::io::Error::from_raw_os_error(111)),
            MitmFlowError::DownstreamSslError(e) => e.into_io_error().unwrap_or(std::io::Error::from_raw_os_error(111)),
            MitmFlowError::WrappedIo(e) => e
        }
    }
}

fn route_connect(r: &Http1Message<H1Request>) -> Result<(SocketAddr, String), String> {
    // let host_header = req.headers.find("host").next();
    let p = r.line.uri.port().unwrap_or(443);

    match r.line.uri.host() {
        None => { println!("No host defined"); Err("invalid http request".to_owned()) }
        // TODO the unwrap there is the name resolution failure
        Some(h) => { 
            format!("{}:{}", h, p)
                .to_socket_addrs()
                .map_err(|e| { format!("{:?}", e) })
                .and_then(|mut a| { a.next().map_or(Err("No Address found".to_owned()), |s| { Ok((s, h.to_owned())) }) })
            }
    }
}


fn do_ssl<A>(sca: Arc<ca::CertAuthority>, ssl: &SslStream<A>) -> SslAcceptor {
    let leaf_cert = {
        ssl.get_ref().ssl().peer_certificate().map(|peer| {
            sca.sign_cert_from_cert(&peer).map_err(|e| println!("{:?}", e)) 
        }).unwrap().unwrap()
    };

    //TODO(matt) - Error handling

    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    acceptor.set_private_key(&sca.child_key).unwrap();
    acceptor.set_certificate(&leaf_cert).unwrap();
    let acceptor = acceptor.build();
    acceptor
}


fn upstream_connect(hostname: &str, t: TcpStream) -> impl Future<Item=SslStream<TcpStream>, Error=MitmFlowError> 
{
    let cx = SslConnector::builder(SslMethod::tls()).unwrap().build(); 
    cx.connect_async(&hostname, t).map_err(MitmFlowError::UpstreamSslError)
}


fn write_error_response<W: AsyncWrite>(w: W) -> impl Future<Item=(), Error=()> {
    let out =  Bytes::from_static(b"HTTP/1.1 503 Server Unavailable"); 
    io::write_all(w, out).map_err(|_| ()).map(|_| ())
}

struct SslPair {
    downstream: SslStream<TcpStream>,
    upstream: SslStream<TcpStream>,
}

fn setup_downstream_ssl(
    downstream: TcpStream, 
    ca: Arc<ca::CertAuthority>,
    upstream_ssl: SslStream<TcpStream>
    ) -> impl Future<Item=SslPair, Error=MitmFlowError>
{
    // TODO(woodyard) - plumb a handler 
    let out = Bytes::from_static(b"HTTP/1.1 200 OK\r\n\r\n");

    let downs = io::write_all(downstream, out)
        .map_err(MitmFlowError::DownstreamError) // TODO we're lost downstream now... ok for the moment
        .and_then(move |(tcp, out)| {
            let downstream_accept = do_ssl(ca.clone(), &upstream_ssl); 
            let downstream_accept = downstream_accept.accept_async(tcp)
                .map_err(MitmFlowError::DownstreamSslError)
                .map(|s| { SslPair { downstream: s, upstream: upstream_ssl }});
            downstream_accept
        });
    downs
}

fn proxy(req: HttpRequest) -> Box<Future<Item = HttpResponse, Error = Error>> {
   
    /* downstream_authz */
    /*     .handle(req) */
    /*     .and_then(add_upstream_authn) */ 
    /*     .and_then(send_header) */
    /*     .and_then(tee_stream_body) */
    /*     .and_then(handle_authn_error) */


}

fn main() {
    // Create the event loop that will drive this server
     std::env::set_var("RUST_LOG", "actix_web=info");
     env_logger::init();

    let key = "/home/matt/projects/mtmprxy/mproxy/server.key";
    let crt = "/home/matt/projects/mtmprxy/mproxy/server.crt";
    let ca = Arc::new(ca::CertAuthority::from_files(key, crt).unwrap());

    let sys = actix::System::new("example");  // <- create Actix system
    let handle = Arbiter::handle();
    // Bind the server's socket
    let addr = "127.0.0.1:12345".parse().unwrap();
    let tcp = TcpListener::bind(&addr, handle).unwrap();

    let conn_pool = Rc::new(RefCell::new(client::ConnectionPool::new()));

    let mserver = tcp.incoming().and_then(move |(tcp, _)| {
        let ca = ca.clone();
    
        // TODO(woodyard) - use the actix machinery instead
        let conn_pool = conn_pool.clone();
        let hp = HeaderParser::new(tcp);

        let handle_conn = hp
            .from_err()
            .and_then(move |(tcp, buf, req)| {
                if req.line.method == http::Method::CONNECT {
                    match route_connect(&req) {
                        Ok((r, hostname)) => {
                            let upstream_ssl_connected = conn_pool
                                .borrow_mut()
                                .checkout(r).map_err(MitmFlowError::UpstreamConnectError) // Why is the lookup error not appearing here
                                .and_then(move |tcp| { upstream_connect(&hostname, tcp) })
                                .and_then(move |sslc| { setup_downstream_ssl(tcp, ca.clone(), sslc) })
                                .map_err(|e| { println!("{:?}", e); e })
                                .map(|p| (p.downstream, ()));
                            // This version drops the upstream connection
                            // it would be better to attach the upstream to an actix connector for reuse
                            // in the next phase
                            Box::new(upstream_ssl_connected.from_err())
                        }
                        Err(e) => { 
                            let out =  Bytes::from_static(b"HTTP/1.1 503 Server Unavailable\r\n\r\n"); 
                            Box::new(io::write_all(tcp, out).and_then(|_| Err(std::io::Error::from_raw_os_error(9))))  as Box<Future<Item=(SslStream<TcpStream>, ()), Error=std::io::Error>>
                        }
                    }
                } else {
                    Box::new(future::err(std::io::Error::from_raw_os_error(9)))
                }
            });
        handle_conn
    });

    let srv = server::new(|| {
        App::new()
        .middleware(middleware::Logger::default())
        .default_resource(|r| { r.f(proxy) })
    });
    srv.start_incoming(mserver, true);
    let _ = sys.run();
}
