// #![deny(warnings)]
extern crate futures;
extern crate hyper;
extern crate mproxy;
extern crate native_tls;
extern crate openssl;
extern crate pretty_env_logger;
extern crate rmp;
extern crate rmp_serde;
extern crate tokio_io;
extern crate tokio_openssl;
extern crate tokio_tcp;
extern crate tokio_tls;
extern crate uuid;

use futures::future::{err, ok, FutureResult};

use futures::sink::Sink;
use futures::stream::Stream;
use hyper::client::connect::{Connect, Connected};
use hyper::http::uri::Authority;
use hyper::rt::Future;
use hyper::server::conn::Http;
use hyper::service::{service_fn, service_fn_ok};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use mproxy::ca;
use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::ToSocketAddrs;
use std::sync::Mutex;
use tokio_io::io::copy;

use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::TcpStream;

use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslStream};
use tokio_openssl::{SslAcceptorExt, SslConnectorExt};

use futures::sync::{mpsc, oneshot};
use std::sync::Arc;

use mproxy::pool;


// use std::sync::mpsc::{channel,Sender};

struct UpstreamConnect<T: AsyncRead + AsyncWrite + Send + 'static + Sync> {
    connect: Mutex<Option<T>>,
}

impl<T> UpstreamConnect<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static + Sync,
{
    fn new(t: T) -> UpstreamConnect<T> {
        UpstreamConnect {
            connect: Mutex::new(Some(t)),
        }
    }
}

impl<T> Connect for UpstreamConnect<T>
where
    T: AsyncRead + AsyncWrite + Send + 'static + Sync,
{
    type Transport = T;
    type Error = io::Error;
    type Future = FutureResult<(Self::Transport, Connected), io::Error>;

    fn connect(
        &self,
        _dst: hyper::client::connect::Destination,
    ) -> <Self as hyper::client::connect::Connect>::Future {
        let mut n = self.connect.lock().unwrap();

        n.take()
            .map(|t| ok((t, Connected::new())))
            .unwrap_or(err(Error::new(ErrorKind::Other, "oh no!")))
    }
}

fn do_forward<T>(t: T, req: Request<Body>) -> Response<Body>
where
    T: AsyncRead + AsyncWrite + Send + 'static + Sync,
{
    let uc = UpstreamConnect::new(t);
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::OK;
    res
}

fn is_adware(host: &String) -> bool {
    host.as_str().starts_with("adservice.google.com")
}

struct SurfTimeConfig {
    blacklist: Vec<String>,
    in_effect: (u64, u64),
}

struct SurfTime {
    config: SurfTimeConfig,
}

struct EndpointMatch {}

struct IdTarget {
    identifier: String,
    realm: String,
}

enum IdMatch {
    Any,
    AnyFromRealm(String),
    RealmGroup { user: String, realms: Vec<String> },
    AnyRealm { user: String },
}

struct AuthzMap {
    auth_input: IdMatch,
    auth_output: IdTarget,
    allowed_roles: Vec<EndpointMatch>,
}
fn result_502_resolve_failed<'a>(m: &'a str) -> Response<Body> {
    let mut res = Response::new(Body::from(format!("Failed to resolve upstream: {}", m)));
    *res.status_mut() = StatusCode::BAD_GATEWAY;
    return res;
}
fn result_unboxed(c: u16) -> Response<Body> {
    let mut res = Response::new(Body::empty());
    // TODO(matt) use constants
    *res.status_mut() = StatusCode::from_u16(c).unwrap();
    res
}
fn result(c: u16) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
    let mut res = Response::new(Body::empty());
    // TODO(matt) use constants
    *res.status_mut() = StatusCode::from_u16(c).unwrap();
    Box::new(futures::future::ok(res))
}

fn crappy_log(r: &Request<Body>) {
    println!("{:?} {}", r.method(), r.uri())
}

fn normalize_authority(uri: &hyper::Uri) -> String {
    // There are 3 forms
    let pp = uri.port_u16().unwrap_or(80);
    format!("{}:{}", uri.host().unwrap_or(""), pp)
}

pub struct UserIdentity {
    pub uuid: String,
    pub friendly_name: Option<String>,
    pub attributes: Option<HashMap<String, String>>,
}

pub enum Identity {
    User(UserIdentity),
    Anonymous,
    Role(String),
}

pub trait Authenticate {
    fn authenticate(&self, req: &Request<Body>) -> Result<Identity, String>;
}

pub enum AuthzResult {
    Allow,
    Disallow,
}

pub trait Authorize {
    fn authorize(&self, i: &Identity, req: &Request<Body>) -> Result<AuthzResult, String>;
}

pub trait SiteAuthorize {
    fn authorize(&self, i: &Identity, url: &str) -> Result<AuthzResult, String>;
}

#[derive(Clone)]
pub struct AuthConfig<U, S, A>
where
    U: Authenticate + Clone,
    S: SiteAuthorize + Clone,
    A: Authorize + Clone,
{
    authenticate: U,
    site: S,
    authorize: A,
}

fn handle_tls_raw<C: Connect + 'static>(
    req_uuid: uuid::Uuid,
    _client: &Client<C>,
    upstream_addr: std::net::SocketAddr,
    req: Request<Body>,
) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
    let (resp_tx, resp_rx) = oneshot::channel();

    // connect, then on_upgrade()
    // this needs to be reworked
    // there is a panic in upgrade none

    let cpair = TcpStream::connect(&upstream_addr)
        .map(|upstream| {
            println!("Connection established");
            let _ = resp_tx.send(()).unwrap();
            upstream
        })
        .map_err(|err| eprintln!("connect: {}", err));

    let upgraded = req.into_body().on_upgrade();

    let upg2 = upgraded
        .map_err(|err| eprintln!("upgrade: {}", err))
        .join(cpair)
        .and_then(|(upstream, downstream)| {
            println!("In up/down");

            let (u2dr, u2dw) = upstream.split();
            let (d2ur, d2uw) = downstream.split();

            let u2df = copy(u2dr, d2uw);
            let d2uf = copy(d2ur, u2dw);
            d2uf.join(u2df).map_err(|err| eprintln!("connect: {}", err))
        })
        .map(|_| ())
        .map_err(|e| println!("Error {:?}", e));

    hyper::rt::spawn(upg2);

    Box::new(
        resp_rx
            .map(|_| 200)
            .or_else(|_| Ok(502))
            .and_then(|i| result(i)),
    )
    // result(200)
}

fn is_mitm(r: &Request<Body>, mitm_enabled: bool) -> bool {
    true
}

#[derive(Clone)]
struct AdWareBlock;

impl SiteAuthorize for AdWareBlock {
    fn authorize(&self, i: &Identity, url: &str) -> Result<AuthzResult, String> {
        if url.starts_with("adservice.google.com") {
            return Ok(AuthzResult::Disallow);
        }
        Ok(AuthzResult::Allow)
    }
}

#[derive(Clone)]
struct AllowAll;

impl Authorize for AllowAll {
    fn authorize(&self, i: &Identity, req: &Request<Body>) -> Result<AuthzResult, String> {
        Ok(AuthzResult::Allow)
    }
}

#[derive(Clone)]
struct NoAuth;

impl Authenticate for NoAuth {
    fn authenticate(&self, req: &Request<Body>) -> Result<Identity, String> {
        Ok(Identity::Anonymous)
    }
}

pub enum Trace {
    TraceId(String),
    TraceSecurity(String, openssl::x509::X509),
    TraceRequest(String, Request<Body>),
    TraceResponse(String, Request<Body>),
}

fn make_absolute(req: &mut Request<Body>) {
    /* RFC 7312 5.4

      When a proxy receives a request with an absolute-form of
      request-target, the proxy MUST ignore the received Host header field
      (if any) and instead replace it with the host information of the
      request-target.  A proxy that forwards such a request MUST generate a
      new Host field-value based on the received request-target rather than
      forward the received Host field-value.
    */
    match req.method() {
        &Method::CONNECT => {}
        _ => {
            let nhost: Option<String> = { req.uri().authority_part().map(|a| a.as_str().into()) };

            if let Some(n) = nhost {
                req.headers_mut()
                    .insert(http::header::HOST, n.parse().unwrap());
                return;
            }

            let nuri = req.headers().get(http::header::HOST).map(|host| {
                let autht: Authority = host.to_str().unwrap().parse().unwrap();
                
                let mut builder = hyper::Uri::builder();
                builder.authority(autht);
                //TODO(matt) do as map[
                if let Some(p) = req.uri().path_and_query() {
                    builder.path_and_query(p.as_str());
                }

                if let Some(p) = req.uri().scheme_part() {
                    builder.scheme(p.as_str());
                } else {
                    // Ok so this kind of sketchy, but since this is fixing up a client connection
                    // we'll never see an https one. Why? https is via  CONNECT at the proxy
                    builder.scheme("http");
                }
                builder.build().unwrap()
            }); 
            match nuri {
                Some(n) => *req.uri_mut() = n,
                None => {}
            }
        }
    }
}

#[derive(Clone)]
struct Proxy<U, S, A>
where
    U: Authenticate + Sync + Send + Clone + 'static,
    S: SiteAuthorize + Sync + Send + Clone + 'static,
    A: Authorize + Sync + Send + Clone + 'static,
{
    //TODO(matt) - trace filter
    tracer: Option<mpsc::Sender<Trace>>,
    ca: Arc<ca::CertAuthority>,
    auth_config: AuthConfig<U, S, A>,
    upstream_ssl_pool: Arc<pool::Pool<tokio_openssl::SslStream<tokio_tcp::TcpStream>>>
      
}

impl<U, S, A> Proxy<U, S, A>
where
    U: Authenticate + Sync + Send + Clone,
    S: SiteAuthorize + Sync + Send + Clone,
    A: Authorize + Sync + Send + Clone,
{
    // Rework this instead of duping proxy do somehting else
    fn dup(&self) -> Proxy<U, S, A> {
        Proxy {
            tracer: self.tracer.iter().map(|t| t.clone()).next(),
            ca: self.ca.clone(),
            auth_config: self.auth_config.clone(),
            upstream_ssl_pool: pool::Pool::empty(100)
        }
    }

    fn handle<C: Connect + 'static>(
        &self,
        client: &Client<C>,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        let req_uuid = uuid::Uuid::new_v4();
        println!("Begin request {}", req_uuid);

        println!("Begin request {:?}", req.uri());

        let hostname = normalize_authority(req.uri());

        // TODO this is slow and not async, and crappy
        let upstream_addr = match hostname.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => return result(502),
            },

            Err(e) => {
                eprintln!("Upstream resolution: ({}): {}", hostname, e);
                return Box::new(futures::future::ok(result_502_resolve_failed(&hostname)));
            }
        };

        let uid = self.auth_config.authenticate.authenticate(&req);

        let x = uid
            .and_then(|u| {
                self.auth_config
                    .site
                    .authorize(&u, &hostname)
                    .map(|r| (u, r))
            })
            .and_then(|(u, site_result)| {
                self.auth_config
                    .authorize
                    .authorize(&u, &req)
                    .map(|ar| (u, site_result, ar))
            });

        let _user = match x {
            Ok((u, AuthzResult::Allow, AuthzResult::Allow)) => u,
            Err(_) => return result(401),
            _ => return result(403),
        };

        self.handle_inner(req_uuid, upstream_addr, client, req)
    }

    fn handle_inner<C: Connect + 'static>(
        &self,
        req_uuid: uuid::Uuid,
        upstream_addr: std::net::SocketAddr,
        client: &Client<C>,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        crappy_log(&req);
        let mitm_enabled = true;

        match req.method() {
            &Method::CONNECT => match is_mitm(&req, mitm_enabled) {
                true => self.handle_mitm(req_uuid, client.clone(), upstream_addr, req),
                false => handle_tls_raw(req_uuid, client, upstream_addr, req),
            },
            _ => self.handle_http(req_uuid, client, req),
        }
    }

    fn handle_http_forward<C: Connect + 'static>(
        &self,
        req_uuid: uuid::Uuid,
        mut client: Client<C>,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        let client = client.request(req);

        match self.tracer.clone() {
            Some(tx) => {
                let f = tx
                    .send(Trace::TraceId(format!("{}", req_uuid)))
                    .map_err(|e| {
                        println!("Error in trace: {:?}", e);
                        io::Error::from(io::ErrorKind::Other)
                    });
                Box::new(
                    f.join(client.map(|resp| resp).map_err(|e| {
                        println!("Error in upstream: {:?}", e);
                        io::Error::from(io::ErrorKind::Other)
                    }))
                    .map(|(_, b)| b),
                )
            }
            None => Box::new(client.map(|resp| resp).map_err(|e| {
                println!("Error in upstream: {:?}", e);
                io::Error::from(io::ErrorKind::Other)
            })),
        }
    }

    fn handle_http<C: Connect + 'static>(
        &self,
        req_uuid: uuid::Uuid,
        client: &Client<C>,
        mut req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        make_absolute(&mut req);

        let client = client.clone().request(req);

        match self.tracer.clone() {
            Some(tx) => {
                let f = tx
                    .send(Trace::TraceId(format!("{}", req_uuid)))
                    .map_err(|e| {
                        println!("Error in trace: {:?}", e);
                        io::Error::from(io::ErrorKind::Other)
                    });
                Box::new(
                    f.join(client.map(|resp| resp).map_err(|e| {
                        println!("Error in upstream: {:?}", e);
                        io::Error::from(io::ErrorKind::Other)
                    }))
                    .map(|(_, b)| b),
                )
            }
            None => Box::new(client.map(|resp| resp).map_err(|e| {
                println!("Error in upstream: {:?}", e);
                io::Error::from(io::ErrorKind::Other)
            })),
        }
    }

    fn handle_mitm<C: Connect + 'static>(
        &self,
        req_uuid: uuid::Uuid,
        client: Client<C>,
        upstream_addr: std::net::SocketAddr,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        let (resp_tx, resp_rx) = oneshot::channel();

        // connect, then on_upgrade()
        // this needs to be reworked
        // there is a panic in upgrade none

        let authority = req.uri().authority_part().unwrap().clone();

        let cpair = TcpStream::connect(&upstream_addr)
            .map_err(|err| eprintln!("mitm tcp connect: {}", err))
            .and_then(move |upstream| {
                let cx = SslConnector::builder(SslMethod::tls()).unwrap().build();

                cx.connect_async(authority.host(), upstream)
                    .map(|ssl_conn| {
                        let _ = resp_tx.send(()).unwrap();
                        println!("MITM Connection established");

                        let peer_cert =
                            { ssl_conn.get_ref().ssl().peer_certificate().unwrap().clone() };

                        // println!(
                        //     "Upstream cert: {}",
                        //     std::str::from_utf8(&peer_cert.to_pem().unwrap()).unwrap()
                        // );
                        (ssl_conn, peer_cert)
                    })
                    .map_err(|e| println!("tls error: {:}", e))
            });

        let upgraded = req.into_body().on_upgrade();

        let ca = self.ca.clone();
        let np = self.clone();
        let req_uuid = req_uuid.clone();

        let upg2 = upgraded
            .map_err(|err| eprintln!("upgrade: {}", err))
            .join(cpair)
            .and_then(move |tuple| {
                let (downstream, (upstream, peer_cert)) = tuple;

                
                
                
                let ca = ca;
                let req_uuid = req_uuid;
                //let ( upstream_conn, peer_cert) = upstream;

                let peer_cert_signed = ca.sign_cert_from_cert(&peer_cert).unwrap();
                // println!(
                //     "downstream cert: {}",
                //     std::str::from_utf8(&peer_cert_signed.to_pem().unwrap()).unwrap()
                // );
                let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
                acceptor.set_private_key(ca.child_key.as_ref()).unwrap();
                acceptor.set_certificate(peer_cert_signed.as_ref()).unwrap();
                acceptor.check_private_key().unwrap();
                let acceptor = acceptor.build();

                acceptor
                    .accept_async(downstream)
                    .map_err(|e| eprintln!("accept: {}", e))
                    .and_then(move |tls_downstream| {

                        // This should cause the pool to have a single entry
                        // and then magic
                        let upstream_pool = {
                            let local_pool = pool::Pool::empty(1);
                            let pooled_upstream = pool::PoolItem::new(upstream);
                            pool::PoolItem::attach(pooled_upstream, local_pool.clone());
                            local_pool
                        };
                        
                        Http::new()
                            .serve_connection(
                                tls_downstream,
                                service_fn(move |req: Request<Body>| {
                                    let upstream_pool = upstream_pool.clone();
                                    let uc = Client::builder().keep_alive(false).build(AlreadyConnected(upstream_pool));
                                    println!("In inner client handler: {} {:?}", req_uuid, req);
                                    np.handle_http(req_uuid, &uc, req)
                                }),
                            )
                            .map_err(|err| {
                                eprintln!("Error in inner http: {}", err);
                                ()
                            })

                        // This is proxy without analysis, just forward
                        // serve_connection
                        // let (u2dr, u2dw) = upstream_conn.split();
                        // let (d2ur, d2uw) = tls_downstream.split();

                        // let u2df = copy(u2dr, d2uw);
                        // let d2uf = copy(d2ur, u2dw);
                        // d2uf.join(u2df)
                        //     .map_err(|err| eprintln!("mitm forward: {}", err));
                    })
            })
            .map(|_| ())
            .map_err(|e| println!("Error {:?}", e));

        hyper::rt::spawn(upg2);

        Box::new(
            resp_rx
                .map(|_| 200)
                .or_else(|_| Ok(502))
                .and_then(|i| result(i)),
        )
    }
}




struct AlreadyConnected<T: Send + 'static + AsyncRead + AsyncWrite + 'static + Sync>(Arc<pool::Pool<T>>);

impl<T: Send + 'static + AsyncRead + AsyncWrite + 'static + Sync> Connect for AlreadyConnected<T> {
    type Transport = pool::PoolItem<T>;
    /// An error occured when trying to connect.
    type Error = io::Error;
    /// A Future that will resolve to the connected Transport.
    type Future = Box<Future<Item = (Self::Transport, Connected), Error = Self::Error> + Send>;
    /// Connect to a destination.
    fn connect(&self, _: hyper::client::connect::Destination) -> Self::Future {
        
        let o = pool::Pool::checkout(self.0.clone()).unwrap();        
        Box::new(futures::future::ok((
            o,
            hyper::client::connect::Connected::new(),
        )))
    }
}

fn trace_handler(mut rx: mpsc::Receiver<Trace>) {
    let _t = std::thread::spawn(move || {
        let done = rx.for_each(|tx| {
            match tx {
                Trace::TraceId(uuid) => {
                    println!("Begin Tracing {}", uuid);
                }

                _ => {}
            }

            println!("Trace recv");
            Ok(())
        });
        hyper::rt::run(done);
    });
}

fn main() {
    pretty_env_logger::init();
    let addr = ([0, 0, 0, 0], 3000).into();

    let key = "/home/matt/projects/proxykit/server.key";
    let crt = "/home/matt/projects/proxykit/server.crt";
    let ca = Arc::new(ca::CertAuthority::from_files(key, crt).unwrap());

    let client = Client::new();
    println!("Hello!");

    let (tx, rx) = mpsc::channel(1024);

    trace_handler(rx);

    let proxy = Proxy {
        tracer: Some(tx),
        ca: ca,
        auth_config: AuthConfig {
            authenticate: NoAuth,
            site: AdWareBlock,
            authorize: AllowAll,
        },
        upstream_ssl_pool: pool::Pool::empty(100)
    };

    let new_svc = move || {
        let proxy = proxy.clone();
        let client = client.clone();
        service_fn(move |req: Request<Body>| proxy.handle(&client, req))
    };

    // Need an Http

    let server = Server::bind(&addr)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}
