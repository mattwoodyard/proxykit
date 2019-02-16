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
use futures::stream::Stream;
use hyper::client::connect::{Connect, Connected};
use hyper::http::uri::Authority;
use hyper::rt::Future;
use hyper::server::conn::Http;
use hyper::service::{service_fn, service_fn_ok};
use hyper::{Body, Client, Method, Request, Response, Server, StatusCode};
use mproxy::ca;
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

fn normalize_authority(a: &Authority) -> String {
    let pp = a.port_u16().unwrap_or(80);
    format!("{}:{}", a.host(), pp)
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

pub struct AuthConfig<U, S, A>
where
    U: Authenticate,
    S: SiteAuthorize,
    A: Authorize,
{
    authenticate: U,
    site: S,
    authorize: A,
}

fn handle_http<C: Connect + 'static>(
    client: &Client<C>,
    req: Request<Body>,
) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
    let client = client.clone().request(req);
    //TODO(matt) - map client errors to 50x codes
    Box::new(client.map(|resp| resp).map_err(|e| {
        println!("Error in upstream: {:?}", e);
        io::Error::from(io::ErrorKind::Other)
    }))
}

fn handle_tls_raw<C: Connect + 'static>(
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

struct AdWareBlock;

impl SiteAuthorize for AdWareBlock {
    fn authorize(&self, i: &Identity, url: &str) -> Result<AuthzResult, String> {
        if url.starts_with("adservice.google.com") {
            return Ok(AuthzResult::Disallow);
        }
        Ok(AuthzResult::Allow)
    }
}

struct AllowAll;

impl Authorize for AllowAll {
    fn authorize(&self, i: &Identity, req: &Request<Body>) -> Result<AuthzResult, String> {
        Ok(AuthzResult::Allow)
    }
}

struct NoAuth;

impl Authenticate for NoAuth {
    fn authenticate(&self, req: &Request<Body>) -> Result<Identity, String> {
        Ok(Identity::Anonymous)
    }
}

pub enum Trace {
    TraceRequest(String, Request<Body>),
    TraceResponse(String, Request<Body>),
}

#[derive(Clone)]
struct Proxy {
    //TODO(matt) - trace filter
    tracer: Option<mpsc::Sender<Trace>>,
    ca: Arc<ca::CertAuthority>,
}

impl Proxy {
    fn handle<C: Connect + 'static, U: Authenticate, S: SiteAuthorize, A: Authorize>(
        &self,
        auth: &AuthConfig<U, S, A>,
        client: &Client<C>,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        let hostname = req
            .uri()
            .authority_part()
            .map(|x| normalize_authority(&x))
            .unwrap();

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

        let uid = auth.authenticate.authenticate(&req);

        let x = uid
            .and_then(|u| auth.site.authorize(&u, &hostname).map(|r| (u, r)))
            .and_then(|(u, site_result)| {
                auth.authorize
                    .authorize(&u, &req)
                    .map(|ar| (u, site_result, ar))
            });

        let _user = match x {
            Ok((u, AuthzResult::Allow, AuthzResult::Allow)) => u,
            Err(_) => return result(401),
            _ => return result(403),
        };

        self.handle_inner(upstream_addr, client, req)
    }

    fn handle_inner<C: Connect + 'static>(
        &self,
        upstream_addr: std::net::SocketAddr,
        client: &Client<C>,
        req: Request<Body>,
    ) -> Box<Future<Item = Response<Body>, Error = io::Error> + Send> {
        crappy_log(&req);
        let mitm_enabled = true;

        match req.method() {
            &Method::CONNECT => match is_mitm(&req, mitm_enabled) {
                true => self.handle_mitm(client.clone(), upstream_addr, req),
                false => handle_tls_raw(client, upstream_addr, req),
            },
            _ => handle_http(client, req),
        }
    }


        
    fn handle_mitm<C: Connect + 'static>(
        &self, 
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

                    println!(
                        "Upstream cert: {}",
                        std::str::from_utf8(&peer_cert.to_pem().unwrap()).unwrap()
                    );
                    (ssl_conn, peer_cert)
                })
                .map_err(|e| println!("tls error: {:}", e))
        });

    let upgraded = req.into_body().on_upgrade();

    let ca = self.ca.clone();
    let upg2 = upgraded
        .map_err(|err| eprintln!("upgrade: {}", err))
        .join(cpair)
        .and_then(move |(downstream, upstream)| {
            let ca = ca;
            let (upstream_conn, peer_cert) = upstream;

            let peer_cert_signed = ca.sign_cert_from_cert(&peer_cert).unwrap();
            println!(
                "downstream cert: {}",
                std::str::from_utf8(&peer_cert_signed.to_pem().unwrap()).unwrap()
            );
            let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
            acceptor.set_private_key(ca.child_key.as_ref()).unwrap();
            acceptor.set_certificate(peer_cert_signed.as_ref()).unwrap();
            acceptor.check_private_key().unwrap();
            let acceptor = acceptor.build();

            acceptor
                .accept_async(downstream)
                .map_err(|e| eprintln!("accept: {}", e))
                .and_then(|tls_downstream| {
                    println!("In MITM up/down");

                    let (u2dr, u2dw) = upstream_conn.split();
                    let (d2ur, d2uw) = tls_downstream.split();

                    let u2df = copy(u2dr, d2uw);
                    let d2uf = copy(d2ur, u2dw);
                    d2uf.join(u2df)
                        .map_err(|err| eprintln!("mitm forward: {}", err))
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

fn trace_handler(mut rx: mpsc::Receiver<Trace>) {
    let _t = std::thread::spawn(move || {
        let done = rx.for_each(|tx| {
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
    };

    let new_svc = move || {
        let proxy = proxy.clone();
        let auth_config = AuthConfig {
            authenticate: NoAuth,
            site: AdWareBlock,
            authorize: AllowAll,
        };

        let client = client.clone();
        service_fn(move |req: Request<Body>| proxy.handle(&auth_config, &client, req))
    };

    let server = Server::bind(&addr)
        .serve(new_svc)
        .map_err(|e| eprintln!("server error: {}", e));

    hyper::rt::run(server);
}
