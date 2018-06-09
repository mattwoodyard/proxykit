
use bytes::{BytesMut, Bytes};
use futures::{Poll, Async};
use futures::stream::Stream;
use headers::*;
use http;
use httparse;
use http::{header, HttpTryFrom, Method, Uri, Version};
use piece_buf::Slice;
use std;
use std::mem;
use std::rc::Rc;



// TODO(matt) - refactor to do this
enum Frame<H, B> {
    Header(H),
    Body(B),
    EndOfMessage
}

struct PeerIdentity {
    mechanism: String,
    value: BytesMut
}

#[derive(Debug)]
pub enum Lazy<T> {
    NotYetEvaluated,
    NoValue,
    Value(T)
}

impl<T> Lazy<T> {
    fn as_option(&self) -> Option<&T> {
        match self {
            &Lazy::NotYetEvaluated => { None }
            &Lazy::NoValue => { None }
            &Lazy::Value(ref v) => {
                Some(v)
            }
        }
    }

/*     fn get_or_eval<F>(&mut self, f: F) -> &T */ 
/*         where F: FnOnce() -> T */
/*     { */
/*         match self { */
/*             Lazy::Value(v) => { */
/*                 v */
/*             } */


/*         } */
/*     } */
}

const MAX_HEADERS:usize = 16;

pub struct HeaderMap {
    headers: Vec<(Slice, Slice)>,
}

impl HeaderMap {
    fn from_pairs(bytes: &Rc<Bytes>, pairs: (usize, usize, usize, usize)) -> (Slice, Slice) {
        (Slice::from_parse_pair(bytes.clone(), pairs.0, pairs.1),
         Slice::from_parse_pair(bytes.clone(), pairs.2, pairs.3))
    }
}


#[derive(Debug)]
pub struct H1Request {
    pub method: Method,
    pub uri: Uri 
}

pub struct H1Response { 
    status: u16  
}

pub struct Http1Message<R> {
    pub line: R,        
    pub version: Version,
    pub headers: HeaderMap,
    pub authority: Lazy<Authority>,
    pub body_length: Lazy<BodyLength>,
    //body_encoding: Lazy<BodyEncoding> // Transfer vs
    //content_type: Lazy<ContentType>
}

#[derive(Debug)]
pub enum ParseError {
    BadMethod,
    BadUri,
    BadVersion,
    Inner(httparse::Error),
    IoError(std::io::Error)
}


impl From<ParseError> for std::io::Error {

    fn from(p: ParseError) -> std::io::Error {
        match p {
            ParseError::BadMethod => std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid Method"),
            ParseError::BadUri => std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid Uri"),
            ParseError::BadVersion => std::io::Error::new(std::io::ErrorKind::InvalidData, "Bad Version"),
            ParseError::Inner(_) => std::io::Error::new(std::io::ErrorKind::InvalidInput, "Malformed http"),
            ParseError::IoError(e) => e,
        }
    }
}





impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> ParseError {
        ParseError::IoError(e)
    }
}



impl From<httparse::Error> for ParseError {
    fn from(e: httparse::Error) -> ParseError {
        ParseError::Inner(e)
    }
}

impl From<http::method::InvalidMethod> for ParseError {
    fn from(e: http::method::InvalidMethod) -> ParseError {
        ParseError::BadMethod
    }
}

impl From<http::uri::InvalidUri> for ParseError {
    fn from(e: http::uri::InvalidUri) -> ParseError {
        ParseError::BadUri
    }
}

pub fn parse_request_head(buf: &mut BytesMut) -> Poll<Http1Message<H1Request>, ParseError> {
    let ptr_st = buf.as_ptr() as usize;
    let (len, version, header_len, h1r, headers) = {
        let (len, version, header_len, h1r, headers) = {
            let mut headers: [httparse::Header; MAX_HEADERS] = 
                unsafe { mem::uninitialized() };

            let mut reqp = httparse::Request::new(&mut headers);

            let status = reqp.parse(buf)?;

            let len = match status {
                httparse::Status::Complete(len) => { len }
                _ => { return Ok(Async::NotReady); }
            };

            let version = reqp.version.map_or(Err(ParseError::BadVersion), |i| if i == 1 { Ok(Version::HTTP_11) } else { Ok(Version::HTTP_10) })?; 
            let method = reqp.method.map_or(Err(ParseError::BadMethod), |m| { Method::from_bytes(m.as_bytes()).map_err(From::from) })?; 
            let uri = reqp.path.map_or(Err(ParseError::BadUri), |p| Uri::try_from(p).map_err(From::from))?; 
            let header_len = reqp.headers.len(); 

            // TODO(matt) - we end up iterating the headers twice, if we take the unsafe 
            //              version of the buf handling then we can skip the second iteration
            //              and dump the nested scopes

            let mheaders:Vec<(usize, usize, usize, usize)> = {
                 reqp.headers.iter().take(header_len).map(|h| {
                    let nms = h.name.as_bytes().as_ptr() as usize - ptr_st;
                    let vs = h.value.as_ptr() as usize - ptr_st;
                    (nms, nms + h.name.as_bytes().len(), vs, vs + h.value.len())
                }).collect()
            };

            (len, version, header_len, H1Request { method: method, uri: uri}, mheaders)
        };
        (len, version, header_len, h1r, headers)
    }; 
    
    let buf = buf.split_to(len).freeze();
    let nbuf = Rc::new(buf);

    
    Ok(Async::Ready(Http1Message { 
        line: h1r,
        version: version,
        headers: HeaderMap { headers: headers.into_iter().map(|t| HeaderMap::from_pairs(&nbuf, t)).collect() },
        authority: Lazy::NotYetEvaluated,
        body_length: Lazy::NotYetEvaluated
    }))
}








