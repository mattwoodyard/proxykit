use bincode;
use futures::Future;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

//
use std::fs::File;
use tempdir::TempDir;

trait ProxyTraceSubscriber {
    type SendFuture: Future<Item = ()>;
    fn filter(&self, event: &ProxyTraceRecord) -> bool;
    fn send(&mut self, event: Arc<ProxyTraceRecord>) -> Self::SendFuture;
}

struct ProxyTraceHandler<W: io::Write + io::Seek> {
    writer: ProxyTraceDatastoreWriter<W>,
    indexer: ProxyTraceDatastoreIndexer,
}

// TODO(matt) - trace file max size rollover
struct ProxyTraceDatastoreWriter<W: io::Write + io::Seek> {
    root: String,
    current_log: String,
    log_counter: usize,
    current_log_writer: W,
    current_log_pos: u64,
    recent_actions: HashMap<String, ProxyTraceRecordLocation>,
}

impl ProxyTraceDatastoreWriter<File> {
    fn new(root: &str) -> io::Result<ProxyTraceDatastoreWriter<File>> {
        let fname = format!("{}/0", root);
        println!("{}", fname);
        let mut f = File::create(&fname)?;

        Ok(ProxyTraceDatastoreWriter {
            root: String::from(root),
            log_counter: 1,
            current_log: fname,
            current_log_writer: f,
            current_log_pos: 0,
            recent_actions: HashMap::new(),
        })
    }

    fn push(&mut self, r: &ProxyTraceRecord) -> io::Result<ProxyTraceRecordLocation> {
        self.log_counter = self.log_counter + 1;
        match r.payload {
            TraceRecordPayload::Body {
                is_final: is_final, ..
            } => {
                let rec_loc = self.output_record(r);
                rec_loc.map(|rloc| {
                    // TODO(matt) figure out a way to avoid the clone

                    
                    let prev = self.recent_actions.get(&r.id).cloned();

                    
                    self.recent_actions.entry(r.id.clone()).and_modify(|e| {
                        //TODO(matt) - logging
                        (*e).location = rloc.location;
                    });
                    
                        

                    if is_final {
                        self.recent_actions.remove(&r.id);
                    }

                    rloc
                })
            }
            _ => self.output_record(r),
        }
    }

    fn output_record(&mut self, r: &ProxyTraceRecord) -> io::Result<()> {
        let mut buf = Vec::new();
        r.serialize(&mut Serializer::new(&mut buf)).unwrap();

        




        
    }

    fn add_body_location_to_previous(
        &mut self,
        loc: &ProxyTraceRecordLocation,
        next_loc: &ProxyTraceRecordLocation,
    ) -> io::Result<()> {
        
        
        Ok(())
    }
}
#[derive(Clone)]
struct ProxyTraceRecordLocation {
    filename: String,
    location: u64,
}

impl ProxyTraceRecordLocation {
    fn new(filen: &str, l: u64) -> ProxyTraceRecordLocation {
        ProxyTraceRecordLocation {
            filename: String::from(filen),
            location: l,
        }
    }
}

struct ProxyTraceDatastoreIndexer {}

struct ProxyTraceDatastoreQuery {
    root: String,
}



#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct ProxyTraceOnDiskRecordHead {
    len: usize,
    has_next: bool,
    next_location: u64,
}


#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct ProxyTraceOnDiskRecord {
    len: usize,
    has_next: bool,
    next_location: u64,
    bytes: Vec<u8>,
}

fn binerrfrom(e: Box<bincode::ErrorKind>) -> io::Error {
    match *e {
        bincode::ErrorKind::Io(e1) => e1,
        e1 @ _ => io::Error::new(io::ErrorKind::Other, format!("{:?}", e1)),
    }
}

impl ProxyTraceOnDiskRecord {
    // i don't normally structure it like that
    fn write<W: io::Write>(&self, b: &mut W) -> io::Result<u64> {
        let sz = bincode::serialized_size(self).map_err(binerrfrom)?;
        bincode::serialize_into(b, self)
            .map(|_| sz)
            .map_err(binerrfrom)
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct ProxyTraceRecord {
    id: String,
    timestamp: u64,
    payload: TraceRecordPayload,
}

impl ProxyTraceRecord {
    fn request_line(id: &str, ts: u64, method: &str, uri: &str, version: &str) -> ProxyTraceRecord {
        ProxyTraceRecord {
            id: String::from(id),
            timestamp: ts,
            payload: TraceRecordPayload::RequestLine(
                String::from(method),
                String::from(uri),
                String::from(version),
            ),
        }
    }

    fn body(id: &str, ts: u64, chunk: Vec<u8>, last_chunk: bool) -> ProxyTraceRecord {
        ProxyTraceRecord {
            id: String::from(id),
            timestamp: ts,
            payload: TraceRecordPayload::Body {
                chunk: chunk,
                is_final: last_chunk,
            },
        }
    }
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum TraceRecordPayload {
    /** Open a tracing stream for request_id */
    BeginTrace(String),
    /** These are very HTTP/1 focused, refactor when I really look at http/2 support */
    RequestLine(String, String, String),
    ResponseLine(String, String, String),
    // TODO(matt) - trailers, chunk headers, etc
    Headers(Vec<(String, String)>),
    /** A chunk of the body and a mark if this is the last chunk */
    Body {
        chunk: Vec<u8>,
        is_final: bool,
    },
}

struct ProxyTraceRecordRequestIndexRecord {
    request_id: String,
    start_time: u64,
    method: String,
    url: String,
    known_status_codes: Vec<u16>,
    request_line: ProxyTraceRecordLocation,
    headers: ProxyTraceRecordLocation,
    body_start: ProxyTraceRecordLocation,
}

struct ProxyTraceRecordResponseIndexRecord {
    response_id: String,
    related_request: String,
    start_time: u64,
    status_code: u16,
    status_line: ProxyTraceRecordLocation,
    headers: ProxyTraceRecordLocation,
    body_start: ProxyTraceRecordLocation,
}

#[test]
fn test_basic_wr() {
    let tmp_dir = TempDir::new("rrdbtest").expect("success");
    let mut ds =
        ProxyTraceDatastoreWriter::new(tmp_dir.path().to_str().expect("dir not ok")).expect("Ok");

    let rl = ProxyTraceRecord::request_line(
        "abc",
        1,
        "GET",
        "http://foo.bar.com/blah/blah/",
        "HTTP/1.1",
    );
    let loc1 = ds.output_record(&rl).expect("is ok");
    assert_eq!(loc1.location, 0);

    let r2 = ProxyTraceRecord::request_line(
        "abc2",
        2,
        "GET",
        "http://foo.bar.com/blah/blah/",
        "HTTP/1.1",
    );
    let loc2 = ds.output_record(&r2).expect("is ok");
    assert!(loc2.location != 0);

    let r3 = ProxyTraceRecord::request_line(
        "abc3",
        3,
        "GET",
        "http://foo.bar.com/blah/bla33h/",
        "HTTP/1.1",
    );
    let loc3 = ds.output_record(&r3).expect("is ok");
    assert!(loc3.location != 0);

    let r4 = ProxyTraceRecord::request_line(
        "abc4",
        5,
        "GET",
        "http://foo.bar.com/blah/bla35553h/",
        "HTTP/1.1",
    );
    let loc4 = ds.push(&r4).expect("is ok");
    assert!(loc3.location != 0);

    let mut ks = ds.recent_actions.keys().collect::<Vec<&String>>();
    ks.sort();
    assert_eq!(
        &ks,
        &[
            &String::from("abc"),
            &String::from("abc2"),
            &String::from("abc3"),
            &String::from("abc4")
        ]
    );
}
