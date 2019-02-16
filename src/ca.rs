use std;
use std::fs::File;
use std::io::Read;

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
// use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder};
// use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage,
//                               SubjectAlternativeName, SubjectKeyIdentifier

use openssl::bn::{BigNum, MsbOption};
use openssl::x509::extension::{SubjectAlternativeName, SubjectKeyIdentifier};

fn read_file(fname: &str) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(fname).unwrap();
    let mut buffer: Vec<u8> = vec![];
    f.read_to_end(&mut buffer).map(|r| buffer)
}

pub struct CertAuthority {
    key: PKey<Private>,
    cert: X509,
    pub child_key: PKey<Private>,
    pub certs: Mutex<Arc<HashMap<String, X509>>>,
    //TODO(matt) - caching serial
    pub serial: AtomicUsize, // pub serial: Atomic<i64>
}

impl CertAuthority {
    pub fn from_files(privf: &str, certf: &str) -> Result<CertAuthority, String> {
        let pkey = match read_file(privf) {
            Ok(buffer) => PKey::private_key_from_pem(&buffer).map_err(|e| format!("{}", e))?,
            Err(e) => {
                return Err(format!("{}", e));
            }
        };

        let cert = match read_file(certf) {
            Ok(buffer) => X509::from_pem(&buffer).map_err(|e| format!("{}", e))?,
            Err(e) => {
                return Err(format!("{}", e));
            }
        };

        let rsa = Rsa::generate(2048).map_err(|e| format!("{}", e))?;
        let privkey = PKey::from_rsa(rsa).map_err(|e| format!("{}", e))?;
        Ok(CertAuthority {
            key: pkey,
            cert: cert,
            child_key: privkey,
            certs: Mutex::new(Arc::new(HashMap::new())),
            serial: AtomicUsize::new(0),
        })
    }

    pub fn sign_cert_from_cert(&self, cert: &X509) -> Result<X509, ErrorStack> {
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_issuer_name(self.cert.subject_name())?;
        builder.set_pubkey(&self.child_key)?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        builder.set_serial_number(&serial_number)?;

        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        builder.set_not_after(&not_after)?;

        match cert.subject_alt_names() {
            Some(names) => {                
                //let _:Vec<Option<()>> = names
                let sans = names
                    .iter()
                    .fold(SubjectAlternativeName::new(), |mut st, n| {
                        n.dnsname().map(|n1| {
                            // println!("SAN: {:?}", n1);
                            st.dns(n1.clone())
                        }).unwrap();
                        st
                    });
                let ext = sans.build(&builder.x509v3_context(Some(&self.cert), None)).unwrap();
                builder.append_extension(ext).unwrap();
            }
            None => {}
        }
        
        builder.set_subject_name(cert.subject_name())?;
        
        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
        builder.append_extension(subject_key_identifier)?;
        builder.sign(&self.key, MessageDigest::sha256())?;
        let cert = builder.build();

        // let _ = cert.clone();
        
        Ok(cert)
    }
}
