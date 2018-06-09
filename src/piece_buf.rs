use bytes::{Bytes};
use std::rc::Rc;



/**
 * Slice's are offsets into a Bytes which have a 
 * "reference" to their underlying Bytes
 * they are not Send (although, really there isn't a 
 * a reason they can't be Arc instead
 * This is in a file called 'piece_buf' because I have
 * plans to introduce operations on collections of 
 * slices, PieceBuffers, that will allow simple immutable
 * piece table like work to be done on Slices. 
 */
pub struct Slice {
    pub bytes: Rc<Bytes>,
    pub start: usize,
    pub end: usize
}

impl Slice {
    pub fn from_ref(base: Rc<Bytes>, b: &[u8]) -> Slice {
        let start = b.as_ptr() as usize - base.as_ptr() as usize;
        assert!(start < base.len());
        Slice { bytes: base, start: start, end: start + b.len() }
    }

    pub fn from_parse_pair(base: Rc<Bytes>, st: usize, ln: usize) -> Slice {
        Slice { bytes: base, start: st, end: st + ln }
    }
}

#[cfg(test)]
mod tests {
//    use super::*;



}

