

use tokio_io::{AsyncRead, AsyncWrite};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::io;
use futures::Poll;
use bytes::BufMut;

pub trait Reusable {
    fn reset(&mut self);
}

/* trait Pool { */
/*     type Pooled; */
/* } */
#[derive(Clone)]
pub struct Pool<A: Sized> {
    max_count: usize,
    objects: Arc<Mutex<VecDeque<A>>>,
}

impl<A: Sized> Pool<A> {
    pub fn empty(size: usize) -> Arc<Pool<A>> {
        let q = VecDeque::with_capacity(size);
        Arc::new(Pool {
            max_count: size,
            objects: Arc::new(Mutex::new(q)),
        })
    }
 
    // pub fn with_capacity(size: usize) -> Arc<Pool<A>> {
    //     let mut q = VecDeque::with_capacity(size);

    //     for _ in 0..size {
    //         q.push_front(Arc::new(A::default()))
    //     }

    //     Arc::new(Pool {
    //         max_count: size,
    //         objects: Mutex::new(q),
    //     })
    // }

    pub fn checkout(_self: Arc<Pool<A>>) -> Result<PoolItem<A>, String> {
        if let Some(m) = { _self.objects.lock().unwrap().pop_front() } {
            Ok(PoolItem::attach(m, _self.clone()))
        } else {
            Err("No objects available".to_owned())
        }
    }

    //TODO - use a Vec and 'in/out' bitset
    pub fn checkin(&self, mut msg: A) {
        let mut v = self
            .objects
            .lock()
            .expect("Error obtaining mutex for checkin");

        // if Arc::strong_count(&msg) == 1 {
        //     Arc::get_mut(&mut msg).unwrap().reset();
        // }

        if v.len() < self.max_count {
            v.push_front(msg);
        }
    }
}

#[derive(Clone)]
pub struct PoolItem<A: Sized> {
    item: Option<A>,
    pool: Option<Arc<Pool<A>>>,
}

impl<A: Sized> PoolItem<A> {
    pub fn new(item: A) -> PoolItem<A> {
        PoolItem {
            item: Some(item),
            pool: None,
        }
    }

    pub fn attach(item: A, pool: Arc<Pool<A>>) -> PoolItem<A> {
        PoolItem {
            item: Some(item),
            pool: Some(pool),
        }
    }
}

impl<A: Sized> Drop for PoolItem<A> {
    fn drop(&mut self) {
        if let Some(p) = self.pool.take() {
            if let Some(i) = self.item.take() {
                p.checkin(i);
            }
        }
    }
}



impl<A: Sized + AsyncRead> AsyncRead for PoolItem<A> {

    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        self.deref().prepare_uninitialized_buffer(buf)
    }
    
    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error>   {
        self.deref_mut().read_buf(buf)
    }
    fn poll_read(&mut self, buf: &mut [u8]) -> Poll<usize, io::Error> {
        self.deref_mut().poll_read(buf)
    }
}

impl<A: Sized + io::Read> io::Read for PoolItem<A> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.deref_mut().read(buf)
    }
}


impl<A: Sized + AsyncWrite> AsyncWrite for PoolItem<A> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.deref_mut().shutdown()
    }
}


impl<A: Sized + io::Write> io::Write for PoolItem<A> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.deref_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.deref_mut().flush()
    }
}

impl<A: Sized> Deref for PoolItem<A> {
    type Target = A;

    fn deref(&self) -> &A {
        self.item.as_ref().expect("No item in the poolitem")
    }
}


impl<A: Sized> DerefMut for PoolItem<A> {

    fn deref_mut(&mut self) -> &mut A {
        self.item.as_mut().unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static next_id: AtomicUsize = AtomicUsize::new(0);

    struct Entity {
        id: usize,
    }

    impl Reusable for Entity {
        fn reset(&mut self) {}
    }

    impl Default for Entity {
        fn default() -> Entity {
            Entity {
                id: next_id.fetch_add(1, Ordering::SeqCst),
            }
        }
    }

    #[test]
    fn test_pool_basic() {
        let mut pool: Arc<Pool<Entity>> = Pool::with_capacity(4);

        {
            let e1 = Pool::checkout(&mut pool).unwrap();
            let e2 = Pool::checkout(&mut pool).unwrap();
            let e3 = Pool::checkout(&mut pool).unwrap();
            let e4 = Pool::checkout(&mut pool).unwrap();
            assert!(Pool::checkout(&mut pool).is_err())
        }
        let e1 = Pool::checkout(&mut pool).unwrap();
    }

}
