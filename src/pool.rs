

use std::rc::Rc;
// use std::borrow::BorrowMut;
use std::collections::VecDeque;
use std::cell::RefCell;




trait Reusable {
    fn reset(&mut self);
}


/* trait Pool { */
/*     type Pooled; */
/* } */

struct Pool<A: Sized + Reusable + Default> {
    max_count: usize,
    objects: RefCell<VecDeque<Rc<A>>>
}


impl<A: Sized + Reusable + Default> Pool<A> {

    fn with_capacity(size: usize) -> Rc<Pool<A>> {
        let mut q = VecDeque::with_capacity(size);
        
        for _ in 0..size {
            q.push_front(Rc::new(A::default()))
        }

        Rc::new(Pool {
            max_count: size,
            objects: RefCell::new(q)
        })
    }


    fn checkout(_self: &mut Rc<Pool<A>>) -> Result<PoolItem<A>, String> {

        if let Some(m) = { _self.objects.borrow_mut().pop_front() } {
            Ok(PoolItem::pooled(m, _self.clone()))
        } else {
           Err("No objects available".to_owned())
        }
    }

    //TODO - use a Vec and 'in/out' bitset
    fn checkin(&self, mut msg: Rc<A>) { 
        let mut v = self.objects.borrow_mut();

        if Rc::strong_count(&msg) == 1 {
            Rc::get_mut(&mut msg).unwrap().reset(); 
        }

        if v.len() < self.max_count {
            v.push_front(msg);
        }
    }
}

#[derive(Clone)]
struct PoolItem<A: Sized + Default + Reusable> {
    item: Option<Rc<A>>,
    pool: Option<Rc<Pool<A>>>
}


impl<A: Sized + Reusable + Default> PoolItem<A> { 
    fn new(item: Rc<A>) -> PoolItem<A> {
        PoolItem  {
            item: Some(item),
            pool: None
        }
    }

    fn pooled(item: Rc<A>, pool: Rc<Pool<A>>) -> PoolItem<A> {
        PoolItem  {
            item: Some(item),
            pool: Some(pool)
        }
    }
}

impl<A: Sized + Reusable + Default> Drop for PoolItem<A> { 
    fn drop(&mut self) {
        if let Some(p) = self.pool.take() {
            if let Some(i) = self.item.take() {
                p.checkin(i);
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static next_id:AtomicUsize = AtomicUsize::new(0);

    struct Entity {
        id: usize
    }


    impl Reusable for Entity {
        fn reset(&mut self) { }
    }

    impl Default for Entity {
        fn default() -> Entity { 
            Entity {
                id: next_id.fetch_add(1, Ordering::SeqCst)
            }
        }
    }


    #[test]
    fn test_pool_basic() {
        let mut pool: Rc<Pool<Entity>> = Pool::with_capacity(4);
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
