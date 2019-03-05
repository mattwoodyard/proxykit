



use warp::Filter;


use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use crate::proto::Trigger;




struct TriggerManager (Arc<RwLock<TriggerManagerInner>>);

struct TriggerManagerInner {
    next_id: usize,
    current_triggers: HashMap<usize,  Trigger>
}


impl TriggerManager {
    
    fn new() -> TriggerManager {
    TriggerManager(Arc::new(RwLock::new(
        TriggerManagerInner {
            next_id: 0,
            current_triggers: HashMap::new()
        })))
    }

    fn add_trigger(&self, t: Trigger) -> Result<usize, String> {
       let mut w = self.0.write().unwrap();
       w.next_id = w.next_id + 1;
       let id = w.next_id;
       w.current_triggers.insert(id, t);
       Ok(w.next_id)
    }

    fn remove_trigger(&self, k: usize) -> Result<(), String> {
       let mut w = self.0.write().unwrap();
       w.current_triggers.remove(&k);
       Ok(())
    }

//    fn get_triggers(&self) -> Result<HashMap<usize, Trigger>, String> {
//        Ok(self.0.read().unwrap().current_triggers)
//    }
}


#[test]
fn basic_ops() {
    let mut tr = TriggerManager::new();
    


}
