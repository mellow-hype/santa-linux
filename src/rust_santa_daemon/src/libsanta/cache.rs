use std::collections::VecDeque;
use std::{fs};
use std::time::SystemTime;
use std::collections::HashMap;
use std::os::linux::fs::MetadataExt;

/// Tests
#[test]
fn cache_insert_to_capacity() {
    let capacity = 1000;
    let hashy = "hashahshahhsa";
    let mut sig = CacheSignature::new("/etc/profile");
    let mut cache = SantaCache::new(capacity);
    for _ in 1..capacity {
        cache.insert(sig.to_string(), hashy.to_string());
        // mutate the signature so we have unique sigs on each iteration
        sig.filepath = String::from(format!("{}xxx", sig.to_string()));
    }
    assert_eq!(cache.buffer.len(), capacity-1);
}


#[test]
fn cache_capacity_is_maintained() {
    let capacity = 1000;
    let hashy = "hashahhs";
    let mut sig = String::from("/ile");
    let mut cache = SantaCache::new(capacity);
    for _ in 1..(capacity*2) {
        cache.insert(sig.to_string(), hashy.to_string());
        // mutate the signature so we have unique sigs on each iteration
        sig = String::from(format!("{}x", sig));
    }
    // the hashmap should not have expanded past capacity-1 entries
    assert_eq!(cache.buffer.len(), capacity-1);
    // the keyvec should not have expanded past capacity-1 entries
    assert_eq!(cache.keyvec.len(), capacity-1);
}

/// SantaCacheSignature
#[derive(Clone, Eq, PartialEq)]
pub struct CacheSignature {
    pub filepath: String,
    pub inode: u64,
    pub last_mod: u64,
}
impl CacheSignature {
    pub fn to_string(&self) -> String {
        let uniq_sig = format!("{}||{}||{}",self.last_mod, self.inode, self.filepath);
        String::from(&uniq_sig)
    }
}

// CacheSignature implementation
impl CacheSignature {
    pub fn new(filepath: &str) -> CacheSignature {
        // get file metadata for signature
        let meta = fs::metadata(filepath).expect("should be able to read file");
        // mod time
        let last_mod = meta.modified()
            .expect("should be on a unix system")
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("should be able to get duration")
            .as_secs();
        // inode
        let inode = meta.st_ino();

        CacheSignature {
            filepath: String::from(filepath),
            inode,
            last_mod,
        }
    }
}


#[derive(Clone, Eq, PartialEq)]
/// SantaCache struct
pub struct SantaCache {
    // this is the actual cache that will be searched against
    buffer: HashMap<String, String>,
    // each time we insert a new item into the hashmap, push its key to the back of this vec.
    keyvec: VecDeque<String>,
    // max size of the cache
    capacity: usize,
}


/// SantaCache: a cache to hold the hashes of the most recently hashed files to avoid having to do
/// the (expensive) hashing operation on each exectution. A unique signature is created using file metadata
/// (inode, last modified time, etc) to use as a key into the cache. The cache has a max capacity, at which
/// point the oldest item in the cache is removed during each subsequent insert.
impl SantaCache {
    /// Create a new SantaCache instance with a given max capacity
    pub fn new(capacity: usize) -> SantaCache {
        SantaCache {
            buffer: HashMap::new(),
            keyvec: VecDeque::with_capacity(capacity),
            capacity: capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Search the cache for the given key
    pub fn find(&self, sig: String) -> Option<&String> {
        self.buffer.get(&sig)
    }

    /// Insert an item into the cache, taking care of managing the queue and removing entries as
    /// needed.
    pub fn insert(&mut self, sig: String, hash: String) {
         // push the signature onto the keyvec.
         self.keyvec.push_back(sig.clone());

         // insert the entry onto the hashmap
         *self.buffer.entry(sig.clone()).or_insert(hash.clone()) += &hash;

         // we have to know whether we need to remove entries
         if self.keyvec.len() == self.capacity {
              // pop the oldest signature from the front of the queue
              let remove_key = self.keyvec.pop_front().unwrap_or(String::new());

              // now we use the key we popped from the keyvec to remove the hashmap entry
              self.buffer.remove(&remove_key);
        }
    }
}
