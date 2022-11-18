use std::collections::VecDeque;
use std::fs;
use std::time::SystemTime;
use std::collections::HashMap;
use std::os::linux::fs::MetadataExt;

use std::error::Error;

/// SantaCacheSignature
#[derive(Clone, Eq, PartialEq)]
pub struct CacheSignature {
    // pub filepath: String,
    pub inode: u64,
    pub last_mod: u64,
    pub created: u64,
}
impl ToString for CacheSignature {
    fn to_string(&self) -> String {
        let uniq_sig = format!("{}||{}||{}",self.last_mod, self.inode, self.created);
        String::from(&uniq_sig)
    }
}

// CacheSignature implementation
impl CacheSignature {
    pub fn new(filepath: &str) -> Result<CacheSignature, Box<dyn Error>> {
        // get file metadata for signature
        let meta = fs::metadata(filepath).expect("should be able to read file");
        // mod time
        let last_mod = meta.modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        // created
        let created = meta.created()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        // inode
        let inode = meta.st_ino();

        Ok(CacheSignature {
            inode,
            last_mod,
            created,
        })
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
            capacity,
        }
    }

    /// Get the current number of items in the cache
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
        // println!("Inserting into cache: {sig}");
        // push the signature onto the keyvec.
        self.keyvec.push_back(sig.clone());

        // insert the entry onto the hashmap
        self.buffer.entry(sig.clone()).or_insert_with(|| hash.clone());

        // we have to know whether we need to remove entries
        if self.keyvec.len() == self.capacity {
            // pop the oldest signature from the front of the queue
            let remove_key = self.keyvec.pop_front().unwrap_or(String::new());

            // now we use the key we popped from the keyvec to remove the hashmap entry
            self.buffer.remove(&remove_key);
        }
    }
}
