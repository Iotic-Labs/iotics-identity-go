package register

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

/**
 * cache is a simple lru expiry cache. Items get expired if they're not used (get). They're also subject
 * to a maximum lifespan.
 * This is done with a map and doubly linked list to keep things fast.
 *
 * You can configure the cache with a maximum size, and maximum age.
 *
 * If you're interested in stats, just get String() and it'll show lookups,hits,expired.
 */

// cacheEntry
type cacheEntry struct {
	id        string
	data      interface{} // TC TODO: Use type here
	ctime     time.Time
	atime     time.Time
	nextChain *cacheEntry
	prevChain *cacheEntry
}

// cache
type cache struct {
	MaxCacheSize int
	MaxItemAge   time.Duration

	LookupCache     map[string]*cacheEntry
	LookupCacheHead *cacheEntry
	LookupCacheTail *cacheEntry
	LookupMutex     sync.Mutex

	MetricTotalLookups int32
	MetricTotalHits    int32
	MetricTotalExpired int32
}

// newCache
func newCache(maxSize int, maxAge time.Duration) *cache {
	return &cache{
		MaxCacheSize: maxSize,
		MaxItemAge:   maxAge,
		LookupCache:  make(map[string]*cacheEntry),
	}
}

// String Show some interesting info about the cache
func (ir *cache) String() string {
	mLookups := atomic.LoadInt32(&ir.MetricTotalLookups)
	mHits := atomic.LoadInt32(&ir.MetricTotalHits)
	mExpired := atomic.LoadInt32(&ir.MetricTotalExpired)

	return fmt.Sprintf("cache size %d/%d lookups %d hits %d expired %d", len(ir.LookupCache), ir.MaxCacheSize, mLookups, mHits, mExpired)
}

// String show some interesting info about the cache entry
func (ice *cacheEntry) String() string {
	next := "nil"
	prev := "nil"
	if ice.nextChain != nil {
		next = ice.nextChain.id
	}
	if ice.prevChain != nil {
		prev = ice.prevChain.id
	}
	return fmt.Sprintf("cacheEntry %s %s %s %s %s\n", ice.id, ice.ctime, ice.atime, next, prev)
}

// Add adds a cache entry
func (ir *cache) Add(id string, data interface{}) {
	if ir.MaxCacheSize == 0 {
		return
	}
	ir.LookupMutex.Lock()
	defer ir.LookupMutex.Unlock()

	// Do not put something in twice!
	_, ok := ir.LookupCache[id]
	if ok {
		return
	}

	ce := &cacheEntry{
		id:    id,
		data:  data,
		ctime: time.Now(),
		atime: time.Now(),
	}

	if ir.LookupCacheHead == nil {
		ir.LookupCacheHead = ce
		ir.LookupCacheTail = ce
	} else {
		// Add it to the end...
		oldTail := ir.LookupCacheTail
		oldTail.nextChain = ce
		ce.prevChain = oldTail
		ir.LookupCacheTail = ce
	}

	ir.LookupCache[id] = ce

	// Now trim if we need to...

	if len(ir.LookupCache) > ir.MaxCacheSize {
		oldHead := ir.LookupCacheHead
		delete(ir.LookupCache, oldHead.id)
		ir.LookupCacheHead = oldHead.nextChain
	}
}

// Lookup looks up a cache entry
func (ir *cache) Lookup(id string) (interface{}, bool) {
	if ir.MaxCacheSize == 0 {
		return nil, false
	}
	ir.LookupMutex.Lock()
	defer ir.LookupMutex.Unlock()

	atomic.AddInt32(&ir.MetricTotalLookups, 1)

	ce, ok := ir.LookupCache[id]
	if ok {

		// Check it's not too old. We're lazy here, so it'll get replaced someday, because
		// we don't update the atime on it.
		if time.Since(ce.ctime) > ir.MaxItemAge {
			atomic.AddInt32(&ir.MetricTotalExpired, 1)
			return nil, false
		}

		// If it's not already at the end...
		if ce.nextChain != nil {
			ce.nextChain.prevChain = ce.prevChain // if it's at the start, ce.prevChain = nil
			if ce.prevChain == nil {
				// Special case it's at the front...
				ir.LookupCacheHead = ce.nextChain
			} else {
				ce.prevChain.nextChain = ce.nextChain
			}

			// Add it on to the end
			ce.nextChain = nil
			ce.prevChain = ir.LookupCacheTail
			ir.LookupCacheTail.nextChain = ce
			ir.LookupCacheTail = ce
		}

		ce.atime = time.Now()
		atomic.AddInt32(&ir.MetricTotalHits, 1)
		return ce.data, true
	}
	return nil, false
}
