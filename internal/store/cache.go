package store

import (
	"sync"
	"time"
)

// Cache is a small, concurrency-safe in-memory read-through cache with optional TTL.
type Cache struct {
	mu         sync.RWMutex
	entries    map[string]cacheEntry
	defaultTTL time.Duration
}

type cacheEntry struct {
	value     any
	expiresAt time.Time
}

// NewCache creates a cache. defaultTTL is used when Set is called with ttl <= 0.
func NewCache(defaultTTL time.Duration) *Cache {
	return &Cache{
		entries:    make(map[string]cacheEntry),
		defaultTTL: defaultTTL,
	}
}

// Get retrieves a non-expired value.
func (c *Cache) Get(key string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.value, true
}

// Set stores a value with an optional TTL. ttl <= 0 falls back to the cache default.
func (c *Cache) Set(key string, value any, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

// Delete removes a single key.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// DeletePrefix removes all keys with the given prefix.
func (c *Cache) DeletePrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.entries, k)
		}
	}
}

// Clear removes all entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// getTyped is a small generic helper for type-safe cache reads.
func getTyped[T any](c *Cache, key string) (T, bool) {
	var zero T
	v, ok := c.Get(key)
	if !ok {
		return zero, false
	}
	t, ok := v.(T)
	if !ok {
		return zero, false
	}
	return t, true
}
