/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
)

// IPCache keeps track of when an IP that is no longer seen should be removed from an IPMap
type IPCacheT struct {
	lock    sync.RWMutex
	storage map[types.NamespacedName]map[string]time.Time
}

func (cache *IPCacheT) Set(name types.NamespacedName, ip string, expires time.Time) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	if cache.storage == nil {
		cache.storage = make(map[types.NamespacedName]map[string]time.Time, 1)
	}
	if cache.storage[name] == nil {
		cache.storage[name] = make(map[string]time.Time, 10)
	}
	cache.storage[name][ip] = expires
}

// Return the expiration time for an IPMap and IP if it exists, the zero time if not
func (cache *IPCacheT) Get(name types.NamespacedName, ip string) time.Time {
	cache.lock.RLock()
	defer cache.lock.RUnlock()
	if cache.storage[name] == nil {
		return time.Time{}
	}
	return cache.storage[name][ip]
}

func (cache *IPCacheT) Delete(name types.NamespacedName, ip string) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	if ip == "" {
		delete(cache.storage, name)
	} else {
		delete(cache.storage[name], ip)
		if len(cache.storage[name]) == 0 {
			delete(cache.storage, name)
		}
	}
}

func (cache *IPCacheT) NameExists(name types.NamespacedName) bool {
	cache.lock.RLock()
	defer cache.lock.RUnlock()
	if cache.storage[name] == nil {
		return false
	}
	return true
}

// Remove expired IPs from cache
func (cache *IPCacheT) CleanUp(name types.NamespacedName) {
	cache.lock.Lock()
	defer cache.lock.Unlock()
	for key, val := range IPCache.storage[name] {
		if val.Before(time.Now()) {
			delete(IPCache.storage[name], key)
		}
	}
}
