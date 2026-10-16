package outbound

import (
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type rejectTracker struct {
	mu          sync.Mutex
	prevCount   int
	currCount   int
	windowStart time.Time
	dropUntil   time.Time
}

func (t *rejectTracker) shouldDrop(now time.Time, maxTriggers int, interval, dropDuration time.Duration, onTrigger func()) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 1. In penalty period: keep dropping, but do NOT extend dropUntil to avoid livelock
	if now.Before(t.dropUntil) {
		return true
	}

	// 2. Initialize or smooth window roll
	if t.windowStart.IsZero() {
		t.windowStart = now
		t.currCount = 1
		t.prevCount = 0
		return false
	}

	elapsed := now.Sub(t.windowStart)
	if elapsed >= interval {
		if elapsed < 2*interval {
			t.prevCount = t.currCount
			t.currCount = 0
			t.windowStart = t.windowStart.Add(interval)
		} else {
			// Idle for 2+ intervals: stale counts reset to zero
			t.prevCount = 0
			t.currCount = 0
			t.windowStart = now
		}
	}

	weight := float64(interval-now.Sub(t.windowStart)) / float64(interval)
	if weight < 0 {
		weight = 0
	}
	estimatedCount := int(float64(t.prevCount)*weight) + t.currCount + 1
	t.currCount++

	if estimatedCount >= maxTriggers {
		t.dropUntil = now.Add(dropDuration)
		t.currCount = 0
		t.prevCount = 0
		t.windowStart = t.dropUntil
		if onTrigger != nil {
			onTrigger()
		}
		return true
	}

	return false
}

type RejectRateLimiter struct {
	mu           sync.RWMutex
	cache        *lru.LruCache[string, *rejectTracker]
	maxTriggers  int
	interval     time.Duration
	dropDuration time.Duration
}

func NewRejectRateLimiter(maxTriggers int, interval, dropDuration time.Duration) *RejectRateLimiter {
	return &RejectRateLimiter{
		cache: lru.New[string, *rejectTracker](
			lru.WithSize[string, *rejectTracker](10000),
			lru.WithAge[string, *rejectTracker](300),
			lru.WithUpdateAgeOnGet[string, *rejectTracker](),
		),
		maxTriggers:  maxTriggers,
		interval:     interval,
		dropDuration: dropDuration,
	}
}

func (l *RejectRateLimiter) UpdateConfig(maxTriggers int, interval, dropDuration time.Duration) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxTriggers = maxTriggers
	l.interval = interval
	l.dropDuration = dropDuration
}

func (l *RejectRateLimiter) ShouldDrop(metadata *C.Metadata) bool {
	if l == nil || metadata == nil {
		return false
	}

	l.mu.RLock()
	maxTriggers := l.maxTriggers
	interval := l.interval
	dropDuration := l.dropDuration
	l.mu.RUnlock()

	if maxTriggers <= 0 {
		return false
	}

	key := getRejectKey(metadata)
	if key == "" {
		return false
	}

	tracker, _ := l.cache.GetOrStore(key, func() *rejectTracker {
		return &rejectTracker{}
	})

	return tracker.shouldDrop(time.Now(), maxTriggers, interval, dropDuration, func() {
		log.Infoln("[Reject] %s triggered rate limit (%d/%s), downgrade to DROP for %s", key, maxTriggers, interval, dropDuration)
	})
}

func getRejectKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}
	src := metadata.SrcIP.String()
	if src == "" {
		src = "unknown"
	}

	target := metadata.Host
	if target == "" && metadata.DstIP.IsValid() {
		target = metadata.DstIP.String()
	}
	if target == "" {
		target = metadata.RemoteAddress()
	}

	return fmt.Sprintf("%s->%s:%d[%s]", src, target, metadata.DstPort, metadata.NetWork.String())
}
