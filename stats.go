package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type timing struct {
	interval     time.Duration
	times        map[int64]time.Duration
	currentIndex int64
	mu           *sync.RWMutex
}

func sumDurations(durs map[int64]time.Duration) time.Duration {
	sum := time.Duration(0)
	for _, d := range durs {
		sum += d
	}
	return sum
}

func (t *timing) rate() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return int64(len(t.times))
}

func (t *timing) mean() float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return (sumDurations(t.times).Seconds() / 1000) / float64(len(t.times))
}

func (t *timing) percentile() float64 {
	return 0
}

func (t *timing) remove(index int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.times, index)
}

func (t *timing) add(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	index := t.currentIndex
	t.times[index] = d
	t.currentIndex++
	go func() {
		time.Sleep(t.interval)
		t.remove(index)
	}()
}

type counter struct {
	interval time.Duration
	counter  int64
}

func (c *counter) decrease(v int64) {
	atomic.AddInt64(&c.counter, -v)
	go func() {
		time.Sleep(c.interval)
		c.increase(v)
	}()
}

func (c *counter) increase(v int64) {
	atomic.AddInt64(&c.counter, v)
	go func() {
		time.Sleep(c.interval)
		c.decrease(v)
	}()
}

func (c *counter) value() int64 {
	return atomic.LoadInt64(&c.counter)
}

type stats struct {
	timings  map[string][]timing
	counters map[string]counter
}

func (s *stats) timing() {

}

func (s *stats) incCounter() {

}
