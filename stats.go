package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// this entire thing is only really needed if we don't want to
// use some push framework like StatsD (or i guess there could
// do both...)

type timing struct {
	interval     time.Duration
	times        map[int64]time.Duration
	currentIndex int64
	mu           *sync.RWMutex
}

func sumDurations(durs []time.Duration) time.Duration {
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
	times := []time.Duration{}
	for _, d := range t.times {
		times = append(times, d)
	}
	sum := sumDurations(times)
	return (sum.Seconds() / 1000) / float64(len(t.times))
}

type durations []time.Duration

func (d durations) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }
func (d durations) Less(i, j int) bool { return i < j }
func (d durations) Len() int           { return len(d) }

func (t *timing) percentile(p float64) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	times := durations{}
	for _, d := range t.times {
		times = append(times, d)
	}
	sort.Sort(times)
	index := (p / 100.0) * float64(len(times))
	percentile := float64(0)
	i := int(index)
	if index == float64(int64(index)) {
		percentile = float64(sumDurations(times[i-1:i+1]).Seconds()/1000) / 2.0
	} else {
		percentile = times[i-1].Seconds() / 1000.0
	}
	return percentile
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
	timings  map[string]*timing
	tMu      *sync.RWMutex
	counters map[string]*counter
	cMu      *sync.RWMutex
	interval time.Duration
}

func newStats(interval time.Duration) *stats {
	return &stats{
		timings:  make(map[string]*timing),
		tMu:      new(sync.RWMutex),
		counters: make(map[string]*counter),
		cMu:      new(sync.RWMutex),
		interval: interval,
	}
}

func (s *stats) addTiming(key string, d time.Duration) {
	s.tMu.RLock()
	t, present := s.timings[key]
	if !present {
		t = &timing{times: make(map[int64]time.Duration), mu: new(sync.RWMutex), interval: s.interval}
		s.tMu.RUnlock()
		s.tMu.Lock()
		s.timings[key] = t
		s.tMu.Unlock()
		s.tMu.RLock()
	}
	defer s.tMu.RUnlock()
	t.add(d)
}

func (s *stats) newCounter(key string) *counter {
	s.cMu.Lock()
	defer s.cMu.Unlock()
	c := &counter{interval: s.interval}
	s.counters[key] = c
	return c
}

func (s *stats) increase(key string, value int64) {
	s.cMu.RLock()
	c, present := s.counters[key]
	if !present {
		s.cMu.RUnlock()
		c = s.newCounter(key)
		s.cMu.RLock()
	}
	defer s.cMu.RUnlock()
	c.increase(value)
}

func (s *stats) decrease(key string, value int64) {
	s.cMu.RLock()
	c, present := s.counters[key]
	if !present {
		s.cMu.RUnlock()
		c = s.newCounter(key)
		s.cMu.RLock()
	}
	defer s.cMu.RUnlock()
	c.decrease(value)
}
