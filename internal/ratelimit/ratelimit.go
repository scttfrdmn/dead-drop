package ratelimit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Limiter tracks request rates per IP
type Limiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	rate     int           // requests
	window   time.Duration // time window
}

type visitor struct {
	limiter  *rate
	lastSeen time.Time
}

type rate struct {
	mu       sync.Mutex
	requests int
	window   time.Time
}

// NewLimiter creates a new rate limiter
// rate: number of requests allowed
// window: time window duration
func NewLimiter(rateLimit int, window time.Duration) *Limiter {
	l := &Limiter{
		visitors: make(map[string]*visitor),
		rate:     rateLimit,
		window:   window,
	}

	// Cleanup old visitors periodically
	go l.cleanupVisitors()

	return l
}

// Allow checks if a request from the given IP is allowed
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	v, exists := l.visitors[ip]
	if !exists {
		v = &visitor{
			limiter: &rate{
				requests: 0,
				window:   time.Now().Add(l.window),
			},
			lastSeen: time.Now(),
		}
		l.visitors[ip] = v
	}
	l.mu.Unlock()

	v.limiter.mu.Lock()
	defer v.limiter.mu.Unlock()

	now := time.Now()

	// Reset window if expired
	if now.After(v.limiter.window) {
		v.limiter.requests = 0
		v.limiter.window = now.Add(l.window)
	}

	// Check rate limit
	if v.limiter.requests >= l.rate {
		return false
	}

	v.limiter.requests++
	v.lastSeen = now
	return true
}

// cleanupVisitors removes stale visitor entries
func (l *Limiter) cleanupVisitors() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		for ip, v := range l.visitors {
			if time.Since(v.lastSeen) > 10*time.Minute {
				delete(l.visitors, ip)
			}
		}
		l.mu.Unlock()
	}
}

// Middleware returns an HTTP middleware that enforces rate limiting
func (l *Limiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract IP address
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		// Check rate limit
		if !l.Allow(ip) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}
