package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestAllow_UnderLimit(t *testing.T) {
	l := NewLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestAllow_ExceedsLimit(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		l.Allow("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("4th request should be blocked")
	}
}

func TestAllow_WindowReset(t *testing.T) {
	l := NewLimiter(2, 50*time.Millisecond)
	l.Allow("1.2.3.4")
	l.Allow("1.2.3.4")

	if l.Allow("1.2.3.4") {
		t.Fatal("3rd request should be blocked before window expires")
	}

	time.Sleep(60 * time.Millisecond)

	if !l.Allow("1.2.3.4") {
		t.Fatal("request should be allowed after window reset")
	}
}

func TestAllow_IndependentIPs(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	if !l.Allow("1.1.1.1") {
		t.Fatal("first IP should be allowed")
	}
	if l.Allow("1.1.1.1") {
		t.Fatal("first IP should be blocked")
	}
	if !l.Allow("2.2.2.2") {
		t.Fatal("second IP should be allowed independently")
	}
}

func TestAllow_ConcurrentAccess(t *testing.T) {
	l := NewLimiter(100, time.Minute)
	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- l.Allow("10.0.0.1")
		}()
	}

	wg.Wait()
	close(allowed)

	count := 0
	for a := range allowed {
		if a {
			count++
		}
	}

	if count != 100 {
		t.Errorf("allowed = %d, want 100", count)
	}
}

func TestMiddleware_AllowedRequest(t *testing.T) {
	l := NewLimiter(10, time.Minute)
	called := false

	handler := l.Middleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMiddleware_RateLimited(t *testing.T) {
	l := NewLimiter(1, time.Minute)

	handler := l.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	// First request — allowed
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first request: status = %d, want 200", rec.Code)
	}

	// Second request — blocked
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request: status = %d, want 429", rec.Code)
	}
}

func TestMiddleware_IPWithoutPort(t *testing.T) {
	l := NewLimiter(1, time.Minute)
	called := false

	handler := l.Middleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1" // no port
	rec := httptest.NewRecorder()

	handler(rec, req)
	if !called {
		t.Fatal("handler should be called even without port in RemoteAddr")
	}
}
