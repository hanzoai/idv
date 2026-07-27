package main

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestListenServesHTTP drives the real listener the binary starts, not
// fiber's in-memory test harness — the only way to prove the "http://"
// transport zip.Listen selects actually answers on the wire.
func TestListenServesHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}

	app := newApp(&fakeProvider{})
	errc := make(chan error, 1)
	go func() { errc <- app.Listen("http://" + addr) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	base := "http://" + addr
	waitReady(t, base+"/healthz", errc)

	t.Run("healthz", func(t *testing.T) {
		assertGet(t, base+"/healthz", 200, "{\"status\":\"ok\"}\n")
	})
	t.Run("status", func(t *testing.T) {
		assertGet(t, base+"/v1/idv/status", 200,
			"{\"enabled\":true,\"label\":\"fake\",\"provider\":\"fake\"}\n")
	})
	t.Run("session-by-id", func(t *testing.T) {
		assertGet(t, base+"/v1/idv/sessions/ver_9", 200,
			"{\"verification_id\":\"ver_9\",\"provider\":\"fake\",\"status\":\"approved\"}\n")
	})
	t.Run("method-not-allowed", func(t *testing.T) {
		assertGet(t, base+"/v1/idv/sessions", 405, "method not allowed\n")
	})
	t.Run("not-found", func(t *testing.T) {
		assertGet(t, base+"/nope", 404, "404 page not found\n")
	})
	t.Run("initiate-session", func(t *testing.T) {
		res, err := http.Post(base+"/v1/idv/sessions", "application/json",
			strings.NewReader(`{"application_id":"app1","email":"a@b.c"}`))
		if err != nil {
			t.Fatalf("POST sessions: %v", err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		const want = "{\"verification_id\":\"ver_1\",\"provider\":\"fake\",\"status\":\"pending\"," +
			"\"redirect_url\":\"https://x/app1\",\"created_at\":\"2026-01-02T03:04:05Z\"}\n"
		if res.StatusCode != 200 || string(body) != want {
			t.Errorf("got %d %q, want 200 %q", res.StatusCode, body, want)
		}
	})
}

func waitReady(t *testing.T, url string, errc <-chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errc:
			t.Fatalf("Listen returned early: %v", err)
		default:
		}
		if res, err := http.Get(url); err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server never became ready")
}

func assertGet(t *testing.T, url string, wantStatus int, wantBody string) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if res.StatusCode != wantStatus {
		t.Errorf("GET %s status = %d, want %d", url, res.StatusCode, wantStatus)
	}
	if string(body) != wantBody {
		t.Errorf("GET %s body = %q, want %q", url, body, wantBody)
	}
}
