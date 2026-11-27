package run

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/server"
	"github.com/apimgr/ipgaze/src/server/handler"
)

func TestRunServesHealthRouteAndShutsDownOnContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	ready := make(chan struct{})
	appConfig := config.DefaultConfig()
	appServer := server.NewHTTPServer(nil, server.NewCache(0))
	appServer.SetConfig(appConfig)
	appServer.HealthHandler = handler.NewHealthHandler("test", "commit", "build", "production", time.Now())
	runtimeConfig := &Config{
		App:      appConfig,
		Listener: listener,
		Ready:    ready,
		runtime: &serverRuntime{
			httpServer: &http.Server{Handler: appServer.Handler()},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- run(ctx, runtimeConfig)
	}()

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("server did not report readiness")
	}

	response, err := http.Get("http://" + listener.Addr().String() + "/api/healthz")
	if err != nil {
		cancel()
		t.Fatalf("request health route: %v", err)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		cancel()
		t.Fatalf("read health response: %v", readErr)
	}
	if closeErr != nil {
		cancel()
		t.Fatalf("close health response: %v", closeErr)
	}
	if response.StatusCode == http.StatusNotFound || len(body) == 0 {
		cancel()
		t.Fatalf("health request returned status %d and body %q", response.StatusCode, body)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("run after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context cancellation")
	}
}
