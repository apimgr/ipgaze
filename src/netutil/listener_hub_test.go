package netutil

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestListenerHubSwitchesAcceptedConnections(t *testing.T) {
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := NewListenerHub(bound)
	t.Cleanup(func() { _ = hub.Close() })
	first := hub.Listener()
	initialClient, err := net.Dial("tcp", bound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	firstAccepted := acceptWithin(t, first)
	_ = firstAccepted.Close()
	_ = initialClient.Close()

	second := hub.Switch()
	if _, err := first.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old generation Accept() error = %v, want net.ErrClosed", err)
	}

	client, err := net.Dial("tcp", bound.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	}()

	accepted := acceptWithin(t, second)
	_ = accepted.Close()
}

func TestListenerHubReplacementServesNewRequestsWhileOldServerDrains(t *testing.T) {
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hub := NewListenerHub(bound)
	t.Cleanup(func() { _ = hub.Close() })
	started := make(chan struct{})
	release := make(chan struct{})
	oldServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "old")
	})}
	go func() { _ = oldServer.Serve(hub.Listener()) }()
	client := &http.Client{Timeout: 3 * time.Second}
	oldResponse := make(chan string, 1)
	oldErr := make(chan error, 1)
	go func() {
		response, requestErr := client.Get("http://" + bound.Addr().String())
		if requestErr != nil {
			oldErr <- requestErr
			return
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			oldErr <- readErr
			return
		}
		if closeErr != nil {
			oldErr <- closeErr
			return
		}
		oldResponse <- string(body)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("old request did not start")
	}

	newServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "new")
	})}
	go func() { _ = newServer.Serve(hub.Switch()) }()
	shutdown := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdown <- oldServer.Shutdown(ctx)
	}()
	response, err := client.Get("http://" + bound.Addr().String())
	if err != nil {
		t.Fatalf("request to replacement server failed: %v", err)
	}
	newBody, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(newBody) != "new" {
		t.Fatalf("replacement response = %q, want %q", newBody, "new")
	}
	select {
	case err := <-shutdown:
		t.Fatalf("old server drained before its in-flight request completed: %v", err)
	default:
	}
	close(release)
	select {
	case body := <-oldResponse:
		if body != "old" {
			t.Fatalf("in-flight response = %q, want %q", body, "old")
		}
	case err := <-oldErr:
		t.Fatalf("in-flight request failed: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	select {
	case err := <-shutdown:
		if err != nil {
			t.Fatalf("old server shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old server did not finish draining")
	}
}

func acceptWithin(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	select {
	case connection := <-accepted:
		return connection
	case err := <-acceptErr:
		t.Fatalf("Accept() error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accepted connection")
	}
	return nil
}
