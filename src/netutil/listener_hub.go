package netutil

import (
	"net"
	"sync"
)

// ListenerHub keeps a bound listener open while accepted connections move to
// successive server generations.
type ListenerHub struct {
	listener net.Listener
	mu       sync.RWMutex
	current  *hubGeneration
	once     sync.Once
}

type hubGeneration struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

// NewListenerHub starts accepting connections from listener and assigns them
// to the initial generation.
func NewListenerHub(listener net.Listener) *ListenerHub {
	hub := &ListenerHub{listener: listener}
	hub.current = newHubGeneration()
	go hub.acceptLoop()
	return hub
}

// Listener returns the initial generation listener. Call Switch to create the
// listener for a replacement server.
func (h *ListenerHub) Listener() net.Listener {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return &generationListener{hub: h, generation: h.current}
}

// Switch moves newly accepted connections to a new generation and closes the
// old generation's Accept loop. Existing connections remain with the old
// server so it can drain them gracefully.
func (h *ListenerHub) Switch() net.Listener {
	generation := newHubGeneration()
	h.mu.Lock()
	previous := h.current
	h.current = generation
	h.mu.Unlock()
	previous.close()
	return &generationListener{hub: h, generation: generation}
}

// Close stops accepting connections and closes the underlying bound socket.
func (h *ListenerHub) Close() error {
	var err error
	h.once.Do(func() {
		h.mu.Lock()
		generation := h.current
		h.current = nil
		h.mu.Unlock()
		if generation != nil {
			generation.close()
		}
		err = h.listener.Close()
	})
	return err
}

func newHubGeneration() *hubGeneration {
	return &hubGeneration{connections: make(chan net.Conn), done: make(chan struct{})}
}

func (g *hubGeneration) close() {
	g.once.Do(func() { close(g.done) })
}

func (h *ListenerHub) acceptLoop() {
	for {
		connection, err := h.listener.Accept()
		if err != nil {
			return
		}
		for {
			h.mu.RLock()
			generation := h.current
			h.mu.RUnlock()
			if generation == nil {
				_ = connection.Close()
				break
			}
			select {
			case generation.connections <- connection:
			case <-generation.done:
				continue
			}
			break
		}
	}
}

type generationListener struct {
	hub        *ListenerHub
	generation *hubGeneration
}

func (l *generationListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.generation.connections:
		return connection, nil
	case <-l.generation.done:
		return nil, net.ErrClosed
	}
}

func (l *generationListener) Close() error {
	l.generation.close()
	return nil
}

func (l *generationListener) Addr() net.Addr {
	if l.hub == nil || l.hub.listener == nil {
		return listenerClosedAddr{}
	}
	return l.hub.listener.Addr()
}

type listenerClosedAddr struct{}

func (listenerClosedAddr) Network() string { return "unknown" }
func (listenerClosedAddr) String() string  { return "closed" }

var _ net.Listener = (*generationListener)(nil)
