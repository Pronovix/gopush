package gopush

import (
	"log"
)

type wshub struct {
	connections map[*wsconnection]bool
	broadcast   chan string
	register    chan *wsconnection
	unregister  chan *wsconnection
	quit        chan bool
	verbose     bool
}

func newWSHub(broadcastBuffer int64) *wshub {
	return &wshub{
		connections: make(map[*wsconnection]bool),
		broadcast:   make(chan string, broadcastBuffer),
		register:    make(chan *wsconnection),
		unregister:  make(chan *wsconnection),
		quit:        make(chan bool),
	}
}

func (h *wshub) run() {
	for {
		select {
		case c := <-h.register:
			if h.verbose {
				log.Println("Registering client")
			}
			h.connections[c] = true
		case c := <-h.unregister:
			if h.verbose {
				log.Println("Unregistering client")
			}
			delete(h.connections, c)
			close(c.send)
		case m := <-h.broadcast:
			for c := range h.connections {
				select {
				case c.send <- m:
					if h.verbose {
						log.Printf("Sending message '%s' to a client.\n", m)
					}
				default:
					delete(h.connections, c)
					close(c.send)
					go c.conn.Close()
				}
			}
		case q := <-h.quit:
			if q {
				for c := range h.connections {
					c.quit()
				}
				return
			}
		}
	}
}
