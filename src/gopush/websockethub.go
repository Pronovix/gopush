package gopush

import (
	"log"
)

type wshub struct {
	connections 	map[*wsconnection]bool
	broadcast 		chan string
	register		chan *wsconnection
	unregister		chan *wsconnection
	quit			chan bool
}

func newWSHub() *wshub {
	return &wshub{
		connections: 	make(map[*wsconnection]bool),
		broadcast: 		make(chan string),
		register:		make(chan *wsconnection),
		unregister:		make(chan *wsconnection),
		quit:			make(chan bool),
	}
}

func (h *wshub) run() {
	for {
		select {
		case c := <-h.register:
			h.connections[c] = true
		case c := <-h.unregister:
			delete(h.connections, c)
			close(c.send)
		case m := <-h.broadcast:
			log.Printf("Broadcasting %s\n", m)
			for c := range h.connections {
				select {
				case c.send <- m:
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
