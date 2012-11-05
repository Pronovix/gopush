package gopush

import (
	"code.google.com/p/go.net/websocket"
)

type wsconnection struct {
	conn 		*websocket.Conn
	send 		chan string
	writequit	chan bool
	hub			*wshub
}

func (c *wsconnection) reader() {
	for {
		var message string
		err := websocket.Message.Receive(c.conn, &message)
		if err != nil {
			break
		}
		c.hub.broadcast <- message
	}
	c.conn.Close()
}

func (c *wsconnection) writer() {
	defer c.conn.Close()

	for {
		select {
		case message := <-c.send:
			err := websocket.Message.Send(c.conn, message)
			if err != nil {
				return
			}
		case q := <-c.writequit:
			if q {
				return
			}
		}
	}
}

func (c *wsconnection) quit() {
	c.writequit <- true
}

func wsHandler(conn *websocket.Conn, h *wshub, allowincoming bool) {
	c := &wsconnection{
		send: make(chan string, 256),
		conn: conn,
		hub: h,
		writequit: make(chan bool),
	}
	c.hub.register <- c
	defer func() { c.hub.unregister <- c }()
	if allowincoming {
		go c.reader()
	}
	c.writer()
}
