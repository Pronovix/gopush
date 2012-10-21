package gopush

import (
	"code.google.com/p/go.net/websocket"
)

type wsconnection struct {
	conn 	*websocket.Conn
	send 	chan string
	hub		*wshub
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
	for message := range c.send {
		err := websocket.Message.Send(c.conn, message)
		if err != nil {
			break
		}
	}

	c.conn.Close()
}

func wsHandler(conn *websocket.Conn, h *wshub, allowincoming bool) {
	c := &wsconnection{
		send: make(chan string, 256),
		conn: conn,
		hub: h,
	}
	c.hub.register <- c
	defer func() { c.hub.unregister <- c }()
	if allowincoming {
		go c.reader()
	}
	c.writer()
}
