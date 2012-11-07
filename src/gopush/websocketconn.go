package gopush

import (
	"log"

	"code.google.com/p/go.net/websocket"
)

type wsconnection struct {
	conn 		*websocket.Conn
	send 		chan string
	writequit	chan bool
	hub			*wshub
	verbose		bool
}

func (c *wsconnection) reader() {
	defer func () {
		c.quit()
		if c.verbose {
			log.Println("Closing reader goroutine.")
		}
	}()

	for {
		var message string
		err := websocket.Message.Receive(c.conn, &message)
		if err != nil {
			return
		}
	}
}

func (c *wsconnection) writer() {
	defer func () {
		if c.verbose {
			log.Println("Closing connection.")
		}
		c.conn.Close()
	}()

	for {
		select {
		case message := <-c.send:
			if c.verbose {
				log.Println("Sending message through websocket.")
			}
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

func wsHandler(conn *websocket.Conn, h *wshub, verbose bool) {
	c := &wsconnection{
		send: make(chan string, 256),
		conn: conn,
		hub: h,
		writequit: make(chan bool),
		verbose: verbose,
	}
	c.hub.register <- c
	defer func() { c.hub.unregister <- c }()
	go c.reader()
	c.writer()
}
