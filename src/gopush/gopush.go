package gopush

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/url"
	"text/template"

	"code.google.com/p/go.net/websocket"

	"log"
)

type GoPushService struct {
	keySize 	int
	authName 	string
	lastState 	map[string]string
	connection 	*sql.DB
	config 		map[string]string
	adminCreds 	string
	server 		*http.Server
	hubs 		map[string]*wshub
}

func NewService(configName string, allowincoming bool) *GoPushService {
	mux := http.NewServeMux()

	instance := &GoPushService{
		keySize: 1024,
		authName: "GoPush ",
		lastState: make(map[string]string),
		connection: nil,
		config: make(map[string]string),
		adminCreds: "",
		server: &http.Server{
				Handler: mux,
			},
		hubs: make(map[string]*wshub),
	}

	config, err := readConfig(configName)
	if err != nil {
		panic(err)
	}
	instance.config = config

	instance.adminCreds = base64.StdEncoding.EncodeToString([]byte(config["adminuser"] + ":" + config["adminpass"]))

	mux.HandleFunc("/admin", func (w http.ResponseWriter, r *http.Request) { instance.handleAdmin(w, r) })
	mux.HandleFunc("/admin/add", func (w http.ResponseWriter, r *http.Request) { instance.handleAdminAdd(w, r) })
	mux.HandleFunc("/admin/remove", func (w http.ResponseWriter, r *http.Request) { instance.handleAdminRemove(w, r) })

	mux.HandleFunc("/newcenter", func (w http.ResponseWriter, r *http.Request) { instance.handleNewCenter(w, r) })
	mux.HandleFunc("/notify", func (w http.ResponseWriter, r *http.Request) { instance.handleNotify(w, r) })
	mux.HandleFunc("/removecenter", func (w http.ResponseWriter, r *http.Request) { instance.handleRemoveCenter(w, r) })

	mux.HandleFunc("/ping", func (w http.ResponseWriter, r *http.Request) { instance.handlePing(w, r) })

	mux.Handle("/listen", websocket.Handler(func (conn *websocket.Conn) {
		v, _ := url.ParseQuery(conn.Request().URL.RawQuery)
		center := v.Get("center")
		if hub, ok := instance.hubs[center]; ok {
			log.Println("Accepted WS request")
			wsHandler(conn, hub, allowincoming)
		} else {
			log.Println("Rejected WS request")
			conn.Close() // TODO figure out if it's possible to send an error message to the client
		}
	}))

	return instance
}

var adminPage = template.Must(template.ParseFiles("admin.html"))
var adminAddGenPriKeyPage = template.Must(template.ParseFiles("adminaddgenprikey.html"))

// TODO refactor the SQL queries related to this structure into nice methods
type APIToken struct {
	Mail 		string
	PublicKey 	string
	Admin		bool
}

func (svc *GoPushService) Start(addr string) {
	svc.server.Addr = addr
	svc.server.ListenAndServe()
}
