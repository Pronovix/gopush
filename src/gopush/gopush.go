package gopush

import (
	"database/sql"
	"encoding/base64"
	"net/http"
	"text/template"

	//"code.google.com/p/go.net/websocket"
)

type GoPushService struct {
	keySize 	int
	authName 	string
	lastState 	map[string]string
	connection 	*sql.DB
	config 		map[string]string
	adminCreds 	string
	server 		*http.Server
}

func NewService(configName string) *GoPushService {
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

	// TODO add channel API
	//mux.HandleFunc("/subscribe", func (w http.ResponseWriter, r *http.Request) { instance.handleSubscribe(w, r) })
	//mux.HandleFunc("/listen", func (w http.ResponseWriter, r *http.Request) { instance.handleListen(w, r) })
	mux.HandleFunc("/ping", func (w http.ResponseWriter, r *http.Request) { instance.handlePing(w, r) })

	return instance
}

var adminPage = template.Must(template.ParseFiles("admin.html"))

// TODO refactor the SQL queries related to this structure into nice methods
type APIToken struct {
	Mail 		string
	PrivateKey 	string
	Admin		bool
}

func (svc *GoPushService) Start(addr string) {
	svc.server.Addr = addr
	svc.server.ListenAndServe()
}
