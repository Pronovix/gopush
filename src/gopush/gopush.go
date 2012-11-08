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
	config 		Config
	adminCreds 	string
	server 		*http.Server
	hubs 		map[string]*wshub
}

func NewService(configName string) *GoPushService {
	mux := http.NewServeMux()

	instance := &GoPushService{
		keySize: 1024,
		authName: "GoPush ",
		lastState: make(map[string]string),
		connection: nil,
		config: Config{},
		adminCreds: "",
		server: &http.Server{
				Handler: mux,
			},
		hubs: make(map[string]*wshub),
	}

	config, err := ReadConfig(configName)
	if err != nil {
		log.Fatal(err)
	}
	instance.config = config

	log.Printf("Notification center timeout is set to %d second(s).\n", config.Timeout)

	instance.adminCreds = base64.StdEncoding.EncodeToString([]byte(config.AdminUser + ":" + config.AdminPass))

	mux.HandleFunc("/admin", func (w http.ResponseWriter, r *http.Request) { instance.handleAdmin(w, r) })
	mux.HandleFunc("/admin/add", func (w http.ResponseWriter, r *http.Request) { instance.handleAdminAdd(w, r) })
	mux.HandleFunc("/admin/remove", func (w http.ResponseWriter, r *http.Request) { instance.handleAdminRemove(w, r) })

	mux.HandleFunc("/newcenter", func (w http.ResponseWriter, r *http.Request) { instance.handleNewCenter(w, r) })
	mux.HandleFunc("/notify", func (w http.ResponseWriter, r *http.Request) { instance.handleNotify(w, r) })
	mux.HandleFunc("/removecenter", func (w http.ResponseWriter, r *http.Request) { instance.handleRemoveCenter(w, r) })

	mux.HandleFunc("/test", func (w http.ResponseWriter, r *http.Request) { instance.handleTest(w, r) })

	mux.HandleFunc("/ping", func (w http.ResponseWriter, r *http.Request) { instance.handlePing(w, r) })

	mux.Handle("/listen", websocket.Handler(func (conn *websocket.Conn) {
		v, _ := url.ParseQuery(conn.Request().URL.RawQuery)
		center := v.Get("center")
		if hub, ok := instance.hubs[center]; ok {
			if instance.config.ExtraLogging {
				log.Println("Client connected.")
			}
			wsHandler(conn, hub, instance.config.ExtraLogging)
		} else {
			if instance.config.ExtraLogging {
				log.Println("Client connection rejected.")
			}
			conn.Close() // TODO figure out if it's possible to send an error message to the client
		}
	}))

	if instance.config.RedirectMainPage != "" {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, instance.config.RedirectMainPage, http.StatusFound)
		})
	}

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

func (svc *GoPushService) Start() {
	var err error
	svc.server.Addr = svc.config.Address
	if svc.config.CertFile != "" && svc.config.KeyFile != "" {
		if svc.server.Addr == "" {
			svc.server.Addr = ":443"
		}
		err = svc.server.ListenAndServeTLS(svc.config.CertFile, svc.config.KeyFile)
	} else {
		if svc.server.Addr == "" {
			svc.server.Addr = ":80"
		}
		err = svc.server.ListenAndServe()
	}
	if err != nil {
		log.Fatal(err)
	}
}
