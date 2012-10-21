package gopush

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"text/template"

	_ "code.google.com/p/go-mysql-driver/mysql"
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

type APIToken struct {
	Mail 		string
	PrivateKey 	string
	Admin		bool
}

func (svc *GoPushService) getConnection() *sql.DB {
	if svc.connection == nil {
		var err error
		svc.connection, err = sql.Open("mysql",
			svc.config["dbuser"] + ":" + svc.config["dbpass"] + "@/" + svc.config["dbname"] + "?charset=utf8")
		if err != nil {
			return nil
		}
	}

	return svc.connection
}

func (svc *GoPushService) genKeyPair() (string, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, svc.keySize)
	if err != nil {
		return "", err
	}

	marshaled := x509.MarshalPKCS1PrivateKey(prikey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: nil,
		Bytes: marshaled,
	})

	return string(privateKeyPEM), nil
}

func serve404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "Not Found")
}

func serve401(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; chatset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, "Unauthorized")
}

func serveError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, "Internal Server Error")
	io.WriteString(w, "\n")
	io.WriteString(w, err.Error())
}

func (svc *GoPushService) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	c := svc.getConnection()
	rows, err := c.Query("SELECT Mail, PrivateKey, Admin FROM APIToken ORDER BY Mail")
	if err != nil {
		serveError(w, err)
		return
	}
	var at []APIToken
	for rows.Next() {
		var a APIToken
		rows.Scan(&a.Mail, &a.PrivateKey, &a.Admin)
		at = append(at, a)
	}
	if err := rows.Err(); err != nil {
		serveError(w, err)
		return
	}

	if err := adminPage.Execute(w, at); err != nil {
		serveError(w, err)
		return
	}
}

func (svc *GoPushService) handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	if err := r.ParseForm(); err != nil {
		serveError(w, err)
		return
	}

	key, errk := svc.genKeyPair()
	if errk != nil {
		serveError(w, errk)
		return
	}

	t := &APIToken{
		Mail: r.FormValue("mail"),
		PrivateKey: key,
		Admin: false,
	}

	c := svc.getConnection()
	if _, err := c.Exec("INSERT INTO APIToken(Mail, PrivateKey, Admin) VALUES(?,?,?)", t.Mail, t.PrivateKey, t.Admin); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (svc *GoPushService) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	if !svc.checkAdminAuth(w, r) {
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)

	mail := v.Get("mail")

	if mail == "" {
		serve404(w)
		return
	}

	c := svc.getConnection()
	if _, err := c.Exec("DELETE FROM APIToken WHERE Mail = ?", mail); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (svc *GoPushService) getPrivateKeyForMailAddress(mail string) *rsa.PrivateKey {
	c := svc.getConnection()
	row := c.QueryRow("SELECT PrivateKey FROM APIToken WHERE Mail = ?", mail)
	var pkey string
	if err := row.Scan(&pkey); err != nil {
		return nil
	}
	
	marshaled, _ := pem.Decode([]byte(pkey))
	prikey, err := x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		return nil
	}

	// TODO cache

	return prikey
}

func (svc *GoPushService) checkAuth(r *http.Request, body []byte) bool {
	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	if mail == "" {
		return false
	}

	authheader := r.Header.Get("Authorization")
	if authheader[0:len(svc.authName)] != svc.authName {
		return false
	}
	signature := authheader[len(svc.authName):]

	h := sha1.New()
	h.Write(body)
	digest := h.Sum(nil)

	sig, _ := hex.DecodeString(signature)

	prikey := svc.getPrivateKeyForMailAddress(mail)

	err := rsa.VerifyPKCS1v15(&prikey.PublicKey, crypto.SHA1, digest, sig)

	return err == nil
}

func (svc *GoPushService) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); auth != "Basic " + svc.adminCreds {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"GoPushNotification admin page\"")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	return true
}

func (svc *GoPushService) handleNewCenter(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if !svc.checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")

	newcenter := string(body)

	svc.lastState[mail + "____" + newcenter] = ""

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, "Created")
}

func (svc *GoPushService) handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	if !svc.checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	center := v.Get("center")
	centername := mail + "____" + center
	if _, ok := svc.lastState[centername]; !ok {
		serve404(w)
		return
	}

	newmessage := string(body)

	svc.lastState[centername] = newmessage

	w.WriteHeader(http.StatusOK)
}

func (svc *GoPushService) handleRemoveCenter(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	if !svc.checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	center := v.Get("center")
	centername := mail + "____" + center
	if _, ok := svc.lastState[centername]; !ok {
		serve404(w)
		return
	}

	delete(svc.lastState, centername)

	w.WriteHeader(http.StatusOK)
}

func (svc *GoPushService) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	id := v.Get("id")

	if _, ok := svc.lastState[id]; id == "" || !ok {
		serve404(w)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, svc.lastState[id])
}

func (svc *GoPushService) Start(addr string) {
	svc.server.Addr = addr
	svc.server.ListenAndServe()
}

func readConfig(path string) (map[string]string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf map[string]string

	jerr := json.Unmarshal(content, &conf)

	if jerr != nil {
		return nil, jerr
	}

	return conf, nil
}
