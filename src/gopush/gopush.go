package gopush

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"database/sql"
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

var keySize = 1024

var authName = "GoPush "

var notifications map[string][]chan string

var adminPage = template.Must(template.ParseFiles("admin.html"))

type APIToken struct {
	Mail 		string
	PrivateKey 	string
	Admin		bool
}

var lastState map[string]string

var connection *sql.DB = nil

var config map[string]string = nil

func getConnection() *sql.DB {
	if connection == nil {
		var err error
		connection, err = sql.Open("mysql",
			config["dbuser"] + ":" + config["dbpass"] + "@/" + config["dbname"] + "?charset=utf8")
		if err != nil {
			return nil
		}
	}

	return connection
}

func genKeyPair() (string, error) {
	prikey, err := rsa.GenerateKey(rand.Reader, keySize)
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
	w.WriteHeader(http.StatusNotFound)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Not Found")
}

func serve401(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Header().Set("Content-Type", "text/plain; chatset=utf-8")
	io.WriteString(w, "Unauthorized")
}

func serveError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Internal Server Error")
	io.WriteString(w, "\n")
	io.WriteString(w, err.Error())
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	c := getConnection()
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

func handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		serveError(w, err)
		return
	}

	key, errk := genKeyPair()
	if errk != nil {
		serveError(w, errk)
		return
	}

	t := &APIToken{
		Mail: r.FormValue("mail"),
		PrivateKey: key,
		Admin: false,
	}

	c := getConnection()
	if _, err := c.Exec("INSERT INTO APIToken(Mail, PrivateKey, Admin) VALUES(?,?,?)", t.Mail, t.PrivateKey, t.Admin); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	v, _ := url.ParseQuery(r.URL.RawQuery)

	mail := v.Get("mail")

	if mail == "" {
		serve404(w)
		return
	}

	c := getConnection()
	if _, err := c.Exec("DELETE FROM APIToken WHERE Mail = ?", mail); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func getPrivateKeyForMailAddress(mail string) *rsa.PrivateKey {
	c := getConnection()
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

func checkAuth(r *http.Request, body []byte) bool {
	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	if mail == "" {
		return false
	}

	authheader := r.Header.Get("Authorization")
	if authheader[0:len(authName)] != authName {
		return false
	}
	signature := authheader[len(authName):]

	h := sha1.New()
	h.Write(body)
	digest := h.Sum(nil)

	sig, _ := hex.DecodeString(signature)

	prikey := getPrivateKeyForMailAddress(mail)

	err := rsa.VerifyPKCS1v15(&prikey.PublicKey, crypto.SHA1, digest, sig)

	return err == nil
}

func handleNewCenter(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if !checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")

	newcenter := string(body)

	lastState[mail + "____" + newcenter] = ""

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Created")
}

func handleNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	if !checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	center := v.Get("center")
	centername := mail + "____" + center
	if _, ok := lastState[centername]; !ok {
		serve404(w)
		return
	}

	newmessage := string(body)

	lastState[centername] = newmessage

	w.WriteHeader(http.StatusOK)
}

func handleRemoveCenter(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	if !checkAuth(r, body) {
		serve401(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	center := v.Get("center")
	centername := mail + "____" + center
	if _, ok := lastState[centername]; !ok {
		serve404(w)
		return
	}

	delete(lastState, centername)

	w.WriteHeader(http.StatusOK)
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	id := v.Get("id")

	if _, ok := lastState[id]; id == "" || !ok {
		serve404(w)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, lastState[id])
}

func StartService() {
	var err error
	config, err = readConfig("config.json")

	if err != nil {
		panic(err)
	}

	notifications = make(map[string][]chan string)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/admin/add", handleAdminAdd)
	http.HandleFunc("/admin/remove", handleAdminRemove)

	http.HandleFunc("/newcenter", handleNewCenter)
	http.HandleFunc("/notify", handleNotify)
	http.HandleFunc("/removecenter", handleRemoveCenter)

	// TODO add channel API
	//http.HandleFunc("/subscribe", handleSubscribe)
	//http.HandleFunc("/listen", handleListen)
	http.HandleFunc("/ping", handlePing)

	http.ListenAndServe(":8080", nil)
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
