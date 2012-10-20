package gopush

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"text/template"

	"appengine"
	"appengine/datastore"
	//"appengine/channel"
)

import _ "appengine/remote_api"

var keySize = 1024

var authName = "GoPush "

var notifications map[string][]chan string

var adminPage = template.Must(template.ParseFiles("admin.html"))

type APIToken struct {
	Mail 		string
	PrivateKey 	string `datastore:",noindex"`
	Admin		bool
}

var lastState map[string]string

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

func serveError(c appengine.Context, w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "Internal Server Error")
	c.Errorf("%v", err)
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	c := appengine.NewContext(r)

	q := datastore.NewQuery("APIToken").Order("Mail")
	var at []*APIToken
	_, err := q.GetAll(c, &at)
	if err != nil {
		serveError(c, w, err)
		return
	}

	if err := adminPage.Execute(w, at); err != nil {
		c.Errorf("%v", err)
	}
}

func handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	c := appengine.NewContext(r)
	if err := r.ParseForm(); err != nil {
		serveError(c, w, err)
		return
	}

	key, errk := genKeyPair()
	if errk != nil {
		serveError(c, w, errk)
		return
	}

	t := &APIToken{
		Mail: r.FormValue("mail"),
		PrivateKey: key,
		Admin: false,
	}

	if _, err := datastore.Put(c, datastore.NewIncompleteKey(c, "APIToken", nil), t); err != nil {
		serveError(c, w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	v, _ := url.ParseQuery(r.URL.RawQuery)
	c := appengine.NewContext(r)

	mail := v.Get("mail")

	if mail == "" {
		serve404(w)
		return
	}

	q := datastore.NewQuery("APIToken").Filter("Mail = ", mail)
	t := q.Run(c)
	var at APIToken
	key, err := t.Next(&at)
	if err != nil {
		serveError(c, w, err)
		return
	}

	if err := datastore.Delete(c, key); err != nil {
		serveError(c, w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func getPrivateKeyForMailAddress(c appengine.Context, mail string) *rsa.PrivateKey {
	q := datastore.NewQuery("APIToken").Filter("Mail =", mail)
	t := q.Run(c)
	var at APIToken
	if _, err := t.Next(&at); err != nil {
		return nil
	}
	
	marshaled, _ := pem.Decode([]byte(at.PrivateKey))
	prikey, err := x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		return nil
	}

	// TODO cache

	return prikey
}

func checkAuth(r *http.Request, body []byte) bool {
	c := appengine.NewContext(r)

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

	prikey := getPrivateKeyForMailAddress(c, mail)

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

func init() {
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
}
