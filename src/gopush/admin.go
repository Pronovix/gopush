package gopush

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"time"
)

var nonces = make(map[string]nonceData)

type adminAdd struct {
	Mail 	string
	Key 	string
}

type adminPageData struct {
	APITokens 	[]APIToken
	Nonce 		string
	FormID		string
}

type nonceData struct {
	nonce string
	timer *time.Timer
}

func genRandomHash(size int) string {
	b := make([]byte, size)
	n, err := io.ReadFull(rand.Reader, b)
	if n != len(b) || err != nil {
		return ""
	}

	h := sha1.New()
	h.Write(b)
	digest := h.Sum(nil)

	return fmt.Sprintf("%x", digest)
}

func genNonce() string {
	return genRandomHash(128)
}

func genFormID() string {
	return genRandomHash(64)
}

func (svc *GoPushService) checkNonce(r *http.Request) bool {
	formid := r.FormValue("formid")
	if formid == "" {
		return false
	}

	if nonce, ok := nonces[formid]; ok {
		delete(nonces, formid)
		nonce.timer.Stop()
		return nonce.nonce != "" && nonce.nonce == r.FormValue("nonce")
	}
	
	return false
}

func (svc *GoPushService) ensureNonce(formid string) string {
	nonce := genNonce()

	// Automatically delete nonces after one day
	timer := time.AfterFunc(time.Hour * 24, func () {
		delete(nonces, formid)
	})

	nonces[formid] = nonceData{nonce: nonce, timer: timer}

	return nonce
}

func (svc *GoPushService) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); auth != "Basic " + svc.adminCreds {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"GoPushNotification admin page\"")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	return true
}

func (svc *GoPushService) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve405(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	formid := genFormID()
	nonce := svc.ensureNonce(formid)

	c := svc.getConnection()
	rows, err := c.Query("SELECT Mail, PublicKey, Admin FROM APIToken ORDER BY Mail")
	if err != nil {
		serveError(w, err)
		return
	}
	var at []APIToken
	for rows.Next() {
		var a APIToken
		rows.Scan(&a.Mail, &a.PublicKey, &a.Admin)
		at = append(at, a)
	}
	if err := rows.Err(); err != nil {
		serveError(w, err)
		return
	}

	if err := adminPage.Execute(w, &adminPageData{Nonce: nonce, FormID: formid, APITokens: at}); err != nil {
		serveError(w, err)
		return
	}
}

func (svc *GoPushService) handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve405(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	if err := r.ParseForm(); err != nil {
		serveError(w, err)
		return
	}

	if !svc.checkNonce(r) {
		serve403(w)
		return
	}

	publicKey := r.FormValue("publickey")
	privateKey := ""
	var errk error

	if publicKey == "" {
		privateKey, publicKey, errk = svc.genKeyPair()
		if errk != nil {
			serveError(w, errk)
			return
		}
	}

	t := &APIToken{
		Mail: r.FormValue("mail"),
		PublicKey: publicKey,
		Admin: false,
	}

	c := svc.getConnection()
	if _, err := c.Exec("INSERT INTO APIToken(Mail, PublicKey, Admin) VALUES(?,?,?)", t.Mail, t.PublicKey, t.Admin); err != nil {
		serveError(w, err)
		return
	}

	if privateKey == "" {
		http.Redirect(w, r, "/admin", http.StatusFound)
	} else {
		data := &adminAdd{
			Mail: r.FormValue("mail"),
			Key: privateKey,
		}
		adminAddGenPriKeyPage.Execute(w, data)
	}
}

func (svc *GoPushService) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve405(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	if err := r.ParseForm(); err != nil {
		serveError(w, err)
		return
	}

	if !svc.checkNonce(r) {
		serve403(w)
		return
	}

	mail := r.FormValue("mail")

	if mail == "" {
		serve404(w)
		return
	}

	if svc.config.UserCache {
		delete(userCache, mail)
	}

	c := svc.getConnection()
	if _, err := c.Exec("DELETE FROM APIToken WHERE Mail = ?", mail); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}
