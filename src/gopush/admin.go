package gopush

import (
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type adminAdd struct {
	Mail 	string
	Key 	string
}

type adminPageData struct {
	APITokens 	[]APIToken
	Nonce 		string
}

func genNonce() string {
	size := 128
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

func (svc *GoPushService) checkNonce(r *http.Request) bool {
	cookie, err := r.Cookie("gopush-nonce")
	if err == nil {
		return cookie.Value == r.FormValue("nonce") && cookie.Value != ""
	}
	
	return false
}

func (svc *GoPushService) ensureNonce(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie("gopush-nonce")
	if err != nil {
		if err == http.ErrNoCookie {
			cookie = &http.Cookie{
				Name: "gopush-nonce",
			}
			// Generate nonce
			nonce := genNonce()
			if nonce == "" {
				return "", errors.New("Empty nonce")
			} else {
				cookie.Value = nonce
			}
		} else {
			return "", err
		}
	}

	cookie.Secure = svc.certFile != "" && svc.keyFile != ""
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add(time.Hour)

	http.SetCookie(w, cookie)

	return cookie.Value, nil
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
		serve404(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	nonce, nerr := svc.ensureNonce(w, r)
	if nerr != nil {
		serveError(w, nerr)
		return
	}

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

	if err := adminPage.Execute(w, &adminPageData{Nonce: nonce, APITokens: at}); err != nil {
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

	if !svc.checkNonce(r) {
		serve401(w)
		return
	}

	svc.ensureNonce(w, r)

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

	if !svc.checkNonce(r) {
		serve401(w)
		return
	}

	svc.ensureNonce(w, r)

	mail := r.FormValue("mail")

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
