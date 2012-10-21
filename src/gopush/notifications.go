package gopush

import (
	"crypto"
	"crypto/sha1"
	"crypto/rsa"
	"encoding/hex"
	"net/http"
	"net/url"
	"io"
	"io/ioutil"
)

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

	go func() { svc.hub.broadcast <- newmessage }()

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
