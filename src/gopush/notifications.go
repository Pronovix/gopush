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

	"log"
)

func (svc *GoPushService) checkAuth(r *http.Request, body []byte) bool {
	v, _ := url.ParseQuery(r.URL.RawQuery)
	mail := v.Get("mail")
	if mail == "" {
		return false
	}

	authheader := r.Header.Get("Authorization")
	if authheader == "" || authheader[0:len(svc.authName)] != svc.authName {
		return false
	}
	signature := authheader[len(svc.authName):]

	h := sha1.New()
	h.Write(body)
	digest := h.Sum(nil)

	sig, _ := hex.DecodeString(signature)

	pubkey := svc.getPublicKeyForMailAddress(mail)

	err := rsa.VerifyPKCS1v15(pubkey, crypto.SHA1, digest, sig)

	return err == nil
}

func (svc *GoPushService) handleNewCenter(w http.ResponseWriter, r *http.Request) {
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

	newcenter := string(body)

	centername := mail + "____" + newcenter

	svc.lastState[centername] = ""
	svc.hubs[centername] = newWSHub()
	go svc.hubs[centername].run()

	log.Printf("Created new notification center: %s\n", centername)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	io.WriteString(w, centername)
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

	log.Printf("Sent notification to %s: %s\n", centername, newmessage)

	svc.lastState[centername] = newmessage

	go func() { svc.hubs[centername].broadcast <- newmessage }()

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
	center := string(body)
	centername := mail + "____" + center
	if _, ok := svc.lastState[centername]; !ok {
		serve404(w)
		return
	}

	log.Printf("Removed notification center: %s\n", centername)

	delete(svc.lastState, centername)

	svc.hubs[centername].quit <- true

	delete(svc.hubs, centername)

	w.WriteHeader(http.StatusOK)
}
