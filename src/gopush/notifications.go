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
	"time"

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

	if pubkey == nil {
		return false
	}

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

	centername := svc.createCenter(mail, newcenter)

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
	centername := getCenterName(mail, center)
	if _, ok := svc.lastState[centername]; !ok {
		serve404(w)
		return
	}

	newmessage := string(body)

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
	centername := getCenterName(mail, center)
	if _, ok := svc.lastState[centername]; !ok {
		serve404(w)
		return
	}

	log.Printf("Removed notification center: %s\n", centername)

	svc.removeCenter(mail, center)

	w.WriteHeader(http.StatusOK)
}

func getCenterName(mail, center string) string {
	return mail + "____" + center
}

func (svc *GoPushService) createCenter(mail, center string) string {
	centername := getCenterName(mail, center)
	svc.lastState[centername] = ""
	svc.hubs[centername] = newWSHub()
	go svc.hubs[centername].run()
	if svc.config.Timeout > 0 {
		go func() {
			time.Sleep(time.Duration(svc.config.Timeout) * time.Second)
			if _, ok := svc.hubs[centername]; ok {
				svc.removeCenter(mail, center)
			}
		}()
	}

	return centername
}

func (svc *GoPushService) removeCenter(mail, center string) {
	centername := getCenterName(mail, center)
	delete(svc.lastState, centername)
	svc.hubs[centername].quit <- true
	delete(svc.hubs, centername)
}
