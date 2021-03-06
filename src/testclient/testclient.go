package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"log"
)

var privateKeyFile = flag.String("privkey", "", "Location of the private key")
var action = flag.String("action", "", "Action do: new, notify, remove")
var centername = flag.String("centername", "", "Name of the notification center")
var message = flag.String("message", "", "Message to send to the clients")
var mail = flag.String("mail", "", "Mail address")
var addr = flag.String("addr", "http://localhost:8080", "Address of the service")
var disableCertCheck = flag.Bool("disable-cert-check", false, "Disables certificate checking")

var prikey *rsa.PrivateKey

func loadPrivateKey() {
	content, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	marshaled, _ := pem.Decode([]byte(content))
	prikey, err = x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		log.Fatal(err)
	}
}

func sign(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(rand.Reader, prikey, crypto.SHA1, digest)
	if err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(s)
}

func doPost(addr, body string) {
	req, err := http.NewRequest("POST", addr, strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}

	signature := sign(body)

	log.Printf("BODY: %s\nSignature: %s\n", body, signature)

	req.Header.Set("Authorization", "GoPush "+signature)

	var resp *http.Response
	var client *http.Client

	if *disableCertCheck {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Transport: tr,
		}
	} else {
		client = http.DefaultClient
	}

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response code: %d\n\n", resp.StatusCode)
	respbody, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s", string(respbody))
}

func main() {
	flag.Parse()
	loadPrivateKey()

	if *mail == "" {
		log.Fatal("Mail must be set")
	}

	if *centername == "" && *action != "test" {
		log.Fatal("centername must be set")
	}

	switch *action {
	case "new":
		doPost(*addr+"/newcenter?mail="+*mail, *centername)
	case "remove":
		doPost(*addr+"/removecenter?mail="+*mail, *centername)
	case "notify":
		if *message == "" {
			log.Fatal("message must be set")
		}

		doPost(*addr+"/notify?mail="+*mail+"&center="+*centername, *message)
	case "test":
		if *message == "" {
			log.Fatal("message must be set")
		}

		doPost(*addr+"/test?mail="+*mail, *message)
	default:
		log.Fatal("invalid action")
	}
}
