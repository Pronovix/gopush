package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

var privateKeyFile = flag.String("privkey", "", "Location of the private key")
var action = flag.String("action", "", "Action do: new, notify, remove")
var centername = flag.String("centername", "", "Name of the notification center")
var message = flag.String("message", "", "Message to send to the clients")
var mail = flag.String("mail", "", "Mail address")
var addr = flag.String("addr", "http://localhost:8080", "Address of the service")

var prikey *rsa.PrivateKey

func loadPrivateKey() {
	content, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		panic(err.Error())
	}
	marshaled, _ := pem.Decode([]byte(content))
	prikey, err = x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		panic(err.Error())
	}
}

func sign(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(rand.Reader, prikey, crypto.SHA1, digest)
	if err != nil {
		panic(err.Error())
	}

	return hex.EncodeToString(s)
}

func doPost(addr, body string) {
	req, err := http.NewRequest("POST", addr, strings.NewReader(body))
	if err != nil {
		panic(err.Error())
	}

	req.Header.Set("Authorization", "GoPush " + sign(body))

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err.Error())
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
		panic("Mail must be set")
	}

	if *centername == "" {
		panic("centername must be set")
	}

	switch *action{
		case "new":
			doPost(*addr + "/newcenter?mail=" + *mail, *centername)
		case "remove":
			doPost(*addr + "/removecenter?mail=" + *mail, *centername)
		case "notify":
			if *message == "" {
				panic("message must be set")
			}

			doPost(*addr + "/notify?mail=" + *mail + "&center=" + *centername, *message)
		default:
			panic("invalid action")
	}
}