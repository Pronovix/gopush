package main

import (
	"flag"
	"net/http"
	"text/template"

	"log"
)

var indexTemplate = template.Must(template.ParseFiles("testindex.html"))

var addr = flag.String("addr", ":8081", "http service address")
var address = flag.String("address", "", "address of the service endpoint")
var secure = flag.Bool("secure", false, "The server is using HTTPS and WSS.")

type templateData struct {
	Address string
	Secure 	bool
}

func main() {
	flag.Parse()

	data := &templateData{
		Address: *address,
		Secure: *secure,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { indexTemplate.Execute(w , data) })
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal(err)
	}
}