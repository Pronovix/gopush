package main

import (
	"flag"
	"net/http"
	"text/template"
)

var indexTemplate = template.Must(template.ParseFiles("testindex.html"))

var addr = flag.String("addr", ":8081", "http service address")
var address = flag.String("address", "", "address of the service endpoint")

type templateData struct {
	Address string
}

func main() {
	flag.Parse()

	data := &templateData{
		Address: *address,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { indexTemplate.Execute(w , data) })
	if err := http.ListenAndServe(*addr, nil); err != nil {
		panic(err.Error())
	}
}