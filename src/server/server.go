package main

import (
	"flag"
	"runtime"

	"gopush"
)

var procs = flag.Int("procs", 0, "Number of logical processors to utilize")
var certFile = flag.String("certfile", "", "Certificate file (HTTPS, WSS)")
var keyFile = flag.String("keyfile", "", "Private key (HTTPS, WSS)")
var addr = flag.String("addr", "", "Network address of the server")

func main() {
	flag.Parse()

	if *procs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(*procs)
	}

	var defaultAddr string

	svc := gopush.NewService("config.json", false)
	if *certFile != "" && *keyFile != "" {
		svc.SetSSL(*certFile, *keyFile)
		defaultAddr = ":443"
	} else {
		defaultAddr = ":80"
	}

	if *addr == "" {
		*addr = defaultAddr
	}

	svc.Start(*addr)
}
