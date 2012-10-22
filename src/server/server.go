package main

import (
	"flag"
	"runtime"

	"gopush"
)

var procs = flag.Int("procs", 0, "Number of logical processors to utilize")

func main() {
	flag.Parse()

	if *procs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(*procs)
	}

	gopush.NewService("config.json", false).Start(":8080")
}
