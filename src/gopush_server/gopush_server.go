package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"

	"log"

	"gopush"
)

var procs = flag.Int("procs", 0, "Number of logical processors to utilize")
var configName = flag.String("config", "config.json", "Path to the server config file.")
var cpuProfile = flag.String("cpuprofile", "", "Enable CPU Profiling and write the results to a file.")
var logFile = flag.String("log", "", "Logfile location. Empty string means stdout.")

func main() {
	flag.Parse()

	if *procs == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	} else {
		runtime.GOMAXPROCS(*procs)
	}

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE | os.O_APPEND | os.O_RDWR, 0666)
		if err != nil {
			log.Fatalln(err.Error())
		}
		log.SetOutput(f)
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatalln(err.Error())
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func () {
		for sig := range c {
			log.Printf("Received signal %d, shutting down\n", sig)
			if *cpuProfile != "" { // Stop profiling
				pprof.StopCPUProfile()
			}
			os.Exit(1)
		}
	}()

	svc := gopush.NewService(*configName)

	svc.Start()
}
