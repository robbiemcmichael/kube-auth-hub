package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"gopkg.in/yaml.v2"

	"github.com/robbiemcmichael/kube-auth-hub/internal"
)

func main() {
	configPath := flag.String("c", "config.yaml", "path to the config file")
	flag.Parse()

	data, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	var config internal.Config

	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", internal.Handler)
	bind := fmt.Sprintf("%s:%d", config.Address, config.Port)
	log.Fatal(http.ListenAndServe(bind, nil))
}