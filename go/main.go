package main

import (
	"fmt"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/oprf-poc/go/server"
	"os"
)

var (
	validP384Ciphersuite = "OPRF-P384-HKDF-SHA512-SSWU-RO"
)

func main() {
	cfg, err := server.CreateConfig(false, validP384Ciphersuite, ecgroup.GroupCurve{})
	if err.Err() != nil {
		fmt.Println("Failed to establish server configuration")
		os.Exit(1)
	}

	// listen
	err = cfg.ListenAndServe()
	if err.Err() != nil {
		fmt.Println(err.Err())
		os.Exit(1)
	}
}
