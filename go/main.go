package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/alxdavids/oprf-poc/go/client"
	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/oprf-poc/go/server"
)

var (
	validP384Ciphersuite = "OPRF-P384-HKDF-SHA512-SSWU-RO"
	validP521Ciphersuite = "OPRF-P521-HKDF-SHA512-SSWU-RO"
)

func main() {
	var mode, ciphersuite, clientOutFolder string
	flag.StringVar(&mode, "mode", "", "Specifies which mode to run in, options: (client|server).")
	flag.StringVar(&ciphersuite, "ciph", validP384Ciphersuite, "Specifies the VOPRF ciphersuite to use.")
	flag.StringVar(&clientOutFolder, "out_folder", "", "Specifies an output folder to write files containing the client's stored variables after invocation. If left empty, output is written to console.")
	flag.Parse()

	switch mode {
	case "client":
		fmt.Println("Starting client...")
		if err := runClient(ciphersuite, clientOutFolder); err.Err() != nil {
			fmt.Println(err.Err())
			os.Exit(1)
		}
		break
	case "server":
		fmt.Println("Starting server...")
		if err := runServer(ciphersuite); err.Err() != nil {
			fmt.Println(err.Err())
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown mode specified")
		flag.Usage()
		os.Exit(1)
	}
}

func runServer(ciphersuite string) oerr.Error {
	cfgServer, err := server.CreateConfig(ciphersuite, ecgroup.GroupCurve{}, false)
	if err.Err() != nil {
		return err
	}

	// listen
	err = cfgServer.ListenAndServe()
	if err.Err() != nil {
		return err
	}

	return oerr.Nil()
}

func runClient(ciphersuite, clientOutFolder string) oerr.Error {
	cfgClient, err := client.CreateConfig(ciphersuite, ecgroup.GroupCurve{}, 1, clientOutFolder)
	if err.Err() != nil {
		return err
	}

	// send request to server, and process response
	err = cfgClient.SendOPRFRequest()
	if err.Err() != nil {
		return err
	}
	err = cfgClient.PrintStorage()
	if err.Err() != nil {
		return err
	}

	return oerr.Nil()
}
