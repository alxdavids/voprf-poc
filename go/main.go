package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/alxdavids/oprf-poc/go/client"
	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/alxdavids/oprf-poc/go/server"
)

var (
	validP384Ciphersuite = "OPRF-P384-HKDF-SHA512-SSWU-RO"
	validP521Ciphersuite = "OPRF-P521-HKDF-SHA512-SSWU-RO"
)

func main() {
	var mode, ciphersuite, clientOutFolder, pk string
	var max, n int
	flag.StringVar(&mode, "mode", "", "Specifies which mode to run in, options: (client|server).")
	flag.StringVar(&ciphersuite, "ciph", validP384Ciphersuite, "Specifies the VOPRF ciphersuite to use.")
	flag.StringVar(&clientOutFolder, "out_folder", "", "Specifies an output folder to write files containing the client's stored variables after invocation. If left empty, output is written to console.")
	flag.IntVar(&max, "max_evals", 1, "Specifies the maximum number of OPRF evaluations that are permitted by the server")
	flag.IntVar(&n, "n", 1, "Specifies the number of OPRF evaluations to be attempted by the client")
	flag.StringVar(&pk, "pk", "", "Specifies a hex-encoded public key for use by the client when verifying server messages")
	flag.Parse()

	switch mode {
	case "client":
		fmt.Println("Starting client...")
		if err := runClient(ciphersuite, clientOutFolder, n, pk); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		break
	case "server":
		fmt.Println("Starting server...")
		if err := runServer(ciphersuite, max); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown mode specified")
		flag.Usage()
		os.Exit(1)
	}
}

func runServer(ciphersuite string, max int) error {
	cfgServer, err := server.CreateConfig(ciphersuite, ecgroup.GroupCurve{}, max, false)
	if err != nil {
		return err
	}

	// listen
	err = cfgServer.ListenAndServe()
	if err != nil {
		return err
	}

	return nil
}

func runClient(ciphersuite, clientOutFolder string, n int, pk string) error {
	cfgClient, err := client.CreateConfig(ciphersuite, ecgroup.GroupCurve{}, n, clientOutFolder)
	if err != nil {
		return err
	}

	// Set the input public key on the client
	if pk != "" {
		cfgClient.SetPublicKey(pk)
	}

	// send request to server, and process response
	err = cfgClient.SendOPRFRequest()
	if err != nil {
		return err
	}
	err = cfgClient.PrintStorage()
	if err != nil {
		return err
	}

	return nil
}
