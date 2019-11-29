package server

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oprf/groups/ecgroup"
	"github.com/stretchr/testify/assert"
)

var (
	validOPRFP384Ciphersuite = "OPRF-P384-HKDF-SHA512-SSWU-RO"
	validOPRFP521Ciphersuite = "OPRF-P521-HKDF-SHA512-SSWU-RO"
)

func TestProcessEvalP384(t *testing.T) {
	processOPRFEval(t, validOPRFP384Ciphersuite)
}

func TestProcessEvalP521(t *testing.T) {
	processOPRFEval(t, validOPRFP521Ciphersuite)
}

func processOPRFEval(t *testing.T, validCiphersuite string) {
	cfg, err := CreateConfig(validCiphersuite, ecgroup.GroupCurve{}, false)
	if err.Err() != nil {
		t.Fatal(err.Err())
	}
	pog := cfg.osrv.Ciphersuite().POG()
	P, err := pog.EncodeToGroup([]byte{1, 3, 4, 2})
	if err.Err() != nil {
		t.Fatal(err.Err())
	}
	buf, err := P.Serialize()
	if err.Err() != nil {
		t.Fatal(err.Err())
	}
	ret, err := cfg.processEval(hex.EncodeToString(buf))
	if err.Err() != nil {
		t.Fatal(err.Err())
	}
	Q, err := ecgroup.Point{}.New(pog).Deserialize(ret)
	if err.Err() != nil {
		t.Fatal(err.Err())
	}

	// check scalar mult
	kP, err := P.ScalarMult(cfg.osrv.SecretKey().K)
	if err.Err() != nil {
		t.Fatal(err.Err())
	}

	fmt.Println(kP)
	fmt.Println(Q)

	assert.True(t, kP.Equal(Q))
}
