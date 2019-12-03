package server

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/alxdavids/oprf-poc/go/jsonrpc"
	"github.com/alxdavids/oprf-poc/go/oerr"
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

func TestCreateConfigP384(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cfg.osrv.Ciphersuite().POG().(ecgroup.GroupCurve).Name(), "P-384")
}

func TestCreateConfigP521(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP521Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cfg.osrv.Ciphersuite().POG().(ecgroup.GroupCurve).Name(), "P-521")
}

func TestCreateConfigBadCiph(t *testing.T) {
	_, err := CreateConfig("OPRF-P521-HKDF-SHA256-SSWU-RO", ecgroup.GroupCurve{}, false)
	if err != oerr.ErrUnsupportedHash {
		t.Fatal("Error should have occurred (bad hash in ciphersuite)")
	}
}

func TestProcessValidJSONRPCRequest(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	pog := cfg.osrv.Ciphersuite().POG()
	P, err := pog.EncodeToGroup([]byte("random_input"))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := P.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		Params:  []string{hex.EncodeToString(buf)},
		ID:      1,
	}
	// actual value checks are done in other tests
	ret, err := cfg.processJSONRPCRequest(jsonrpcReq)
	if err != nil {
		t.Fatal(err)
	}
	// expecting compressed points
	assert.Equal(t, len(ret), pog.ByteLength()+1)
}

func TestInvalidJSONRPCRequestMethod(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	P, err := cfg.osrv.Ciphersuite().POG().EncodeToGroup([]byte("random_input"))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := P.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "2.0",
		Method:  "bad_method",
		Params:  []string{hex.EncodeToString(buf)},
		ID:      1,
	}
	// actual value checks are done in other tests
	_, err = cfg.processJSONRPCRequest(jsonrpcReq)
	if err != oerr.ErrJSONRPCMethodNotFound {
		t.Fatal("bad method should have caused errors")
	}
}

func TestInvalidJSONRPCRequestVersion(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	P, err := cfg.osrv.Ciphersuite().POG().EncodeToGroup([]byte("random_input"))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := P.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "1.0",
		Method:  "eval",
		Params:  []string{hex.EncodeToString(buf)},
		ID:      1,
	}
	// actual value checks are done in other tests
	_, err = cfg.processJSONRPCRequest(jsonrpcReq)
	if err != oerr.ErrJSONRPCInvalidRequest {
		t.Fatal("bad version should have caused errors")
	}
}

func TestInvalidJSONRPCRequestEmptyParams(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		ID:      1,
	}
	// actual value checks are done in other tests
	_, err = cfg.processJSONRPCRequest(jsonrpcReq)
	if err != oerr.ErrJSONRPCInvalidMethodParams {
		fmt.Println(err)
		t.Fatal("bad method params should have caused errors")
	}
}

func TestInvalidJSONRPCRequestBadlyEncodedParam(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		Params:  []string{"badly_encoded_string"},
		ID:      1,
	}
	// actual value checks are done in other tests
	_, err = cfg.processJSONRPCRequest(jsonrpcReq)
	if err != oerr.ErrJSONRPCInvalidMethodParams {
		fmt.Println(err)
		t.Fatal("bad method params should have caused errors")
	}
}

func TestInvalidJSONRPCRequestBadParams(t *testing.T) {
	cfg, err := CreateConfig(validOPRFP384Ciphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq := &jsonrpc.Request{
		Version: "2.0",
		Method:  "eval",
		Params:  []string{hex.EncodeToString([]byte("bad_byte_string"))},
		ID:      1,
	}
	// actual value checks are done in other tests
	_, err = cfg.processJSONRPCRequest(jsonrpcReq)
	if err != oerr.ErrDeserializing {
		fmt.Println(err)
		t.Fatal("bad method params should have caused errors")
	}
}

func processOPRFEval(t *testing.T, validCiphersuite string) {
	cfg, err := CreateConfig(validCiphersuite, ecgroup.GroupCurve{}, false)
	if err != nil {
		t.Fatal(err)
	}
	pog := cfg.osrv.Ciphersuite().POG()
	P, err := pog.EncodeToGroup([]byte{1, 3, 4, 2})
	if err != nil {
		t.Fatal(err)
	}
	buf, err := P.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ret, err := cfg.processEval(hex.EncodeToString(buf))
	if err != nil {
		t.Fatal(err)
	}
	Q, err := ecgroup.Point{}.New(pog).Deserialize(ret)
	if err != nil {
		t.Fatal(err)
	}

	// check scalar mult
	kP, err := P.ScalarMult(cfg.osrv.SecretKey().K)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, kP.Equal(Q))
}
