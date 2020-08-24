package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/alxdavids/voprf-poc/go/jsonrpc"
	"github.com/alxdavids/voprf-poc/go/oerr"
	gg "github.com/alxdavids/voprf-poc/go/oprf/groups"
	"github.com/alxdavids/voprf-poc/go/oprf/groups/ecgroup"
	"github.com/stretchr/testify/assert"
)

func TestCreateConfigP384(t *testing.T) {
	cfg, err := CreateConfig(gg.OPRF_P384_SHA512, ecgroup.GroupCurve{}, 1, "some_file", -1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cfg.ocli.Ciphersuite().POG().Name(), ecgroup.CurveNameP384)
	assert.Equal(t, cfg.n, 1)
	assert.Equal(t, cfg.addr, "http://localhost:3001")
	assert.Equal(t, cfg.outputPath, "some_file")
}

func TestCreateConfigP521(t *testing.T) {
	cfg, err := CreateConfig(gg.OPRF_P521_SHA512, ecgroup.GroupCurve{}, 1, "some_file", -1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cfg.ocli.Ciphersuite().POG().Name(), ecgroup.CurveNameP521)
	assert.Equal(t, cfg.n, 1)
	assert.Equal(t, cfg.addr, "http://localhost:3001")
	assert.Equal(t, cfg.outputPath, "some_file")
}

func TestCreateConfigC448(t *testing.T) {
	cfg, err := CreateConfig(gg.OPRF_CURVE448_SHA512, ecgroup.GroupCurve{}, 1, "some_file", -1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cfg.ocli.Ciphersuite().POG().Name(), ecgroup.CurveNameCurve448)
	assert.Equal(t, cfg.n, 1)
	assert.Equal(t, cfg.addr, "http://localhost:3001")
	assert.Equal(t, cfg.outputPath, "some_file")
}

func TestInvalidCiphersuite(t *testing.T) {
	_, err := CreateConfig(gg.GROUP_P256, ecgroup.GroupCurve{}, 1, "", -1)
	if !errors.Is(err, oerr.ErrUnsupportedGroup) {
		t.Fatal("bad group should have triggered a bad ciphersuite error")
	}
}

func TestCreateOPRFRequestP384(t *testing.T) {
	CreateOPRFRequest(t, gg.OPRF_P384_SHA512)
}

func TestCreateOPRFRequestP521(t *testing.T) {
	CreateOPRFRequest(t, gg.OPRF_P521_SHA512)
}

func TestCreateOPRFRequestC448(t *testing.T) {
	CreateOPRFRequest(t, gg.OPRF_CURVE448_SHA512)
}

func CreateOPRFRequest(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcReq, err := cfg.createOPRFRequest()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, jsonrpcReq.Version, version2)
	assert.Equal(t, jsonrpcReq.Method, "eval")
	assert.Equal(t, jsonrpcReq.ID, 1)
	assert.Equal(t, 1, len(jsonrpcReq.Params.Data))
	buf, err := hex.DecodeString(jsonrpcReq.Params.Data[0])
	if err != nil {
		t.Fatal(err)
	}
	// compressed encoding
	pog := cfg.ocli.Ciphersuite().POG()
	assert.Equal(t, pog.ByteLength()+1, len(buf))
	ge, err := gg.CreateGroupElement(pog).Deserialize(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, ge.IsValid())
	assert.Equal(t, len(storedTokens), 1)

	// check that the point is correctly formed
	geChk, err := pog.HashToGroup(storedTokens[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	blindChk, err := geChk.ScalarMult(storedTokens[0].Blind)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, ge.Equal(blindChk))
}

func TestCreateOPRFRequestBadNP384(t *testing.T) {
	CreateOPRFRequestBadN(t, gg.OPRF_P384_SHA512)
}

func TestCreateOPRFRequestBadNP521(t *testing.T) {
	CreateOPRFRequestBadN(t, gg.OPRF_P521_SHA512)
}

func TestCreateOPRFRequestBadNC448(t *testing.T) {
	CreateOPRFRequestBadN(t, gg.OPRF_CURVE448_SHA512)
}

func CreateOPRFRequestBadN(t *testing.T, ciphID int) {
	cfg, err := CreateConfig(ciphID, ecgroup.GroupCurve{}, -1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.createOPRFRequest()
	if err == nil {
		t.Fatal("n < 0 should be unsupported")
	}
}

func TestCreateJSONRPCRequestP384(t *testing.T) {
	CreateJSONRPCRequest(t, gg.OPRF_P384_SHA512)
}

func TestCreateJSONRPCRequestP521(t *testing.T) {
	CreateJSONRPCRequest(t, gg.OPRF_P521_SHA512)
}

func TestCreateJSONRPCRequestC448(t *testing.T) {
	CreateJSONRPCRequest(t, gg.OPRF_CURVE448_SHA512)
}

func CreateJSONRPCRequest(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	buf0 := []byte{1, 2, 3, 4}
	buf1 := []byte{3, 4, 5, 6}
	jsonrpcReq := cfg.createJSONRPCRequest([][]byte{buf0, buf1}, 3)
	assert.Equal(t, jsonrpcReq.Version, version2)
	assert.Equal(t, jsonrpcReq.Method, "eval")
	assert.Equal(t, jsonrpcReq.Params.Data[0], hex.EncodeToString(buf0))
	assert.Equal(t, jsonrpcReq.Params.Data[1], hex.EncodeToString(buf1))
	assert.Equal(t, jsonrpcReq.ID, 3)
}

func TestParseJSONRPCResponseSuccessP384(t *testing.T) {
	ParseJSONRPCResponseSuccess(t, gg.OPRF_P384_SHA512)
}

func TestParseJSONRPCResponseSuccessP521(t *testing.T) {
	ParseJSONRPCResponseSuccess(t, gg.OPRF_P521_SHA512)
}

func TestParseJSONRPCResponseSuccessC448(t *testing.T) {
	ParseJSONRPCResponseSuccess(t, gg.OPRF_CURVE448_SHA512)
}

func ParseJSONRPCResponseSuccess(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcResp := &jsonrpc.ResponseSuccess{
		Version: version2,
		Result:  jsonrpc.ResponseResult{Data: []string{"some_response_string"}},
		ID:      1,
	}
	buf, e := json.Marshal(jsonrpcResp)
	if e != nil {
		t.Fatal(e)
	}
	jsonrpcSuccess, err := cfg.parseJSONRPCResponse(buf)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, jsonrpcSuccess.Version, jsonrpcResp.Version)
	assert.Equal(t, jsonrpcSuccess.ID, jsonrpcResp.ID)
	results := jsonrpcSuccess.Result.Data
	assert.Equal(t, len(results), 1)
	assert.Equal(t, results[0], jsonrpcResp.Result.Data[0])
}

func TestParseJSONRPCResponseErrorP384(t *testing.T) {
	ParseJSONRPCResponseError(t, gg.OPRF_P384_SHA512)
}

func TestParseJSONRPCResponseErrorP521(t *testing.T) {
	ParseJSONRPCResponseError(t, gg.OPRF_P521_SHA512)
}

func TestParseJSONRPCResponseErrorC448(t *testing.T) {
	ParseJSONRPCResponseError(t, gg.OPRF_CURVE448_SHA512)
}

func ParseJSONRPCResponseError(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	errorMessage := "error_message"
	errorCode := -33001
	jsonrpcResp := &jsonrpc.ResponseError{
		Version: version2,
		Error: oerr.ErrorJSON{
			Message: errorMessage,
			Code:    errorCode,
		},
		ID: 1,
	}
	buf, e := json.Marshal(jsonrpcResp)
	if e != nil {
		t.Fatal(e)
	}
	ret, err := cfg.parseJSONRPCResponse(buf)
	if err == nil {
		fmt.Println(ret)
		t.Fatal("Error should have occurred")
	}
	assert.Equal(t, err, errors.New(errorMessage))
}

func TestParseJSONRPCResponseInvalidResultP384(t *testing.T) {
	ParseJSONRPCResponseInvalidResult(t, gg.OPRF_P384_SHA512)
}

func TestParseJSONRPCResponseInvalidResultP521(t *testing.T) {
	ParseJSONRPCResponseInvalidResult(t, gg.OPRF_P521_SHA512)
}

func TestParseJSONRPCResponseInvalidResultC448(t *testing.T) {
	ParseJSONRPCResponseInvalidResult(t, gg.OPRF_CURVE448_SHA512)
}

func ParseJSONRPCResponseInvalidResult(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcResp := make(map[string]interface{})
	jsonrpcResp["Version"] = version2
	jsonrpcResp["Result"] = 7
	jsonrpcResp["ID"] = 3
	buf, e := json.Marshal(jsonrpcResp)
	if e != nil {
		t.Fatal(e)
	}
	_, err = cfg.parseJSONRPCResponse(buf)
	if err == nil {
		t.Fatal("Server response error should have occurred")
	}
}

func TestParseJSONRPCResponseInvalidFieldP384(t *testing.T) {
	ParseJSONRPCResponseInvalidField(t, gg.OPRF_P384_SHA512)
}

func TestParseJSONRPCResponseInvalidFieldP521(t *testing.T) {
	ParseJSONRPCResponseInvalidField(t, gg.OPRF_P521_SHA512)
}

func TestParseJSONRPCResponseInvalidFieldC448(t *testing.T) {
	ParseJSONRPCResponseInvalidField(t, gg.OPRF_CURVE448_SHA512)
}

func ParseJSONRPCResponseInvalidField(t *testing.T, ciph int) {
	cfg, err := CreateConfig(ciph, ecgroup.GroupCurve{}, 1, "", -1)
	if err != nil {
		t.Fatal(err)
	}
	jsonrpcResp := make(map[string]interface{})
	jsonrpcResp["Version"] = version2
	jsonrpcResp["Weird"] = []string{"some_string"}
	jsonrpcResp["ID"] = 3
	buf, e := json.Marshal(jsonrpcResp)
	if e != nil {
		t.Fatal(e)
	}
	_, err = cfg.parseJSONRPCResponse(buf)
	if err == nil {
		t.Fatal("Server response error should have occurred")
	}
}
