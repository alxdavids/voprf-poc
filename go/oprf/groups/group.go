package groups

import (
	"crypto/hmac"
	"crypto/sha512"
	"hash"
	"math/big"
	"reflect"
	"strings"

	"github.com/alxdavids/oprf-poc/go/oerr"
	"github.com/alxdavids/oprf-poc/go/oprf/utils"
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen
type Ciphersuite struct {
	name        string
	pog         PrimeOrderGroup
	hash1       func([]byte) (GroupElement, error)
	hash2       func(func() hash.Hash, []byte) hash.Hash
	hashGeneric hash.Hash
	hash5       utils.ExtractorExpander
	verifiable  bool
}

// FromString derives a ciphersuite from the string that was provided,
// corresponding to a given PrimeOrderGroup implementation
func (c Ciphersuite) FromString(s string, pog PrimeOrderGroup) (Ciphersuite, error) {
	split := strings.SplitN(s, "-", 5)

	// construct the PrimeOrderGroup object
	var pogNew PrimeOrderGroup
	var err error
	switch split[1] {
	case "P384":
		pogNew, err = pog.New("P-384")
		break
	case "P521":
		pogNew, err = pog.New("P-521")
		break
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedGroup
	}
	if err != nil {
		return Ciphersuite{}, err
	}

	// Check ExtractorExpander{} is supported (only HKDF currently)
	switch split[2] {
	case "HKDF":
		if reflect.TypeOf(pogNew.EE()).Name() != "HKDFExtExp" {
			return Ciphersuite{}, oerr.ErrUnsupportedEE
		}
		break
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedEE
	}

	// check hash function support
	switch split[3] {
	case "SHA512":
		if reflect.DeepEqual(pog.Hash(), sha512.New()) {
			// do a quick check to see if the hash function is the same
			return Ciphersuite{}, oerr.ErrUnsupportedHash
		}
		break
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedHash
	}

	// check hash-to-curve support
	switch split[4] {
	case "SSWU-RO":
		// do nothing
		break
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedH2C
	}

	// derive Ciphersuite object
	h1 := pogNew.EncodeToGroup
	h2 := hmac.New
	hashGeneric := pogNew.Hash()
	var h5 utils.ExtractorExpander
	verifiable := false
	if split[0] == "VOPRF" {
		verifiable = true
		h5 = pogNew.EE()
	}
	return Ciphersuite{
		name:        s,
		pog:         pogNew,
		hash1:       h1,
		hash2:       h2,
		hashGeneric: hashGeneric,
		hash5:       h5,
		verifiable:  verifiable,
	}, nil
}

// Name returns the name of the Ciphersuite
func (c Ciphersuite) Name() string { return c.name }

// H1 returns the hash1 function specified in Ciphersuite
func (c Ciphersuite) H1() func([]byte) (GroupElement, error) { return c.hash1 }

// H2 returns the hash2 function specified in Ciphersuite
func (c Ciphersuite) H2() func(func() hash.Hash, []byte) hash.Hash { return c.hash2 }

// H3 returns the hashGeneric function specified in Ciphersuite
func (c Ciphersuite) H3() hash.Hash {
	c.hashGeneric.Reset()
	return c.hashGeneric
}

// H4 returns the hashGeneric function specified in Ciphersuite
func (c Ciphersuite) H4() hash.Hash {
	c.hashGeneric.Reset()
	return c.hashGeneric
}

// H5 returns the hash5 function specified in Ciphersuite
func (c Ciphersuite) H5() utils.ExtractorExpander { return c.hash5 }

// POG returns the PrimeOrderGroup for the current Ciphersuite
func (c Ciphersuite) POG() PrimeOrderGroup { return c.pog }

// Verifiable returns whether the ciphersuite corresponds to a VOPRF or not
func (c Ciphersuite) Verifiable() bool { return c.verifiable }

// PrimeOrderGroup is an interface that defines operations within additive
// groups of prime order
type PrimeOrderGroup interface {
	New(string) (PrimeOrderGroup, error)
	Name() string
	Generator() GroupElement
	GeneratorMult(*big.Int) (GroupElement, error)
	Order() *big.Int
	ByteLength() int
	EncodeToGroup([]byte) (GroupElement, error)
	Hash() hash.Hash
	EE() utils.ExtractorExpander
	UniformFieldElement() (*big.Int, error)
}

// GroupElement is the interface that represents group elements in a given Group
// instantiation
type GroupElement interface {
	New(PrimeOrderGroup) GroupElement
	IsValid() bool
	ScalarMult(*big.Int) (GroupElement, error)
	Add(GroupElement) (GroupElement, error)
	Serialize() ([]byte, error)
	Deserialize([]byte) (GroupElement, error)
	Equal(GroupElement) bool
}

// CreateGroupElement creates a new group element from scratch
func CreateGroupElement(pog PrimeOrderGroup) GroupElement {
	return pog.Generator().New(pog)
}
