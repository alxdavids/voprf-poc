package groups

import (
	"hash"
	"math/big"

	"github.com/alxdavids/voprf-poc/go/oerr"
	"github.com/alxdavids/voprf-poc/go/oprf/utils"
)

// IDs for supported ciphersuites.
const (
	OPRF_CURVE25519_SHA512 = iota + 1
	OPRF_CURVE448_SHA512
	OPRF_P256_SHA512
	OPRF_P384_SHA512
	OPRF_P521_SHA512

	OPRF_INVALID_CIPHERSUITE = 255
)

const (
	GROUP_CURVE25519 = iota + 1
	GROUP_CURVE448
	GROUP_P256
	GROUP_P384
	GROUP_P521
)

// Ciphersuite corresponds to the OPRF ciphersuite that is chosen. The
// Ciphersuite object determines the prime-order group (pog) that is used for
// performing the (V)OPRF operations, along with the different hash function
// definitions.
// Should be created using FromString, using a string of the form:
//	  <function>-<curve>-<extractor_expander>-<hash_func>-<h2c-name>
// The supported settings are: function ∈ ["OPRF", "VOPRF"], curve ∈ ["P384",
// "P521"], extractor-expander ∈ ["HKDF"], hash_func ∈ ["SHA-512"], h2c-name ∈
// ["SSWU-RO"].
type Ciphersuite struct {
	// id of the ciphersuite
	id int

	// PrimeOrderGroup instantiation for performing the OPRF operations.
	pog PrimeOrderGroup

	// hash function
	hash hash.Hash
}

// FromID creates a Ciphersuite object can be created from a
// ciphersuite ID.
func (c Ciphersuite) FromID(id int, pog PrimeOrderGroup) (Ciphersuite, error) {
	// TODO: construct the PrimeOrderGroup object
	var pogNew PrimeOrderGroup
	var err error
	switch id {
	case OPRF_CURVE25519_SHA512:
		pogNew, err = pog.New(GROUP_CURVE25519)
	case OPRF_CURVE448_SHA512:
		pogNew, err = pog.New(GROUP_CURVE448)
	case OPRF_P521_SHA512:
		pogNew, err = pog.New(GROUP_P521)
	case OPRF_P256_SHA512:
		pogNew, err = pog.New(GROUP_P256)
	case OPRF_P384_SHA512:
		pogNew, err = pog.New(GROUP_P384)
	default:
		return Ciphersuite{}, oerr.ErrUnsupportedCiphersuite
	}
	if err != nil {
		return Ciphersuite{}, err
	}

	return Ciphersuite{
		id:   id,
		pog:  pogNew,
		hash: pogNew.Hash(),
	}, nil
}

// Name returns the name of the Ciphersuite
func (c Ciphersuite) Name() string { return IDtoName(c.id) }

// ID returns the ID of the Ciphersuite
func (c Ciphersuite) ID() int { return c.id }

// Hash returns the hash function specified in Ciphersuite
func (c Ciphersuite) Hash() hash.Hash {
	c.hash.Reset()
	return c.hash
}

// POG returns the PrimeOrderGroup for the current Ciphersuite
func (c Ciphersuite) POG() PrimeOrderGroup { return c.pog }

func IDtoName(id int) string {
	switch id {
	case OPRF_CURVE25519_SHA512:
		return "OPRF_CURVE25519_SHA512"
	case OPRF_CURVE448_SHA512:
		return "OPRF_CURVE448_SHA512"
	case OPRF_P256_SHA512:
		return "OPRF_P256_SHA512"
	case OPRF_P384_SHA512:
		return "OPRF_P384_SHA512"
	case OPRF_P521_SHA512:
		return "OPRF_P521_SHA512"
	}
	return "Unsupported Ciphersuite"
}

// PrimeOrderGroup is an interface that defines operations within additive
// groups of prime order. This is the setting in which the (V)OPRF operations
// take place.
//
// Any valid OPRF instantiation should extend this interface. Currently, only
// prime-order-groups derived from the NIST P384 and P521 curves are supported.
type PrimeOrderGroup interface {
	// Creates a new PrimeOrderGroup object
	New(int) (PrimeOrderGroup, error)

	// Returns the identifying name of the group
	Name() string

	// Returns the identity element of the group
	Identity() GroupElement

	// Returns the canonical (fixed) generator for defined group
	Generator() GroupElement

	// Returns kG, where G is the canonical generator of the group, and k is
	// some scalar value provided as input.
	GeneratorMult(*big.Int) (GroupElement, error)

	// Returns the order of the canonical generator in the group.
	Order() *big.Int

	// Returns the ByteLength of GroupElement objects associated with the group
	ByteLength() int

	// Performs a transformation to encode bytes as a GroupElement object in the
	// group. We expect that HashToGroup models a random oracle
	HashToGroup([]byte) (GroupElement, error)

	// Performs a transformation to encode bytes as a scalar from the field
	// of scalars defined by the group order
	HashToScalar([]byte) (*big.Int, error)

	// Base hash function used in conjunction with the PrimeOrderGroup
	Hash() hash.Hash

	// Base extractor-expander function used with the PrimeOrderGroup. We
	// currently only support HKDF using the HKDF_Extract and HKDF_Expand modes.
	EE() utils.ExtractorExpander

	// Samples a random scalar value from the field of scalars defined by the
	// group order.
	RandomScalar() (*big.Int, error)

	// Casts a scalar for the given group to the correct number of bytes
	ScalarToBytes(*big.Int) []byte
}

// GroupElement is the interface that represents group elements in a given
// PrimeOrderGroup instantiation.
//
// Any valid group element in the prime-order-group must extend this interface.
// Currently, only prime-order-groups derived from the NIST P384 and P521 curves
// are supported. In these settings, we instantiate GroupElement as points along
// these curves
type GroupElement interface {
	// New constructs a GroupElement object for the associated PrimeOrderGroup
	// instantiation
	New(PrimeOrderGroup) GroupElement

	// Returns a bool indicating that the GroupElement is valid for the
	// PrimeOrderGroup
	IsValid() bool

	// Performs a scalar multiplication of the group element with some scalar
	// input
	ScalarMult(*big.Int) (GroupElement, error)

	// Performs the group addition operation on the calling GroupElement object
	// along with a separate GroupElement provided as input
	Add(GroupElement) (GroupElement, error)

	// Serializes the GroupElement into a byte slice
	Serialize() ([]byte, error)

	// Attempts to deserialize a byte slice into a group element
	Deserialize([]byte) (GroupElement, error)

	// Returns a bool indicating whether two GroupElements are equal
	Equal(GroupElement) bool
}

// CreateGroupElement inits a new group element
func CreateGroupElement(pog PrimeOrderGroup) GroupElement {
	return pog.Generator().New(pog)
}

type GroupElementList []GroupElement

func (gel GroupElementList) Serialize() ([]byte, error) {
	result := make([]byte, 0)

	for _, ge := range gel {
		raw, err := ge.Serialize()
		if err != nil {
			return nil, err
		}

		result = append(result, raw...)
	}

	return result, nil
}
