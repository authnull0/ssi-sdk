package did

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

type (
	DIDBrcm string
)

const (
	// DIDBrcmPrefix did:key prefix
	DIDBrcmPrefix = "did:brcm"
)

func (d DIDBrcm) IsValid() bool {
	_, err := d.Expand()
	return err == nil
}

func (d DIDBrcm) String() string {
	return string(d)
}

// Suffix returns the value without the `did:key` prefix
func (d DIDBrcm) Suffix() (string, error) {
	split := strings.Split(string(d), DIDBrcmPrefix+":")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid did:key: %s", d)
	}
	return split[1], nil
}

func (DIDBrcm) Method() Method {
	return KeyMethod
}

// GenerateDIDBrcm takes in a key type value that this library supports and constructs a conformant did:key identifier.
// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
// To use the private key, it is recommended to re-cast to the associated type. For example, called with the input
// for a secp256k1 key:
// privKey, didKey, err := GenerateDIDBrcm(SECP256k1)
// if err != nil { ... }
// // where secp is an import alias to the secp256k1 library we use "github.com/decred/dcrd/dcrec/secp256k1/v4"
// secpPrivKey, ok := privKey.(secp.PrivateKey)
// if !ok { ... }
func GenerateDIDBrcm(kt crypto.KeyType) (gocrypto.PrivateKey, *DIDBrcm, error) {
	if !isSupportedKeyType(kt) {
		return nil, nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for did:key")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not convert public key to byte")
	}

	didKey, err := CreateDIDBrcm(kt, pubKeyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not create DID key")
	}
	return privKey, didKey, err
}

// CreateDIDBrcm constructs a did:key from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type.
// A safer method is `GenerateDIDBrcm` which handles key generation based on the provided key type.
func CreateDIDBrcm(kt crypto.KeyType, publicKey []byte) (*DIDBrcm, error) {
	if !isSupportedKeyType(kt) {
		return nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	// did:key:<multibase encoded, multicodec identified, public key>
	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		return nil, fmt.Errorf("could find mutlicodec for key type<%s> for did:key", kt)
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(Base58BTCMultiBase, codec)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode did:key")
	}
	did := DIDBrcm(fmt.Sprintf("%s:%s", DIDBrcmPrefix, encoded))
	return &did, nil
}

// Decode takes a did:key and returns the underlying public key value as bytes, the LD key type, and a possible error
func (d DIDBrcm) Decode() ([]byte, cryptosuite.LDKeyType, crypto.KeyType, error) {
	parsed, err := d.Suffix()
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not parse did:key")
	}
	if parsed == "" {
		return nil, "", "", fmt.Errorf("could not decode did:key value: %s", string(d))
	}

	encoding, decoded, err := multibase.Decode(parsed)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not decode did:key")
	}
	if encoding != Base58BTCMultiBase {
		return nil, "", "", fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", "", err
	}
	if n != 2 {
		return nil, "", "", errors.New("error parsing did:key varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	ldKeyType, err := codecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining LD key type")
	}
	cryptoKeyType, err := codecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining key type")
	}
	return pubKeyBytes, ldKeyType, cryptoKeyType, nil
}

// Expand turns the DID key into a compliant DID Document
func (d DIDBrcm) Expand() (*DIDDocument, error) {
	parsed, err := d.Suffix()
	if err != nil {
		return nil, errors.Wrap(err, "could not parse did:key")
	}

	keyReference := "#" + parsed
	id := string(d)

	pubKey, keyType, cryptoKeyType, err := d.Decode()
	if err != nil {
		return nil, errors.Wrap(err, "could not decode did:key")
	}

	verificationMethod, err := constructVerificationMethod(id, keyReference, pubKey, keyType, cryptoKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct verification method")
	}

	verificationMethodSet := []VerificationMethodSet{
		[]string{keyReference},
	}

	return &DIDDocument{
		Context:              KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}, nil
}

func GetSupportedDIDBrcmTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}
