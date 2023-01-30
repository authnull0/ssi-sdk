package pkg

import (
	"encoding/json"
	"fmt"

	"github.com/authnull0/ssi-sdk/credential"
	"github.com/authnull0/ssi-sdk/credential/exchange"
	"github.com/authnull0/ssi-sdk/crypto"
	"github.com/authnull0/ssi-sdk/cryptosuite"
	"github.com/authnull0/ssi-sdk/did"
	"github.com/authnull0/ssi-sdk/example"
	"github.com/authnull0/ssi-sdk/util"
	"github.com/sirupsen/logrus"
)

type Entity struct {
	wallet *example.SimpleWallet
	Name   string
}

func (e *Entity) GetWallet() *example.SimpleWallet {
	return e.wallet
}
func NewEntity(name string, keyType string) (*Entity, error) {
	e := Entity{
		wallet: example.NewSimpleWallet(),
		Name:   name,
	}
	if err := e.wallet.Init(keyType); err != nil {
		return nil, err
	}
	return &e, nil
}

func GenerateDIDPeer() (did.DID, error) {
	kt := crypto.Ed25519
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, err
	}
	peer, err := did.PeerMethod0{}.Generate(kt, pubKey)
	if err != nil {
		return nil, err
	}
	return peer, nil
}

// This validates the VC.
// TODO: Expand on this more
// Simplify it?
func validateVC(vc credential.VerifiableCredential) error {
	issuer := "https://example.edu/issuers/565049"
	assertionMethod := cryptosuite.ProofPurpose("assertionMethod")

	var vc2 credential.VerifiableCredential
	if err := util.Copy(&vc, &vc2); err != nil {
		return err
	}

	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	if err != nil {
		return err
	}

	signer, err := cryptosuite.NewJSONWebKeySigner(issuer, jwk.PrivateKeyJWK, assertionMethod)
	if err != nil {
		return err
	}

	suite := cryptosuite.GetJSONWebSignature2020Suite()
	if err = suite.Sign(signer, &vc2); err != nil {
		return err
	}

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(issuer, jwk.PublicKeyJWK)
	if err != nil {
		return err
	}

	return suite.Verify(verifier, &vc2)
}

// MakePresentationRequest Builds a presentation request (PR). A PR is sent by a holder to a verifier. It can be sent
// over multiple mechanisms. For more information, please go to here:
// https://identity.foundation/presentation-exchange/#presentation-request and for the source code with the sdk,
// https://github.com/authnull0/ssi-sdk/blob/main/credential/exchange/request.go is appropriate to start off with.
func MakePresentationRequest(jwk cryptosuite.JSONWebKey2020, presentationData exchange.PresentationDefinition, targetID string) (pr []byte, signer *crypto.JWTSigner, err error) {
	example.WriteNote("Presentation Request (JWT) is created")

	// Signer uses a JWK
	signer, err = crypto.NewJWTSignerFromJWK(jwk.ID, jwk.PrivateKeyJWK)
	if err != nil {
		return nil, nil, err
	}

	// Builds a presentation request
	// Requires a signer, the presentation data, and a target which is the Audience Key
	requestJWTBytes, err := exchange.BuildJWTPresentationRequest(*signer, presentationData, targetID)
	if err != nil {
		return nil, nil, err
	}

	return requestJWTBytes, signer, err
}

// normalizePresentationClaims takes a set of Presentation Claims and turns them into map[string]interface{} as
// go-JSON representations. The claim format and signature algorithm type are noted as well.
// This method is greedy, meaning it returns the set of claims it was able to normalize.
func normalizePresentationClaims(claims []exchange.PresentationClaim) []exchange.NormalizedClaim {
	var normalizedClaims []exchange.NormalizedClaim
	for _, claim := range claims {
		ae := util.NewAppendError()
		claimJSON, err := claim.GetClaimJSON()
		if err != nil {
			ae.Append(err)
		}
		claimFormat, err := claim.GetClaimFormat()
		if err != nil {
			ae.Append(err)
		}
		if ae.Error() != nil {
			logrus.WithError(ae.Error()).Error("could not normalize claim")
			continue
		}
		var id string
		if claimID, ok := claimJSON["id"]; ok {
			id = claimID.(string)
		}
		normalizedClaims = append(normalizedClaims, exchange.NormalizedClaim{
			ID:             id,
			Data:           claimJSON,
			Format:         claimFormat,
			AlgOrProofType: claim.SignatureAlgorithmOrProofType,
		})
	}
	return normalizedClaims
}

// BuildPresentationSubmission builds a submission using...
// https://github.com/authnull0/ssi-sdk/blob/d279ca2779361091a70b8aa3c685a388067409a9/credential/exchange/submission.go#L126
func BuildPresentationSubmission(presentationRequest []byte, signer crypto.JWTSigner, verifier crypto.JWTVerifier, vc credential.VerifiableCredential) ([]byte, error) {
	presentationClaim := exchange.PresentationClaim{
		Credential:                    &vc,
		LDPFormat:                     exchange.LDPVC.Ptr(),
		SignatureAlgorithmOrProofType: string(cryptosuite.JSONWebSignature2020),
	}

	parsed, err := verifier.VerifyAndParseJWT(string(presentationRequest))
	if err != nil {
		return nil, err
	}

	def, ok := parsed.Get(exchange.PresentationDefinitionKey)
	if !ok {
		return nil, fmt.Errorf("presentation definition key<%s> not found in token", exchange.PresentationDefinitionKey)
	}

	dat, err := json.Marshal(def)
	if err != nil {
		return nil, err
	}
	var pd exchange.PresentationDefinition
	if err = json.Unmarshal(dat, &pd); err != nil {
		return nil, err
	}

	submissionBytes, err := exchange.BuildPresentationSubmission(signer, pd, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)
	if err != nil {
		return nil, err
	}

	return submissionBytes, nil
}

// MakePresentationData Makes a dummy presentation definition. These are eventually transported via Presentation Request.
// For more information on presentation definitions view the spec here:
// https://identity.foundation/presentation-exchange/#term:presentation-definition
func MakePresentationData(id string, inputID string) (exchange.PresentationDefinition, error) {
	// Input Descriptors: Describe the information the verifier requires of the holder
	// https://identity.foundation/presentation-exchange/#input-descriptor
	// Required fields: ID and Input Descriptors
	def := exchange.PresentationDefinition{
		ID: id,
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID: inputID,
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
						{
							Path:    []string{"$.vc.issuer", "$.issuer"},
							ID:      "issuer-input-descriptor",
							Purpose: "need to check the issuer",
						},
					},
				},
			},
		},
	}
	example.WriteNote("Presentation Definition is formed. Asks for the issuer and the data from the issuer")
	err := def.IsValid()
	return def, err
}
