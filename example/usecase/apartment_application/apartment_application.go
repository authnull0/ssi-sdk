// This is a full example flow of an apartment's manager verifying the age of a potential tenant.

// The apartment manager will create a Presentation Request that is to be fulfilled by the tenant.
// The tenant will fulfil the Presentation Request by submitting a Presentation Submission.
// This presentation submission will contain a verifiable credential that has been previously issued and signed from the government issuer.

// The tenant will verify that the apartment's presentation request is valid and the apartment will also verify that the tenant's
// presentation submission is valid.

// At the end the apartment manager will verify the authenticity of the presentation submission and will be able to verify the birthdate of the tenant.

package main

import (
	"fmt"

	"github.com/authnull0/ssi-sdk/credential"
	"github.com/authnull0/ssi-sdk/credential/exchange"
	"github.com/authnull0/ssi-sdk/credential/signing"
	"github.com/authnull0/ssi-sdk/crypto"
	"github.com/authnull0/ssi-sdk/did"
	"github.com/authnull0/ssi-sdk/example"
	"github.com/authnull0/ssi-sdk/util"
	"github.com/goccy/go-json"
)

func main() {
	/**
		 Step 1: Create new entities as DIDs. Govt Issuer, User Holder, and Apartment Verifier.
	**/

	// User Holder
	holderDIDPrivateKey, holderDIDKey, err := did.GenerateDIDKey(crypto.Ed25519)
	example.HandleExampleError(err, "Failed to generate DID")
	holderSigner, err := crypto.NewJWTSigner(holderDIDKey.String(), holderDIDPrivateKey)
	example.HandleExampleError(err, "Failed to generate signer")
	holderVerifier, err := holderSigner.ToVerifier()
	example.HandleExampleError(err, "Failed to generate verifier")

	// Apt Verifier
	aptDIDPrivateKey, aptDIDKey, err := did.GenerateDIDKey(crypto.Ed25519)
	example.HandleExampleError(err, "Failed to generate DID key")
	aptSigner, err := crypto.NewJWTSigner(aptDIDKey.String(), aptDIDPrivateKey)
	example.HandleExampleError(err, "Failed to generate signer")
	aptVerifier, err := aptSigner.ToVerifier()
	example.HandleExampleError(err, "Failed to generate verifier")

	// Government Issuer
	govtDIDPrivateKey, govtDIDKey, err := did.GenerateDIDKey(crypto.Ed25519)
	example.HandleExampleError(err, "Failed to generate DID key")
	govtSigner, err := crypto.NewJWTSigner(govtDIDKey.String(), govtDIDPrivateKey)
	example.HandleExampleError(err, "Failed to generate signer")

	_, _ = fmt.Print("\n\nStep 1: Create new DIDs for entities\n\n")
	_, _ = fmt.Printf("Tenant: %s\n", string(*holderDIDKey))
	_, _ = fmt.Printf("Apartment: %s\n", string(*aptDIDKey))
	_, _ = fmt.Printf("Government: %s\n", string(*govtDIDKey))

	/**
		 Step 2: Government issuer issues a credential to the holder providing their age. The government issuer then signs the verifiable credentials to holder claiming age.
	**/

	knownIssuer := govtDIDKey
	knownIssuanceDate := "2020-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id":        string(*holderDIDKey),
		"birthdate": "1975-01-01",
	}

	vcBuilder := credential.NewVerifiableCredentialBuilder()

	err = vcBuilder.SetIssuer(string(*knownIssuer))
	example.HandleExampleError(err, "Failed to set issuer")
	err = vcBuilder.SetIssuanceDate(knownIssuanceDate)
	example.HandleExampleError(err, "Failed to set issuance date")
	err = vcBuilder.SetCredentialSubject(knownSubject)
	example.HandleExampleError(err, "Failed to set subject")

	vc, err := vcBuilder.Build()
	example.HandleExampleError(err, "Failed to make verifiable credential")
	example.HandleExampleError(vc.IsValid(), "Verifiable credential is not valid")

	signedVCBytes, err := signing.SignVerifiableCredentialJWT(*govtSigner, *vc)

	example.HandleExampleError(err, "Failed to sign vc")

	_, _ = fmt.Print("\n\nStep 2: Government issues Verifiable Credential new for tenant verifying birthdate and signs\n\n")
	if dat, err := util.PrettyJSON(vc); err == nil {
		_, _ = fmt.Printf("Verifiable Credential:%s\n", string(dat))
	}

	/**
		Step 3: Create presentation definition from the apartment manager to the holder which goes into a presentation request.
		The apartment manager is saying "here tenant, here is my what information I am requesting from you."
	**/

	presentationDefinitionBuilder := exchange.NewPresentationDefinitionBuilder()

	err = presentationDefinitionBuilder.SetInputDescriptors([]exchange.InputDescriptor{
		{
			ID:      "birthdate",
			Purpose: "Age verification",
			Format: &exchange.ClaimFormat{
				JWTVC: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{Fields: []exchange.Field{
				{
					Path: []string{"$.credentialSubject.birthdate"},
					ID:   "birthdate",
				},
			}},
		},
	})
	example.HandleExampleError(err, "Failed to set input descriptors")

	presentationDefinition, err := presentationDefinitionBuilder.Build()
	example.HandleExampleError(err, "Failed to make presentation definition")
	example.HandleExampleError(presentationDefinition.IsValid(), "Presentation definition is not valid")

	presentationRequestBytes, err := exchange.BuildPresentationRequest(*aptSigner, exchange.JWTRequest, *presentationDefinition, string(*holderDIDKey))
	example.HandleExampleError(err, "Failed to make presentation request")

	_, _ = fmt.Print("\n\nStep 3: The apartment creates a presentation request that confirms which information is required from the tenant\n\n")
	if dat, err := util.PrettyJSON(presentationDefinition); err == nil {
		_, _ = fmt.Printf("Presentation Definition that gets added to presentation request:%s\n", string(dat))
	}

	/**
		Step 4: Tenant holder verifies the presentation request from the apt is valid and then constructs and signs a presentation submission.
	**/

	verifiedPresentationDefinition, err := exchange.VerifyPresentationRequest(*aptVerifier, exchange.JWTRequest, presentationRequestBytes)
	example.HandleExampleError(err, "Failed to verify presentation request")
	example.HandleExampleError(verifiedPresentationDefinition.IsValid(), "Verified presentation definition is not valid")

	// TODO: (neal) (issue https://github.com/authnull0/ssi-sdk/issues/165)
	// Have the presentation claim's token format support signedVCBytes for the BuildPresentationSubmission function
	vsJSON, err := signing.ParseVerifiableCredentialFromJWT(string(signedVCBytes))
	example.HandleExampleError(err, "Failed to parse VC")
	vcJSONBytes, err := json.Marshal(vsJSON)
	example.HandleExampleError(err, "Failed to marshal vc jwt")

	presentationClaim := exchange.PresentationClaim{
		TokenJSON:                     util.StringPtr(string(vcJSONBytes)),
		JWTFormat:                     exchange.JWTVC.Ptr(),
		SignatureAlgorithmOrProofType: string(crypto.EdDSA),
	}

	presentationSubmissionBytes, err := exchange.BuildPresentationSubmission(*holderSigner, *presentationDefinition, []exchange.PresentationClaim{presentationClaim}, exchange.JWTVPTarget)
	example.HandleExampleError(err, "Failed to create presentation submission")

	_, _ = fmt.Print("\n\nStep 4: The holder creates a presentation submission to give to the apartment\n\n")
	if dat, err := util.PrettyJSON(presentationClaim); err == nil {
		_, _ = fmt.Printf("Presentation Claim that gets added to presentation submission:%s\n", string(dat))
	}

	/**
		Step 5: The apartment will verify the presentation submission. This is done to make sure the presentation is in compliance with the definition.
	**/

	err = exchange.VerifyPresentationSubmission(*holderVerifier, exchange.JWTVPTarget, *presentationDefinition, presentationSubmissionBytes)
	example.HandleExampleError(err, "Failed to verify presentation submission")

	_, _ = fmt.Print("\n\nStep 5: The apartment verifies that the presentation submission is valid and then can cryptographically verify that the birthdate of the tenant is authentic\n\n")

	_, _ = fmt.Print("\n\n\n🎉 The tenant's age has now been verified and can now move into the apartment! 🎉\n\n\n")
}
