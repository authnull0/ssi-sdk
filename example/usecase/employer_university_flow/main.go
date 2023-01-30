// A dead simple example of a full. Simulates that a student has graduated from a university. They are given a VC
// from the university. An employer wants to ascertain if the student graduated from the university. They will request
// the information, the student will respond.
//
// We use two different did methods here. did:key and a custom did method specified in this file: did:example.
// The university uses did:example and the user uses did:key.

// Initialization Step: Initialize the Wallet/Holder and the University
// Step 0: University issues a VC to the Holder and sends it over
// Step 1: Verifier requests data from the holder
// Step 2: Holder sends credential
// Step 3: Verifier grants access based on the result

//                          |--------------------------|
//                          |                          |
//                          |   Issuer (University)    |
//                          |                          |
//                          |__________________________|
//                             /                       \
//                            /                          \ Trusts University
//      -----------------    / Issues VC               -------------------------
//     |                |   /                         |                         |
//     |   Holder       |  / <--------------------->  |    Verifier (Employer)  |
//     |      \Wallet   |      PresentationRequest    |                         |
//     |----------------|                              --------------------------
//
//  A couple nuances that are necessary to understand at a high level before
//  digging into this code.
//
//  1. A DID can be used against different method types. Each method has
//  different functions. For example, bitcoin works differently than peer.
//  did:btc vs. did:peer is how these methods specified.
//
//  2. A Verified Credential (VC) contains a cyrptographic proof, either explicit
//   or embedded into the VC. For the purposes of this demo, the proof is
//   embedded in a JSON Web Token (JTW)
//
//  3. When the Verifier wants to validate a user, they send a Presentation Request.
//   The response will contain the VC. The Verifier will be able to determine if the VC
//   has been tampered with due to the proof.
//
//   The objects being created are in the following order:
//
//  1. DIDs and wallets are created for the holder, issuer, and verifier
//  3. VC is issued to the student holder
//  4. PresentationRequest submitted by the verifier
//  5. PresentationSubmission returned by the holder
//  6. Authorization from the Verifier.

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/authnull0/ssi-sdk/crypto"
	"github.com/authnull0/ssi-sdk/example"
	emp "github.com/authnull0/ssi-sdk/example/usecase/employer_university_flow/pkg"

	"github.com/authnull0/ssi-sdk/credential/signing"
	"github.com/authnull0/ssi-sdk/cryptosuite"
	"github.com/sirupsen/logrus"
)

// Set to debug mode here
var debug = os.Getenv("DEBUG")

const (
	DebugMode = "1"
)

// set mode for debugging
// in bash:
// export DEBUG=1
func init() {
	if debug == DebugMode {
		println("Debug mode")
		logrus.SetLevel(logrus.DebugLevel)
	}
}

// In this example, we will build a simple example of a standard flow between a student, a university, and an employer
// 1. A student graduates from a university. The university issues a VC to the student, saying they graduated
// 2. The student will store it in a "wallet"
// 3. An employer sends a request to verify that the student graduated from the university.
func main() {
	step := 0

	example.WriteStep("Starting University Flow", step)
	step += 1

	// Wallet initialization
	example.WriteStep("Initializing Student", step)
	step += 1

	student, err := emp.NewEntity("Student", "key")
	example.HandleExampleError(err, "failed to create student")

	example.WriteStep("Initializing Employer", step)
	step += 1

	employer, err := emp.NewEntity("Employer", "peer")
	example.HandleExampleError(err, "failed to make employer identity")
	verifierDID, err := employer.GetWallet().GetDID("main")
	example.HandleExampleError(err, "failed to create employer")

	example.WriteStep("Initializing University", step)
	step += 1

	university, err := emp.NewEntity("University", "peer")
	example.HandleExampleError(err, "failed to create university")
	vcDID, err := university.GetWallet().GetDID("main")

	example.HandleExampleError(err, "failed to initialize verifier")
	example.WriteNote(fmt.Sprintf("Initialized Verifier DID: %s and registered it", vcDID))
	emp.TrustedEntities.Issuers[vcDID] = true

	example.WriteStep("Example University Creates VC for Holder", step)
	step += 1

	example.WriteNote("DID is shared from holder")
	holderDID, err := student.GetWallet().GetDID("main")
	example.HandleExampleError(err, "failed to store did from university")

	vc, err := emp.BuildExampleUniversityVC(vcDID, holderDID)
	example.HandleExampleError(err, "failed to build vc")

	example.WriteStep("Example University Sends VC to Holder", step)
	step += 1

	err = student.GetWallet().AddCredentials(*vc)
	example.HandleExampleError(err, "failed to add credentials to wallet")

	msg := fmt.Sprintf("VC puts into wallet. Wallet size is now: %d", student.GetWallet().Size())
	example.WriteNote(msg)

	example.WriteNote(fmt.Sprintf("initialized verifier DID: %v", verifierDID))
	example.WriteStep("Employer wants to verify student graduated from Example University. Sends a presentation request", step)
	step += 1

	presentationData, err := emp.MakePresentationData("test-id", "id-1")
	example.HandleExampleError(err, "failed to create pd")

	dat, err := json.Marshal(presentationData)
	example.HandleExampleError(err, "failed to marshal presentation data")
	logrus.Debugf("Presentation Data:\n%v", string(dat))

	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	example.HandleExampleError(err, "failed to generate json web key")

	presentationRequest, _, err := emp.MakePresentationRequest(*jwk, presentationData, holderDID)
	example.HandleExampleError(err, "failed to make presentation request")

	verifier, err := crypto.NewJWTVerifierFromJWK(jwk.ID, jwk.PublicKeyJWK)
	example.HandleExampleError(err, "failed to build json web key verifier")

	signer, err := crypto.NewJWTSignerFromJWK(jwk.ID, jwk.PrivateKeyJWK)
	example.HandleExampleError(err, "failed to build json web key signer")

	example.WriteNote("Student returns claims via a Presentation Submission")
	submission, err := emp.BuildPresentationSubmission(presentationRequest, *signer, *verifier, *vc)
	example.HandleExampleError(err, "failed to build presentation submission")
	vp, err := signing.VerifyVerifiablePresentationJWT(*verifier, string(submission))
	example.HandleExampleError(err, "failed to verify jwt")

	dat, err = json.Marshal(vp)
	example.HandleExampleError(err, "failed to marshal submission")
	logrus.Debugf("Submission:\n%v", string(dat))

	example.WriteStep(fmt.Sprintf("Employer Attempting to Grant Access"), step)
	if err = emp.ValidateAccess(*verifier, submission); err == nil {
		example.WriteOK("Access Granted!")
	} else {
		example.WriteError(fmt.Sprintf("Access was not granted! Reason: %s", err))
	}
}
