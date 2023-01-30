package exchange

import (
	"fmt"
	"strings"

	credutil "github.com/authnull0/ssi-sdk/credential/util"

	"github.com/authnull0/ssi-sdk/credential"
	"github.com/authnull0/ssi-sdk/credential/signing"
	"github.com/authnull0/ssi-sdk/crypto"
	"github.com/authnull0/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
)

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer.
// Note: this method does not support LD cryptosuites, and prefers JWT representations. Future refactors
// may include an analog method for LD suites.
func VerifyPresentationSubmission(verifier crypto.JWTVerifier, et EmbedTarget, def PresentationDefinition, submission []byte) error {
	if err := canProcessDefinition(def); err != nil {
		return errors.Wrap(err, "not able to verify submission; feature not supported")
	}
	if !IsSupportedEmbedTarget(et) {
		return fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		vp, err := signing.VerifyVerifiablePresentationJWT(verifier, string(submission))
		if err != nil {
			return errors.Wrap(err, "verification of the presentation submission failed")
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		return fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition.
// TODO(gabe) handle signature validation of submission claims https://github.com/authnull0/ssi-sdk/issues/71
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) error {
	if err := vp.IsValid(); err != nil {
		return errors.Wrap(err, "presentation submission does not contain a valid VP")
	}

	// first, validate the presentation submission in the VP
	submission, err := toPresentationSubmission(vp.PresentationSubmission)
	if err != nil {
		return errors.Wrap(err, "unable to parse presentation submission from verifiable presentation")
	}
	if err = submission.IsValid(); err != nil {
		return errors.Wrap(err, "invalid presentation submission in provided verifiable presentation")
	}
	if submission.DefinitionID != def.ID {
		return fmt.Errorf("mismatched between presentation definition ID<%s> and submission's definition ID<%s>",
			def.ID, submission.DefinitionID)
	}

	// index submission descriptors by id of the input descriptor
	submissionDescriptorLookup := make(map[string]SubmissionDescriptor)
	for _, d := range submission.DescriptorMap {
		submissionDescriptorLookup[d.ID] = d
	}

	// turn the vp into JSON so we can use the paths from the submission descriptor to resolve each claim
	vpJSON, err := util.ToJSONMap(vp)
	if err != nil {
		return errors.Wrap(err, "could not turn VP into JSON representation")
	}

	// validate each input descriptor is fulfilled
	for _, inputDescriptor := range def.InputDescriptors {
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			return fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptor.ID)
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if inputDescriptor.Format != nil && !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("for input descriptor<%s>, the format of submission descriptor<%s> is not one"+
				"  of the supported formats: %s", inputDescriptor.ID, submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// TODO(gabe) support nested paths in presentation submissions
		// https://github.com/authnull0/ssi-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			return fmt.Errorf("submission with nested paths not supported: %s", submissionDescriptor.ID)
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		claim, err := jsonpath.JsonPathLookup(vpJSON, submissionDescriptor.Path)
		if err != nil {
			return errors.Wrapf(err, "could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
		}
		submittedClaim, err := credutil.ClaimAsJSON(claim)
		if err != nil {
			return errors.Wrapf(err, "getting claim as go-json: <%s>", claim)
		}

		// verify the submitted claim complies with the input descriptor

		// if there are no constraints, we are done checking for validity
		if inputDescriptor.Constraints == nil {
			continue
		}

		// TODO(gabe) consider enforcing limited disclosure if present
		// for each field we need to verify at least one path matches
		for _, field := range inputDescriptor.Constraints.Fields {
			if err = findMatchingPath(submittedClaim, field.Path); err != nil {
				return errors.Wrapf(err, "input descriptor<%s> not fulfilled for field: %s", inputDescriptor.ID, field.ID)
			}
		}
	}
	return nil
}

func toPresentationSubmission(maybePresentationSubmission interface{}) (*PresentationSubmission, error) {
	bytes, err := json.Marshal(maybePresentationSubmission)
	if err != nil {
		return nil, err
	}
	var submission PresentationSubmission
	if err = json.Unmarshal(bytes, &submission); err != nil {
		return nil, err
	}
	return &submission, nil
}

func findMatchingPath(claim interface{}, paths []string) error {
	for _, path := range paths {
		if _, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			return nil
		}
	}
	return errors.New("matching path for claim could not be found")
}
