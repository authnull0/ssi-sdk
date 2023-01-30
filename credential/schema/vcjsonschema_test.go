package schema

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	vc "github.com/authnull0/ssi-sdk/credential"
)

const (
	vcJSONTestVector1           string = "vc-json-schema-example-1.json"
	vcJSONCredentialTestVector1 string = "vc-with-schema-example-11.json"
)

var (
	//go:embed testdata
	testVectors       embed.FS
	vcJSONTestVectors = []string{vcJSONTestVector1}
)

func TestIsValidCredentialSchema(t *testing.T) {
	for _, tv := range vcJSONTestVectors {
		schema, err := getTestVector(tv)
		assert.NoError(t, err)
		assert.NoError(t, IsValidCredentialSchema(schema))
	}
}

func TestIsCredentialValidForSchema(t *testing.T) {
	// Load VC
	credential, err := getTestVector(vcJSONCredentialTestVector1)
	assert.NoError(t, err)
	var cred vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &cred)
	assert.NoError(t, err)

	// Load vcJSONSchema
	vcJSONSchemaString, err := getTestVector(vcJSONTestVector1)
	assert.NoError(t, err)

	vcJSONSchema, err := StringToVCJSONCredentialSchema(vcJSONSchemaString)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcJSONSchema)

	// Validate credential against vcJSONSchema
	err = IsCredentialValidForVCJSONSchema(cred, *vcJSONSchema)
	assert.NoError(t, err)

	// make sure the cred was not modified
	var credCopy vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &credCopy)
	assert.NoError(t, err)
	assert.Equal(t, credCopy, cred)
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
