//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"syscall/js"
	"time"

	"github.com/goccy/go-json"

	"github.com/authnull0/ssi-sdk/crypto"
	"github.com/authnull0/ssi-sdk/did"
)

/*
 * This is the glue to bind the functions into javascript so they can be called
 */
func main() {
	done := make(chan struct{})

	// Bind the functions to javascript
	js.Global().Set("sayHello", js.FuncOf(sayHello))
	js.Global().Set("generateKey", js.FuncOf(generateKey))
	js.Global().Set("makeDid", js.FuncOf(makeDid))
	js.Global().Set("resolveDid", js.FuncOf(resolveDid))

	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered from panic:", r)
					time.Sleep(time.Second)
				}
			}()

			<-done
		}()
	}
}

// 1. Simplest function - note we wrap things with js.ValueOf (if a primitive you don't technically need to)
func sayHello(_ js.Value, args []js.Value) interface{} {
	return js.ValueOf("Hello from golang via wasm!")
}

// 2. Calling a ssi-sdk function directly - but returning a plain old string
// TODO: check arg lentgh and return an error if not correct
func generateKey(_ js.Value, args []js.Value) interface{} {

	keyType := args[0].String()
	kt := crypto.KeyType(keyType)
	if !crypto.IsSupportedKeyType(kt) {
		return js.ValueOf("Unknown key type")
	}
	publicKey, _, _ := crypto.GenerateKeyByKeyType(kt)
	pubKeyBytes, _ := crypto.PubKeyToBytes(publicKey)
	return js.ValueOf(base64.StdEncoding.EncodeToString(pubKeyBytes))
}

// 3. Returning a richer object, converting to json and then unmarshalling to make it a js object
func makeDid(_ js.Value, args []js.Value) interface{} {

	pubKey, _, _ := crypto.GenerateKeyByKeyType(crypto.Ed25519)
	didKey, _ := did.CreateDIDKey(crypto.Ed25519, pubKey.(ed25519.PublicKey))
	result, _ := didKey.Expand()

	// unmarshall into json bytes, then back into a simple struct for converting to js
	resultBytes, _ := json.Marshal(result)
	var resultObj map[string]interface{}
	json.Unmarshal(resultBytes, &resultObj)
	return js.ValueOf(resultObj)

}

func resolveDid(_ js.Value, args []js.Value) interface{} {

	didString := args[0].String()
	resolvers := []did.Resolution{did.KeyResolver{}, did.WebResolver{}, did.PKHResolver{}, did.PeerResolver{}}
	resolver, err := did.NewResolver(resolvers...)
	if err != nil {
		return err
	}

	doc, err := resolver.Resolve(didString)
	if err != nil {
		return err
	}

	resultBytes, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var resultObj map[string]interface{}
	err = json.Unmarshal(resultBytes, &resultObj)
	if err != nil {
		return err
	}

	return js.ValueOf(resultObj)
}
