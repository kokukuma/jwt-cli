package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/subcommands"
)

type encodeCmd struct {
	keyPath string
}

func (*encodeCmd) Name() string     { return "encode" }
func (*encodeCmd) Synopsis() string { return "encode" }
func (*encodeCmd) Usage() string    { return "encode <jwt>" }

func (d *encodeCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.keyPath, "path", "/Users/kanotatsuya/tmp/php/key/ec.key", "private key path")
}

func (d *encodeCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	iat := time.Now()
	jwt, err := createJWT(map[string]interface{}{
		"iss": "kokukuma",
		"aud": "kokukuma",
		"iat": iat.Unix(),
		"exp": iat.Add(time.Hour).Unix(),
		"sub": "kokukuma",
	}, "ES256", d.keyPath)
	if err != nil {
		fmt.Println(err)
		return subcommands.ExitFailure
	}

	// Created jwt
	fmt.Println(jwt)

	return subcommands.ExitSuccess
}

func createJWT(claims map[string]interface{}, alg string, keyPath string) (string, error) {
	jwtClaims := jwt.MapClaims(claims)
	jwtAlg := jwt.GetSigningMethod(alg)

	// create a new token
	token := jwt.NewWithClaims(jwtAlg, jwtClaims)

	token.Header["kid"] = "BF4R44V675"

	privKey, err := loadP8Key(keyPath)
	if err != nil {
		return "", err
	}
	sig, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}
	return sig, nil
}

func loadP8Key(path string) (*ecdsa.PrivateKey, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	der := block.Bytes

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
	}
}
