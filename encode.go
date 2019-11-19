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

const ()

type encodeCmd struct {
	keyPath string
	datPath string
	alg     string
	claims  map[string]string
	iat     time.Time
	exp     time.Time
}

func (*encodeCmd) Name() string     { return "encode" }
func (*encodeCmd) Synopsis() string { return "encode" }
func (*encodeCmd) Usage() string    { return "encode <jwt>" }

func (d *encodeCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.keyPath, "path", "/Users/kanotatsuya/tmp/php/key/ec.key", "private key path")
	f.StringVar(&d.alg, "alg", "ES256", "signing method")

	f.Var(newMapFlags(map[string]string{}, &d.claims), "claim", "jwt claim")

	now := time.Now()
	f.Var(newTimeFlag(now, &d.iat), "iat", "<2006-01-02T15:04:05>")
	f.Var(newTimeFlag(time.Time{}, &d.exp), "exp", "<2006-01-02T15:04:05>")
}

func (d *encodeCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if d.exp.Unix() < 0 {
		d.exp = d.iat.Add(time.Second * 60)
	}
	claims := map[string]interface{}{
		"iss": "kokukuma",
		"aud": "kokukuma",
		"iat": d.iat.Unix(),
		"exp": d.exp.Unix(),
		"sub": "kokukuma",
	}
	for k, v := range d.claims {
		claims[k] = v
	}

	jwt, err := createJWT(claims, d.alg, d.keyPath)
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
