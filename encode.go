package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/subcommands"
)

const ()

type encodeCmd struct {
	key     string
	keyPath string
	alg     string
	claims  map[string]string
	iat     time.Time
	exp     time.Time
}

func (*encodeCmd) Name() string     { return "encode" }
func (*encodeCmd) Synopsis() string { return "encode" }
func (*encodeCmd) Usage() string    { return "encode <jwt>" }

func (d *encodeCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.key, "key", "", "secret string for HMAC")
	f.StringVar(&d.keyPath, "path", "", "private key path")
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
		"sub": "kokukuma",
		"iat": d.iat.Unix(),
		"exp": d.exp.Unix(),
	}
	for k, v := range d.claims {
		claims[k] = v
	}

	key, err := getKey(d.keyPath, d.key)
	if err != nil {
		fmt.Println(err)
		return subcommands.ExitFailure
	}

	jwt, err := createJWT(claims, d.alg, key)
	if err != nil {
		fmt.Println(err)
		return subcommands.ExitFailure
	}

	// Created jwt
	fmt.Println(jwt)

	return subcommands.ExitSuccess
}

func createJWT(claims map[string]interface{}, alg string, key interface{}) (string, error) {
	jwtClaims := jwt.MapClaims(claims)
	jwtAlg := jwt.GetSigningMethod(alg)

	// create a new token
	token := jwt.NewWithClaims(jwtAlg, jwtClaims)

	token.Header["kid"] = "BF4R44V675"

	sig, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return sig, nil
}
