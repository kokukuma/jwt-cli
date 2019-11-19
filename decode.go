package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/subcommands"
)

type decodeCmd struct {
	certPath string
}

func (*decodeCmd) Name() string     { return "decode" }
func (*decodeCmd) Synopsis() string { return "decode" }
func (*decodeCmd) Usage() string    { return "decode <jwt>" }

func (d *decodeCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.certPath, "path", "/Users/kanotatsuya/tmp/php/key/ec.crt", "public cert path")
}

func (d *decodeCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		fmt.Println("You must provide a jwt")
		return subcommands.ExitUsageError
	}
	jwtStr := f.Args()[0]

	// parse jwt
	token, err := decodeJWT(jwtStr, d.certPath)
	if err != nil {
		fmt.Println(err)
		//return subcommands.ExitUsageError
	}

	// show jwt contant
	h, err := json.MarshalIndent(token.Header, "", " ")
	fmt.Println("--- Header")
	fmt.Println(string(h))

	claims := token.Claims.(jwt.MapClaims)
	b, err := json.MarshalIndent(claims, "", " ")
	fmt.Println("--- Claims")
	fmt.Println(string(b))

	// TODO: なぜfloat64に？
	if iat, ok := claims["iat"].(float64); ok {
		fmt.Println("iat : ", time.Unix(int64(iat), 0))
	}
	if exp, ok := claims["exp"].(float64); ok {
		fmt.Println("exp : ", time.Unix(int64(exp), 0))
	}
	return subcommands.ExitSuccess
}

func decodeJWT(jwtStr, certPath string) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtStr, func(token *jwt.Token) (interface{}, error) {
		return ReadCertificate(certPath)
	})
	return token, err
}

// ReadCertificate is used for read public key from file
func ReadCertificate(certPath string) (interface{}, error) {
	bytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	var cert *x509.Certificate
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey, nil
}
