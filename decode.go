package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/subcommands"
)

type decodeCmd struct {
	certPath string
	key      string
}

func (*decodeCmd) Name() string     { return "decode" }
func (*decodeCmd) Synopsis() string { return "decode" }
func (*decodeCmd) Usage() string    { return "decode <jwt>" }

func (d *decodeCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.certPath, "path", "", "public cert path")
	f.StringVar(&d.key, "key", "", "secret string for HMAC")
}

func (d *decodeCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if len(f.Args()) == 0 {
		fmt.Println("You must provide a jwt")
		return subcommands.ExitUsageError
	}
	jwtStr := f.Args()[0]

	// key
	key, err := getPubKey(d.certPath, d.key)
	if err != nil {
		fmt.Println(err)
		return subcommands.ExitUsageError
	}

	// parse jwt
	token, err := decodeJWT(jwtStr, key)
	if err != nil {
		fmt.Println(err)
		//return subcommands.ExitUsageError
	}

	// TODO: 表示は別の所に切り出す

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

	fmt.Println("--- Signature")
	return subcommands.ExitSuccess
}

func decodeJWT(jwtStr string, key interface{}) (*jwt.Token, error) {
	token, err := jwt.Parse(jwtStr, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	return token, err
}
