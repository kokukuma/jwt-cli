package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// TODO: key structを作る

// TODO: 共通にしたほうがいい気がする

func getPubKey(keyPath, keyStr string) (interface{}, error) {
	var key interface{}
	var err error

	if keyStr != "" && keyPath == "" {
		key = []byte(keyStr)
	} else if keyPath != "" && keyStr == "" {
		key, err = ReadCertificate(keyPath)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("specify certPath or key")
	}
	return key, nil

}

func getKey(keyPath, keyStr string) (interface{}, error) {
	var key interface{}
	var err error

	if keyStr != "" && keyPath == "" {
		key = []byte(keyStr)
	} else if keyPath != "" && keyStr == "" {
		key, err = loadP8Key(keyPath)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("specify certPath or key")
	}
	return key, nil
}

func loadP8Key(path string) (interface{}, error) {
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
	case *rsa.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
	}
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
