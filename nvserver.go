package main

import (
	"crypto/rsa"
	"crypto/x509"
	"net/http"
)

type NvServer struct {
	HTTPClient http.Client
	PrivKey    rsa.PrivateKey
	ClientCert x509.Certificate
	ServerCert x509.Certificate
	Address    string
	BaseURL    string
	GfeVersion string
	AppVersion string
	PairStatus int
	State      string
	AppList    []GfeApp
}

func (server NvServer) Cleanup() {
	server.DEBUGQuery("unpair", "", 0)
}
