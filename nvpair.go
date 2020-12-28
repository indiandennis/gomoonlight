package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

func (server *NvServer) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	hashSlice := hash[:]
	signedData, err := rsa.SignPKCS1v15(rand.Reader, &server.PrivKey, crypto.SHA256, hashSlice)
	if err != nil {
		return nil, err
	}
	return signedData, nil
}

func (server *NvServer) Pair(pin string) error {
	//need to do this in a separate routine, the http call blocks until reading the whole response, which only comes after submitting the pin on the server
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}

	err = server.CreateCredentials()
	if err != nil {
		fmt.Println(err)
		return err
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.ClientCert.Raw})
	if pemCert == nil {
		return errors.New("Failed to generate pem")
	}

	saltedPin := append(salt, []byte(pin)...)

	//only use sha256 on NvGS server >=7
	hashedSaltedPin := sha256.Sum256(saltedPin)

	getCert := NvPairingState{}
	err = server.Query("pair", "devicename=roth&updateState=1&phrase=getservercert&salt="+hex.EncodeToString(salt)+"&clientcert="+hex.EncodeToString(pemCert), 0, &getCert)
	if err != nil {
		return err
	}

	if getCert.Paired != 1 {
		return errors.New("Failed pairing at stage #1")
	}

	if getCert.PlainCert == "" {
		return errors.New("Server likely already pairing")
	}

	// Decode server certificate
	serverCert, err := hex.DecodeString(getCert.PlainCert)
	if err != nil {
		return err
	}

	PEMblock, _ := pem.Decode(serverCert)
	if PEMblock == nil {
		return errors.New("Error decoding server PEM cert")
	}

	cert, err := x509.ParseCertificate(PEMblock.Bytes)
	if err != nil {
		return err
	}
	server.ServerCert = *cert

	//next pairing step
	randomChallenge := make([]byte, 16)

	_, err = rand.Read(salt)
	if err != nil {
		return err
	}

	aesKey := hashedSaltedPin[:16]
	encryptedRandomChallenge, err := EncryptAes128Ecb(randomChallenge, aesKey)
	if err != nil {
		return err
	}

	serverChallengeResponse := NvPairingState{}
	err = server.Query("pair", "devicename=roth&updateState=1&clientchallenge="+
		hex.EncodeToString(encryptedRandomChallenge), 0, &serverChallengeResponse)
	if err != nil {
		return err
	}

	if serverChallengeResponse.Paired != 1 {
		return errors.New("Failed pairing at stage #2")
	}

	challengeResponseData, err := hex.DecodeString(serverChallengeResponse.ChallengeResponse)
	if err != nil {
		return err
	}

	decryptedChallengeResponse, err := DecryptAes128Ecb(challengeResponseData, aesKey)
	if err != nil {
		return err
	}

	serverResponse := decryptedChallengeResponse[:32]
	clientSecretData := make([]byte, 16)
	_, err = rand.Read(clientSecretData)
	if err != nil {
		return err
	}

	certSignature := server.ClientCert.Signature

	challengeResponse := []byte{}
	challengeResponse = append(challengeResponse, decryptedChallengeResponse[32:48]...)
	challengeResponse = append(challengeResponse, certSignature...)
	challengeResponse = append(challengeResponse, clientSecretData...)
	paddedHash := sha256.Sum256(challengeResponse)
	paddedHashSlice := paddedHash[:]
	encryptedChallengeResponseHash, err := EncryptAes128Ecb(paddedHashSlice, aesKey)
	if err != nil {
		return err
	}

	err = server.Query("pair", "devicename=roth&updateState=1&serverchallengeresp="+
		hex.EncodeToString(encryptedChallengeResponseHash), 0, &serverChallengeResponse)
	if err != nil {
		return err
	}

	if serverChallengeResponse.Paired != 1 {
		return errors.New("Failed pairing at stage #3")
	}

	pairingSecret, err := hex.DecodeString(serverChallengeResponse.PairingSecret)
	if err != nil {
		return err
	}

	serverSecret := pairingSecret[:16]
	serverSignature := pairingSecret[16:]

	err = server.ServerCert.CheckSignature(x509.SHA256WithRSA, serverSecret, serverSignature)
	if err != nil {
		return errors.New("MITM Detected during pairing")
	}

	expectedResponse := []byte{}
	expectedResponse = append(expectedResponse, randomChallenge...)
	expectedResponse = append(expectedResponse, server.ServerCert.Signature...)
	expectedResponse = append(expectedResponse, serverSecret...)
	hashedExpectedResponse := sha256.Sum256(expectedResponse)
	expectedResponseSlice := hashedExpectedResponse[:]
	if bytes.Compare(expectedResponseSlice, serverResponse) != 0 {
		return errors.New("Incorrect pin")
	}

	clientPairingSecret := []byte{}
	clientPairingSecret = append(clientPairingSecret, clientSecretData...)
	signedSecret, err := server.Sign(clientSecretData)
	if err != nil {
		return err
	}

	clientPairingSecret = append(clientPairingSecret, signedSecret...)

	secretResponse := NvPairingState{}
	err = server.Query("pair", "devicename=roth&updateState=1&clientpairingsecret="+
		hex.EncodeToString(clientPairingSecret), 0, &secretResponse)

	if err != nil {
		return err
	}

	if secretResponse.Paired != 1 {
		return errors.New("Failed pairing at stage #4")
	}

	pairChallenge := NvPairingState{}
	server.Query("pair", "devicename=roth&updateState=1&phrase=pairchallenge", 0, &pairChallenge)
	if err != nil {
		return err
	}

	if secretResponse.Paired != 1 {
		return errors.New("Failed pairing at stage #5")
	}

	server.BaseURL = "https://" + server.Address + ":47984"

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(serverCert)
	if ok != true {
		return errors.New("error loading server pem as CA cert")
	}

	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(&server.PrivKey)})
	tlsCert, err := tls.X509KeyPair(pemCert, pemKey)
	if err != nil {
		return err
	}

	server.HTTPClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{tlsCert},
			InsecureSkipVerify: true,
		},
	}

	err = server.GetInfo()
	if err != nil {
		return err
	}

	return nil
}

func (server *NvServer) CreateCredentials() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	now := time.Now()
	daylater := now.Add(24 * time.Hour)

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: "NVIDIA GameStream Client",
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             now,
		NotAfter:              daylater,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	clientCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	server.ClientCert = *clientCert
	server.PrivKey = *priv
	return nil
}

func EncryptAes128Ecb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], data[bs:be])
	}

	return encrypted, nil
}

func DecryptAes128Ecb(data, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	size := 16

	for bs, be := 0, size; bs < len(data); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], data[bs:be])
	}

	return decrypted, nil
}
