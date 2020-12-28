package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"sort"

	"github.com/google/uuid"
	"golang.org/x/net/html/charset"
)

type NvResponseStatus struct {
	XMLName       xml.Name `xml:"root"`
	StatusCode    int      `xml:"status_code,attr"`
	StatusMessage string   `xml:"status_message,attr"`
}

type NvPairingState struct {
	XMLName           xml.Name `xml:"root"`
	ChallengeResponse string   `xml:"challengeresponse"`
	EncodedCipher     string   `xml:"encodedcipher"`
	IsBusy            int      `xml:"isbusy"`
	Paired            int      `xml:"paired"`
	PairingSecret     string   `xml:"pairingsecret"`
	PlainCert         string   `xml:"plaincert"`
}

type GfeServerInfo struct {
	XMLName    xml.Name `xml:"root"`
	GfeVersion string   `xml:"GfeVersion"`
	AppVersion string   `xml:"appversion"`
	PairStatus int      `xml:"PairStatus"`
	State      string   `xml:"state"`
}

type GfeAppList struct {
	XMLName xml.Name `xml:"root"`
	Apps    []GfeApp `xml:"App"`
}

type GfeApp struct {
	XMLName                        xml.Name `xml:"App"`
	Title                          string   `xml:"AppTitle"`
	ID                             int      `xml:"ID"`
	MaxControllersForSingleSession int      `xml:"MaxControllersForSingleSession"`
}

func BypassReader(label string, input io.Reader) (io.Reader, error) {
	return input, nil
}

func DecodeUtf16XML(b []byte, v interface{}) (err error) {
	// https://www.tipitaka.org/romn/cscd/vin01m.mul.toc.xml
	// The Tipiṭaka XML is encoded in UTF-16
	// Google search: golang xml utf-16
	// https://stackoverflow.com/questions/6002619/unmarshal-an-iso-8859-1-xml-input-in-go
	// https://groups.google.com/forum/#!topic/golang-nuts/tXcECEKC2rs
	r := bytes.NewBuffer(b)
	nr, err := charset.NewReader(r, "utf-16")
	if err != nil {
		return
	}
	decoder := xml.NewDecoder(nr)
	decoder.CharsetReader = BypassReader
	err = decoder.Decode(v)
	return
}

func (server *NvServer) GetInfo() error {
	info := GfeServerInfo{}
	err := server.Query("serverinfo", "", 0, &info)
	if err != nil {
		return err
	}

	server.AppVersion = info.AppVersion
	server.GfeVersion = info.GfeVersion
	server.PairStatus = info.PairStatus
	server.State = info.State
	return nil
}

func (server *NvServer) GetAppList() error {
	if server.PairStatus == 0 {
		return errors.New("Not paired with server, can't get applist")
	}

	appList := GfeAppList{}
	err := server.Query("applist", "", 0, &appList)
	if err != nil {
		return err
	}

	server.AppList = appList.Apps
	sort.Slice(server.AppList, func(i, j int) bool {
		return server.AppList[i].Title < server.AppList[j].Title
	})
	return nil
}

func (server *NvServer) DEBUGQuery(command string, args string, timeout int) (string, error) {
	resp, err := server.HTTPClient.Get(server.BaseURL + "/" + command + "?uniqueid=0123456789FFFFFF&uuid=" + uuid.New().String() + args)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	xmlResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(xmlResponse), nil
}

func (server *NvServer) Query(command string, args string, timeout int, retStruct interface{}) error {
	resp, err := server.HTTPClient.Get(server.BaseURL + "/" + command + "?uniqueid=0123456789FFFFFF&uuid=" + uuid.New().String() + args)

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	xmlResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	//fmt.Println(string(resp.Body))
	status := NvResponseStatus{}
	err = DecodeUtf16XML(xmlResponse, &status)
	if err != nil {
		return err
	}

	err = VerifyResponse(status)
	if err != nil {
		return err
	}

	err = DecodeUtf16XML(xmlResponse, retStruct)
	if err != nil {
		return err
	}

	return nil
}

func VerifyResponse(status NvResponseStatus) error {
	if status.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Error %d: %s", status.StatusCode, status.StatusMessage))
	}
	return nil
}
