package client

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
)

type SingedAuthResponse struct {
	Username    string `json:"username"`
	Certificate string `json:"certificate"`
	Ttl         uint32 `json:"ttl"`
}

type TokenAuthResponse struct {
	Token string `json:"token"`
}

type PublicKeyPayload struct {
	Public string `json:"public"`
}

func ConfigureSSHAgent(key *rsa.PrivateKey, certificate *ssh.Certificate, username string, ttl uint32) {
	addedKey := agent.AddedKey{
		PrivateKey:   key,
		Certificate:  certificate,
		Comment:      username,
		LifetimeSecs: ttl,
	}

	socket, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatal("Unable to connect to SSH_AUTH_SOCK: ", err)
	}

	conn := agent.NewClient(socket)
	if err := conn.Add(addedKey); err != nil {
		log.Fatal("Unable to load SSH keys into the SSH agent: ", err)
	}
}

func Authenticate(client http.Client, endpoint, username, password string) (string, error) {
	token := TokenAuthResponse{}

	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	req, _ := http.NewRequest("POST", endpoint+"/auth/", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
	}

	if resp.StatusCode != 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", errors.New(string(body))
	}

	json.NewDecoder(resp.Body).Decode(&token)

	resp.Body.Close()

	return token.Token, nil
}

func SignCertificate(client http.Client, endpoint, token, otp, publicKey string) SingedAuthResponse {
	keypair := SingedAuthResponse{}

	payload := PublicKeyPayload{Public: publicKey}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", endpoint+"/management/sign/", bytes.NewBuffer(jsonPayload))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", token))
	req.Header.Add("X-MiruSSH-OTP", otp)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to request signed certificate: %v\n", err)
	}

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Fatal(string(body))
	}

	json.NewDecoder(resp.Body).Decode(&keypair)

	defer resp.Body.Close()

	return keypair
}
