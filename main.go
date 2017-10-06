package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"bytes"
	"strconv"
)

type AuthReponse struct {
	Username    string `json:"username"`
	Certificate string `json:"certificate"`
	Ttl         uint32 `json:"ttl"`
}

// Read from a configuration file
const MIRUSSH_ADDR = "http://127.0.0.1:8080/management/sign/"

func main() {
	flagToken := flag.String("token", "", "Authentication token")
	flagKeySize := flag.Int("keysize", 2048, "SSH key size")
	flagOtp := flag.Int("otp", 0, "Multi-factor authentication token")
	flag.Parse()

	if len(*flagToken) == 0 {
		log.Fatal("Authentication token is required")
	} else if *flagOtp == 0 {
		log.Fatal("Multi-factor authentication token is required")
	}

	key, err := rsa.GenerateKey(rand.Reader, *flagKeySize)
	if err != nil {
		log.Fatal("Unable to generate SSH keypair: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("Unsupported key type: %v", err)
	}

	cert := Authenticate(*flagToken, strconv.Itoa(*flagOtp), string(ssh.MarshalAuthorizedKey(publicKey)))

	sshCertificate, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(cert.Certificate))

	sshCert, _ := sshCertificate.(*ssh.Certificate)

	ConfigureSSHAgent(key, sshCert, cert.Username, cert.Ttl)
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
		log.Fatal("Unable to connect to SSH_AUTH_SOCK: %v", err)
	}

	conn := agent.NewClient(socket)
	if err := conn.Add(addedKey); err != nil {
		log.Fatal("Unable to load SSH keys into the SSH agent: ", err)
	}
}

func Authenticate(token string, opt string, publicKey string) AuthReponse {
	client := &http.Client{}
	keypair := AuthReponse{}

	payload := map[string]string{"public": publicKey}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", MIRUSSH_ADDR, bytes.NewBuffer(jsonPayload))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", token))
	req.Header.Add("X-MiruSSH-OTP", opt)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to request signed certificate: %v\n", err)
	}

	if resp.StatusCode != 200 {
		//log.Fatal("Unable to authenticate: ", resp.StatusCode)
		body, _ := ioutil.ReadAll(resp.Body)

		log.Fatal(string(body))
	}

	json.NewDecoder(resp.Body).Decode(&keypair)

	defer resp.Body.Close()

	//return keypair.Certificate
	return keypair
}
