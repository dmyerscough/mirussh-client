package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"bufio"
	"bytes"
	"flag"
	"path"
)

//annotate type structs
type AuthReponse struct {
	Username    string `json:"username"`
	Certificate string `json:"certificate"`
	Ttl         uint32 `json:"ttl"`
}

type Config struct {
	Endpoint string `yaml:"endpoint"`
	Token    string `yaml:"token"`
}

func main() {
	config := Config{}

	flagKeySize := flag.Int("keysize", 2048, "SSH key size")
	flag.Parse()

	configFile, err := ioutil.ReadFile(path.Join(os.Getenv("HOME"), ".mirussh"))
	if err != nil {
		log.Fatal("Unable to read ~/.mirussh configuration: %v", err)
	}

	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatal("~/.mirussh contains invalid YAML")
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter one time token: ")
	otp, _ := reader.ReadString('\n')

	otp = strings.TrimSuffix(otp, "\n")

	key, err := rsa.GenerateKey(rand.Reader, *flagKeySize)
	if err != nil {
		log.Fatal("Unable to generate SSH key pair: %v", err)
	}

	publicKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("Unsupported key type: %v", err)
	}

	cert := Authenticate(fmt.Sprintf("http://%s/management/sign/", config.Endpoint), config.Token, otp, string(ssh.MarshalAuthorizedKey(publicKey)))

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

func Authenticate(endpoint string, token string, opt string, publicKey string) AuthReponse {
	client := &http.Client{}
	keypair := AuthReponse{}

	payload := map[string]string{"public": publicKey}

	jsonPayload, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonPayload))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Token %s", token))
	req.Header.Add("X-MiruSSH-OTP", opt)

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
