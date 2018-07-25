// Copyright © 2018 Damian Myerscough <Damian.Myerscough@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/dmyerscough/mirussh-client/client"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"strings"
	"syscall"
)

const MIRUSSHURL = "https://mirulabs.xyz"

var (
	cfgFile  string
	username string
	keysize  int
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mirussh-client",
	Short: "MiruSSH Certificate Authentication",
	Long: `Provisions a SSH certificate valid for a certin period of time and loads
the certificate into the SSH agent.`,
	Run: func(cmd *cobra.Command, args []string) {
		var endpoint string

		if url := os.Getenv("MIRUSSH"); url != "" {
			endpoint = url
		} else {
			endpoint = MIRUSSHURL
		}

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter password: ")
		bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))

		fmt.Print("\nEnter MFA token: ")

		otp, _ := reader.ReadString('\n')
		otp = strings.TrimSuffix(otp, "\n")

		key, err := rsa.GenerateKey(rand.Reader, keysize)
		if err != nil {
			log.Fatal("Unable to generate SSH key pair: %v", err)
		}

		publicKey, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			log.Fatalf("Unsupported key type: %v", err)
		}

		token, err := client.Authenticate(endpoint+"/auth/", username, string(bytePassword))
		if err != nil {
			log.Fatal(err)
		}

		cert := client.SignCertificate(fmt.Sprintf(endpoint+"/management/sign/"), token, otp, string(ssh.MarshalAuthorizedKey(publicKey)))

		sshCertificate, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(cert.Certificate))

		sshCert, _ := sshCertificate.(*ssh.Certificate)

		client.ConfigureSSHAgent(key, sshCert, cert.Username, cert.Ttl)
		log.Println("SSH certificate successfully added to your ssh-agent")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Login username")
	rootCmd.Flags().IntVarP(&keysize, "keysize", "k", 4096, "SSH key size")

	rootCmd.MarkFlagRequired("username")
}
