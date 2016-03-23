package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"golang.org/x/crypto/ssh"

	 "github.com/howeyc/gopass"

	"github.com/voxelbrain/goptions"
)

const (
	PUBKEY_NAME  = "%v"
	PRIVKEY_NAME = "%v.priv"
)

func main() {
	options := struct {
		Host *net.TCPAddr  `goptions:"-s, --server"`
		Help goptions.Help `goptions:"-h, --help, description='Show this help'"`

		goptions.Verbs
		Token struct {
			User string `goptions:"-u, --username, obligatory, description='Username to authenticate with'"`
		} `goptions:"token"`

		Get struct {
			To string `goptions:"-t, --save-to, description='Directory to save keypair in'"`
			User string `goptions:"-u, --username, obligatory, description='Target user to fetch keys of'"`
			Token string `goptions:"-t, --token, obligatory, description='Authentication token'"`
		} `goptions:"get"`

		Set struct {
			Pubkey  string `goptions:"-p, --pubkey, obligatory, description='Filename of the public key'"`
			Privkey string `goptions:"-i, --privkey, obligatory, description='Filename of the private key'"`
			User string `goptions:"-u, --username, obligatory, description='Target user to fetch keys of'"`
			Token string `goptions:"-t, --token, obligatory, description='Authentication token'"`
		} `goptions:"set"`

		Dispatch struct {
			User string `goptions:"-u, --username, obligatory, description='Target user to fetch keys of'"`
			Token string `goptions:"-t, --token, obligatory, description='Authentication token'"`
		} `goptions:"dispatch"`

		Generate struct {
			User string `goptions:"-u, --username, obligatory, description='Target user to fetch keys of'"`
			Token string `goptions:"-t, --token, obligatory, description='Authentication token'"`
		} `goptions:"generate"`
	}{ // Default values go here
		Host: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 7654,
		},
	}
	//options.Host.IP = net.ParseIP(os.Getenv("KE_HOST"))
	fmt.Println("CDC Key Escrow Client v1")
	goptions.ParseAndFail(&options)

	if len(options.Verbs) <= 0 {
		fmt.Println("You must specify a verb")
		return
	}

	switch options.Verbs {
	case "token":
		fmt.Print("password> ")
		password, _ := gopass.GetPasswd()
		authToken(options.Host, options.Token.User, string(password))
		break
	case "get":
		getKey(options.Host, options.Get.User, options.Get.Token, options.Get.To)
		break
	case "set":
		setKey(options.Host, options.Set.User, options.Set.Token, options.Set.Pubkey, options.Set.Privkey)
		break
	case "dispatch":
		dispatchKey(options.Host, options.Dispatch.User, options.Dispatch.Token)
		break
	case "generate":
		user := options.Generate.User
		pubLoc := path.Join("/tmp", fmt.Sprintf("%v.pub", user))
		priLoc := path.Join("/tmp", user)

		// https://stackoverflow.com/questions/21151714/go-generate-an-ssh-public-key
		privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			log.Fatalf("There was an error generating the private key")
		}

		// generate and write private key as PEM
		privKeyFile, err := os.Create(priLoc)
		defer privKeyFile.Close()
		if err != nil {
			log.Fatalln("Error generating private key")
		}
		privKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
		if err := pem.Encode(privKeyFile, privKeyPEM); err != nil {
			log.Fatalln("Error generating key")
		}

		// generate and write public key
		pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatalf("Error generating public key")
		}

		ioutil.WriteFile(pubLoc, ssh.MarshalAuthorizedKey(pub), 0777)

		setKey(options.Host, user, options.Generate.Token, pubLoc, priLoc)
		break
	}
}

func authToken(host *net.TCPAddr, username string, password string) {
	client, err := NewClient(host)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err.Error())
	}
	// Close the connection by the end of the function
	defer client.Close()

	token, err := client.GetToken(username, password)
	if err != nil {
		log.Fatalf("Error retrieving token: %v", err.Error())
	}

	fmt.Println()
	fmt.Printf("User:  %v\n", token.User)
	fmt.Printf("Token: %v\n", token.Token)
}

func getKey(host *net.TCPAddr, username string, token string, to string) {
	client, err := NewClient(host)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err.Error())
	}
	// Close the connection by the end of the function
	defer client.Close()

	key, err := client.GetKey(username, token)
	if err != nil {
		log.Fatalf("Error retrieving key: %v", err.Error())
	}

	if to == "" {
		fmt.Println()
		fmt.Printf("User: %v\n", key.User)
		fmt.Printf("Public Key: %v\n", key.PublicKey)
		fmt.Printf("Private Key: %v\n", key.PrivateKey)
	} else {
		if _, err = os.Stat(to); os.IsNotExist(err) {
			os.MkdirAll(to, 0700)
		}

		f, err := os.Create(path.Join(to, fmt.Sprintf(PUBKEY_NAME, key.User)))
		if err != nil {
			log.Printf("Could not create public key")
		}
		_, err = f.WriteString(key.PublicKey)
		if err != nil {
			log.Printf("Could not write public key")
		}

		f, err = os.Create(path.Join(to, fmt.Sprintf(PRIVKEY_NAME, key.User)))
		if err != nil {
			log.Printf("Could not create private key")
		}
		f.Chmod(0600)
		_, err = f.WriteString(key.PrivateKey)
		if err != nil {
			log.Printf("Could not write private key")
		}
	}
}

func setKey(host *net.TCPAddr, username string, token string, pubkey string, privkey string) {
	client, err := NewClient(host)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err.Error())
	}
	defer client.Close()

	err = client.SetKey(username, token, pubkey, privkey)
	if err != nil {
		log.Fatalf("Error setting key: %v", err.Error())
	}
}

func dispatchKey(host *net.TCPAddr, username string, token string) {
	client, err := NewClient(host)
	if err != nil {
		log.Fatalf("Error connecting to server: %v", err.Error())
	}
	defer client.Close()

	err = client.Dispatch(username, token)
	if err != nil {
		log.Fatalf("Error setting key: %v", err.Error())
	}
}
