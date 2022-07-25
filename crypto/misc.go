package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type SshAuth struct {
	Password           string
	PrivateKeyFile     string
	PrivateKeyPassword string
}

type SshClient struct {
	Address         string
	Port            uint16
	Username        string
	Auth            []SshAuth
	HostKeyCallback ssh.HostKeyCallback
	KnownHostsFile  string
	// These get filled in when we request connection
	SshConfig  *ssh.ClientConfig
	SftpConfig *sftp.Client
}

type CryptoContext struct {
	SshClient  *SshClient
	SshConfig  *ssh.ClientConfig
	SftpConfig *sftp.Client
}

type SshKeyPair struct {
	PrivateKeyFile     string
	PublicKeyFile      string
	BitSize            int
	PrivateKeyPassword string
}

/*
 * Helper functions
 */

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey, privateKeyPassword string) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	if privateKeyPassword != "" {
		privBlock, _ = x509.EncryptPEMBlock(rand.Reader, privBlock.Type, privBlock.Bytes, []byte(privateKeyPassword), x509.PEMCipherAES256)
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(privBlock)

	return privatePEM
}

func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

func signerFromPem(pemBytes []byte, password []byte) (ssh.Signer, error) {

	// read pem block
	err := errors.New("Pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// handle encrypted key
	if x509.IsEncryptedPEMBlock(pemBlock) {
		// decrypt PEM
		pemBlock.Bytes, err = x509.DecryptPEMBlock(pemBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("Decrypting PEM block failed %v", err)
		}

		// get RSA, EC or DSA key
		key, err := parsePemBlock(pemBlock)
		if err != nil {
			return nil, err
		}

		// generate signer instance from key
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("Creating signer from encrypted key failed %v", err)
		}

		return signer, nil
	} else {
		// generate signer instance from plain key
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing plain private key failed %v", err)
		}

		return signer, nil
	}
}

func parsePemBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing PKCS private key failed %v", err)
		} else {
			return key, nil
		}
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing EC private key failed %v", err)
		} else {
			return key, nil
		}
	case "DSA PRIVATE KEY":
		key, err := ssh.ParseDSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing DSA private key failed %v", err)
		} else {
			return key, nil
		}
	default:
		return nil, fmt.Errorf("Parsing private key failed, unsupported key type %q", block.Type)
	}
}

func getHomeDir() (error, string) {
	user, err := user.Current()
	if err != nil {
		return err, ""
	}
	return nil, user.HomeDir
}

/*
 * Easy way of adding auth methods
 */
func (c *SshClient) SetPasswordAuth(password string) {
	c.Auth = append(c.Auth, SshAuth{
		Password: password,
	})
}

func (c *SshClient) SetPrivateKeyAuth(privateKeyFile string, privateKeyPassword string) {
	c.Auth = append(c.Auth, SshAuth{
		PrivateKeyFile:     privateKeyFile,
		PrivateKeyPassword: privateKeyPassword,
	})
}

/*
 * Get a crypto context for SSH/SFTP commands
 */

func (c *SshClient) NewCryptoContext() error {

	/*
	 * Set defaults for unset
	 */
	if c.KnownHostsFile == "" {
		err, homeDir := getHomeDir()
		if err != nil {
			return err
		}
		c.KnownHostsFile = path.Join(homeDir, ".ssh", "known_hosts")
		_, err = os.Stat(c.KnownHostsFile)
		if os.IsNotExist(err) {
			// Create empty known_hosts file
			f, err := os.Create(c.KnownHostsFile)
			if err != nil {
				return err
			}
			defer f.Close()
		}
	}

	if len(c.Auth) == 0 {
		err, homeDir := getHomeDir()
		if err != nil {
			return err
		}
		// We will use key auth by default
		c.Auth = append(c.Auth, SshAuth{
			PrivateKeyFile: path.Join(homeDir, ".ssh", "id_rsa"),
		})
	}

	if c.HostKeyCallback == nil {
		hostKeyCallback, err := knownhosts.New(c.KnownHostsFile)
		if err != nil {
			return err
		}
		c.HostKeyCallback = hostKeyCallback
	}

	if c.Port == 0 {
		c.Port = 22
	}

	// Create auth methods to pass
	var authMethods []ssh.AuthMethod
	for _, a := range c.Auth {
		if a.Password != "" {
			// This is password auth
			authMethods = append(authMethods, ssh.Password(a.Password))
		} else {
			// read private key file
			pemBytes, err := ioutil.ReadFile(a.PrivateKeyFile)
			if err != nil {
				return fmt.Errorf("Reading private key file failed %v", err)
			}

			// create signer
			signer, err := signerFromPem(pemBytes, []byte(a.PrivateKeyPassword))
			if err != nil {
				return err
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		}
	}

	config := &ssh.ClientConfig{
		User:            c.Username,
		Auth:            authMethods,
		HostKeyCallback: c.HostKeyCallback,
	}

	c.SshConfig = config

	return nil
}

func (pair *SshKeyPair) CreateKeyPair(privateKeyPassword string) error {

	// Set defaults
	if pair.PublicKeyFile == "" {
		err, homePath := getHomeDir()
		if err != nil {
			return err
		}
		pair.PublicKeyFile = path.Join(homePath, ".ssh", "id_rsa.pub")
	}

	if pair.PrivateKeyFile == "" {
		err, homePath := getHomeDir()
		if err != nil {
			return err
		}
		pair.PrivateKeyFile = path.Join(homePath, ".ssh", "id_rsa")
	}

	if pair.BitSize == 0 {
		pair.BitSize = 4096
	}

	pair.PrivateKeyPassword = privateKeyPassword

	return nil

}

func (pair *SshKeyPair) GenerateNewKeyPair(privateKeyPassword string) error {

	pair.CreateKeyPair(privateKeyPassword)

	// Generate a new private key
	privateKey, err := generatePrivateKey(pair.BitSize)
	if err != nil {
		return err
	}

	// generate a new public key
	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey, privateKeyPassword)

	err = writeKeyToFile(privateKeyBytes, pair.PrivateKeyFile)
	if err != nil {
		return errors.New(fmt.Sprint("Failed writing private key to file: %s", err))
	}

	err = writeKeyToFile([]byte(publicKeyBytes), pair.PublicKeyFile)
	if err != nil {
		return errors.New(fmt.Sprint("Failed writing public key to file: %s", err))
	}

	return nil
}
