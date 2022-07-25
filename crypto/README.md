# github.com/justinschw/gofigure/crypto

I made this library to facilitate some basic SSH/SFTP functionality that I want in my software.

Some of the useful things this library does:
* Generate a new SSH private/key pair
* Run a group of SSH commands
* Run commands with answers to expected prompts
* SFTP PUT copy of files to remote server
* Recursive SFTP PUT copy of directory to remote server

## Installation
```
go get github.com/justinschw/gofigure/crypto
```
## Example code: Run SSH commands using password authentication
```
import (
    "fmt"

    "github.com/justinschw/gofigure/crypto"
)

func main() {

	client := crypto.SshClient{
		Address:  "192.168.4.2",
		Port:     22,
		Username: "pi",
	}

	client.SetPasswordAuth("mysecretpassword")

	err, ctx := crypto.NewCryptoContext(client)
	if err != nil {
		fmt.Println("Failed to create SSH context: ", err)
		return
	}

	// if 'print' option is set to true, it prints the output as it is written to stdout
	// instead of returning all the output at the end. That way the user can see
	// it live.
	err, _ := ctx.RunCommands([]string{
		"cd /home/pi/somedir",
		"ls -lh",
	}, true) // print live output
	if err != nil {
		fmt.Println("Failed to run commands: ", err)
		return
	}

	fmt.Println(str)

}
```

## Example code (snippet): Generate new SSH key/pair and copy to remote host
```
	// Generate a new key pair in the default location (~/.ssh/id_rsa ~/.ssh/id_rsa.pub)
	// Note: if the files specified exist then they will be overwritten
	pair := crypto.SshKeyPair{
		PrivateKeyFile:     "/home/jusschwa/newkeys/id_rsa",
		PublicKeyFile:      "/home/jusschwa/newkeys/id_rsa",
		BitSize:            4096,
		PrivateKeyPassword: "privkeypassword",
	}
	err := pair.GenerateNewKeyPair("privkeypassword")
	if err != nil {
		fmt.Println("Failed to generate key pair: ", err)
		return
	}

	// We have to use password auth to copy over the keys first
	client.SetPasswordAuth("mysecretpassword")

	err, ctx := crypto.NewCryptoContext(client)
	if err != nil {
		fmt.Println("Failed to create SSH context: ", err)
		return
	}

	err = ctx.CopyKeyToRemote(pair)
	if err != nil {
		fmt.Println("Failed to copy keys to remote host ", err)
		return
	}
```

## Example code (snippet): Run SSH commands using private key authenticatino
```
	var pair crypto.SshKeyPair
	// By default, pair points to default key pairs in $HOME/.ssh
	// and 4096 bit RSA is assumed. Empty password indicates no encryption.
	err := pair.CreateKeyPair("")

	client.SetPrivateKeyAuth(pair.PrivateKeyFile, pair.PrivateKeyPassword)

	err, ctx := crypto.NewCryptoContext(client)
	if err != nil {
		fmt.Println("Failed to create SSH context: ", err)
		return
	}

	err, output := ctx.RunCommands([]string{
		"cd /home/pi",
		"ls -lh",
	}, false) // return all output at the end
	if err != nil {
		fmt.Println("Failed to run SSH commands: ", err)
		return
	}
	fmt.Println(output)
```

## Example code (snippet): Run SSH and wait for prompt
```
	err, _ := ctx.RunCommandsWithPrompts([]string{
		"cd /home/pi",
		"sudo ls -lh",
	}, map[string]string{
		"[sudo] password for ": "mysudopassword",
	}, true) // print output live
	if err != nil {
		fmt.Println("Failed to run SSH commands: ", err)
		return
	}
```
## Example code (snippet): Copy file to remote server
```
	// Note: destination should match the full path of the file.
	err = ctx.Put("/home/jusschwa/copydir/file", "/home/pi/copydir/file")
	if err != nil {
		fmt.Println("Error copying file: ", err)
	}
```
## Example code (snippet): Recursively copy entire directory to remote server
```
	// Note: destination should match the full path of the target directory.
	err = ctx.Put("/home/jusschwa/copydir", "/home/pi/copydir")
	if err != nil {
		fmt.Println("Error copying file: ", err)
	}
```

TODO: implement Get in addition to Put