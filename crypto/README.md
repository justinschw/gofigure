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

	err, str := ctx.RunCommands([]string{
		"cd /home/pi/somedir",
		"ls -lh",
	})
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
    var pair crypto.SshKeyPair
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
	err := pair.CreateKeyPair("privkeypassword")

	client.SetPrivateKeyAuth(pair.PrivateKeyFile, pair.PrivateKeyPassword)

	err, ctx := crypto.NewCryptoContext(client)
	if err != nil {
		fmt.Println("Failed to create SSH context: ", err)
		return
	}

	err, output := ctx.RunCommands([]string{
		"cd /home/pi",
		"ls -lh",
	})
	if err != nil {
		fmt.Println("Failed to run SSH commands: ", err)
		return
	}
	fmt.Println(output)
```

## Example code (snippet): Run SSH and wait for prompt
```
    err, output := ctx.RunCommandsWithPrompts([]string{
		"cd /home/pi",
		"sudo ls -lh",
	}, map[string]string{
		"[sudo] password for ": "mysudopassword",
	})
	if err != nil {
		fmt.Println("Failed to run SSH commands: ", err)
		return
	}
	fmt.Println(output)
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