package crypto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

/*
 * Run commands and output to stdout
 */
func (s *CryptoContext) RunCommands(commands []string, print bool) (error, string) {

	server := fmt.Sprintf("%s:%d", s.SshClient.Address, s.SshClient.Port)

	// open connection
	conn, err := ssh.Dial("tcp", server, s.SshConfig)
	if err != nil {
		return fmt.Errorf("Dial to %v failed %v", server, err), ""
	}
	defer conn.Close()

	// open session
	session, err := conn.NewSession()
	if err != nil {
		return err, ""
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return err, ""
	}

	output := ""
	allCommands := strings.Join(commands, "; ")
	if print {
		session.Stdout = os.Stdout
		err = session.Run(allCommands)
	} else {
		var buff bytes.Buffer
		session.Stdout = &buff
		err = session.Run(allCommands)
		output = buff.String()
	}

	if err != nil {
		return err, ""
	}

	return err, output

}

/*
 * Run commands with stdin responses to expected prompts
 */
func (s *CryptoContext) RunCommandsWithPrompts(commands []string, prompts map[string]string, print bool) (error, string) {

	server := fmt.Sprintf("%s:%d", s.SshClient.Address, s.SshClient.Port)

	// open connection
	conn, err := ssh.Dial("tcp", server, s.SshConfig)
	if err != nil {
		return fmt.Errorf("Dial to %v failed %v", server, err), ""
	}
	defer conn.Close()

	// open session
	session, err := conn.NewSession()
	if err != nil {
		return err, ""
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return err, ""
	}

	in, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	out, err := session.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	var output []byte
	go func(in io.WriteCloser, out io.Reader, output *[]byte, prompts map[string]string) {
		var (
			line string
			r    = bufio.NewReader(out)
		)
		for {
			b, err := r.ReadByte()
			if err != nil {
				break
			}

			*output = append(*output, b)

			if b == byte('\n') {
				if print {
					fmt.Println(line)
				}
				line = ""
				continue
			}

			line += string(b)

			for prompt, command := range prompts {
				if strings.HasPrefix(line, prompt) {
					if print {
						// print before resetting line but also before entering prompt
						fmt.Print(line)
					}
					_, err = in.Write([]byte(command + "\n"))
					if err != nil {
						break
					}
					line = ""
				}
			}
		}
	}(in, out, &output, prompts)

	allCommands := strings.Join(commands, "; ")
	err = session.Run(allCommands)
	if err != nil {
		return err, ""
	}

	return err, string(output)

}

/*
 * Simple method to copy keys to remote server
 */
func (s *CryptoContext) CopyKeyToRemote(p SshKeyPair) error {
	keyData, err := ioutil.ReadFile(p.PublicKeyFile)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(keyData))
	cmd := fmt.Sprintf("if [ -z \"$(cat $HOME/.ssh/authorized_keys | grep '%s')\" ]; then echo '%s' >> $HOME/.ssh/authorized_keys; fi", key, key)
	err, _ = s.RunCommands([]string{
		cmd,
	}, false)
	return err
}

/*
 * Simple method to remove keys from remote server
 */
func (s *CryptoContext) RemoveKeyFromRemote(p SshKeyPair) error {
	keyData, err := ioutil.ReadFile(p.PublicKeyFile)
	if err != nil {
		return err
	}
	key := strings.TrimSpace(string(keyData))
	cmd := fmt.Sprintf("cat $HOME/.ssh/authorized_keys | grep %s > $HOME/.ssh/authorized_keys", key)
	err, _ = s.RunCommands([]string{
		cmd,
	}, false)
	return err
}
