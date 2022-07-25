package crypto

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func putFile(s *SshClient, src string, dst string) error {

	// Create containing directory if it doesn't exist
	dstPath := filepath.Dir(dst)
	_, err := s.SftpConfig.Stat(dstPath)
	if os.IsNotExist(err) {
		err := s.SftpConfig.MkdirAll(dstPath)
		if err != nil {
			return err
		}
	}

	dstFile, err := s.SftpConfig.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	_, err = io.Copy(dstFile, srcFile)

	return err
}

func putDir(s *SshClient, src string, dst string) error {
	err := filepath.Walk(src, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(src, srcPath)
		dstPath := path.Join(dst, relPath)

		if info.IsDir() {
			return s.SftpConfig.MkdirAll(dstPath)
		} else {
			return putFile(s, srcPath, dstPath)
		}

	})

	if err != nil {
		return err
	}

	return nil
}

func RmFile(s *SshClient, src string, dst string) error {
	return s.SftpConfig.Remove(dst)
}

func RmDir(s *SshClient, src string, dst string) error {
	return s.SftpConfig.RemoveDirectory(dst)
}

func (s *SshClient) Put(src string, dst string) error {

	server := fmt.Sprintf("%s:%d", s.Address, s.Port)
	// open connection
	conn, err := ssh.Dial("tcp", server, s.SshConfig)
	if err != nil {
		return fmt.Errorf("dial to %v failed %v", server, err)
	}
	defer conn.Close()

	sftpc, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer sftpc.Close()
	s.SftpConfig = sftpc

	/*file, err := os.Open(src)
	if err != nil {
		return err
	}*/

	fileInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return putDir(s, src, dst)
	} else {
		return putFile(s, src, dst)
	}
}

func (s *SshClient) Delete(dst string) error {

	server := fmt.Sprintf("%s:%d", s.Address, s.Port)
	// open connection
	conn, err := ssh.Dial("tcp", server, s.SshConfig)
	if err != nil {
		return fmt.Errorf("dial to %v failed %v", server, err)
	}
	defer conn.Close()

	sftpc, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer sftpc.Close()
	s.SftpConfig = sftpc

	fileInfo, err := s.SftpConfig.Stat(dst)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return s.SftpConfig.RemoveDirectory(dst)
	} else {
		return s.SftpConfig.Remove(dst)
	}

}
