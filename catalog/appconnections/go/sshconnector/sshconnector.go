package sshconnector

import (
	"cowlibrary/vo"
	"fmt"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSH struct {
	UserName string   `json:"userName" yaml:"UserName"`
	SSHKey   vo.Bytes `json:"sSHKey" yaml:"SSHKey"`
}

type UserDefinedCredentials struct {
	SSH SSH `json:"sSH" yaml:"SSH"`
}

type SSHConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
}

func (thisObj *SSHConnector) Validate() (bool, error) {
	if errStr := thisObj.UserDefinedCredentials.SSH.ValidateAttributes(); errStr != "" {
		return false, errors.New(errStr)
	}

	_, _, err := thisObj.ExecCommand("pwd")
	if err != nil {
		return false, errors.New(err.Error())
	}

	return true, nil
}

func (ssh *SSH) ValidateAttributes() string {
	var emptyAttributes []string
	if ssh.UserName == "" {
		emptyAttributes = append(emptyAttributes, "UserName")
	}
	if len(ssh.SSHKey) == 0 {
		emptyAttributes = append(emptyAttributes, "SSHKey")
	}

	if len(emptyAttributes) > 0 {
		return fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return ""
}

func (thisObj *SSHConnector) ExecCommand(command string) (string, string, error) {
	client, err := thisObj.EstablishSSHConnection()
	if err != nil {
		return "", "", errors.New(err.Error())
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", errors.New(err.Error())
	}
	defer session.Close()

	output, err := session.Output(command)
	if err != nil {
		return "", "", errors.New("Failed to execute command")
	}

	return string(output), "", nil
}

func (thisObj *SSHConnector) EstablishSSHConnection() (*ssh.Client, error) {
	decodedKey := string(thisObj.UserDefinedCredentials.SSH.SSHKey)
	privateKey, err := ssh.ParsePrivateKey([]byte(decodedKey))
	if err != nil {
		return nil, errors.New("Invalid SSHKey")
	}

	sshConfig := &ssh.ClientConfig{
		User: thisObj.UserDefinedCredentials.SSH.UserName,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%d", thisObj.AppURL, thisObj.AppPort)
	u, err := url.Parse(addr)
	if err != nil {
		return nil, errors.New("Invalid URL")
	}

	ip := u.Hostname()
	port := thisObj.AppPort
	if port == 0 {
		port = 22
	}
	ipWithPort := fmt.Sprintf("%s:%d", ip, port)
	client, err := ssh.Dial("tcp", ipWithPort, sshConfig)
	if err != nil {
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, errors.New("Invalid UserName or SSHKey")
		} else if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "no such host") {
			return nil, errors.New("Invalid URL")
		} else if strings.Contains(err.Error(), "can't assign requested address") {
			return nil, errors.New("Invalid Port")
		} else {
			return nil, errors.New("Failed to connect to SSH server")
		}
	}

	return client, nil
}
