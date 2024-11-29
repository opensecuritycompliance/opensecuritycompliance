package kubernetes

import (
	"bytes"
	"cowlibrary/vo"
	"errors"
	"net"
	"time"

	argocdconnector "appconnections/argocdconnector"

	awsappconnector "appconnections/awsappconnector"

	servicenowconnector "appconnections/servicenowconnector"
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/ssh"
)

type Jumphost struct {
	UserID        string   `json:"userID" yaml:"UserID"`
	SshPrivateKey vo.Bytes `json:"sshPrivateKey" yaml:"SshPrivateKey"`
}

type UserDefinedCredentials struct {
	Jumphost Jumphost `json:"jumphost" yaml:"Jumphost"`
}

type LinkedApplications struct {
	awsappconnector.AWSAppConnector         `yaml:",inline"`
	servicenowconnector.ServiceNowConnector `yaml:",inline"`
	argocdconnector.ArgoCDConnector         `yaml:",inline"`
}

type Kubernetes struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"appPort"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	LinkedApplications     *LinkedApplications     `json:"linkedApplications" yaml:"linkedApplications"`
}

func (thisObj *Kubernetes) Validate() (bool, error) {
	err := thisObj.CheckJumphostCredentials()
	if err != nil {
		return false, err
	}
	valid, err := thisObj.ValidateJumpHostCredential()
	if err != nil {
		return false, err
	}
	return valid, nil
}

func (thisObj *Kubernetes) ValidateJumpHostCredential() (bool, error) {
	clusterCommand := fmt.Sprintf("%v", "ls")

	sshKey := string(thisObj.UserDefinedCredentials.Jumphost.SshPrivateKey)
	userName := thisObj.UserDefinedCredentials.Jumphost.UserID

	key, err := ssh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		if strings.Contains(err.Error(), "data truncated") {
			return false, errors.New("Invalid SSH Key.")
		}
		return false, err
	}
	appUrl := thisObj.GetIPFromAppURL()

	sshConfig := &ssh.ClientConfig{User: userName, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{(ssh.PublicKeys(key))}}
	connection, err := ssh.Dial("tcp", appUrl, sshConfig)
	if err != nil {
		if strings.Contains(err.Error(), "ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain") {
			return false, errors.New("Invalid username or SSH key.")
		} else if strings.Contains(err.Error(), "operation timed out") {
			return false, errors.New("Invalid AppURL.")
		} else if _, ok := err.(*net.OpError); ok {
			return false, errors.New("Invalid AppURL.")
		}
		return false, fmt.Errorf("Cannot connect %s", err.Error())
	}
	session, err := connection.NewSession()
	if err != nil {
		return false, errors.New("Cannot create session.")
	}
	defer session.Close()
	var out bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &out
	session.Stderr = &stderr
	err = session.Run(clusterCommand)
	if err != nil {
		return false, errors.New("Error while running command.")
	}
	return true, nil
}
func (thisObj *Kubernetes) GetIPFromAppURL() string {

	publicIPAddress := thisObj.AppURL
	if strings.Contains(thisObj.AppURL, "http://") {
		publicIPAddress = strings.ReplaceAll(thisObj.AppURL, "http://", "")
	} else if strings.Contains(thisObj.AppURL, "https://") {
		publicIPAddress = strings.ReplaceAll(thisObj.AppURL, "https://", "")
	}
	if strings.Contains(publicIPAddress, "/") {
		publicIPAddress = strings.ReplaceAll(publicIPAddress, "/", "")
	}
	return publicIPAddress

}

func (thisObj *Kubernetes) CheckJumphostCredentials() error {
	creds := []string{}
	if thisObj.UserDefinedCredentials == nil {
		return fmt.Errorf("UserInputs is empty")
	}
	if thisObj.AppURL == "" {
		creds = append(creds, "AppURL is empty")
	}

	if len(thisObj.UserDefinedCredentials.Jumphost.SshPrivateKey) == 0 {
		creds = append(creds, "SshPrivateKey is empty")
	}
	if thisObj.UserDefinedCredentials.Jumphost.UserID == "" {
		creds = append(creds, "UserID is empty")
	}

	if len(creds) > 0 {
		return fmt.Errorf("%s", strings.Join(creds, ", "))
	}

	return nil

}

func (thisObj *Kubernetes) GetJumphostCredential() (*JumphostCredentialVO, error) {
	err := thisObj.CheckJumphostCredentials()
	if err != nil {
		return nil, err
	}
	jumphostCredentialVO := &JumphostCredentialVO{}

	jumphost := thisObj.UserDefinedCredentials.Jumphost
	appUrl := thisObj.GetIPFromAppURL()

	login := strings.Split(appUrl, ":")
	if len(login) >= 2 {
		jumphostCredentialVO.Host = login[0]
		jumphostCredentialVO.Port = login[1]
	}
	jumphostCredentialVO.UserID = jumphost.UserID
	jumphostCredentialVO.Key = []byte(jumphost.SshPrivateKey)

	return jumphostCredentialVO, nil
}

func (thisObj *Kubernetes) RunUnixCommandsWithRetry(clustercommand string, maxRetries int) (string, error) {
	retryCount := 0
	var cmdOutput string
	var err error

	for retryCount < maxRetries {
		cmdOutput, err = thisObj.RunUnixCommands(clustercommand)
		if err == nil || !strings.Contains(err.Error(), "ssh: handshake failed:") {
			break
		}
		retryCount++
		time.Sleep(3 * time.Second)
	}

	return cmdOutput, err
}

func (thisObj *Kubernetes) RunUnixCommands(cmd string) (string, error) {

	jumphostCredential, err := thisObj.GetJumphostCredential()
	if err != nil {
		return "", err
	}

	key, err := ssh.ParsePrivateKey([]byte(jumphostCredential.Key))
	if err != nil {
		return "", err
	}
	sshConfig := &ssh.ClientConfig{User: jumphostCredential.UserID, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{(ssh.PublicKeys(key))}}
	connection, err := ssh.Dial("tcp", jumphostCredential.Host+":"+jumphostCredential.Port, sshConfig)
	if err != nil {
		return "", err
	}
	session, err := connection.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var out bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &out
	session.Stderr = &stderr

	err = session.Run(cmd)
	if err != nil {
		return stderr.String(), err
	}
	return out.String(), nil
}

func GetCurrentDatetime() time.Time {
	return time.Now().UTC()
}

func (thisObj *Kubernetes) ValidateStruct(s interface{}) error {
	validate := validator.New()
	if err := validate.Struct(s); err != nil {
		return err
	}
	return nil
}

type JumphostCredentialVO struct {
	Host              string
	UserID            string
	Port              string
	Key               []byte
	Context           string
	SubscriptionID    string
	SubscriptionName  string
	ResourceGroupName string
}
