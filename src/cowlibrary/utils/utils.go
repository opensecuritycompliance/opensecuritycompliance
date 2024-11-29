package utils

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/dmnlk/stringUtils"
	resty "github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/iancoleman/strcase"
	version "github.com/mcuadros/go-version"
	minio "github.com/minio/minio-go/v7"
	credentials "github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"

	"cowlibrary/constants"
	"cowlibrary/vo"
)

const MinGoVersion = "go1.19"

func IsFileExist(path string) bool {
	time.Now()
	_, err := os.Stat(path)
	return err == nil
}

func IsFolderExist(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func IsFolderNotExist(path string) bool {
	return !IsFolderExist(path)
}

func IsFileNotExist(path string) bool {
	return !IsFileExist(path)
}

// m:TODO Revisit the function and evaluate the utility
func GetRulePath(path, ruleName string) (string, error) {
	if IsEmpty(ruleName) {
		return "", errors.New("rule name cannot be empty")
	}

	ruleName = strcase.ToCamel(ruleName)

	directoryPath := ``

	if IsEmpty(path) {
		mydir, err := os.Getwd()
		if err != nil {
			return "", errors.New("not a valid path")
		}
		path = mydir
	}

	if IsNotEmpty(path) {

		if IsFolderNotExist(path) {
			return "", fmt.Errorf("%s not a valid directory", path)
		}

		if stringUtils.IsNotBlank(path) {
			if strings.HasSuffix(path, string(os.PathSeparator)) {
				path = path[:len(path)-1]
			}

		}

		if IsFileNotExist(path) {
			return "", errors.New("not a valid path")
		}

		directoryPath = filepath.Join(path, ruleName)
	}

	return directoryPath, nil
}

func GetSynthesizerPath(path, synthesizerName string) (string, error) {
	if IsEmpty(synthesizerName) {
		return "", errors.New("synthesizer name cannot be empty")
	}

	synthesizerName = GetValidSynthesizerName(synthesizerName)

	directoryPath := ``

	if IsEmpty(path) {
		mydir, err := os.Getwd()
		if err != nil {
			return "", errors.New("not a valid path")
		}
		path = mydir
	}

	if IsNotEmpty(path) {
		fileInfo, err := os.Stat(path)
		if os.IsNotExist(err) {
			return "", errors.New("not a valid path")
		}

		if !fileInfo.IsDir() {
			return "", errors.New("not a valid directory")
		}

		if stringUtils.IsNotBlank(path) {
			if strings.HasSuffix(path, string(os.PathSeparator)) {
				path = path[:len(path)-1]
			}

		}

		if IsFileNotExist(path) {
			return "", errors.New("not a valid path")
		}

		directoryPath = filepath.Join(path, synthesizerName)
	}

	return directoryPath, nil
}

func GetValidSynthesizerName(synthesizerName string) string {
	regex := regexp.MustCompile("[^a-zA-Z0-9]+")
	return strings.Join(regex.Split(strings.ToLower(synthesizerName), -1), "")
}

func GetSynthesizerClassName(synthesizerName string) string {
	regex := regexp.MustCompile("[^a-zA-Z0-9]+")
	return strcase.ToCamel(strings.Join(regex.Split(synthesizerName, -1), ""))
}

// ToDo:Check if we can avoid the GetTaskDetails function
func GetTaskDetails(path, taskName string, additionalInfo *vo.AdditionalInfo) (*vo.TaskDetails, error) {
	if IsEmpty(taskName) {
		return nil, errors.New("task name cannot be empty")
	}

	taskName = strcase.ToCamel(taskName)
	taskDetails := &vo.TaskDetails{SrcTaskName: taskName}

	if IsEmpty(path) {
		if additionalInfo.GlobalCatalog {
			path = additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath

		} else {
			path = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks")

		}
	}
	if IsEmpty(path) {
		mydir, err := os.Getwd()
		if err != nil {
			return nil, errors.New("not a valid path")
		}
		path = mydir
	}

	tasksPath := path
	if strings.Contains(path, "rules") {
		last_index := strings.LastIndex(path, "rules")
		if last_index != -1 {
			tasksPath = path[:last_index]
		}
	}
	if filepath.Base(tasksPath) != "tasks" {
		tasksPath = filepath.Join(tasksPath, "tasks")
	}
	taskPath := filepath.Join(tasksPath, taskName)
	taskDetails.TaskPath = taskPath

	return taskDetails, nil
}

func IsGoOutDated() bool {
	return version.Compare(runtime.Version(), MinGoVersion, "<=")
}

func ReverseSlice[K comparable](ss []K) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

func DownloadFileFromMinioWithDefaultCred(bucketName, objectName, fileName string) error {
	hostName, _ := os.LookupEnv("MINIO_HOST_NAME")
	portNo, _ := os.LookupEnv("MINIO_PORT_NUMBER")
	accessKey, _ := os.LookupEnv("MINIO_ROOT_USER")
	secretKey, _ := os.LookupEnv("MINIO_ROOT_PASSWORD")
	return DownloadFileFromMinio(bucketName, objectName, fileName, hostName+":"+portNo, accessKey, secretKey)
}

func DownloadFileFromMinio(bucketName, objectName, fileName, url, accessKey, secretKey string) error {

	minioClient, err := minio.New(url, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: true,
	})
	if err != nil {
		return err
	}

	if err := minioClient.FGetObject(context.Background(), bucketName, objectName, fileName, minio.GetObjectOptions{}); err != nil {
		return err
	}

	return nil

}

func IsRulePath(rulePath string) bool {
	return IsFileExist(filepath.Join(rulePath, constants.RuleFile)) || IsFileExist(filepath.Join(rulePath, constants.RuleYamlFile))
}
func IsNotValidRulePath(rulePath string) bool {
	return !IsRulePath(rulePath)
}

func IsValidRulePath(rulePath string) bool {
	return IsRulePath(rulePath)
}

func IsRulesDependencyFolder(rulePath string) bool {
	return IsFileExist(filepath.Join(rulePath, constants.RuleGroupFile)) || IsRuleGroupFolder(rulePath)
}

func IsRuleGroupFolder(rulePath string) bool {
	return IsFileExist(filepath.Join(rulePath, constants.RuleGroupYAMLFileName))
}

func FetchRuleCountInFolder(directoryPath string) (int64, error) {

	var ruleCount int64 = 0

	isToBeIgnore := func(path string, parentPaths []string) bool {
		for _, val := range parentPaths {
			if strings.HasPrefix(path, val) {
				return true
			}
		}
		return false
	}

	pathsToBeIgnore := []string{}

	err := filepath.WalkDir(directoryPath, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !isToBeIgnore(path, pathsToBeIgnore) && info.IsDir() {
			if IsRulesDependencyFolder(path) {

				if IsRuleGroupFolder(path) {
					byts, err := os.ReadFile(filepath.Join(path, constants.RuleGroupYAMLFileName))
					if err == nil {
						ruleDependency := &vo.RuleGroupYAMLVO{}
						err = yaml.Unmarshal(byts, ruleDependency)
						if err == nil && ruleDependency != nil && ruleDependency.Spec.RulesInfo != nil {
							ruleCount += int64(len(ruleDependency.Spec.RulesInfo))
						}
					}

				} else {
					byts, err := os.ReadFile(filepath.Join(path, constants.RuleGroupFile))
					if err == nil {
						ruleDependency := &vo.RuleDependency{}
						err = json.Unmarshal(byts, ruleDependency)
						if err == nil {
							ruleCount += int64(len(ruleDependency.RulesInfo))
						}
					}
				}

			} else if IsValidRulePath(path) {

				ruleCount++
			}
		}
		return nil
	})

	return ruleCount, err
}

func ReadFromFileHelper(inputFileDir, fileName string, target interface{}) {
	isTargetFilledWithData := false
	if _, err := os.Stat(inputFileDir); err == nil {
		if !strings.HasSuffix(inputFileDir, string(os.PathSeparator)) {
			inputFileDir += string(os.PathSeparator)
		}

		filePath := inputFileDir + fileName + ".json"
		if _, err := os.Stat(filePath); err == nil {
			byts, err := os.ReadFile(filePath)
			if err != nil {
				return
			}
			err = json.Unmarshal(byts, target)
			if err == nil {
				isTargetFilledWithData = true
			}
		}
	}

	if !isTargetFilledWithData {
		ReadFromFile(fileName, target)
	}

}

func ReadFromFile(fileName string, target interface{}) {
	ReadFileHelperWithExtension(fileName, "json", target)
}

func ReadFileHelperWithExtension(fileName, extension string, target interface{}) {
	if !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	if !strings.HasSuffix(fileName, extension) {
		fileName += extension
	}
	ReadFileHelper(fileName, target, 4, 0)
}

func ReadFileHelperWithExtensionAndReturnFileInfo(fileName, extension string, nestedLevelLimit int, count int) *vo.PolicyCowFileInfo {

	if !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	if !strings.HasSuffix(fileName, extension) {
		fileName += extension
	}
	return ReadFileHelperWithFileInfo(fileName, nestedLevelLimit, count)

}

func ReadFileHelperWithExtLookUpAndReturnFileInfo(fileName, extension, lookUpFolder string, nestedLevelLimit int, count int) *vo.PolicyCowFileInfo {

	if !strings.HasPrefix(extension, ".") {
		extension = "." + extension
	}
	if !strings.HasSuffix(fileName, extension) {
		fileName += extension
	}
	return ReadFileHelperWithLookUpFolder(fileName, lookUpFolder, nestedLevelLimit, count)

}

func ReadFileHelper(fileName string, target interface{}, nestedLevelLimit int, count int) {

	fileInfo := ReadFileHelperWithFileInfo(fileName, nestedLevelLimit, count)
	if fileInfo != nil {
		json.Unmarshal(fileInfo.FileByts, target)
	}

}

func ReadFileHelperWithFileInfo(fileName string, nestedLevelLimit int, count int) *vo.PolicyCowFileInfo {
	return ReadFileHelperWithLookUpFolderAndReturnFileInfo(fileName, "files", nestedLevelLimit, count)
}

func ReadFileHelperWithLookUpFolder(fileName, lookupFolder string, nestedLevelLimit int, count int) *vo.PolicyCowFileInfo {
	return ReadFileHelperWithLookUpFolderAndReturnFileInfo(fileName, lookupFolder, nestedLevelLimit, count)
}

func ReadFileHelperWithLookUpFolderAndReturnFileInfo(fileName, lookupFolder string, nestedLevelLimit int, count int) *vo.PolicyCowFileInfo {

	if nestedLevelLimit < count {
		return nil
	}
	count++
	if !strings.Contains(fileName, string(os.PathSeparator)) {
		fileName = lookupFolder + string(os.PathSeparator) + fileName
	} else {
		fileName = ".." + string(os.PathSeparator) + fileName
	}

	fs, err := os.Stat(fileName)
	if err != nil || fs.IsDir() {
		return ReadFileHelperWithFileInfo(fileName, nestedLevelLimit, count)
	}

	byts, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Println("error while reading " + fileName)
		return nil
	}

	fileInfo := &vo.PolicyCowFileInfo{FileName: fs.Name(), FileByts: byts, FilePath: fileName}
	return fileInfo
}

func GetTaskLanguage(taskPath string) constants.SupportedLanguage {

	switch {
	case IsFileExist(filepath.Join(taskPath, constants.AutoGeneratedFilePrefix+"main.py")) || IsFileExist(filepath.Join(taskPath, "task.py")):
		return constants.SupportedLanguagePython
	default:
		return constants.SupportedLanguageGo
	}

}

func IsGoTask(taskPath string) bool {
	return GetTaskLanguage(taskPath) == constants.SupportedLanguageGo
}

func GetConfigFromFile(filePath string) (*vo.PolicyCowConfig, error) {

	if IsFileExist(filePath) {
		policyCowConfig := &vo.PolicyCowConfig{PathConfiguration: &vo.CowPathConfiguration{}}
		if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
			fileByts, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}

			err = yaml.Unmarshal(fileByts, policyCowConfig)
			if err != nil {
				return nil, err
			}
			return policyCowConfig, nil
		} else if strings.HasSuffix(filePath, ".json") {
			fileByts, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal(fileByts, policyCowConfig)
			if err != nil {
				return nil, err
			}
			return policyCowConfig, nil
		}
	}

	return nil, errors.New("not a valid file")
}

func IsRulePresentInSystem(ruleName string, additionalInfo *vo.AdditionalInfo) bool {

	rulePath := GetRuleNameFromAdditionalInfoWithRuleName(ruleName, additionalInfo)

	return IsFileExist(rulePath) && IsRulePath(rulePath)
}

func GetRuleNameFromAdditionalInfoWithRuleName(ruleName string, additionalInfo *vo.AdditionalInfo) string {
	return GetRulePathFromCatalog(additionalInfo, ruleName)
}

func GetNewUUID() string {
	uuid_, _ := uuid.NewUUID()
	return uuid_.String()
}

func RemoveChildrensFromFolder(filePath string) error {
	if IsFolderExist(filePath) {
		err := os.RemoveAll(filePath)
		if err != nil {
			return err
		}
		return os.MkdirAll(filePath, os.ModePerm)
	}
	return errors.New("folder not available")

}

func TARFiles(srcDir, targetDir, fileName string) error {
	if IsEmpty(targetDir) {
		currentDir, err := os.Getwd()
		if err != nil {
			return err
		}
		targetDir = currentDir
	}
	if IsNotEmpty(targetDir) && !IsFolderExist(targetDir) {
		err := os.MkdirAll(targetDir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	if !strings.HasSuffix(fileName, ".tar") {
		fileName += ".tar"
	}

	commandSeq := fmt.Sprintf(`tar -C %s --exclude={"task_output.json","files","inputs.yaml"} -zcf %s ./`, srcDir, filepath.Join(targetDir, fileName))

	cmd := exec.Command("bash", "-c", commandSeq)
	_, err := cmd.Output()
	if err != nil {
		return err
	}

	return nil
}

func ZIPFilesWithCommands(srcDir, targetDir, fileOrFolderName string) error {
	if IsEmpty(targetDir) {
		currentDir, err := os.Getwd()
		if err != nil {
			return err
		}
		targetDir = currentDir
	}
	if IsNotEmpty(targetDir) && !IsFolderExist(targetDir) {
		err := os.MkdirAll(targetDir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	zipActionCommand := fmt.Sprintf("zip -r %s %s", filepath.Join(targetDir, fileOrFolderName+".zip"), fileOrFolderName)

	cmd := exec.Command("bash", "-c", zipActionCommand)
	cmd.Dir = srcDir
	_, err := cmd.Output()
	if err != nil {
		return err
	}

	return nil
}

func ZIPFiles(srcDir, targetDir, fileName string) error {

	if IsEmpty(targetDir) {
		currentDir, err := os.Getwd()
		if err != nil {
			return err
		}
		targetDir = currentDir
	}

	if !strings.HasSuffix(fileName, ".zip") {
		fileName += ".zip"
	}

	return zipDirectory(filepath.Join(targetDir, fileName), srcDir)
}

func zipDirectory(zipFilepath, directoryPath string) error {
	outFile, err := os.Create(zipFilepath)
	if err != nil {
		return err
	}

	w := zip.NewWriter(outFile)

	if err := addFilesToZip(w, directoryPath, ""); err != nil {
		_ = outFile.Close()
		return err
	}

	if err := w.Close(); err != nil {
		_ = outFile.Close()
		return fmt.Errorf("Warning: closing zipfile writer failed: %s", err.Error())
	}

	if err := outFile.Close(); err != nil {
		return fmt.Errorf("Warning: closing zipfile failed: %s", err.Error())
	}

	return nil
}

func addFilesToZip(w *zip.Writer, basePath, baseInZip string) error {
	files, err := ioutil.ReadDir(basePath)
	if err != nil {
		return err
	}

	for _, file := range files {
		fullfilepath := filepath.Join(basePath, file.Name())
		if _, err := os.Stat(fullfilepath); os.IsNotExist(err) {
			// ensure the file exists. For example a symlink pointing to a non-existing location might be listed but not actually exist
			continue
		}

		if file.Mode()&os.ModeSymlink != 0 {
			continue
		}

		if file.IsDir() {
			if err := addFilesToZip(w, fullfilepath, filepath.Join(baseInZip, file.Name())); err != nil {
				return err
			}
		} else if file.Mode().IsRegular() {
			dat, err := os.ReadFile(fullfilepath)
			if err != nil {
				return err
			}
			f, err := w.Create(filepath.Join(baseInZip, file.Name()))
			if err != nil {
				return err
			}
			_, err = f.Write(dat)
			if err != nil {
				return err
			}
		} else {
		}
	}
	return nil
}

func GetUniqueValuesFromString(values []string) []string {
	uiqueElements := make([]string, 0)
	elements := make(map[string]struct{})
	for _, value := range values {
		elements[value] = struct{}{}
	}
	for element := range elements {
		uiqueElements = append(uiqueElements, element)
	}
	return uiqueElements
}

func IsValidCredentials(additionalInfo *vo.AdditionalInfo) bool {
	_, err := GetAuthToken(additionalInfo)
	return err == nil
}

func GetAuthToken(additionalInfo *vo.AdditionalInfo) (*vo.AuthorizationResponse, error) {

	authResponse := &vo.AuthorizationResponse{}

	if additionalInfo.InternalFlow && additionalInfo.SecurityContext != nil && IsNotEmpty(additionalInfo.SecurityContext.AuthToken) {
		authResponse.AuthToken = additionalInfo.SecurityContext.AuthToken
		return authResponse, nil
	}

	clientID, clientSecret := constants.CowClientID, constants.CowClientSecret

	if additionalInfo.PolicyCowConfig.UserData != nil {
		if IsNotEmpty(additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientID) {
			clientID = additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientID
		}
		if IsNotEmpty(additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientSecret) {
			clientSecret = additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientSecret
		}
	}

	if IsNotEmpty(additionalInfo.ClientID) {
		clientID = additionalInfo.ClientID
	}

	if IsNotEmpty(additionalInfo.ClientSecret) {
		clientSecret = additionalInfo.ClientSecret
	}

	apiServEndpoint := GetCowAPIEndpoint(additionalInfo)

	url := fmt.Sprintf("%s/v1/oauth2/token", apiServEndpoint)

	client := resty.New()

	formData := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     clientID,
		"client_secret": clientSecret,
	}

	if IsNotEmpty(additionalInfo.UserDomain) {
		formData["domain_name"] = additionalInfo.UserDomain
	}

	errorVO := &vo.ErrorVO{}

	resp, err := client.R().SetFormData(formData).SetResult(authResponse).SetError(errorVO).Post(url)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		if errorVO != nil && (IsNotEmpty(errorVO.Description)) {
			return nil, errors.New(errorVO.Description)
		} else if authResponse == nil || IsEmpty(authResponse.AuthToken) || IsEmpty(authResponse.TokenType) {
			return nil, errors.New("cannot get auth token")
		}
	}

	return authResponse, nil

}

func GetCowAPIEndpoint(additionalInfo *vo.AdditionalInfo) string {
	return fmt.Sprintf("%s/api", GetCowDomain(additionalInfo))
}

func GetCowDomain(additionalInfo *vo.AdditionalInfo) string {
	if additionalInfo.InternalFlow {
		return constants.COWAPIServiceURL
	}
	subDomain := constants.CowPublishSubDomain
	host := additionalInfo.Host
	if host != "" {
		if strings.HasPrefix(host, "https://") {
			return host
		}
		return fmt.Sprintf("https://%s", host)
	}
	if additionalInfo.PolicyCowConfig.UserData != nil {
		if IsNotEmpty(additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.SubDomain) {
			subDomain = additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.SubDomain
		}
	}

	if IsNotEmpty(additionalInfo.SubDomain) {
		subDomain = additionalInfo.SubDomain
	}

	domain := constants.CowPublishDomain
	domain = strings.Join([]string{subDomain, domain}, ".")

	return fmt.Sprintf("https://%s", domain)
}

func GetAuthHeader(additionalInfo *vo.AdditionalInfo) (map[string]string, error) {
	authResponse, err := GetAuthToken(additionalInfo)

	if err != nil {
		return nil, err
	}

	authToken := fmt.Sprintf("%s %s", authResponse.TokenType, authResponse.AuthToken)

	if additionalInfo.InternalFlow && additionalInfo.SecurityContext != nil && IsNotEmpty(additionalInfo.SecurityContext.AuthToken) {
		authToken = additionalInfo.SecurityContext.AuthToken
	}

	header := map[string]string{
		"Authorization": authToken,
	}

	return header, nil
}

type FileMeta struct {
	Path  string
	IsDir bool
}

func IsNotEmpty(val string) bool {
	return len(val) > 0 && len(strings.TrimSpace(val)) > 0
}

func IsEmpty(val string) bool {
	return !IsNotEmpty(val)
}

func IsNoneEmpty(strArr []string) bool {
	if len(strArr) == 0 {
		return false
	}
	for _, s := range strArr {
		if IsEmpty(s) {
			return false
		}
	}
	return true
}

func IsAnyEmpty(strArr []string) bool {
	return !IsNoneEmpty(strArr)
}

func IsValidArray(strArr []string) bool {
	return len(strArr) > 0
}

func IsEmptyArray(strArr []string) bool {
	return !IsValidArray(strArr)
}

func GetNonEmptyValuesFromArray(strArr []string) []string {
	nonEmptyStrArr := make([]string, 0)

	for _, s := range strArr {
		if IsNotEmpty(s) {
			nonEmptyStrArr = append(nonEmptyStrArr, s)
		}
	}
	return nonEmptyStrArr
}

func IsStringContainsAny(val string, arr []string) bool {
	val = strings.ToLower(val)
	for _, va := range arr {
		if strings.Contains(val, strings.ToLower(va)) {
			return true
		}
	}
	return false
}

func SliceContains(arr []string, val string) bool {
	for _, va := range arr {
		if val == va {
			return true
		}
	}
	return false
}

func GetRuleExecution(fileName string, id string) string {
	f, _ := os.Open(fileName)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, id) {
			return line
		}
	}
	return ""
}

func TitleFormat(input string) string {
	return cases.Title(language.English).String(input)
}

func RemoveCommentsFromFile(filePath string, comments []string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	updatedContent := string(content)
	for _, comment := range comments {
		updatedContent = strings.ReplaceAll(updatedContent, comment, "")
	}
	err = os.WriteFile(filePath, []byte(updatedContent), 0)
	if err != nil {
		return err
	}
	return nil
}
func RemoveCommentsFromPythonFiles(rootDir string, comments []string) error {
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".py" {
			err = RemoveCommentsFromFile(path, comments)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

// GetGlobalCatalogPath
func GetPathFromGlobalCatalog(path, name string) string {
	fullPath := filepath.Join(path, name)
	if IsFolderExist(fullPath) || IsFileExist(fullPath) {
		return fullPath
	}
	return ""

}
func GetPathFromLocalCatalogSubDir(localCatalogPath, dirName, name string) string {
	pattern := filepath.Join(localCatalogPath, "*", dirName, name)
	matches, _ := filepath.Glob(pattern)
	if len(matches) > 0 {
		return matches[0]
	}
	return ""

}

func GetPathFromLocalCatalog(localCatalogPath, dirName, name string) string {
	if IsEmpty(name) {
		return ""
	}
	fullPath := filepath.Join(localCatalogPath, dirName, name)
	if IsFolderExist(fullPath) || IsFileExist(fullPath) {
		return fullPath
	}
	return GetPathFromLocalCatalogSubDir(localCatalogPath, dirName, name)

}

func GetCatalogPath(additionalInfo *vo.AdditionalInfo, globalCatalogPath, dirName, name string) string {
	localCatalogPath := GetPathFromLocalCatalog(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, dirName, name)
	if IsEmpty(localCatalogPath) || additionalInfo.GlobalCatalog {
		return GetPathFromGlobalCatalog(globalCatalogPath, name)
	}
	return localCatalogPath

}

// rule path
func GetRulePathFromCatalog(additionalInfo *vo.AdditionalInfo, ruleName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "rules", ruleName)
}

// rule group path
func GetRuleGroupPathFromCatalog(additionalInfo *vo.AdditionalInfo, ruleGroupName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.RuleGroupPath, "rulegroups", ruleGroupName)

}

// catalog dashboard path
func GetDashboardPathFromCatalog(additionalInfo *vo.AdditionalInfo, dashboardName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.DashboardsPath, "dashboards", dashboardName)
}

// yaml path
func GetYamlFilesPathFromCatalog(additionalInfo *vo.AdditionalInfo, yamlFileName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.YamlFilesPath, "yamlfiles", yamlFileName)
}

// applications yaml path
func GetYamlFilesPathFromApplicationCatalog(additionalInfo *vo.AdditionalInfo, yamlFileName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.YamlFilesPath, filepath.Join("yamlfiles", "applications"), yamlFileName)
}

// credentials yaml path
func GetYamlFilesPathFromCredentialsCatalog(additionalInfo *vo.AdditionalInfo, yamlFileName string) string {
	return GetCatalogPath(additionalInfo, additionalInfo.PolicyCowConfig.PathConfiguration.YamlFilesPath, filepath.Join("yamlfiles", "credentials"), yamlFileName)
}

// local catalog path using rule path
func GetPathFromLocalCatalogWithRulePath(rulePath, localCatalogPath, dirName, name string) string {
	possible_path := localCatalogPath
	if IsNotEmpty(rulePath) {

		ruleBasePath := filepath.Dir(rulePath)
		if filepath.Base(ruleBasePath) == "rules" {
			possible_path = filepath.Dir(ruleBasePath)
		}
	}
	if IsNotEmpty(possible_path) && IsNotEmpty(name) && IsFolderExist(filepath.Join(possible_path, dirName, name)) {
		return filepath.Join(possible_path, dirName, name)
	}
	return GetPathFromLocalCatalog(localCatalogPath, dirName, name)
}

func GetCatalogPathUsingRuleName(additionalInfo *vo.AdditionalInfo, ruleName, dirName, name, globalCatalogPath string) string {
	if !additionalInfo.GlobalCatalog {
		localCatalogRulePath := GetPathFromLocalCatalog(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "rules", ruleName)
		pathFromLocalCatalog := GetPathFromLocalCatalogWithRulePath(localCatalogRulePath, additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, dirName, name)
		if IsNotEmpty(pathFromLocalCatalog) {
			return pathFromLocalCatalog
		}
	}
	return GetPathFromGlobalCatalog(globalCatalogPath, name)
}

// Task path
func GetTaskPathFromCatalog(additionalInfo *vo.AdditionalInfo, ruleName, taskName string) string {
	return GetCatalogPathUsingRuleName(additionalInfo, ruleName, "tasks", taskName, additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath)
}

func GetTaskPathFromCatalogForInit(additionalInfo *vo.AdditionalInfo, taskName string, isExistingTask bool) string {
	if isExistingTask {
		if IsFileExist(filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, taskName)) {
			return GetPathFromGlobalCatalog(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, taskName)
		} else {
			return GetPathFromLocalCatalog(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks", taskName)
		}
	} else {
		return GetPathFromLocalCatalog(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks", taskName)
	}
}

// synthesizer path
func GetSynthesizerPathFromCatalog(additionalInfo *vo.AdditionalInfo, ruleName, synthesizerName string) string {
	return GetCatalogPathUsingRuleName(additionalInfo, ruleName, "synthesizers", synthesizerName, additionalInfo.PolicyCowConfig.PathConfiguration.SynthesizersPath)

}

func AssignDefaultCatalogPath(additionalInfo *vo.AdditionalInfo, dirPath, dirName string) string {
	path := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, dirName)
	if additionalInfo.GlobalCatalog {
		path = dirPath
	}
	return path
}

func CreateDeclarativeFiles(srcData, generatedData []byte, folderPath string) []*vo.ErrorDetailVO {

	errorDetails := make([]*vo.ErrorDetailVO, 0)

	err := os.WriteFile(filepath.Join(folderPath, constants.YAMLTypeSrc), srcData, os.ModePerm)

	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateSrcFile})
		return errorDetails
	}

	err = os.WriteFile(filepath.Join(folderPath, constants.YAMLTypeGenerated), generatedData, os.ModePerm)

	if err != nil {
		errorDetails = append(errorDetails, &vo.ErrorDetailVO{Issue: constants.ErrorCannotCreateGeneratedFile})
		return errorDetails
	}

	return nil
}

func GetDeclarativePathWithAvailability(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo, subPath string) (folderPath, credentialsPath string, isAlreadyAvailable bool) {
	version := constants.VersionLatest
	if IsNotEmpty(meta.Version) {
		version = meta.Version
	}

	// folderName := strings.ToLower(meta.Name)
	folderName := meta.Name

	credentialsPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, subPath)

	folderPath = filepath.Join(credentialsPath, folderName, version)
	return folderPath, credentialsPath, IsFolderExist(folderPath)
}

func GetDeclarativePathWithAvailabilityV2(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo, subPath string) (folderPath, credentialsPath string, isAlreadyAvailable bool) {
	folderName := meta.Name

	credentialsPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, subPath)

	folderPath = filepath.Join(credentialsPath, folderName)
	return folderPath, credentialsPath, IsFolderExist(folderPath)
}

func IsDeclarativesAlreadyPresent(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo, subPath string) bool {
	_, _, isAlreadyAvailable := GetDeclarativePathWithAvailability(meta, additionalInfo, subPath)
	return isAlreadyAvailable
}

func ValidateLinkedApplications(spec *vo.CowApplicationSpecVO, additionalInfo *vo.AdditionalInfo, yamlFilePath string) *vo.ErrorDetailVO {
	visited := make(map[string]bool)
	for _, linkedApp := range spec.LinkableApplicationClasses {
		if errorDetailVO := validateLinkedApplicationsRecursively(linkedApp.Name, visited, yamlFilePath); errorDetailVO != nil {
			return errorDetailVO
		}
	}
	return nil
}

func validateLinkedApplicationsRecursively(appName string, visited map[string]bool, yamlFilePath string) *vo.ErrorDetailVO {
	if visited[appName] {
		return &vo.ErrorDetailVO{Field: "LinkedApplication", Issue: fmt.Sprintf("Cycle detected: Unable to create application. The linked application '%s' is creating a circular dependency.", appName)}
	}
	visited[appName] = true
	filepath := replaceFilename(yamlFilePath, appName+".yaml")
	applicationVO := &vo.UserDefinedApplicationVO{}
	yamlFileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return &vo.ErrorDetailVO{Issue: fmt.Sprintf("Error reading file %s: %v", filepath, err)}

	}
	err = yaml.Unmarshal(yamlFileBytes, &applicationVO)
	if err != nil {
		return &vo.ErrorDetailVO{Issue: fmt.Sprintf("Error unmarshaling YAML file %s: %v", filepath, err)}
	}
	for _, linkedApp := range applicationVO.Spec.LinkableApplicationClasses {
		if err := validateLinkedApplicationsRecursively(linkedApp.Name, visited, yamlFilePath); err != nil {
			return err
		}
	}
	return nil
}

func replaceFilename(filePath, newFilename string) string {
	dir := filepath.Dir(filePath)
	return filepath.Join(dir, newFilename)
}

func IsDeclarativesAlreadyPresentWithoutVersion(meta *vo.CowMetaVO, additionalInfo *vo.AdditionalInfo, subPath string) bool {
	_, _, isAlreadyAvailable := GetDeclarativePathWithAvailabilityV2(meta, additionalInfo, subPath)
	return isAlreadyAvailable
}

func Contains[V comparable](val V, values []V) bool {
	for _, i := range values {
		if i == val {
			return true
		}
	}
	return false
}

func GetCredentialYAMLObject(credentials []*vo.UserDefinedCredentialVO) *vo.CredentialYAML {

	credentialYAML := &vo.CredentialYAML{
		UserDefinedCredentials: make(map[string]map[string]interface{}),
	}

	for _, cred := range credentials {
		credential := make(map[string]interface{})
		for _, attribute := range cred.Spec.Attributes {
			if attribute.MultiSelect {
				credential[attribute.Name] = []interface{}{}
				if IsNotEmpty(attribute.DefaultValue) {
					credential[attribute.Name] = []interface{}{attribute.DefaultValue}
				}
			} else {
				credential[attribute.Name] = getDefaultValueForType(string(attribute.DataType))
				if IsNotEmpty(attribute.DefaultValue) {
					credential[attribute.Name] = attribute.DefaultValue
				}
			}

		}
		credentialYAML.UserDefinedCredentials[cred.Meta.Name] = credential
	}
	return credentialYAML
}

// func GetCredentialYAMLObjectV2(credentials []*vo.UserDefinedCredentialVO) *vo.CredentialYAMLV2 {

// 	credentialYAML := &vo.CredentialYAMLV2{}

// 	userCredMap := linkedhashmap.New()

// 	// credentialYAML.UserDefinedCredentials = linkedhashmap.New()

// 	for _, cred := range credentials {
// 		credential := linkedhashmap.New()
// 		// credential := make(map[string]interface{})
// 		for _, attribute := range cred.Spec.Attributes {
// 			if attribute.MultiSelect {
// 				credential.Put(attribute.Name, []interface{}{})
// 				// credential[attribute.Name] = []interface{}{}
// 				if IsNotEmpty(attribute.DefaultValue) {
// 					credential.Put(attribute.Name, []interface{}{attribute.DefaultValue})
// 					// credential[attribute.Name] = []interface{}{attribute.DefaultValue}
// 				}
// 			} else {
// 				fmt.Println("string(attribute.DataType) :", string(attribute.DataType))
// 				fmt.Println("getDefaultValueForType(string(attribute.DataType)) :", getDefaultValueForType(string(attribute.DataType)))
// 				credential.Put(attribute.Name, getDefaultValueForType(string(attribute.DataType)))
// 				// credential[attribute.Name] = getDefaultValueForType(string(attribute.DataType))

// 				if IsNotEmpty(attribute.DefaultValue) {
// 					credential.Put(attribute.Name, attribute.DefaultValue)
// 					// credential[attribute.Name] = attribute.DefaultValue
// 				}
// 			}

// 		}
// 		userCredMap.Put(cred.Meta.Name, credential)
// 	}

// 	credentialYAML.UserDefinedCredentials = userCredMap

// 	return credentialYAML
// }

func GetCredentialYAMLObjectV2(credentials []*vo.UserDefinedCredentialVO) *vo.CredentialYAMLV2 {

	credentialYAML := &vo.CredentialYAMLV2{}

	credYAMLMapSlice := make([]yaml.MapItem, 0)

	for _, cred := range credentials {

		credAttrYAMLMapSlice := make([]yaml.MapItem, 0)

		for _, attribute := range cred.Spec.Attributes {

			var val interface{}

			if attribute.MultiSelect {
				val = []interface{}{}
				if IsNotEmpty(attribute.DefaultValue) {
					val = []interface{}{attribute.DefaultValue}
				}
			} else {
				val = getDefaultValueForType(string(attribute.DataType))

				if IsNotEmpty(attribute.DefaultValue) {
					val = attribute.DefaultValue
				}

			}

			credAttrYAMLMapSlice = append(credAttrYAMLMapSlice, yaml.MapItem{Key: attribute.Name, Value: val})

		}

		credYAMLMapSlice = append(credYAMLMapSlice, yaml.MapItem{Key: cred.Meta.Name, Value: credAttrYAMLMapSlice})

	}

	credentialYAML.UserDefinedCredentials = credYAMLMapSlice

	return credentialYAML
}

func getDefaultValueForType(dataType string) interface{} {
	switch strings.ToUpper(dataType) {
	case "STRING":
		return ""
	case "INT":
		return 0
	case "FILE":
		return []byte{}
	case "FLOAT", "FLOAT64":
		return 0.0
	default:
		return nil
	}
}

func GetAppConnectionsPathWithLanguage(additionalInfo *vo.AdditionalInfo, language string) string {

	if pyLang := constants.SupportedLanguagePython.String(); language == pyLang {
		appConnPath := additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath
		return filepath.Join(appConnPath, pyLang, filepath.Base(appConnPath))
	}

	return filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.AppConnectionPath, constants.SupportedLanguageGo.String())
}

func InitializeGoModFile(folderPath, Name string) error {
	if IsFileNotExist(filepath.Join(folderPath, "go.mod")) {
		commandSeq := fmt.Sprintf("go mod init %s", Name)

		cmd := exec.Command("bash", "-c", commandSeq)
		cmd.Dir = folderPath
		_, err := cmd.Output()
		if err != nil {
			return err
		}
	}
	goModFilePath := filepath.Join(folderPath, "go.mod")

	if IsFileExist(goModFilePath) {
		file, err := os.OpenFile(goModFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer file.Close()
		// Create a new bufio.Writer for efficient writing
		writer := bufio.NewWriter(file)
		// Append the string to the next line
		_, err = fmt.Fprint(writer, constants.TaskGoModLibraryPointers)
		if err != nil {
			return err
		}
		// Flush the buffer to ensure data is written to the file
		err = writer.Flush()
		if err != nil {
			return err
		}

	}

	return nil
}

// func GetCowLibraryPath() (string, error) {
// 	return findFolder("src/cowlibrary")
// }

// func GetAppConnectionsPath() (string, error) {
// 	return findFolder("catalog/appconnections")
// }

// func findFolder(filePath string) (string, error) {
// 	maxCount := 5

// 	dir, err := os.Getwd()
// 	if err == nil {
// 		maxCount = len(strings.Split(dir, string(os.PathSeparator)))
// 	}

// 	return findPolicyCowLibrary(filePath, maxCount)

// }

// func findPolicyCowLibrary(filePath string, maxCount int) (string, error) {

// 	if maxCount == 0 {
// 		return "", fmt.Errorf("max depth reached:%d", maxCount)
// 	}

// 	if fileInfo, err := os.Stat(filePath); err == nil && fileInfo.IsDir() {
// 		return filePath, nil
// 	}

// 	maxCount = maxCount - 1

// 	return findPolicyCowLibrary(filepath.Join("..", filePath), maxCount)

// }

func GetYAMLFileNameWithVersion(namePointer *vo.CowNamePointersVO) string {
	return namePointer.Name + "_v_" + strings.ReplaceAll(namePointer.Version, ".", "_") + ".yaml"
}

func GetYAMLFileNameWithoutVersion(namePointer *vo.CowNamePointersVO) string {
	return namePointer.Name + ".yaml"
}

func GetBytes(key interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(key)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil

}

func GetTasks(additionalInfo *vo.AdditionalInfo) []*vo.PolicyCowTaskVO {

	availableTasks := make([]*vo.PolicyCowTaskVO, 0)
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath

	pathPrefixs := []string{
		filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, "*", "__meta.json")}

	pathPrefixs = append(pathPrefixs, filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, "*", constants.TaskMetaYAMLFileName))
	pathPrefixs = append(pathPrefixs, filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, "*", "__meta.yml"))

	if !additionalInfo.GlobalCatalog {
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "tasks", "*", "__meta.json"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "tasks", "*", "__meta.json"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "tasks", "*", constants.TaskMetaYAMLFileName))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "tasks", "*", constants.TaskMetaYAMLFileName))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "tasks", "*", "__meta.yml"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "tasks", "*", "__meta.yml"))
	}

	for _, pattern := range pathPrefixs {
		catalogType := "globalcatalog"
		if strings.Contains(pattern, "localcatalog") {
			catalogType = "localcatalog"
		}
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {

			if strings.Contains(path, "localcatalog") {
				domain := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path))))
				if filepath.Base(domain) != "localcatalog" {
					catalogType = filepath.Base(domain)
				}
			}

			bytes, err := os.ReadFile(path)

			if err == nil {
				extension := filepath.Ext(path)
				taskVO := &vo.PolicyCowTaskVO{}
				if extension == ".json" {
					err = json.Unmarshal(bytes, taskVO)
				} else if extension == ".yaml" || extension == ".yml" {
					err = yaml.Unmarshal(bytes, taskVO)
				}

				if err == nil {
					taskVO.CatalogType = catalogType
					availableTasks = append(availableTasks, taskVO)
				}
			}
		}
	}

	return availableTasks

}

func GetTasksV2(additionalInfo *vo.AdditionalInfo) []*vo.PolicyCowTaskVO {

	availableTasks := make([]*vo.PolicyCowTaskVO, 0)
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath

	var pathPrefixs string
	if !additionalInfo.GlobalCatalog {
		pathPrefixs = filepath.Join(localcatalogPath, "tasks", "*")
	} else {
		pathPrefixs = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, "*")
	}

	catalogType := "globalcatalog"
	if strings.Contains(pathPrefixs, "localcatalog") {
		catalogType = "localcatalog"
	}
	matches, _ := filepath.Glob(pathPrefixs)
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			taskName := filepath.Base(path)

			taskVO := &vo.PolicyCowTaskVO{
				Name:        taskName,
				CatalogType: catalogType,
			}
			availableTasks = append(availableTasks, taskVO)
		}
	}

	return availableTasks
}

func GetAdditionalInfoFromEnv() (additionalInfo *vo.AdditionalInfo, err error) {

	configPath := constants.CowDataDefaultConfigFilePath

	if IsFileNotExist(configPath) {
		err = errors.New("cannot find the config file")
	} else {
		fileByts, err := os.ReadFile(configPath)
		if err == nil {
			additionalInfo = &vo.AdditionalInfo{}
			pathConfig := &vo.PolicyCowConfig{}
			yaml.Unmarshal(fileByts, pathConfig)
			additionalInfo.PolicyCowConfig = pathConfig
		}
	}
	return additionalInfo, err
}

func FindAndRemove[T string | int](slice []T, target T) []T {
	if index, ok := slices.BinarySearch(slice, target); index != -1 && ok {
		slice = append(slice[:index], slice[index+1:]...)
	}
	return slice
}

func FindAndRemoveAllOccurrences[T string | int](slice []T, target T) []T {
	for i := 0; i < len(slice); {
		if slice[i] == target {
			slice = append(slice[:i], slice[i+1:]...)
		} else {
			i++
		}
	}
	return slice
}

func ValidateRefMap(refMaps []*vo.RefStruct) []string {

	errorMsgs := make([]string, 0)

	// Assigning the output variable 'ss' as an input to the flow is not allowed.

	targetOutputVariables := make([]string, 0)
	srcInputVariables := make([]string, 0)

	selfAssignVars := make([]string, 0)

	for _, refMap := range refMaps {

		if refMap.TargetRef.FieldType == refMap.SourceRef.FieldType && refMap.SourceRef.AliasRef == refMap.TargetRef.AliasRef &&
			refMap.TargetRef.VarName == refMap.SourceRef.VarName {
			selfAssignVars = append(selfAssignVars, fmt.Sprintf("'%s'", refMap.TargetRef.VarName))
		}

		if refMap.TargetRef.FieldType == "Input" && refMap.TargetRef.AliasRef == "*" {
			targetOutputVariables = append(targetOutputVariables, fmt.Sprintf("'%s'", refMap.TargetRef.VarName))
		}

		if refMap.SourceRef.FieldType == "Output" && refMap.SourceRef.AliasRef == "*" {
			srcInputVariables = append(srcInputVariables, fmt.Sprintf("'%s'", refMap.SourceRef.VarName))
		}
	}

	if len(targetOutputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Assigning the output variable {%s} as input to the flow is not allowed.", strings.Join(targetOutputVariables, ",")))
	}

	if len(srcInputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("You cannot use the output variable of the rule as an input. {%s}", strings.Join(srcInputVariables, ",")))
	}

	if len(selfAssignVars) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Cannot assign a variable to itself. {%s}", strings.Join(selfAssignVars, ",")))
	}

	return errorMsgs
}

func GetApplications(appCriteria *vo.CowApplicationCriteriaVO) ([]*vo.UserDefinedApplicationVO, error) {
	additionalInfo, err := GetAdditionalInfoFromEnv()
	if err != nil {
		return nil, err
	}
	return GetApplicationsV2(additionalInfo, appCriteria)
}

func GetApplicationsV2(additionalInfo *vo.AdditionalInfo, appCriteria *vo.CowApplicationCriteriaVO) ([]*vo.UserDefinedApplicationVO, error) {
	if additionalInfo == nil {
		additionalInfoCopy, err := GetAdditionalInfoFromEnv()
		if err != nil {
			return nil, err
		}
		additionalInfo = additionalInfoCopy
	}
	applications := make([]*vo.UserDefinedApplicationVO, 0)
	// for _, pattern := range pathPrefixs {
	matches, _ := filepath.Glob(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath)
	for _, path := range matches {
		files, err := os.ReadDir(path)
		if err != nil {
			continue
		}
		for _, file := range files {
			if filepath.Ext(file.Name()) == ".yaml" {
				filePath := filepath.Join(path, file.Name())
				yamlContent, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}
				var data *vo.UserDefinedApplicationVO
				if err := yaml.Unmarshal(yamlContent, &data); err != nil {
					continue
				}
				if appCriteria.ShowLinkedApp && len(data.Spec.LinkableApplicationClasses) > 0 {
					addLinkedApplicationDetails(path, data.Spec.LinkableApplicationClasses)
				} else {
					data.Spec.LinkableApplicationClasses = nil
				}

				applications = append(applications, data)
			}
		}
	}
	// }

	filteredApplications := make([]*vo.UserDefinedApplicationVO, 0)

	for _, app := range applications {

		if
		// (libraryUtils.IsNoneEmpty(appCriteria.Type) && (libraryUtils.IsEmpty(task.Type) || !utils.StringInSlice(task.Type, taskCriteria.Type))) ||
		// (libraryUtils.IsNoneEmpty(appCriteria.Tags) && (libraryUtils.IsEmptyArray(app.Meta.Annotations) || !utils.IsAnyValueIntersected(task.Tags, taskCriteria.Tags))) ||
		(IsNoneEmpty(appCriteria.Version) && (IsEmpty(app.Meta.Version) || !IsStringContainsAny(app.Meta.Version, appCriteria.Version))) ||
			(IsNotEmpty(appCriteria.StartsWith) && (IsEmpty(app.Meta.Name) || !IsStringContainsAny(app.Meta.Name, []string{appCriteria.StartsWith}))) ||
			(IsNotEmpty(appCriteria.Like) && (IsEmpty(app.Meta.Name) || !IsStringContainsAny(app.Meta.Name, []string{appCriteria.Like}))) ||
			(IsNoneEmpty(appCriteria.Name) && (IsEmpty(app.Meta.Name) || !SliceContains(appCriteria.Name, app.Meta.Name))) ||
			(appCriteria.ShowLinkedApp) && len(app.Spec.LinkableApplicationClasses) == 0 {
			continue
		}

		filteredApplications = append(filteredApplications, app)
	}

	return filteredApplications, nil
}

func addLinkedApplicationDetails(path string, apps []*vo.CowNamePointersVO) {
	for _, linkedApp := range apps {
		linkedAppFilePath := filepath.Join(path, linkedApp.Name+".yaml")
		yamlContent, err := os.ReadFile(linkedAppFilePath)
		if err != nil {
			continue
		}
		var linkedAppData vo.UserDefinedApplicationVO
		if err := yaml.Unmarshal(yamlContent, &linkedAppData); err != nil {
			continue
		}
		linkedApp.AppDetails = &linkedAppData
		if len(linkedAppData.Spec.LinkableApplicationClasses) > 0 {
			addLinkedApplicationDetails(path, linkedAppData.Spec.LinkableApplicationClasses)
		}

	}
}

func GetCredentials(credentialCriteria *vo.CowCredentialCriteriaVO) ([]*vo.UserDefinedCredentialVO, error) {
	additionalInfo, err := GetAdditionalInfoFromEnv()
	if err != nil {
		return nil, err
	}

	return GetCredentialsV2(additionalInfo, credentialCriteria)
}

func GetCredentialsV2(additionalInfo *vo.AdditionalInfo, credentialCriteria *vo.CowCredentialCriteriaVO) ([]*vo.UserDefinedCredentialVO, error) {
	if additionalInfo == nil {
		additionalInfoCopy, err := GetAdditionalInfoFromEnv()
		if err != nil {
			return nil, err
		}
		additionalInfo = additionalInfoCopy
	}
	credentials := make([]*vo.UserDefinedCredentialVO, 0)
	credPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.DeclarativePath, "credentials")

	matches, _ := filepath.Glob(credPath)
	for _, path := range matches {
		dirs, err := os.ReadDir(path)
		if err != nil {
			continue
		}

		for _, dir := range dirs {
			files, err := os.ReadDir(filepath.Join(credPath, dir.Name()))
			if err != nil {
				continue
			}
			for _, file := range files {
				filePath := filepath.Join(path, dir.Name(), file.Name(), "generated.yaml")
				yamlContent, err := os.ReadFile(filePath)
				if err != nil {
					continue
				}
				var data *vo.UserDefinedCredentialVO
				if err := yaml.Unmarshal(yamlContent, &data); err != nil {
					continue
				}
				credentials = append(credentials, data)

			}
		}

	}

	filteredCredentials := make([]*vo.UserDefinedCredentialVO, 0)

	for _, credential := range credentials {

		if
		// (libraryUtils.IsNoneEmpty(appCriteria.Type) && (libraryUtils.IsEmpty(task.Type) || !utils.StringInSlice(task.Type, taskCriteria.Type))) ||
		// (libraryUtils.IsNoneEmpty(appCriteria.Tags) && (libraryUtils.IsEmptyArray(app.Meta.Annotations) || !utils.IsAnyValueIntersected(task.Tags, taskCriteria.Tags))) ||
		(IsNoneEmpty(credentialCriteria.Version) && (IsEmpty(credential.Meta.Version) || !IsStringContainsAny(credential.Meta.Version, credentialCriteria.Version))) ||
			(IsNotEmpty(credentialCriteria.StartsWith) && (IsEmpty(credential.Meta.Name) || !IsStringContainsAny(credential.Meta.Name, []string{credentialCriteria.StartsWith}))) ||
			(IsNotEmpty(credentialCriteria.Like) && (IsEmpty(credential.Meta.Name) || !IsStringContainsAny(credential.Meta.Name, []string{credentialCriteria.Like}))) ||
			(IsNoneEmpty(credentialCriteria.Name) && (IsEmpty(credential.Meta.Name) || !SliceContains(credentialCriteria.Name, credential.Meta.Name))) {
			continue
		}

		filteredCredentials = append(filteredCredentials, credential)
	}

	return filteredCredentials, nil

}

func HandlePagination[T any](criteria *vo.CriteriaVO, datas []*T) (*vo.Collection, error) {
	count := len(datas)
	if criteria.Page > 0 && criteria.PageSize > 0 {
		skip := (criteria.Page - 1) * criteria.PageSize
		size := criteria.PageSize
		limit := func() int {
			if skip+size > count {
				return count
			} else {
				return skip + size
			}
		}
		start := func() int {
			if skip > count {
				return count
			} else {
				return skip
			}
		}
		datas = datas[start():limit()]
	}

	collection := &vo.Collection{Items: datas, TotalItems: count}

	if criteria.Page > 0 && criteria.PageSize > 0 {
		collection.TotalPage = count / criteria.PageSize
		collection.Page = criteria.Page
		if count%criteria.PageSize != 0 {
			collection.TotalPage++
		}
	}

	return collection, nil
}

func GetRules(cowRulesCriteriaVO *vo.CowRulesCriteriaVO) ([]*vo.RuleYAMLVO, error) {
	return GetRulesV2(nil, cowRulesCriteriaVO)
}

func GetRulesV2(additionalInfo *vo.AdditionalInfo, cowRulesCriteriaVO *vo.CowRulesCriteriaVO) ([]*vo.RuleYAMLVO, error) {
	if additionalInfo == nil {
		additionalInfoCopy, err := GetAdditionalInfoFromEnv()
		if err != nil {
			return nil, err
		}
		additionalInfo = additionalInfoCopy
	}
	localcatalogPath := additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath
	pathPrefixs := []string{
		filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.json"),
		filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, "*", "rule.yaml")}
	if !additionalInfo.GlobalCatalog {
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rules", "*", "rule.json"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "rules", "*", "rule.yaml"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.json"))
		pathPrefixs = append(pathPrefixs, filepath.Join(localcatalogPath, "*", "rules", "*", "rule.yaml"))
	}
	policyCowDataSet := make([]*vo.RuleYAMLVO, 0)
	for _, pattern := range pathPrefixs {
		description := "The Resource is present in "
		if strings.Contains(pattern, "localcatalog") {
			description += "localcatalog"
		} else {
			description += "globalcatalog"

		}
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {

			folder := "globalcatalog"
			if strings.Contains(path, "localcatalog") {
				folder = "localcatalog"
				domain := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path))))
				if filepath.Base(domain) != "localcatalog" {
					folder = filepath.Base(domain)
					description += " in " + folder + " domain"
				}
			}
			bytes, err := os.ReadFile(path)
			if err == nil {
				extension := filepath.Ext(path)
				rulevo := &vo.RuleYAMLVO{}
				if extension == ".json" {
					err = json.Unmarshal(bytes, rulevo)
				} else if extension == ".yaml" || extension == ".yml" {
					err = yaml.Unmarshal(bytes, rulevo)
				}
				if err == nil {
					rulevo.Catalog = folder
					if rulevo.Spec != nil {
						for key, value := range rulevo.Spec.Input {
							if inputsMap, ok := value.(map[interface{}]interface{}); ok {
								rulevo.Spec.Input[key] = ConvertMap(inputsMap)
							}
						}
						for key, input := range rulevo.Spec.InputsMeta__ {
							if inputsMetaMap, ok := input.DefaultValue.(map[interface{}]interface{}); ok {
								rulevo.Spec.InputsMeta__[key].DefaultValue = ConvertMap(inputsMetaMap)
							}
						}
					}
					policyCowDataSet = append(policyCowDataSet, rulevo)
				}
			}
		}
	}

	filteredRules := make([]*vo.RuleYAMLVO, 0)

	for _, policyCowData := range policyCowDataSet {
		if cowRulesCriteriaVO != nil && policyCowData != nil && policyCowData.Meta != nil {
			if (IsNotEmpty(cowRulesCriteriaVO.StartsWith) && (IsEmpty(policyCowData.Meta.Name) || !strings.Contains(policyCowData.Meta.Name, cowRulesCriteriaVO.StartsWith))) ||
				(IsNotEmpty(cowRulesCriteriaVO.Like) && (IsEmpty(policyCowData.Meta.Name) || !IsStringContainsAny(policyCowData.Meta.Name, []string{cowRulesCriteriaVO.Like}))) ||
				(IsNoneEmpty(cowRulesCriteriaVO.Name) && (IsEmpty(policyCowData.Meta.Name) || !SliceContains(cowRulesCriteriaVO.Name, policyCowData.Meta.Name))) {
				continue
			}
			filteredRules = append(filteredRules, policyCowData)
		}
	}
	return filteredRules, nil
}

func IsMinioCredAvailable() bool {
	return IsNotEmpty(Getenv("MINIO_ROOT_USER", "")) && IsNotEmpty(Getenv("MINIO_ROOT_PASSWORD", ""))
}

func GetTaskInfosFromRule(ruleYAML *vo.RuleYAMLVO, additionalInfo *vo.AdditionalInfo) (*vo.RuleAdditionalInfo, *vo.ErrorVO) {

	taskInfos := make([]*vo.TaskInputVO, 0)
	err := Validate.Struct(ruleYAML)
	if err != nil {
		return nil, &vo.ErrorVO{
			Message: "Invalid rule", Description: "Basic validation failed",
			ErrorDetails: GetValidationError(err)}
	}

	ruleIOInfo, err := GetRuleIOMapInfo(ruleYAML.Spec.IoMap)
	if err != nil {
		return nil, &vo.ErrorVO{
			Message: "Invalid I/O mapping detected", Description: "Invalid I/O mapping detected",
			ErrorDetails: GetValidationError(err)}
	}

	ruleAddInfo := &vo.RuleAdditionalInfo{RuleIOMapInfo: ruleIOInfo}

	if IsEmpty(ruleYAML.Meta.App) {
		return nil, &vo.ErrorVO{
			Message: "Invalid App", Description: "'App' cannot be empty",
			ErrorDetails: GetValidationError(err)}
	}

	appClassPath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath, fmt.Sprintf("%s.yaml", ruleYAML.Meta.App))

	fmt.Println("appClassPath :", appClassPath)

	if IsFileNotExist(appClassPath) {
		return nil, &vo.ErrorVO{
			Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' application", ruleYAML.Meta.App),
			ErrorDetails: GetValidationError(err)}
	}

	primaryAppInfo, err := GetApplicationWithCredential(appClassPath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
	if err != nil {
		return nil, &vo.ErrorVO{
			Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' application", ruleYAML.Meta.App),
			ErrorDetails: GetValidationError(err)}
	}
	additionalInfo.PrimaryApplicationInfo = primaryAppInfo

	unAvailableTasks := make([]string, 0)
	additionalInfo.ApplicationInfo = make([]*vo.ApplicationInfoVO, len(ruleYAML.Spec.Tasks))

	hasAppTags := false
	for i, task := range ruleYAML.Spec.Tasks {

		if task.AppTags != nil {
			hasAppTags = true
			var appClassPath string
			appName := task.AppTags["appType"]

			appDir := additionalInfo.PolicyCowConfig.PathConfiguration.ApplicationClassPath
			files, err := ioutil.ReadDir(appDir)
			if err != nil {
				return nil, &vo.ErrorVO{Message: "Application Directory Read Error", Description: fmt.Sprintf("Unable to access the directory at '%s'.", appDir),
					ErrorDetails: GetValidationError(err),
				}
			}
			var appData *vo.UserDefinedApplicationVO
			for _, file := range files {
				if !file.IsDir() && filepath.Ext(file.Name()) == ".yaml" {
					path := filepath.Join(appDir, file.Name())
					if applicationYamlContent, err := ioutil.ReadFile(path); err == nil {
						if err := yaml.Unmarshal(applicationYamlContent, &appData); err == nil {
							if appType, exists := appData.Meta.Labels["appType"]; exists && len(appType) > 0 {
								if appType[0] == appName[0] {
									appClassPath = path
									break
								}
							}
						}
					}
				}
			}

			if IsFileNotExist(appClassPath) {
				return nil, &vo.ErrorVO{
					Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' application", appName[0]),
					ErrorDetails: GetValidationError(err)}
			}

			applicationInfo, err := GetApplicationWithCredential(appClassPath, additionalInfo.PolicyCowConfig.PathConfiguration.CredentialsPath)
			if err != nil {
				return nil, &vo.ErrorVO{
					Message: "Invalid App", Description: fmt.Sprintf("not able to find '%s' application", appName[0]),
					ErrorDetails: GetValidationError(err)}
			}
			applicationInfo.App.AppTags = task.AppTags
			additionalInfo.ApplicationInfo[i] = applicationInfo
		}

		// INFO : Flexing the utility method to verify the task is present or not
		taskPath := GetTaskPathFromCatalogForInit(additionalInfo, task.Name, true)

		// tasksPath := additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath
		// if task.Catalog == constants.CatalogTypeLocal {
		// 	tasksPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks")

		// }
		// taskPath := filepath.Join(tasksPath, task.Name)
		if IsEmpty(taskPath) || IsFileNotExist(taskPath) {
			unAvailableTasks = append(unAvailableTasks, task.Name)
		} else {
			languageFromPath := GetTaskLanguage(taskPath)
			languageFromCmd := languageFromPath.String()

			taskInfos = append(taskInfos, &vo.TaskInputVO{TaskName: task.Name, Language: languageFromCmd, Alias: task.Alias, Description: task.Description})
		}
	}
	if !hasAppTags {
		return nil, &vo.ErrorVO{
			Message: "Missing appTags", Description: "None of the tasks contain AppTags, at least one task must have AppTags",
			ErrorDetails: []*vo.ErrorDetailVO{{Field: "AppTags", Value: "nil or empty in all tasks", Location: "task",
				Issue: "AppTags are required for at least one task",
			}},
		}
	}

	if len(unAvailableTasks) > 0 {
		return nil, &vo.ErrorVO{
			Message: "Invalid task", Description: "Invalid task",
			ErrorDetails: []*vo.ErrorDetailVO{&vo.ErrorDetailVO{Field: "tasks", Value: strings.Join(unAvailableTasks, ","), Location: "name",
				Issue: "Some tasks are missing :" + strings.Join(unAvailableTasks, ",")}}}
	}

	ruleAddInfo.TaskInfos = taskInfos

	return ruleAddInfo, nil
}

func GetApplicationWithCredential(filePath string, directory string) (*vo.ApplicationInfoVO, error) {
	applicationInfoVO := vo.ApplicationInfoVO{}
	applicationYamlContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var appData *vo.UserDefinedApplicationVO
	if err := yaml.Unmarshal(applicationYamlContent, &appData); err != nil {
		return nil, err
	}
	applicationInfoVO.App = appData
	userDefinedCredentials, err := GetAvailableCredntialsFromAppClass(directory)
	if err != nil {
		return nil, err
	}
	credentials := make([]*vo.UserDefinedCredentialVO, 0)
	for _, credentialType := range appData.Spec.CredentialTypes {
		for _, userDefinedCredential := range userDefinedCredentials {
			if userDefinedCredential.Meta.Name == credentialType.Name && userDefinedCredential.Meta.Version == credentialType.Version {
				credentials = append(credentials, userDefinedCredential)
			}
		}
	}
	applicationInfoVO.Credential = credentials
	appTags := make(map[string][]string)
	appTags["appType"] = []string{appData.Meta.Name}
	applicationInfoVO.App.AppTags = appTags

	linkedApplications := make([]*vo.ApplicationInfoVO, 0)
	for _, linkedapp := range appData.Spec.LinkableApplicationClasses {
		linkedAppPath := filepath.Join(filepath.Dir(filePath), linkedapp.Name+".yaml")
		linkedAppInfo, err := GetApplicationWithCredential(linkedAppPath, directory)
		if err != nil {
			return nil, err
		}
		linkedApplications = append(linkedApplications, linkedAppInfo)
	}
	applicationInfoVO.LinkedApplications = linkedApplications

	return &applicationInfoVO, nil

}

func GetAvailableCredntialsFromAppClass(directory string) ([]*vo.UserDefinedCredentialVO, error) {
	userDefinedCredentials := make([]*vo.UserDefinedCredentialVO, 0)
	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			filePath := filepath.Join(directory, file.Name())
			yamlContent, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}
			var data *vo.UserDefinedCredentialVO
			if err := yaml.Unmarshal(yamlContent, &data); err != nil {
				continue
			}
			userDefinedCredentials = append(userDefinedCredentials, data)
		}
	}
	return userDefinedCredentials, nil
}

// StringInSlice :
func StringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
func IsAnyValueIntersected(arr1, arr2 []string) bool {
	return len(GetIntersectValues(arr1, arr2)) > 0
}

// GetIntersectValues : The values which are presented in both arrays will be return
func GetIntersectValues(srcArr, compArr []string) (resultArr []string) {
	resultArr = make([]string, 0)
	for _, v1 := range srcArr {
		isPresent := false
		for _, v2 := range compArr {
			if v1 == v2 {
				isPresent = true
				break
			}
		}
		if isPresent {
			resultArr = append(resultArr, v1)
		}
	}
	return resultArr
}

func GetRuleIOMapInfo(ioMap []string) (*vo.RuleIOMapInfo, error) {

	inputs := make(map[string]interface{}, 0)

	targetOutputVariables := make([]string, 0)
	srcInputVariables := make([]string, 0)

	selfAssignVars := make([]string, 0)
	incorrectFormatErrors := make([]string, 0)
	sourceRefFormatErrors := make([]string, 0)
	targetRefFormatErrors := make([]string, 0)
	inValidFieldTypes := make([]string, 0)

	ruleIOMapInfo := &vo.RuleIOMapInfo{}

	for _, iomap := range ioMap {
		iomapArr := strings.Split(iomap, ":=")

		if len(iomapArr) < 2 {
			incorrectFormatErrors = append(incorrectFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		targetArr := strings.Split(iomapArr[0], ".")
		if len(targetArr) < 3 {
			targetRefFormatErrors = append(targetRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}
		sourceArr := strings.Split(iomapArr[1], ".")
		if len(sourceArr) < 3 {
			sourceRefFormatErrors = append(sourceRefFormatErrors, fmt.Sprintf("'%s'", iomap))
			continue
		}

		if sourceArr[0] == "*" && sourceArr[1] == "Input" {
			ruleIOMapInfo.InputVaribales = append(ruleIOMapInfo.InputVaribales, sourceArr[2])
			inputs[sourceArr[2]] = nil
		}

		if sourceArr[0] == targetArr[0] && sourceArr[1] == targetArr[1] && sourceArr[2] == targetArr[2] {
			selfAssignVars = append(selfAssignVars, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if targetArr[1] == "Input" && targetArr[0] == "*" {
			targetOutputVariables = append(targetOutputVariables, fmt.Sprintf("'%s'", targetArr[2]))
			continue
		}

		if sourceArr[1] == "Output" && sourceArr[0] == "*" {
			srcInputVariables = append(srcInputVariables, fmt.Sprintf("'%s'", sourceArr[2]))
			continue
		}

		fieldTypes := []string{"Input", "Output"}

		if !SliceContains(fieldTypes, sourceArr[1]) || !SliceContains(fieldTypes, targetArr[1]) {
			inValidFieldTypes = append(inValidFieldTypes, iomap)
		}

	}

	errorMsgs := make([]string, 0)

	if len(targetOutputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Assigning the output variable {%s} as input to the flow is not allowed.", strings.Join(targetOutputVariables, ",")))
	}

	if len(srcInputVariables) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("You cannot use the output variable of the rule as an input. {%s}", strings.Join(srcInputVariables, ",")))
	}

	if len(selfAssignVars) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Cannot assign a variable to itself. {%s}", strings.Join(selfAssignVars, ",")))
	}

	if len(incorrectFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("The provided mappings are incorrect. {%s}", strings.Join(incorrectFormatErrors, ",")))
	}

	if len(sourceRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid source format. {%s}", strings.Join(sourceRefFormatErrors, ",")))
	}

	if len(targetRefFormatErrors) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid target format. {%s}", strings.Join(targetRefFormatErrors, ",")))
	}

	if len(inValidFieldTypes) > 0 {
		errorMsgs = append(errorMsgs, fmt.Sprintf("Invalid field types. {%s}", strings.Join(inValidFieldTypes, ",")))
	}

	if len(errorMsgs) > 0 {

		if len(errorMsgs) == 1 {
			return nil, errors.New(errorMsgs[0])
		}

		orderedErrorMsgs := make([]string, 0)

		for i, errorMsg := range errorMsgs {
			orderedErrorMsgs = append(orderedErrorMsgs, fmt.Sprintf("%d. %s", i+1, errorMsg))
		}

		return nil, errors.New(strings.Join(orderedErrorMsgs, "\n"))
	}

	return ruleIOMapInfo, nil

}

func GoRecover(Context context.Context) {
	if Context == nil {
		Context = context.Background()
	}
	if r := recover(); r != nil {
		fmt.Println(Context, "Panic error: %v\n", r)
		fmt.Println(Context, "Panic stack trace: %v\n", string(debug.Stack()))
	}

}

func GoRoutine(Context context.Context, apply func()) {
	go func() {
		defer GoRecover(Context)
		apply()
	}()
}

func UpdateAuthConfig(authConfig *vo.AuthConfigVO, additionalInfo *vo.AdditionalInfo) {
	if authConfig != nil && IsNotEmpty(authConfig.ClientID) {
		additionalInfo.PolicyCowConfig.UserData = &vo.UserData{}
		additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientID = authConfig.ClientID
		additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.ClientSecret = authConfig.ClientSecret
		additionalInfo.PolicyCowConfig.UserData.Credentials.Compliancecow.SubDomain = authConfig.SubDomain
		additionalInfo.Host = authConfig.Host
		additionalInfo.UserDomain = authConfig.UserDomain

		if strings.HasSuffix(additionalInfo.Host, "/") {
			additionalInfo.Host = strings.TrimRight(additionalInfo.Host, "/")
		}
	}
}

func ConvertMap(inputMap map[interface{}]interface{}) map[string]interface{} {
	resultMap := make(map[string]interface{})
	for key, value := range inputMap {
		stringKey := fmt.Sprintf("%v", key)
		switch v := value.(type) {
		case map[interface{}]interface{}:
			resultMap[stringKey] = ConvertMap(v)
		default:
			resultMap[stringKey] = v
		}
	}
	return resultMap
}

func GetApplicationLanguageFromRule(ruleName string, additionalInfo *vo.AdditionalInfo) (map[string]string, error) {
	rulePath := filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "rules")
	if IsFileExist(filepath.Join(rulePath, ruleName)) {
		rulePath = filepath.Join(rulePath, ruleName)
	} else {
		rulePath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.RulesPath, ruleName)
	}

	if IsNotEmpty(additionalInfo.Path) {
		rulePath = additionalInfo.Path
	}

	ruleyamlpath := filepath.Join(rulePath, constants.RuleYamlFile)
	ruleYaml := &vo.RuleYAMLVO{}

	ruleFile, err := os.ReadFile(ruleyamlpath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule YAML file: %w", err)
	}

	err = yaml.Unmarshal(ruleFile, &ruleYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal rule YAML file: %w", err)
	}
	languages := make(map[string]string)
	for _, task := range ruleYaml.Spec.Tasks {
		var taskPath string
		if IsFileExist(filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, task.Name)) {
			taskPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.TasksPath, task.Name)
		} else {
			taskPath = filepath.Join(additionalInfo.PolicyCowConfig.PathConfiguration.LocalCatalogPath, "tasks", task.Name)
		}

		if IsFileExist(taskPath) {
			language := GetTaskLanguage(taskPath).String()
			if IsNotEmpty(language) {
				languages[task.Name] = language
			}
		}
	}
	return languages, nil
}

var dateFormats = []string{
	constants.DateFormatDefault,
	constants.DateTimeFormatDefault,
	constants.DateTimeFormatWithoutSecondsUTC,
	constants.DateTimeFormatWithoutSeconds,
}

func ParseDateString(dateStr string) (time.Time, error) {
	for _, format := range dateFormats {
		parsedTime, err := time.Parse(format, dateStr)
		if err == nil {
			return parsedTime, nil
		}
	}
	return time.Time{}, errors.New("unable to parse date string")
}

func IsDefaultConfigPath(path string) bool {
	return strings.HasPrefix(path, "/policycow")
}
