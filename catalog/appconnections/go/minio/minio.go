package minio

import (
	"bufio"
	"bytes"
	"cowlibrary/constants"
	cowlibutils "cowlibrary/utils"
	"cowlibrary/vo"
	cowvo "cowlibrary/vo"
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/minio/minio-go"
	goparquet "github.com/parquet-go/parquet-go"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
)

const (
	DEFAULT_PARQUET_READER_CONCURRENCY = 4
	DEFAULT_ROW_GROUP_SIZE             = 128 * 1024 * 1024
	DEFAULT_PAGE_SIZE                  = 8 * 1024
	DEFAULT_COMPRESSION                = parquet.CompressionCodec_SNAPPY
)

func GetMinioCredential(systemInputs cowvo.SystemInputs) (string, string, string, error) {
	var endpoint, accessKey, secretKey string
	if systemInputs.SystemObjects == nil {
		return "", "", "", fmt.Errorf("system object is empty")
	}
	for _, systemInput := range systemInputs.SystemObjects {
		switch {
		case systemInput.App != nil:
			if systemInput.App.ApplicationName == "minio" {
				for _, cred := range systemInput.Credentials {
					if cred.LoginURL != "" && cred.CredTags["servicename"] != nil && cred.CredTags["servicetype"] != nil {
						endpoint = cred.LoginURL
						accessKey = cred.OtherCredInfo["MINIO_ACCESS_KEY"].(string)
						secretKey = cred.OtherCredInfo["MINIO_SECRET_KEY"].(string)
						break
					}
				}
			}
		}
	}
	if cowlibutils.IsEmpty(endpoint) {
		return "", "", "", fmt.Errorf("minio login url is empty")
	} else if cowlibutils.IsEmpty(accessKey) {
		return "", "", "", fmt.Errorf("minio accesskey is empty")
	} else if cowlibutils.IsEmpty(secretKey) {
		return "", "", "", fmt.Errorf("minio secretkey is empty")
	}
	return endpoint, accessKey, secretKey, nil
}

func RegisterMinio(endpoint string, accessKey string, secretKey string, bucketName string) (*minio.Client, error) {
	minioClient, err := minio.New(endpoint, accessKey, secretKey, false)
	if err != nil {
		return nil, err
	}
	exists, err := minioClient.BucketExists(bucketName)
	if !exists && err == nil {
		err = minioClient.MakeBucket(bucketName, "")
		if err != nil {
			return nil, err
		}
	}
	if err == nil && exists {
		log.Printf("We already own %s", bucketName)
	}
	return minioClient, err
}

func GetFolderName(metaData *cowvo.MetaDataTemplate) string {
	return GetHash(metaData.PlanExecutionGUID, metaData.ControlID, metaData.RuleGUID, metaData.RuleTaskGUID)
}

func GetHash(values ...string) string {
	hash := ""
	for _, value := range values {
		h := sha1.New()
		h.Write([]byte(value))
		hash = hash + fmt.Sprintf("%x/", h.Sum(nil))
	}
	return hash
}

func Recordize(input interface{}, cols []string) [][]string {
	var records [][]string
	var includeCols []int
	var header []string
	object := reflect.ValueOf(input)
	if object.Len() > 0 {
		first := object.Index(0)
		typ := first.Type()
		for i := 0; i < first.NumField(); i++ {
			if len(cols) != 0 {
				for _, heading := range cols {
					if (typ.Field(i).Tag.Get("json")) == heading {
						header = append(header, typ.Field(i).Tag.Get("json"))
						includeCols = append(includeCols, i)
					}
				}
			} else {
				header = append(header, typ.Field(i).Tag.Get("json"))
			}

		}
		records = append(records, header)
	}
	var items []interface{}
	for i := 0; i < object.Len(); i++ {
		items = append(items, object.Index(i).Interface())
	}
	for _, v := range items {
		item := reflect.ValueOf(v)
		var record []string
		for i := 0; i < item.NumField(); i++ {
			itm := item.Field(i).Interface()
			if len(includeCols) > 0 {
				for _, colNo := range includeCols {
					if colNo == i {
						record = append(record, fmt.Sprintf("%v", itm))
					}
				}
			} else {
				record = append(record, fmt.Sprintf("%v", itm))
			}

		}
		records = append(records, record)
	}
	return records
}

func CreateAndUploadJSONFile(data interface{}, fileName string, bucketName string, systemInputs interface{}) (string, string, error) {
	// Default bucketName demo
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", "", err
	}

	if bucketName == "" {
		bucketName = "demo"
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)
	payload, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return "", "", err
	}
	tempFileName := fmt.Sprintf("%v%v", strings.Replace(folderName, "/", "-", -1), fileName)
	err = ioutil.WriteFile(tempFileName, payload, 0644)
	if err != nil {
		return "", "", err
	}
	if err = UploadFileToMinio(minioClient, bucketName, folderName+fileName, tempFileName, "application/json"); err != nil {
		return "", "", err
	}
	fileName = "http://" + endpoint + "/" + bucketName + "/" + folderName + fileName
	defer os.Remove(tempFileName)
	return fileName, folderName, nil
}

func UploadJSONFile(fileName string, fileContent interface{}, systemInputs interface{}) (string, error) {
	bucketName := "demo"
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)
	payload, err := json.MarshalIndent(fileContent, "", "\t")
	if err != nil {
		return "", err
	}
	reader := bytes.NewReader(payload)
	objectName := folderName + fileName
	_, err = minioClient.PutObject(bucketName, objectName, reader, int64(len(payload)), minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return "", err
	}
	absoluteFilePath, err := url.JoinPath("http://", endpoint, bucketName, objectName)
	if err != nil {
		return "", err
	}
	return absoluteFilePath, nil
}

func UploadNDJSONFile(fileName string, fileContent interface{}, systemInputs interface{}) (string, error) {
	bucketName := "demo"
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)

	// Create a buffer to hold the NDJSON data
	var buffer bytes.Buffer

	// Check if fileContent is a slice
	if reflect.TypeOf(fileContent).Kind() != reflect.Slice {
		return "", fmt.Errorf("Data must be a slice")
	}

	jsonBytes, err := json.Marshal(fileContent)
	if err != nil {
		return "", err
	}

	var objects []json.RawMessage
	err = json.Unmarshal(jsonBytes, &objects)
	if err != nil {
		return "", err
	}

	// Write the JSON bytes one by one to the buffer
	for _, object := range objects {
		buffer.Write(object)
		buffer.WriteByte('\n')
	}

	reader := bytes.NewReader(buffer.Bytes())

	objectName := folderName + fileName
	_, err = minioClient.PutObject(bucketName, objectName, reader, reader.Size(), minio.PutObjectOptions{ContentType: "application/ndjson"})
	if err != nil {
		return "", err
	}

	absoluteFilePath, err := url.JoinPath("http://", endpoint, bucketName, objectName)
	if err != nil {
		return "", err
	}

	return absoluteFilePath, nil
}

func UploadCSVFile(fileName string, fileContent interface{}, systemInputs interface{}) (string, error) {
	bucketName := "demo"
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)

	// https://github.com/gocarina/
	csvBytes, err := gocsv.MarshalBytes(fileContent)
	if err != nil {
		return "", err
	}
	reader := bytes.NewReader(csvBytes)
	objectName := folderName + fileName
	_, err = minioClient.PutObject(bucketName, objectName, reader, reader.Size(), minio.PutObjectOptions{ContentType: "application/csv"})
	if err != nil {
		return "", err
	}
	absoluteFilePath, err := url.JoinPath("http://", endpoint, bucketName, objectName)
	if err != nil {
		return "", err
	}
	return absoluteFilePath, nil
}

func UploadZipFile(fileName string, outputBytes []byte, systemInputs interface{}) (string, error) {
	bucketName := "demo"
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", err
	}

	folderName := GetFolderName(systemInputsVO.MetaData)
	contentBuffer := bytes.NewReader(outputBytes)

	_, err = minioClient.PutObject(bucketName, folderName+fileName, contentBuffer, int64(len(outputBytes)), minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", err
	}
	fileName = fmt.Sprintf("http://%v/%v/%v", endpoint, bucketName, filepath.Join(folderName, fileName))
	return fileName, nil
}

func UploadParquetFile[T any](fileName string, instance interface{}, fileContent []T, systemInputs interface{}) (string, error) {
	bucketName := "demo"
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", fmt.Errorf("failed to load system inputs: %v", err)
	}

	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", fmt.Errorf("failed to get Minio credentials: %v", err)
	}

	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", fmt.Errorf("failed to register Minio client: %v", err)
	}
	folderName := GetFolderName(systemInputsVO.MetaData)
	fw, err := local.NewLocalFileWriter(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to create local file writer: %v", err)
	}
	defer fw.Close()
	defer os.Remove(fileName)

	pw, err := writer.NewParquetWriter(fw, instance, 4)
	if err != nil {
		return "", fmt.Errorf("failed to create Parquet writer: %v", err)
	}
	pw.RowGroupSize = DEFAULT_ROW_GROUP_SIZE
	pw.PageSize = DEFAULT_PAGE_SIZE
	pw.CompressionType = DEFAULT_COMPRESSION

	for _, dataVal := range fileContent {
		if err = pw.Write(dataVal); err != nil {
			return "", fmt.Errorf("failed to write data to Parquet file: %v", err)
		}
	}
	if err = pw.WriteStop(); err != nil {
		return "", fmt.Errorf("failed to stop Parquet writer: %v", err)
	}

	if err = UploadFileToMinio(minioClient, bucketName, folderName+fileName, fileName, "application/parquet"); err != nil {
		return "", fmt.Errorf("failed to upload file to Minio: %v", err)
	}
	absoluteFilePath, err := url.JoinPath("http://", endpoint, bucketName, folderName, fileName)
	if err != nil {
		return "", err
	}
	return absoluteFilePath, nil
}

func DownloadParquetFile(absoluteFilePath string, systemInputs interface{}) ([]interface{}, error) {
	fileURL, err := url.Parse(absoluteFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file URL: %w", err)
	}

	// Default bucketName
	bucketName := "demo"
	hash := ""
	if fileURL.Scheme == "http" {
		splitPath := strings.Split(fileURL.Path, "/")
		if len(splitPath) > 2 {
			bucketName = splitPath[1]
			hash = strings.Join(splitPath[2:], "/")
		}
	}
	fileName := filepath.Base(fileURL.Path)

	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return nil, fmt.Errorf("failed to load system inputs: %w", err)
	}

	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return nil, fmt.Errorf("failed to get Minio credentials: %w", err)
	}

	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to register Minio client: %w", err)
	}

	tmpFile, err := os.Create(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create a file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	objectName := fileURL.Path
	if hash != "" {
		objectName = hash
	}

	err = minioClient.FGetObject(bucketName, objectName, tmpFile.Name(), minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch object from Minio: %w", err)
	}
	data, err := goparquet.ReadFile[interface{}](tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("Invalid file format: The provided file does not adhere to any recognized format.")
	}

	return data, nil
}

func DownloadFile(absoluteFilePath string, systemInputs interface{}) ([]byte, error) {
	if strings.HasPrefix(absoluteFilePath, "file://") {
		fileName := filepath.Base(absoluteFilePath)
		userdataFilePath := filepath.Join(constants.LocalFolder, fileName)
		fileContent, err := ioutil.ReadFile(userdataFilePath)
		if err != nil {
			return nil, err
		}
		return fileContent, nil
	}

	fileURL, err := url.Parse(absoluteFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid file URL: %w", err)
	}
	// Default bucketName
	bucketName := "demo"
	if fileURL.Scheme == "http" {
		splitPath := strings.Split(fileURL.Path, "/")
		if len(splitPath) > 2 {
			bucketName = splitPath[1]
		}
	}
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return nil, err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return nil, err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return nil, err
	}
	fileURL.Path = strings.TrimPrefix(fileURL.Path, fmt.Sprintf("/%v", bucketName))
	object, err := minioClient.GetObject(bucketName, fileURL.Path, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer object.Close()
	fileContent, err := io.ReadAll(object)
	if err != nil {
		return nil, err
	}
	return fileContent, nil
}

func DownloadJSONFile[T comparable](absoluteFilePath string, systemInputs interface{}, outputStruct T) ([]*T, error) {
	fileBytes, err := DownloadFile(absoluteFilePath, systemInputs)
	if err != nil {
		return nil, err
	}

	output := make([]*T, 0)

	err = json.Unmarshal(fileBytes, &output)
	if err != nil {
		return nil, errors.New("Invalid file format: The provided file does not adhere to any recognized format.")
	}

	return output, nil
}

func DownloadCSVFile[T comparable](absoluteFilePath string, systemInputs interface{}, outputStruct T) ([]*T, error) {
	fileBytes, err := DownloadFile(absoluteFilePath, systemInputs)
	if err != nil {
		return nil, err
	}

	output := make([]*T, 0)

	// https://github.com/gocarina/gocsv
	err = gocsv.UnmarshalBytes(fileBytes, &output)
	if err != nil {
		return nil, errors.New("Invalid file format: The provided file does not adhere to any recognized format.")
	}

	return output, nil
}

func DownloadNDJSONFile[T comparable](absoluteFilePath string, systemInputs interface{}, outputStruct T) ([]*T, error) {
	fileBytes, err := DownloadFile(absoluteFilePath, systemInputs)
	if err != nil {
		return nil, err
	}

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(bytes.NewReader(fileBytes))

	// Create a slice with the outputStruct type
	output := make([]*T, 0)

	// Read each line and unmarshal it into a struct
	for scanner.Scan() {
		// Create a new instance of the outputStruct type
		var v T
		err := json.Unmarshal(scanner.Bytes(), &v)
		if err != nil {
			return nil, errors.New("Invalid file format: The provided file does not adhere to any recognized format.")
		}

		// Append the unmarshalled object to the slice
		output = append(output, &v)
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.New("Invalid file format: The provided file does not adhere to any recognized format.")
	}

	return output, nil
}

func CreateAndUploadCSVFile(data [][]string, fileName string, bucketName string, systemInputs interface{}) (string, string, error) {
	// Default bucketName demo
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", "", err
	}
	if bucketName == "" {
		bucketName = "demo"
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)
	tempFileName := fmt.Sprintf("%v%v", strings.Replace(folderName, "/", "-", -1), fileName)
	file, err := os.Create(tempFileName)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	err = writer.WriteAll(data)
	if err != nil {
		return "", "", err
	}
	if err = UploadFileToMinio(minioClient, bucketName, folderName+fileName, tempFileName, "application/csv"); err != nil {
		return "", "", err
	}
	fileName = "http://" + endpoint + "/" + bucketName + "/" + folderName + fileName
	defer os.Remove(tempFileName)
	return fileName, folderName, nil
}

func CreateAndUploadYAMLFile(data []byte, fileName string, bucketName string, systemInputs interface{}) (string, string, error) {
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", "", err
	}
	// Default bucketName demo
	if bucketName == "" {
		bucketName = "demo"
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", "", err
	}
	folderName := GetFolderName(systemInputsVO.MetaData)

	tempFileName := fmt.Sprintf("%v%v", strings.Replace(folderName, "/", "-", -1), fileName)
	err = ioutil.WriteFile(tempFileName, data, 0644)
	if err != nil {
		return "", "", err
	}
	if err = UploadFileToMinio(minioClient, bucketName, folderName+fileName, tempFileName, "application/yaml"); err != nil {
		return "", "", err
	}
	fileName = "http://" + endpoint + "/" + bucketName + "/" + folderName + fileName
	defer os.Remove(tempFileName)
	return fileName, folderName, nil
}

func UploadZipFileInMinio(outputBytes []byte, fileName string, bucketName string, systemInputs interface{}) (string, string, error) {
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return "", "", err
	}
	if bucketName == "" {
		bucketName = "demo"
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return "", "", err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", "", err
	}

	folderName := GetFolderName(systemInputsVO.MetaData)
	contentBuffer := bytes.NewReader(outputBytes)

	_, err = minioClient.PutObject(bucketName, folderName+fileName, contentBuffer, int64(len(outputBytes)), minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", "", err
	}
	fileName = fmt.Sprintf("http://%v/%v/%v", endpoint, bucketName, filepath.Join(folderName, fileName))
	return fileName, folderName, nil
}

func UploadFileToMinio(minioClient *minio.Client, bucketName string, objectName string, fileName string, contentType string) (err error) {
	_, err = minioClient.FPutObject(bucketName, objectName, fileName, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return err
	}
	return nil
}

func DownloadFileFromMinio(systemInputs interface{}, bucketName string, hash string, fileName string) error {
	systemInputsVO, err := LoadSystemInputsFromInterface(systemInputs)
	if err != nil {
		return err
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputsVO)
	if err != nil {
		return err
	}
	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return err
	}
	length := len(hash)
	if length > 0 && hash[length-1] != '/' {
		hash += "/"
	}
	objectName := hash + fileName
	err = minioClient.FGetObject(bucketName, objectName, fileName, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	_, err = os.Stat(fileName)
	if err != nil {
		return err
	}
	return nil
}

func LoadSystemInputsFromInterface(input interface{}) (vo.SystemInputs, error) {
	var systemInputs vo.SystemInputs

	if input == nil {
		return systemInputs, errors.New("input cannot be nil")
	}

	data, err := json.Marshal(input)
	if err != nil {
		return systemInputs, err
	}
	err = json.Unmarshal(data, &systemInputs)
	if err != nil {
		return systemInputs, err
	}

	return systemInputs, nil
}

func ValidateFileExtension(fileUrl string, extension string, fileName string) error {

	if cowlibutils.IsEmpty(fileUrl) {
		return errors.New("File path cannot be empty")
	}

	ext := filepath.Ext(fileUrl)
	if ext == "" {
		return fmt.Errorf("Expected %v is missing. Please provide a valid file.", fileName)
	} else if ext != extension {
		return fmt.Errorf("Provided file type is not supported. Please upload a %v with the %v extension. The provided file is of type %v", fileName, extension, ext)
	}

	return nil

}

func ParseCSVToMap(csvData []byte) ([]map[string]interface{}, error) {
	reader := csv.NewReader(strings.NewReader(string(csvData)))

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	headers := records[0]

	for _, row := range records[1:] {
		m := make(map[string]interface{})
		for i, header := range headers {
			m[header] = row[i]
		}
		result = append(result, m)
	}

	return result, nil
}
