package minio

import (
	"bufio"
	"bytes"
	"context"
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
	"strconv"
	"strings"

	"github.com/gocarina/gocsv"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	goparquet "github.com/parquet-go/parquet-go"
	"github.com/pelletier/go-toml/v2"
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

var (
	fileStoreBucketName = os.Getenv("COW_STORAGE_BUCKET_NAME")
	fileStorePrefix     = os.Getenv("COW_STORAGE_FILE_PREFIX")
	createBucket        = loadBool("COW_STORAGE_CREATE_BUCKET", true)
)

type MinioFileVO struct {
	ObjectPath string `json:"objectPath,omitempty"`
}

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

	secure := false
	if IsAmazonS3Host(endpoint) {
		secure = true
	}

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
	})
	if err != nil {
		return nil, err
	}
	if createBucket {
		bucketName, _ = GetBucketAndPrefix(bucketName)
		exists, err := minioClient.BucketExists(context.Background(), bucketName)
		if !exists && err == nil {
			// Bucket does not exist. Create one
			err = minioClient.MakeBucket(context.Background(), bucketName, minio.MakeBucketOptions{})
			if err != nil {
				log.Printf("%v", err)
				return nil, err
			}
		}
		if err == nil && exists {
			log.Printf("We already own %s\n", bucketName)
		}
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
	minioFileVO, err := UploadFileToMinioV2(minioClient, bucketName, folderName+fileName, tempFileName, "application/json")
	if err != nil {
		return "", "", err
	}
	fileName = minioFileVO.ObjectPath
	defer os.Remove(tempFileName)
	_, prefix := GetBucketAndPrefix(bucketName)
	return fileName, prefix + folderName, nil
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

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName = prefix + objectName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, reader, int64(len(payload)), minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return "", err
	}
	absoluteFilePath, err := BuildObjectURLWithHost(minioClient, bucketName, objectName, endpoint)
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

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName = prefix + objectName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, reader, reader.Size(), minio.PutObjectOptions{ContentType: "application/ndjson"})
	if err != nil {
		return "", err
	}

	absoluteFilePath, err := BuildObjectURLWithHost(minioClient, bucketName, objectName, endpoint)
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

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName = prefix + objectName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, reader, reader.Size(), minio.PutObjectOptions{ContentType: "application/csv"})
	if err != nil {
		return "", err
	}
	absoluteFilePath, err := BuildObjectURLWithHost(minioClient, bucketName, objectName, endpoint)
	if err != nil {
		return "", err
	}
	return absoluteFilePath, nil
}

func UploadTOMLFile(fileName string, fileContent interface{}, systemInputs interface{}) (string, error) {
	if reflect.TypeOf(fileContent).Kind() == reflect.Array || reflect.TypeOf(fileContent).Kind() == reflect.Slice {
		return "", errors.New("File content must be an object, not an array of objects.")
	}

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
	payload, err := toml.Marshal(fileContent)
	if err != nil {
		return "", err
	}
	reader := bytes.NewReader(payload)
	objectName := folderName + fileName

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName = prefix + objectName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, reader, int64(len(payload)), minio.PutObjectOptions{ContentType: "application/toml"})
	if err != nil {
		return "", err
	}
	absoluteFilePath, err := BuildObjectURLWithHost(minioClient, bucketName, objectName, endpoint)
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

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName := prefix + folderName + fileName

	_, err = minioClient.PutObject(context.Background(), bucketName, objectName, contentBuffer, int64(len(outputBytes)), minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", err
	}

	absoluteFilePath, err := BuildObjectURLWithHost(minioClient, bucketName, objectName, endpoint)
	if err != nil {
		return "", err
	}

	return absoluteFilePath, nil
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

	minioFileVO, err := UploadFileToMinioV2(minioClient, bucketName, folderName+fileName, fileName, "application/parquet")
	if err != nil {
		return "", fmt.Errorf("failed to upload file to Minio: %v", err)
	}

	return minioFileVO.ObjectPath, nil
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

	objectPath := fileURL.Path
	if hash != "" {
		objectPath = hash
	}

	if IsAmazonS3Host(absoluteFilePath) {
		parts := strings.Split(fileURL.Path, "/")
		if len(parts) < 4 {
			return nil, fmt.Errorf("invalid URL structure, cannot extract bucket and object")
		}
		bucketName = parts[3]
		objectPath = strings.Join(parts[4:], "/")
	}

	if prefix := fileURL.Query().Get("prefix"); prefix != "" {
		objectPath = prefix
	}

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

	err = minioClient.FGetObject(context.Background(), bucketName, objectPath, tmpFile.Name(), minio.GetObjectOptions{})
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

	objectPath := strings.TrimPrefix(fileURL.Path, fmt.Sprintf("/%v", bucketName))

	if IsAmazonS3Host(absoluteFilePath) {
		parts := strings.Split(fileURL.Path, "/")
		if len(parts) < 4 {
			return nil, fmt.Errorf("invalid URL structure, cannot extract bucket and object")
		}
		bucketName = parts[3]
		objectPath = strings.Join(parts[4:], "/")
	}

	if prefix := fileURL.Query().Get("prefix"); prefix != "" {
		objectPath = prefix
	}

	minioClient, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return nil, err
	}

	object, err := minioClient.GetObject(context.Background(), bucketName, objectPath, minio.GetObjectOptions{})
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

func DownloadTOMLFile[T comparable](absoluteFilePath string, systemInputs interface{}, outputStruct T) (*T, error) {
	fileBytes, err := DownloadFile(absoluteFilePath, systemInputs)
	if err != nil {
		return nil, err
	}

	var output *T

	err = toml.Unmarshal(fileBytes, &output)
	if err != nil {
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
	minioFileVO, err := UploadFileToMinioV2(minioClient, bucketName, folderName+fileName, tempFileName, "application/csv")
	if err != nil {
		return "", "", err
	}
	fileName = minioFileVO.ObjectPath
	defer os.Remove(tempFileName)
	_, prefix := GetBucketAndPrefix(bucketName)
	return fileName, prefix + folderName, nil
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
	minioFileVO, err := UploadFileToMinioV2(minioClient, bucketName, folderName+fileName, tempFileName, "application/yaml")
	if err != nil {
		return "", "", err
	}
	fileName = minioFileVO.ObjectPath
	defer os.Remove(tempFileName)
	_, prefix := GetBucketAndPrefix(bucketName)
	return fileName, prefix + folderName, nil
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

	bucketName, prefix := GetBucketAndPrefix(bucketName)
	_, err = minioClient.PutObject(context.Background(), bucketName, prefix+folderName+fileName, contentBuffer, int64(len(outputBytes)), minio.PutObjectOptions{ContentType: "application/gzip"})
	if err != nil {
		return "", "", err
	}
	fileName, err = BuildObjectURLWithHost(minioClient, bucketName, filepath.Join(folderName, fileName), endpoint)
	if err != nil {
		return "", "", err
	}
	return fileName, folderName, nil
}

func UploadFileToMinio(minioClient *minio.Client, bucketName string, objectName string, fileName string, contentType string) (err error) {
	_, err = UploadFileToMinioV2(minioClient, bucketName, objectName, fileName, contentType)
	if err != nil {
		return err
	}
	return nil
}

func UploadFileToMinioV2(minioClient *minio.Client, bucketName string, objectName string, fileName string, contentType string) (*MinioFileVO, error) {
	bucketName, prefix := GetBucketAndPrefix(bucketName)
	objectName = prefix + objectName
	_, err := minioClient.FPutObject(context.Background(), bucketName, objectName, fileName, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return nil, err
	}

	objectPath, err := BuildObjectURL(minioClient, bucketName, objectName)

	if err != nil {
		return nil, err
	}

	return &MinioFileVO{ObjectPath: objectPath}, nil
}

func BuildObjectURL(minioClient *minio.Client, bucket string, object string) (string, error) {
	return BuildObjectURLWithHost(minioClient, bucket, object, "")
}

func BuildObjectURLWithHost(minioClient *minio.Client, bucket, object, host string) (string, error) {
	if host == "" {
		host = minioClient.EndpointURL().Host
	}
	isAmazonS3 := IsAmazonS3Host(host)
	region, err := minioClient.GetBucketLocation(context.Background(), bucket)
	if err != nil {
		return "", err
	}

	scheme := "https"
	if minioClient.EndpointURL().Scheme != "https" {
		scheme = "http"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	var s3URL string
	if isAmazonS3 {
		// s3URL = fmt.Sprintf("https://%s.console.aws.amazon.com/s3/buckets/%s?region=%s&prefix=%s", region, bucket, region, object)
		s3URL = fmt.Sprintf("https://%s.console.aws.amazon.com/s3/buckets/%s?prefix=%s", region, bucket, object)
	} else {
		s3URL = fmt.Sprintf("%s/%s/%s", baseURL, bucket, object)
	}

	return s3URL, nil
}

func IsAmazonS3Host(host string) bool {
	return strings.Contains(host, "s3.amazonaws.com") || strings.HasPrefix(host, "s3.") || strings.Contains(host, "console.aws.amazon.com")
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
	bucketName, prefix := GetBucketAndPrefix(bucketName)
	err = minioClient.FGetObject(context.Background(), bucketName, prefix+objectName, fileName, minio.GetObjectOptions{})
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

func GetBucketAndPrefix(bucketName string) (string, string) {
	newBucketName, prefix := bucketName, ""
	if fileStoreBucketName != "" {
		newBucketName = fileStoreBucketName
		prefix = bucketName + "/"
		if fileStorePrefix != "" {
			prefix += fileStorePrefix + "/"
		}
	}
	return newBucketName, prefix
}
func loadBool(name string, defaultValue bool) bool {
	boolV, err := strconv.ParseBool(name)
	if err != nil {
		return defaultValue
	}
	return boolV
}
