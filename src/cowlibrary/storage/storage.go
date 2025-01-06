package storage

import (
	"bytes"
	"context"
	"cowlibrary/constants"
	"cowlibrary/utils"
	"cowlibrary/vo"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	cowStorage "appconnections/minio"

	"github.com/minio/minio-go/v7"
)

func UploadFileToMinio(minioFileVO *vo.MinioFileVO, additionalInfoVO *vo.AdditionalInfo) (*vo.MinioFileInfoVO, *vo.ErrorResponseVO) {
	minoEndpoint := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")
	// Supress log
	log.SetOutput(io.Discard)

	minioClient, err := cowStorage.RegisterMinio(minoEndpoint, utils.Getenv(constants.EnvMinioRootUser, ""), utils.Getenv(constants.EnvMinioRootPassword, ""), minioFileVO.BucketName)

	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusInternalServerError, Error: &vo.ErrorVO{
			Message: "MINIO_CLIENT_REGISTRTION_FAILED", Description: "Unable to register the MinIO client with the MinIO server.",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("Unable to register the MinIO client with the MinIO server: %w", err))}}
	}

	if minioClient == nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusInternalServerError, Error: &vo.ErrorVO{
			Message: "MINIO_CLIENT_CONNECTION_FAILED", Description: "Unable to initialize the MinIO client.",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("Unable to initialize the MinIO client.: %w", err))}}
	}

	folderPath := path.Join(minioFileVO.Path, minioFileVO.FileName)

	fileExtension := filepath.Ext(minioFileVO.FileName)
	contentType := "text/csv/jpg/jpeg"
	if utils.IsNotEmpty(fileExtension) {
		contentType = fileExtension
	}

	bucketName, prefix := cowStorage.GetBucketAndPrefix(minioFileVO.BucketName)

	folderPath = prefix + folderPath

	_, err = minioClient.PutObject(context.Background(), bucketName, folderPath, bytes.NewBuffer(minioFileVO.FileContent), int64(len(minioFileVO.FileContent)), minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusInternalServerError, Error: &vo.ErrorVO{
			Message: "FILE_UPLOAD_FAILED", Description: "Unable to upload the file to storage.",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("Unable to upload the file to storage.: %w", err))}}
	}
	var urlValues url.Values

	defaultDuration := 7 * time.Hour * 24

	presignedURL, err := minioClient.PresignedGetObject(context.Background(), bucketName, folderPath, defaultDuration, urlValues)

	presignedURL.RawQuery = ""

	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusInternalServerError, Error: &vo.ErrorVO{
			Message: "PRESIGNED_URL_GENERATION_FAILED", Description: "Getting an error while generating the presigned URL for objects",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("Getting an error while generating the presigned URL for objects.: %w", err))}}
	}
	url, err := url.QueryUnescape(presignedURL.String())
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusInternalServerError, Error: &vo.ErrorVO{
			Message: "URL_DECODING_FAILED", Description: "Error decoding the presigned URL",
			ErrorDetails: utils.GetValidationError(fmt.Errorf("Error decoding the presigned URL: %w", err)),
		},
		}
	}
	return &vo.MinioFileInfoVO{FileURL: url}, nil

}

func DownloadFile(minioFileInfoVO *vo.MinioFileInfoVO, additionalInfoVO *vo.AdditionalInfo) (*vo.MinioFileVO, *vo.ErrorResponseVO) {

	fileURL, err := url.Parse(minioFileInfoVO.FileURL)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "CANNOT_PARSE_FILE", Description: "failed to parse the file"}}
	}
	// Default bucketName
	bucketName := "demo"
	if fileURL.Scheme == "http" {
		splitPath := strings.Split(fileURL.Path, "/")
		if len(splitPath) > 2 {
			bucketName = splitPath[1]
		}
	}

	minoEndpoint := utils.Getenv(constants.EnvMinioLoginURL, "cowstorage:9000")
	// Supress log
	log.SetOutput(io.Discard)
	fileURL.Host = minoEndpoint

	objectPath := strings.TrimPrefix(fileURL.Path, fmt.Sprintf("/%v", bucketName))

	bucketName, prefix := cowStorage.GetBucketAndPrefix(bucketName)
	objectPath = prefix + objectPath

	if cowStorage.IsAmazonS3Host(minioFileInfoVO.FileURL) {
		parts := strings.Split(fileURL.Path, "/")
		if len(parts) < 4 {
			return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
				Message: "INVALID_RULE_STRUCTURE", Description: "invalid URL structure, cannot extract bucket and object"}}
		}
		bucketName = parts[3]
		objectPath = strings.Join(parts[4:], "/")
	}

	if prefix := fileURL.Query().Get("prefix"); prefix != "" {
		objectPath = prefix
	}

	minioClient, err := cowStorage.RegisterMinio(minoEndpoint, utils.Getenv(constants.EnvMinioRootUser, ""), utils.Getenv(constants.EnvMinioRootPassword, ""), bucketName)

	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "CANNOT_CONNECT_TO_MINIO", Description: "Cannot connect to the minio system"}}
	}

	if minioClient == nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "CANNOT_CREATE_MINIO_CLIENT", Description: "cannot create minio client"}}
	}

	fileObject, err := minioClient.GetObject(context.Background(), bucketName, objectPath, minio.GetObjectOptions{})
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "CANNOT_FIND_FILE", Description: fmt.Sprintf("file not found in bucket %s", bucketName)}}
	}
	fileContent, err := io.ReadAll(fileObject)
	if err != nil {
		return nil, &vo.ErrorResponseVO{StatusCode: http.StatusBadRequest, Error: &vo.ErrorVO{
			Message: "CANNOT_READ_FILE", Description: "cannot read the file"}}
	}

	fmt.Println("fileContent :", string(fileContent))

	return &vo.MinioFileVO{FileContent: fileContent, FileName: filepath.Base(objectPath)}, nil

}
