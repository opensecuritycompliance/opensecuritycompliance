package minio

import (
	"bytes"
	"context"
	"cowlibrary/localstorage"
	cowvo "cowlibrary/vo"
	"fmt"
	"os"

	"github.com/minio/minio-go/v7"
	goparquet "github.com/parquet-go/parquet-go"
)

// With COW_DATA_PERSISTENCE_TYPE=local the Upload* and Download* functions use
// the local disk (cowlibrary/localstorage) instead of an object store: no
// credentials, no client, and the URLs they return are file:// URLs. Anything
// else leaves them exactly as they were.

// connect opens the destination of an upload. It returns no client when files
// are local, and the object-storage client and its endpoint otherwise.
func connect(systemInputs cowvo.SystemInputs, bucketName string) (string, *minio.Client, error) {
	if localstorage.Enabled() {
		return "", nil, nil
	}
	endpoint, accessKey, secretKey, err := GetMinioCredential(systemInputs)
	if err != nil {
		return "", nil, err
	}
	client, err := RegisterMinio(endpoint, accessKey, secretKey, bucketName)
	if err != nil {
		return "", nil, err
	}
	return endpoint, client, nil
}

// putObject stores data as bucket/objectName and returns its URL. urlObject is
// the object name the URL is built from; it is objectName except where an upload
// has always built the URL from a different path.
func putObject(client *minio.Client, endpoint, bucketName, objectName, urlObject string, data []byte, contentType string) (string, error) {
	if localstorage.Enabled() {
		return localstorage.Put(bucketName, objectName, data)
	}
	_, err := client.PutObject(context.Background(), bucketName, objectName, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", err
	}
	return BuildObjectURLWithHost(client, bucketName, urlObject, endpoint)
}

// readLocalParquet reads a parquet file named by a file:// URL.
func readLocalParquet(fileURL string) ([]interface{}, error) {
	path, _ := localstorage.PathFromURL(fileURL)
	data, err := goparquet.ReadFile[interface{}](path)
	if err != nil {
		return nil, fmt.Errorf("Invalid file format: The provided file does not adhere to any recognized format.")
	}
	return data, nil
}

// downloadFromLocal copies bucketName/hash/fileName from the local storage
// folder to fileName in the working directory, as DownloadFileFromMinio does
// from an object store.
func downloadFromLocal(bucketName, hash, fileName string) error {
	if len(hash) > 0 && hash[len(hash)-1] != '/' {
		hash += "/"
	}
	bucketName, prefix := GetBucketAndPrefix(bucketName)
	src, err := localstorage.Path(bucketName, prefix+hash+fileName)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(fileName, data, 0o644)
}
