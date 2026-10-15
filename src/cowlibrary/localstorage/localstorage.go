// Package localstorage is the file-system backend for object storage. With
// COW_DATA_PERSISTENCE_TYPE=local, files that would go to MinIO (or any
// S3-compatible store) are written under a folder on disk instead, and
// referred to by file:// URLs, so a rule can run end to end without Docker or a
// storage server.
//
// Layout: <root>/<bucket>/<object>, the same shape as a bucket in object
// storage, and file://localhost/<root>/<bucket>/<object> as the URL. The host
// is written out because tasks check their URL inputs for a scheme and a host
// (urlparse(url).netloc), which file:///path would fail. The Python
// library (compliancecowcards/utils/cowlocalstorage.py) does the same, so a
// file written by a Python task is read by a Go task and the other way round.
//
// The package uses only the standard library: the application types and the
// task runtime import it, and nothing here may pull them in turn.
package localstorage

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	// EnvPersistenceType selects where files go. "local" (or
	// "local_file_store_path") means this package; anything else, including
	// unset, leaves the object-storage behaviour as it was.
	EnvPersistenceType = "COW_DATA_PERSISTENCE_TYPE"
	// EnvRoot is the folder the files live in. When unset it is ~/.cowctl/storage.
	EnvRoot = "COW_LOCAL_STORAGE_PATH"
	// DefaultBucket is used when a caller names none, as with object storage.
	DefaultBucket = "demo"
)

// Enabled reports whether files should be kept on the local disk. Only an
// explicit setting turns it on: a deployment that doesn't set the variable
// must keep using object storage.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvPersistenceType))) {
	case "local", "local_file_store_path":
		return true
	}
	return false
}

// Root is the folder the files live in, as an absolute path.
func Root() string {
	if r := strings.TrimSpace(os.Getenv(EnvRoot)); r != "" {
		r = expandHome(r)
		if abs, err := filepath.Abs(r); err == nil {
			return abs
		}
		return r
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".cowctl", "storage")
}

// Init creates the root folder and exports it in the environment. Tasks run in
// child processes with their own working directories, so they must be told
// where the root is instead of working it out for themselves. Call it once
// before anything is executed; it does nothing unless Enabled.
func Init() (string, error) {
	if !Enabled() {
		return "", nil
	}
	root := Root()
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("cannot create the local storage folder %s: %w", root, err)
	}
	if err := os.Setenv(EnvRoot, root); err != nil {
		return "", err
	}
	return root, nil
}

// objectPath maps bucket and object name to a path under the root. A name that
// would leave the root (.. or an absolute path) is refused: object names come
// from task inputs.
func objectPath(bucket, object string) (string, error) {
	if bucket == "" {
		bucket = DefaultBucket
	}
	object = strings.TrimLeft(object, "/")
	for _, part := range strings.Split(bucket+"/"+object, "/") {
		if part == ".." {
			return "", fmt.Errorf("invalid object name %q: it must stay inside the storage folder", bucket+"/"+object)
		}
	}
	if object == "" {
		return "", errors.New("the object name is empty")
	}
	root := Root()
	p := filepath.Join(root, filepath.FromSlash(path.Clean(bucket)), filepath.FromSlash(path.Clean(object)))
	if !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid object name %q: it must stay inside the storage folder", object)
	}
	return p, nil
}

// Path is where bucket/object is (or would be) on disk.
func Path(bucket, object string) (string, error) { return objectPath(bucket, object) }

// Put stores data as bucket/object and returns its file:// URL.
func Put(bucket, object string, data []byte) (string, error) {
	p, err := objectPath(bucket, object)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return "", err
	}
	return URL(p), nil
}

// PutFile stores the file at src as bucket/object and returns its file:// URL.
func PutFile(bucket, object, src string) (string, error) {
	p, err := objectPath(bucket, object)
	if err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	out, err := os.Create(p)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return URL(p), nil
}

// URL is the file:// URL of a path on disk: file://localhost/abs/path.
func URL(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/dir/file on Windows
	}
	return (&url.URL{Scheme: "file", Host: "localhost", Path: p}).String()
}

// PathFromURL returns the path a file:// URL names, written file://localhost/path
// or file:///path. It is false for anything else, and for the older file://name form, which names a file in the LOCAL_FOLDER
// and is handled by the callers that know about it.
func PathFromURL(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "file://") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Host != "" && u.Host != "localhost") || !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	p := u.Path
	if runtime.GOOS == "windows" && len(p) > 2 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

// IsLocalURL reports whether raw is a file:// URL with an absolute path, the
// form this package writes.
func IsLocalURL(raw string) bool {
	_, ok := PathFromURL(raw)
	return ok
}

// Read returns the content of a file:// URL.
func Read(raw string) ([]byte, error) {
	p, ok := PathFromURL(raw)
	if !ok {
		return nil, fmt.Errorf("%q is not a local file URL (expected file:///absolute/path)", raw)
	}
	return os.ReadFile(p)
}

// NormalizeInput turns a path to an existing file, as a user types it for a
// FILE input, into its file:// URL. Anything else (a URL, a value that is not
// a file, an empty value) is returned unchanged, and so is everything when local
// storage is off.
func NormalizeInput(v string) string {
	if !Enabled() {
		return v
	}
	t := strings.TrimSpace(v)
	if t == "" || strings.Contains(t, "://") {
		return v
	}
	t = expandHome(t)
	abs, err := filepath.Abs(t)
	if err != nil {
		return v
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		return v
	}
	return URL(abs)
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
