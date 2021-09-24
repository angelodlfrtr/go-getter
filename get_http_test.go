package getter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHTTPGetter_impl(t *testing.T) {
	var _ Getter = new(HTTPGetter)
}

func TestHTTPGetter_header(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/header"

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "main.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter_requestHeader(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	g.Header = make(http.Header)
	g.Header.Add("X-Foobar", "foobar")
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/expect-header"
	u.RawQuery = "expected=X-Foobar"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "Hello\n")
}

func TestHTTPGetter_meta(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta"

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "main.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter_metaSubdir(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta-subdir"

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "sub.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter_metaSubdirGlob(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta-subdir-glob"

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "sub.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter_none(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/none"

	// Get it!
	if err := g.Get(dst, &u); err == nil {
		t.Fatal("should error")
	}
}

func TestHTTPGetter_resume(t *testing.T) {
	load := []byte(testHTTPMetaStr)
	sha := sha256.New()
	if n, err := sha.Write(load); n != len(load) || err != nil {
		t.Fatalf("sha write failed: %d, %s", n, err)
	}
	checksum := hex.EncodeToString(sha.Sum(nil))
	downloadFrom := len(load) / 2

	ln := testHTTPServer(t)
	defer ln.Close()

	dst := tempDir(t)
	defer os.RemoveAll(dst)

	dst = filepath.Join(dst, "..", "range")
	f, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n, err := f.Write(load[:downloadFrom]); n != downloadFrom || err != nil {
		t.Fatalf("partial file write failed: %d, %s", n, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close failed: %s", err)
	}

	u := url.URL{
		Scheme:   "http",
		Host:     ln.Addr().String(),
		Path:     "/range",
		RawQuery: "checksum=" + checksum,
	}
	t.Logf("url: %s", u.String())

	// Finish getting it!
	if err := GetFile(dst, u.String()); err != nil {
		t.Fatalf("finishing download should not error: %v", err)
	}

	b, err := ioutil.ReadFile(dst)
	if err != nil {
		t.Fatalf("readfile failed: %v", err)
	}

	if string(b) != string(load) {
		t.Fatalf("file differs: got:\n%s\n expected:\n%s\n", string(b), string(load))
	}

	// Get it again
	if err := GetFile(dst, u.String()); err != nil {
		t.Fatalf("should not error: %v", err)
	}
}

// The server may support Byte-Range, but has no size for the requested object
func TestHTTPGetter_resumeNoRange(t *testing.T) {
	load := []byte(testHTTPMetaStr)
	sha := sha256.New()
	if n, err := sha.Write(load); n != len(load) || err != nil {
		t.Fatalf("sha write failed: %d, %s", n, err)
	}
	checksum := hex.EncodeToString(sha.Sum(nil))
	downloadFrom := len(load) / 2

	ln := testHTTPServer(t)
	defer ln.Close()

	dst := tempDir(t)
	defer os.RemoveAll(dst)

	dst = filepath.Join(dst, "..", "range")
	f, err := os.Create(dst)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n, err := f.Write(load[:downloadFrom]); n != downloadFrom || err != nil {
		t.Fatalf("partial file write failed: %d, %s", n, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close failed: %s", err)
	}

	u := url.URL{
		Scheme:   "http",
		Host:     ln.Addr().String(),
		Path:     "/no-range",
		RawQuery: "checksum=" + checksum,
	}
	t.Logf("url: %s", u.String())

	// Finish getting it!
	if err := GetFile(dst, u.String()); err != nil {
		t.Fatalf("finishing download should not error: %v", err)
	}

	b, err := ioutil.ReadFile(dst)
	if err != nil {
		t.Fatalf("readfile failed: %v", err)
	}

	if string(b) != string(load) {
		t.Fatalf("file differs: got:\n%s\n expected:\n%s\n", string(b), string(load))
	}
}

func TestHTTPGetter_file(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempTestFile(t)
	defer os.RemoveAll(filepath.Dir(dst))

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/file"

	// Get it!
	if err := g.GetFile(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("err: %s", err)
	}
	assertContents(t, dst, "Hello\n")
}

// TestHTTPGetter_http2server tests that http.Request is not reused
// between HEAD & GET, which would lead to race condition in HTTP/2.
// This test is only meaningful for the race detector (go test -race).
func TestHTTPGetter_http2server(t *testing.T) {
	g := new(HTTPGetter)
	src, err := url.Parse("https://releases.hashicorp.com/terraform/0.14.0/terraform_0.14.0_SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	dst := tempTestFile(t)

	err = g.GetFile(dst, src)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTPGetter_auth(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta-auth"
	u.User = url.UserPassword("foo", "bar")

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "main.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter_authNetrc(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/meta"

	// Write the netrc file
	path, closer := tempFileContents(t, fmt.Sprintf(testHTTPNetrc, ln.Addr().String()))
	defer closer()
	defer tempEnv(t, "NETRC", path)()

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}

	// Verify the main file exists
	mainPath := filepath.Join(dst, "main.tf")
	if _, err := os.Stat(mainPath); err != nil {
		t.Fatalf("err: %s", err)
	}
}

// test round tripper that only returns an error
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("test round tripper")
}

// verify that the default httpClient no longer comes from http.DefaultClient
func TestHTTPGetter_cleanhttp(t *testing.T) {
	ln := testHTTPServer(t)
	defer ln.Close()

	// break the default http client
	http.DefaultClient.Transport = errRoundTripper{}
	defer func() {
		http.DefaultClient.Transport = http.DefaultTransport
	}()

	g := new(HTTPGetter)
	dst := tempDir(t)
	defer os.RemoveAll(dst)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/header"

	// Get it!
	if err := g.Get(dst, &u); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestHTTPGetter__RespectsContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ln := testHTTPServer(t)

	var u url.URL
	u.Scheme = "http"
	u.Host = ln.Addr().String()
	u.Path = "/file"
	dst := tempDir(t)

	rt := hookableHTTPRoundTripper{
		before: func(req *http.Request) {
			err := req.Context().Err()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Expected http.Request with canceled.Context, got: %v", err)
			}
		},
		RoundTripper: http.DefaultTransport,
	}

	g := new(HTTPGetter)
	g.client = &Client{
		Ctx: ctx,
	}
	g.Client = &http.Client{
		Transport: &rt,
	}

	err := g.Get(dst, &u)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
}

func testHTTPServer(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/expect-header", testHTTPHandlerExpectHeader)
	mux.HandleFunc("/file", testHTTPHandlerFile)
	mux.HandleFunc("/header", testHTTPHandlerHeader)
	mux.HandleFunc("/meta", testHTTPHandlerMeta)
	mux.HandleFunc("/meta-auth", testHTTPHandlerMetaAuth)
	mux.HandleFunc("/meta-subdir", testHTTPHandlerMetaSubdir)
	mux.HandleFunc("/meta-subdir-glob", testHTTPHandlerMetaSubdirGlob)
	mux.HandleFunc("/range", testHTTPHandlerRange)
	mux.HandleFunc("/no-range", testHTTPHandlerNoRange)

	var server http.Server
	server.Handler = mux
	go server.Serve(ln)

	return ln
}

func testHTTPHandlerExpectHeader(w http.ResponseWriter, r *http.Request) {
	if expected, ok := r.URL.Query()["expected"]; ok {
		if r.Header.Get(expected[0]) != "" {
			w.Write([]byte("Hello\n"))
			return
		}
	}

	w.WriteHeader(400)
}

func testHTTPHandlerFile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello\n"))
}

func testHTTPHandlerHeader(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("X-Terraform-Get", testModuleURL("basic").String())
	w.WriteHeader(200)
}

func testHTTPHandlerMeta(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf(testHTTPMetaStr, testModuleURL("basic").String())))
}

func testHTTPHandlerMetaAuth(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(401)
		return
	}

	if user != "foo" || pass != "bar" {
		w.WriteHeader(401)
		return
	}

	w.Write([]byte(fmt.Sprintf(testHTTPMetaStr, testModuleURL("basic").String())))
}

func testHTTPHandlerMetaSubdir(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf(testHTTPMetaStr, testModuleURL("basic//subdir").String())))
}

func testHTTPHandlerMetaSubdirGlob(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf(testHTTPMetaStr, testModuleURL("basic//sub*").String())))
}

// func testHTTPHandlerNone(w http.ResponseWriter, r *http.Request) {
// w.Write([]byte(testHTTPNoneStr))
// }

func testHTTPHandlerRange(w http.ResponseWriter, r *http.Request) {
	load := []byte(testHTTPMetaStr)
	switch r.Method {
	case "HEAD":
		w.Header().Add("accept-ranges", "bytes")
		w.Header().Add("content-length", strconv.Itoa(len(load)))
	default:
		// request should have header "Range: bytes=0-1023"
		// or                         "Range: bytes=123-"
		rangeHeaderValue := strings.Split(r.Header.Get("Range"), "=")[1]
		rng, _ := strconv.Atoi(strings.Split(rangeHeaderValue, "-")[0])
		if rng < 1 || rng > len(load) {
			http.Error(w, "", http.StatusBadRequest)
		}
		w.Write(load[rng:])
	}
}

func testHTTPHandlerNoRange(w http.ResponseWriter, r *http.Request) {
	load := []byte(testHTTPMetaStr)
	switch r.Method {
	case "HEAD":
		// we support range, but the object size isn't known
		w.Header().Add("accept-ranges", "bytes")
	default:
		if r.Header.Get("Range") != "" {
			http.Error(w, "range not supported", http.StatusBadRequest)
		}
		w.Write(load)
	}
}

const testHTTPMetaStr = `
<html>
<head>
<meta name="terraform-get" content="%s">
</head>
</html>
`

// const testHTTPNoneStr = `
// <html>
// <head>
// </head>
// </html>
// `

const testHTTPNetrc = `
machine %s
login foo
password bar
`

type hookableHTTPRoundTripper struct {
	before func(req *http.Request)
	http.RoundTripper
}

func (m *hookableHTTPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.before != nil {
		m.before(req)
	}
	return m.RoundTripper.RoundTrip(req)
}
