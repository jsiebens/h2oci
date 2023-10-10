package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"flag"
	"fmt"
	"github.com/google/go-containerregistry/pkg/crane"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

func main() {
	var port int
	var upstream string

	flag.StringVar(&upstream, "upstream", "", "")
	flag.IntVar(&port, "port", 8080, "The port to listen on")
	flag.Parse()

	if len(upstream) == 0 {
		fmt.Fprintln(os.Stderr, "--upstream is required")
		os.Exit(1)
		return
	}

	username := os.Getenv("H2OCI_BASIC_AUTH_USERNAME")
	password := os.Getenv("H2OCI_BASIC_AUTH_PASSWORD")

	slog.Info(fmt.Sprintf("Listening on %d, upstream: %s", port, upstream))

	handler := basicAuth(username, password, serve(upstream))

	http.ListenAndServe(fmt.Sprintf(":%d", port), handler)
}

func serve(upstream string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()

		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if !(strings.HasSuffix(req.URL.Path, ".tgz") || strings.HasSuffix(req.URL.Path, "tar.gz")) {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		sha := req.URL.Query().Get("sha")
		tag := req.URL.Query().Get("tag")

		if tag == "" && sha == "" {
			tag = "latest"
		}

		path := req.URL.Path
		path = strings.TrimSuffix(path, ".tgz")
		path = strings.TrimSuffix(path, ".tar.gz")

		target := fmt.Sprintf("%s%s:%s", upstream, path, tag)

		if sha != "" {
			target = fmt.Sprintf("%s%s@sha:%s", upstream, path, sha)
		}

		slog.Info("fetching oci artifact", "target", target)

		img, err := crane.Pull(target, crane.WithContext(ctx))
		if err != nil {
			slog.Error("error fetching resource", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		layers, err := img.Layers()
		if err != nil {
			slog.Error("failed to list layers", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(layers) < 1 {
			slog.Error("no layers found in artifact")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		blob, err := layers[0].Compressed()
		if err != nil {
			slog.Error("extracting first layer failed", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, blob)
	}
}

func basicAuth(expectedUsername, expectedPassword string, next http.HandlerFunc) http.HandlerFunc {
	if expectedUsername == "" && expectedPassword == "" {
		return next
	}

	expectedUsernameHash := sha256.Sum256([]byte(expectedUsername))
	expectedPasswordHash := sha256.Sum256([]byte(expectedPassword))

	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))

			usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
			passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.WriteHeader(http.StatusUnauthorized)
	}
}
