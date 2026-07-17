package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vyuvaraj/ServShared"
	"servsecret/pkg/handlers"
	"servsecret/pkg/storage"
)

func main() {
	// Client Mode Flags
	clientMode := flag.Bool("client", false, "Run in client mode to connect to a remote ServSecret instance")
	clientAction := flag.String("action", "", "Client action: set, get, delete, list")
	clientKey := flag.String("key", "", "Secret key for client action")
	clientValue := flag.String("value", "", "Secret value for client set action")
	clientURL := flag.String("server-url", "http://localhost:8091", "ServSecret server URL")
	clientTenant := flag.String("tenant-id", "default", "Tenant ID header")

	port := flag.String("port", "8091", "Port to listen on")
	filePath := flag.String("file", "secrets.enc", "Path to encrypted secrets file")
	flag.Parse()

	if *clientMode {
		runClient(*clientAction, *clientKey, *clientValue, *clientURL, *clientTenant)
		return
	}

	log.Printf("Starting ServSecret Secret & Credential Manager on port %s...", *port)

	// Fetch master key from environment
	masterKeyHex := os.Getenv("SERVSECRET_MASTER_KEY")
	var masterKey []byte
	var err error

	if masterKeyHex != "" {
		masterKey, err = hex.DecodeString(masterKeyHex)
		if err != nil || len(masterKey) != 32 {
			masterKey = []byte(masterKeyHex)
			if len(masterKey) != 32 {
				log.Println("WARNING: SERVSECRET_MASTER_KEY is not 32 bytes. Adjusting key size...")
				padded := make([]byte, 32)
				copy(padded, masterKey)
				masterKey = padded
			}
		}
	} else {
		log.Println("WARNING: SERVSECRET_MASTER_KEY environment variable not set. Generating temporary master key...")
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			log.Fatalf("failed to generate random temporary master key: %v", err)
		}
		log.Printf("Temporary master key (hex): %s", hex.EncodeToString(masterKey))
	}

	// Initialize Storage
	store, err := storage.NewEncryptedFileStore(*filePath, masterKey)
	if err != nil {
		log.Printf("Failed to initialize encrypted file store: %v. Falling back to in-memory store.", err)
		handlers.Store = storage.NewInMemoryStore()
	} else {
		handlers.Store = store
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", ServShared.HealthzHandler)
	mux.HandleFunc("/readyz", ServShared.ReadyzHandler)
	mux.HandleFunc("/api/version", ServShared.VersionHandler("servsecret", "1.0.0"))
	mux.HandleFunc("/api/v1/version", ServShared.VersionHandler("servsecret", "1.0.0"))

	// Secret manager endpoints
	mux.HandleFunc("/api/secrets", handlers.HandleSecretRoute)
	mux.HandleFunc("/api/secrets/", handlers.HandleSecretRoute)

	// Wrapper handler for /api/v1/ prefix rewriting
	v1Wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			r.URL.Path = "/api/" + strings.TrimPrefix(r.URL.Path, "/api/v1/")
		}
		mux.ServeHTTP(w, r)
	})

	rateLimiter := ServShared.RateLimitMiddleware
	if flag.Lookup("test.v") != nil {
		rateLimiter = func(next http.Handler) http.Handler {
			return next
		}
	}

	// Wrap in ServShared middleware chain
	serverHandler := ServShared.TraceMiddleware("servsecret",
		rateLimiter(
			ServShared.CORSMiddleware(
				ServShared.MaxBytesMiddleware(10*1024*1024)(
					ServShared.AuthMiddleware(
						ServShared.TenantMiddleware(v1Wrapper),
					),
				),
			),
		),
	)

	server := &http.Server{
		Addr:    ":" + *port,
		Handler: serverHandler,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe failed: %v", err)
		}
	}()

	log.Printf("ServSecret is ready to manage credentials.")

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down ServSecret server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("ServSecret stopped cleanly.")
}

func runClient(action, key, val, serverURL, tenant string) {
	if action == "" {
		log.Fatalf("Action is required (set, get, delete, list)")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var req *http.Request
	var err error

	switch action {
	case "set":
		if key == "" || val == "" {
			log.Fatalf("Key and Value are required for set")
		}
		body, _ := json.Marshal(map[string]string{"key": key, "value": val})
		req, err = http.NewRequest(http.MethodPost, serverURL+"/api/v1/secrets", bytes.NewBuffer(body))
	case "get":
		if key == "" {
			log.Fatalf("Key is required for get")
		}
		req, err = http.NewRequest(http.MethodGet, serverURL+"/api/v1/secrets/"+key, nil)
	case "delete":
		if key == "" {
			log.Fatalf("Key is required for delete")
		}
		req, err = http.NewRequest(http.MethodDelete, serverURL+"/api/v1/secrets/"+key, nil)
	case "list":
		req, err = http.NewRequest(http.MethodGet, serverURL+"/api/v1/secrets", nil)
	default:
		log.Fatalf("Unknown action: %s", action)
	}

	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("X-Tenant-ID", tenant)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(bodyBytes))
}
