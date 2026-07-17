package handlers

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/vyuvaraj/ServShared"
	"servsecret/pkg/storage"
)

var Store storage.SecretStore

type SecretRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type SecretResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type ListResponse struct {
	Keys []string `json:"keys"`
}

type RotateRequest struct {
	NewMasterKey string `json:"new_master_key"`
}

// HandleSecretRoute routes requests for /api/secrets and /api/secrets/
func HandleSecretRoute(w http.ResponseWriter, r *http.Request) {
	tenantID := ServShared.GetTenantID(r)
	if tenantID == "" {
		tenantID = "default"
	}

	path := r.URL.Path
	key := strings.TrimPrefix(path, "/api/secrets")
	key = strings.TrimPrefix(key, "/v1") // in case of /api/v1/secrets
	key = strings.TrimPrefix(key, "/")

	// If request is to rotate master key
	if key == "rotate" {
		if r.Method == http.MethodPost {
			handleRotate(w, r)
			return
		}
		ServShared.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	// If request is GET /api/secrets (no specific key)
	if key == "" {
		if r.Method == http.MethodGet {
			handleList(w, r, tenantID)
			return
		} else if r.Method == http.MethodPost {
			handleSet(w, r, tenantID)
			return
		}
		ServShared.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}

	// Request is for a specific key /api/secrets/{key}
	switch r.Method {
	case http.MethodGet:
		handleGet(w, r, tenantID, key)
	case http.MethodDelete:
		handleDelete(w, r, tenantID, key)
	default:
		ServShared.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
	}
}

func handleSet(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ServShared.WriteJSONError(w, r, "Invalid request body", "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}

	if req.Key == "" || req.Value == "" {
		ServShared.WriteJSONError(w, r, "Key and Value are required fields", "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}

	if err := Store.Set(tenantID, req.Key, req.Value); err != nil {
		ServShared.WriteJSONError(w, r, "Failed to save secret: "+err.Error(), "ERR_INTERNAL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(SecretResponse{Key: req.Key, Value: req.Value})
}

func handleGet(w http.ResponseWriter, r *http.Request, tenantID, key string) {
	// IP CIDR Restriction Check (SS.13)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !Store.VerifyIPRestriction(tenantID, key, ip) {
		ServShared.WriteJSONError(w, r, "Forbidden: IP policy restriction", "ERR_FORBIDDEN", http.StatusForbidden)
		return
	}

	val, err := Store.Get(tenantID, key)
	if err != nil {
		if err == storage.ErrSecretNotFound {
			ServShared.WriteJSONError(w, r, "Secret not found", "ERR_NOT_FOUND", http.StatusNotFound)
			return
		}
		ServShared.WriteJSONError(w, r, "Failed to get secret: "+err.Error(), "ERR_INTERNAL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SecretResponse{Key: key, Value: val})
}

func handleDelete(w http.ResponseWriter, r *http.Request, tenantID, key string) {
	err := Store.Delete(tenantID, key)
	if err != nil {
		if err == storage.ErrSecretNotFound {
			ServShared.WriteJSONError(w, r, "Secret not found", "ERR_NOT_FOUND", http.StatusNotFound)
			return
		}
		ServShared.WriteJSONError(w, r, "Failed to delete secret: "+err.Error(), "ERR_INTERNAL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "key": key})
}

func handleList(w http.ResponseWriter, r *http.Request, tenantID string) {
	keys, err := Store.List(tenantID)
	if err != nil {
		ServShared.WriteJSONError(w, r, "Failed to list secrets: "+err.Error(), "ERR_INTERNAL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ListResponse{Keys: keys})
}

func handleRotate(w http.ResponseWriter, r *http.Request) {
	var req RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ServShared.WriteJSONError(w, r, "Invalid request body", "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}

	newKey, err := hex.DecodeString(req.NewMasterKey)
	if err != nil || len(newKey) != 32 {
		newKey = []byte(req.NewMasterKey)
		if len(newKey) != 32 {
			ServShared.WriteJSONError(w, r, "New master key must be 32 bytes (or 64-character hex)", "ERR_BAD_REQUEST", http.StatusBadRequest)
			return
		}
	}

	if err := Store.RotateMasterKey(newKey); err != nil {
		ServShared.WriteJSONError(w, r, "Failed to rotate master key: "+err.Error(), "ERR_INTERNAL", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Master key rotated and secrets re-encrypted successfully"})
}

type RollbackRequest struct {
	Key string `json:"key"`
}

func HandleSecretRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ServShared.WriteJSONError(w, r, "Method not allowed", "ERR_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	var req RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ServShared.WriteJSONError(w, r, "Invalid request body", "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if req.Key == "" {
		ServShared.WriteJSONError(w, r, "Key is required", "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if err := Store.Rollback(tenantID, req.Key); err != nil {
		ServShared.WriteJSONError(w, r, err.Error(), "ERR_BAD_REQUEST", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"rolled_back"}`))
}


