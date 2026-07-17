package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

type AuditRecord struct {
	Timestamp string `json:"timestamp"`
	TenantID  string `json:"tenant_id"`
	Action    string `json:"action"`
	Key       string `json:"key"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

var (
	auditMu      sync.Mutex
	lastHash     string
	auditKey     = []byte("servsecret-audit-signing-key-12345") // HMAC key
	auditLogPath = "audit.log"
)

func SetAuditLogPath(path string) {
	auditMu.Lock()
	defer auditMu.Unlock()
	auditLogPath = path
	lastHash = "" // reset chain
}

func LogAuditEvent(tenantID, action, key string) {
	auditMu.Lock()
	defer auditMu.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := timestamp + "|" + tenantID + "|" + action + "|" + key + "|" + lastHash

	mac := hmac.New(sha256.New, auditKey)
	mac.Write([]byte(payload))
	currentHash := hex.EncodeToString(mac.Sum(nil))

	record := AuditRecord{
		Timestamp: timestamp,
		TenantID:  tenantID,
		Action:    action,
		Key:       key,
		PrevHash:  lastHash,
		Hash:      currentHash,
	}

	lastHash = currentHash

	f, err := os.OpenFile(auditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("failed to write audit log: %v", err)
		return
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(record); err != nil {
		log.Printf("failed to encode audit log record: %v", err)
	}
}

func VerifyAuditLog() (bool, error) {
	auditMu.Lock()
	defer auditMu.Unlock()

	f, err := os.Open(auditLogPath)
	if os.IsNotExist(err) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	defer f.Close()

	var expectedPrevHash string
	decoder := json.NewDecoder(f)
	for {
		var record AuditRecord
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			return false, err
		}

		payload := record.Timestamp + "|" + record.TenantID + "|" + record.Action + "|" + record.Key + "|" + record.PrevHash
		mac := hmac.New(sha256.New, auditKey)
		mac.Write([]byte(payload))
		recomputed := hex.EncodeToString(mac.Sum(nil))

		if recomputed != record.Hash {
			return false, fmt.Errorf("audit log corruption detected at record timestamp %s", record.Timestamp)
		}

		if record.PrevHash != expectedPrevHash {
			return false, fmt.Errorf("audit log chain broken at record timestamp %s", record.Timestamp)
		}

		expectedPrevHash = record.Hash
	}

	return true, nil
}
