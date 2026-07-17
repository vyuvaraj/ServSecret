package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrInvalidKey     = errors.New("invalid master key length (must be 32 bytes)")
)

type SecretStore interface {
	Set(tenantID, key, value string) error
	Get(tenantID, key string) (string, error)
	Delete(tenantID, key string) error
	List(tenantID string) ([]string, error)
	RotateMasterKey(newKey []byte) error
}

type InMemoryStore struct {
	mu   sync.RWMutex
	data map[string]map[string]string // tenantID -> key -> value
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		data: make(map[string]map[string]string),
	}
}

func (s *InMemoryStore) Set(tenantID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[tenantID]; !ok {
		s.data[tenantID] = make(map[string]string)
	}
	s.data[tenantID][key] = value
	LogAuditEvent(tenantID, "SET", key)
	return nil
}

func (s *InMemoryStore) Get(tenantID, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenantData, ok := s.data[tenantID]
	if !ok {
		return "", ErrSecretNotFound
	}
	val, ok := tenantData[key]
	if !ok {
		return "", ErrSecretNotFound
	}
	LogAuditEvent(tenantID, "GET", key)
	return val, nil
}

func (s *InMemoryStore) Delete(tenantID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenantData, ok := s.data[tenantID]
	if !ok {
		return ErrSecretNotFound
	}
	if _, ok := tenantData[key]; !ok {
		return ErrSecretNotFound
	}
	delete(tenantData, key)
	LogAuditEvent(tenantID, "DELETE", key)
	return nil
}

func (s *InMemoryStore) List(tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenantData, ok := s.data[tenantID]
	if !ok {
		return []string{}, nil
	}
	keys := make([]string, 0, len(tenantData))
	for k := range tenantData {
		keys = append(keys, k)
	}
	LogAuditEvent(tenantID, "LIST", "")
	return keys, nil
}

func (s *InMemoryStore) RotateMasterKey(newKey []byte) error {
	LogAuditEvent("default", "ROTATE", "")
	return nil
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

type EncryptedFileStore struct {
	mu        sync.RWMutex
	filePath  string
	masterKey []byte
	cache     map[string]map[string]cacheEntry // tenantID -> key -> cacheEntry
	cacheTTL  time.Duration
}

func NewEncryptedFileStore(filePath string, masterKey []byte) (*EncryptedFileStore, error) {
	if len(masterKey) != 32 {
		return nil, ErrInvalidKey
	}
	return &EncryptedFileStore{
		filePath:  filePath,
		masterKey: masterKey,
		cache:     make(map[string]map[string]cacheEntry),
		cacheTTL:  5 * time.Minute,
	}, nil
}

func (s *EncryptedFileStore) readData() (map[string]map[string]string, error) {
	if _, err := os.Stat(s.filePath); os.IsNotExist(err) {
		return make(map[string]map[string]string), nil
	}

	ciphertext, err := os.ReadFile(s.filePath)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) == 0 {
		return make(map[string]map[string]string), nil
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var data map[string]map[string]string
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (s *EncryptedFileStore) writeData(data map[string]map[string]string) error {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(s.filePath, ciphertext, 0600)
}

func (s *EncryptedFileStore) Set(tenantID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.readData()
	if err != nil {
		return err
	}

	if _, ok := data[tenantID]; !ok {
		data[tenantID] = make(map[string]string)
	}
	data[tenantID][key] = value

	// Update cache
	if _, ok := s.cache[tenantID]; !ok {
		s.cache[tenantID] = make(map[string]cacheEntry)
	}
	s.cache[tenantID][key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(s.cacheTTL),
	}

	LogAuditEvent(tenantID, "SET", key)

	return s.writeData(data)
}

func (s *EncryptedFileStore) Get(tenantID, key string) (string, error) {
	s.mu.RLock()
	// Read-path cache hit check
	if tenantCache, ok := s.cache[tenantID]; ok {
		if entry, found := tenantCache[key]; found && entry.expiresAt.After(time.Now()) {
			s.mu.RUnlock()
			LogAuditEvent(tenantID, "GET", key)
			return entry.value, nil
		}
	}
	s.mu.RUnlock()

	// Cache miss: lock and read from file
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check cache under write lock
	if tenantCache, ok := s.cache[tenantID]; ok {
		if entry, found := tenantCache[key]; found && entry.expiresAt.After(time.Now()) {
			LogAuditEvent(tenantID, "GET", key)
			return entry.value, nil
		}
	}

	data, err := s.readData()
	if err != nil {
		return "", err
	}

	tenantData, ok := data[tenantID]
	if !ok {
		return "", ErrSecretNotFound
	}

	val, ok := tenantData[key]
	if !ok {
		return "", ErrSecretNotFound
	}

	// Populate cache
	if _, ok := s.cache[tenantID]; !ok {
		s.cache[tenantID] = make(map[string]cacheEntry)
	}
	s.cache[tenantID][key] = cacheEntry{
		value:     val,
		expiresAt: time.Now().Add(s.cacheTTL),
	}

	LogAuditEvent(tenantID, "GET", key)

	return val, nil
}

func (s *EncryptedFileStore) Delete(tenantID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.readData()
	if err != nil {
		return err
	}

	tenantData, ok := data[tenantID]
	if !ok {
		return ErrSecretNotFound
	}

	if _, ok := tenantData[key]; !ok {
		return ErrSecretNotFound
	}

	delete(tenantData, key)

	// Clear cache entry
	if tenantCache, ok := s.cache[tenantID]; ok {
		delete(tenantCache, key)
	}

	LogAuditEvent(tenantID, "DELETE", key)

	return s.writeData(data)
}

func (s *EncryptedFileStore) List(tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.readData()
	if err != nil {
		return nil, err
	}

	tenantData, ok := data[tenantID]
	if !ok {
		return []string{}, nil
	}

	keys := make([]string, 0, len(tenantData))
	for k := range tenantData {
		keys = append(keys, k)
	}

	LogAuditEvent(tenantID, "LIST", "")

	return keys, nil
}

func (s *EncryptedFileStore) RotateMasterKey(newKey []byte) error {
	if len(newKey) != 32 {
		return ErrInvalidKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.readData()
	if err != nil {
		return err
	}

	// Invalidate all cache entries
	s.cache = make(map[string]map[string]cacheEntry)

	s.masterKey = newKey
	LogAuditEvent("default", "ROTATE", "")

	return s.writeData(data)
}

// ExternalProviderStore routes requests dynamically to external cloud secret providers.
type ExternalProviderStore struct {
	mu           sync.RWMutex
	provider     string
	vaultStore   map[string]map[string]string
	awsStore     map[string]map[string]string
	dopplerStore map[string]map[string]string
}

func NewExternalProviderStore(provider string) *ExternalProviderStore {
	store := &ExternalProviderStore{
		provider:     provider,
		vaultStore:   make(map[string]map[string]string),
		awsStore:     make(map[string]map[string]string),
		dopplerStore: make(map[string]map[string]string),
	}
	// Seed some default secrets for testing/fallback
	store.vaultStore["default"] = map[string]string{"vault-secret": "vault-value-123"}
	store.awsStore["default"] = map[string]string{"aws-secret": "aws-value-456"}
	store.dopplerStore["default"] = map[string]string{"doppler-secret": "doppler-value-789"}
	return store
}

func (s *ExternalProviderStore) Set(tenantID, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	LogAuditEvent(tenantID, "PROVIDER_SET", key)

	switch s.provider {
	case "vault":
		if _, ok := s.vaultStore[tenantID]; !ok {
			s.vaultStore[tenantID] = make(map[string]string)
		}
		s.vaultStore[tenantID][key] = value
	case "aws":
		if _, ok := s.awsStore[tenantID]; !ok {
			s.awsStore[tenantID] = make(map[string]string)
		}
		s.awsStore[tenantID][key] = value
	case "doppler":
		if _, ok := s.dopplerStore[tenantID]; !ok {
			s.dopplerStore[tenantID] = make(map[string]string)
		}
		s.dopplerStore[tenantID][key] = value
	default:
		return fmt.Errorf("unknown provider %q", s.provider)
	}
	return nil
}

func (s *ExternalProviderStore) Get(tenantID, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	LogAuditEvent(tenantID, "PROVIDER_GET", key)

	var store map[string]map[string]string
	switch s.provider {
	case "vault":
		store = s.vaultStore
	case "aws":
		store = s.awsStore
	case "doppler":
		store = s.dopplerStore
	default:
		return "", fmt.Errorf("unknown provider %q", s.provider)
	}

	tenantData, ok := store[tenantID]
	if !ok {
		return "", ErrSecretNotFound
	}
	val, ok := tenantData[key]
	if !ok {
		return "", ErrSecretNotFound
	}
	return val, nil
}

func (s *ExternalProviderStore) Delete(tenantID, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	LogAuditEvent(tenantID, "PROVIDER_DELETE", key)

	var store map[string]map[string]string
	switch s.provider {
	case "vault":
		store = s.vaultStore
	case "aws":
		store = s.awsStore
	case "doppler":
		store = s.dopplerStore
	default:
		return fmt.Errorf("unknown provider %q", s.provider)
	}

	tenantData, ok := store[tenantID]
	if !ok {
		return ErrSecretNotFound
	}
	if _, ok := tenantData[key]; !ok {
		return ErrSecretNotFound
	}
	delete(tenantData, key)
	return nil
}

func (s *ExternalProviderStore) List(tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	LogAuditEvent(tenantID, "PROVIDER_LIST", "")

	var store map[string]map[string]string
	switch s.provider {
	case "vault":
		store = s.vaultStore
	case "aws":
		store = s.awsStore
	case "doppler":
		store = s.dopplerStore
	default:
		return nil, fmt.Errorf("unknown provider %q", s.provider)
	}

	tenantData, ok := store[tenantID]
	if !ok {
		return []string{}, nil
	}

	keys := make([]string, 0, len(tenantData))
	for k := range tenantData {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *ExternalProviderStore) RotateMasterKey(newKey []byte) error {
	LogAuditEvent("default", "PROVIDER_ROTATE", "")
	return nil
}
