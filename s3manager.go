package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

// S3Config holds S3 configuration for a user
type S3Config struct {
	Enabled       bool
	Endpoint      string
	Region        string
	Bucket        string
	AccessKey     string
	SecretKey     string
	PathStyle     bool
	PublicURL     string
	MediaDelivery string
	RetentionDays int
}

// LogFields returns a representation of the S3 config safe for logging: it omits
// AccessKey and SecretKey, which are credentials and MUST NOT reach any log, at any
// level, per the ZapperHub constitution (Principle VI) and feature 023-storage-r2
// (FR-013a). Callers MUST use this instead of logging the struct directly.
func (c *S3Config) LogFields() map[string]interface{} {
	if c == nil {
		return nil
	}
	return map[string]interface{}{
		"enabled":        c.Enabled,
		"endpoint":       c.Endpoint,
		"region":         c.Region,
		"bucket":         c.Bucket,
		"path_style":     c.PathStyle,
		"public_url":     c.PublicURL,
		"media_delivery": c.MediaDelivery,
		"retention_days": c.RetentionDays,
	}
}

// S3Manager manages S3 operations
type S3Manager struct {
	mu      sync.RWMutex
	db      *sqlx.DB
	clients map[string]*s3.Client
	configs map[string]*S3Config

	// Segundo slot (feature 028, US2): o storage próprio do integrador, tentado antes do slot
	// padrão acima. Ver a seção "Segundo slot" no fim deste arquivo.
	customSlots   map[string]*customS3Slot
	customMissing map[string]time.Time
	breakers      map[string]customS3Breaker

	// customHTTPClient substitui o cliente HTTP anti-SSRF do slot do integrador. Só os testes
	// o preenchem, para alcançar o loopback do httptest; nil usa o cliente seguro.
	customHTTPClient *http.Client
	// now e customTimeout existem para os testes; zero usa o relógio e CUSTOM_S3_TIMEOUT_MS.
	now           func() time.Time
	customTimeout time.Duration
}

// newS3Manager cria um S3Manager com os mapas inicializados.
func newS3Manager() *S3Manager {
	return &S3Manager{
		clients:       make(map[string]*s3.Client),
		configs:       make(map[string]*S3Config),
		customSlots:   make(map[string]*customS3Slot),
		customMissing: make(map[string]time.Time),
		breakers:      make(map[string]customS3Breaker),
	}
}

// Global S3 manager instance
var s3Manager = newS3Manager()

// GetS3Manager returns the global S3 manager instance
func GetS3Manager() *S3Manager {
	return s3Manager
}

// SetDB sets the database reference for lazy S3 client initialization
func (m *S3Manager) SetDB(db *sqlx.DB) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
}

// EnsureClientFromDB loads S3 config from DB and initializes client if enabled. Returns true if client is available.
func (m *S3Manager) EnsureClientFromDB(userID string) bool {
	if _, _, ok := m.GetClient(userID); ok {
		return true
	}
	m.mu.RLock()
	db := m.db
	m.mu.RUnlock()
	if db == nil {
		return false
	}
	var s3DbConfig struct {
		Enabled       bool   `db:"s3_enabled"`
		Endpoint      string `db:"s3_endpoint"`
		Region        string `db:"s3_region"`
		Bucket        string `db:"s3_bucket"`
		AccessKey     string `db:"s3_access_key"`
		SecretKey     string `db:"s3_secret_key"`
		PathStyle     bool   `db:"s3_path_style"`
		PublicURL     string `db:"s3_public_url"`
		MediaDelivery string `db:"media_delivery"`
		RetentionDays int    `db:"s3_retention_days"`
	}
	query := `SELECT s3_enabled, s3_endpoint, s3_region, s3_bucket, s3_access_key, s3_secret_key, s3_path_style, s3_public_url, COALESCE(media_delivery, 'base64') AS media_delivery, COALESCE(s3_retention_days, 30) AS s3_retention_days FROM users WHERE id = $1`
	query = db.Rebind(query)
	if err := db.Get(&s3DbConfig, query, userID); err != nil || !s3DbConfig.Enabled {
		return false
	}
	config := &S3Config{
		Enabled:       s3DbConfig.Enabled,
		Endpoint:      s3DbConfig.Endpoint,
		Region:        s3DbConfig.Region,
		Bucket:        s3DbConfig.Bucket,
		AccessKey:     s3DbConfig.AccessKey,
		SecretKey:     s3DbConfig.SecretKey,
		PathStyle:     s3DbConfig.PathStyle,
		PublicURL:     s3DbConfig.PublicURL,
		MediaDelivery: s3DbConfig.MediaDelivery,
		RetentionDays: s3DbConfig.RetentionDays,
	}
	return m.InitializeS3Client(userID, config) == nil
}

// InitializeS3Client creates or updates S3 client for a user
func (m *S3Manager) InitializeS3Client(userID string, config *S3Config) error {
	if !config.Enabled {
		m.RemoveClient(userID)
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Create custom credentials provider
	credProvider := credentials.NewStaticCredentialsProvider(
		config.AccessKey,
		config.SecretKey,
		"",
	)

	// Configure S3 client
	cfg := aws.Config{
		Region:      config.Region,
		Credentials: credProvider,
	}

	if config.Endpoint != "" {
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			if service == s3.ServiceID {
				return aws.Endpoint{
					URL:               config.Endpoint,
					HostnameImmutable: config.PathStyle,
				}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
		cfg.EndpointResolverWithOptions = customResolver
	}

	// Create S3 client
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = config.PathStyle
	})

	m.clients[userID] = client
	m.configs[userID] = config

	log.Info().Str("userID", userID).Str("bucket", config.Bucket).Msg("S3 client initialized")
	return nil
}

// RemoveClient removes S3 client for a user
func (m *S3Manager) RemoveClient(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.clients, userID)
	delete(m.configs, userID)
}

// GetClient returns S3 client for a user
func (m *S3Manager) GetClient(userID string) (*s3.Client, *S3Config, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	client, clientOk := m.clients[userID]
	config, configOk := m.configs[userID]

	return client, config, clientOk && configOk
}

// GenerateS3Key generates S3 object key based on message metadata
func (m *S3Manager) GenerateS3Key(userID, contactJID, messageID string, mimeType string, isIncoming bool) string {
	// Determine direction
	direction := "outbox"
	if isIncoming {
		direction = "inbox"
	}

	// Clean contact JID
	contactJID = strings.ReplaceAll(contactJID, "@", "_")
	contactJID = strings.ReplaceAll(contactJID, ":", "_")

	// Get current time
	now := time.Now()
	year := now.Format("2025")
	month := now.Format("05")
	day := now.Format("25")

	// Determine media type folder
	mediaType := "documents"
	if strings.HasPrefix(mimeType, "image/") {
		mediaType = "images"
	} else if strings.HasPrefix(mimeType, "video/") {
		mediaType = "videos"
	} else if strings.HasPrefix(mimeType, "audio/") {
		mediaType = "audio"
	}

	// Get file extension
	ext := s3ExtensionForMime(mimeType, ".bin")

	// Build S3 key
	key := fmt.Sprintf("users/%s/%s/%s/%s/%s/%s/%s/%s%s",
		userID,
		direction,
		contactJID,
		year,
		month,
		day,
		mediaType,
		messageID,
		ext,
	)

	return key
}

// s3ExtensionForMime devolve a extensão da chave a partir do mimetype. Sem correspondência,
// devolve fallback (ou ".bin" se fallback vier vazio).
func s3ExtensionForMime(mimeType, fallback string) string {
	switch {
	case strings.Contains(mimeType, "jpeg"), strings.Contains(mimeType, "jpg"):
		return ".jpg"
	case strings.Contains(mimeType, "png"):
		return ".png"
	case strings.Contains(mimeType, "gif"):
		return ".gif"
	case strings.Contains(mimeType, "webp"):
		return ".webp"
	case strings.Contains(mimeType, "mp4"):
		return ".mp4"
	case strings.Contains(mimeType, "webm"):
		return ".webm"
	case strings.Contains(mimeType, "ogg"):
		return ".ogg"
	case strings.Contains(mimeType, "opus"):
		return ".opus"
	case strings.Contains(mimeType, "pdf"):
		return ".pdf"
	case strings.Contains(mimeType, "spreadsheetml"):
		return ".xlsx"
	case strings.Contains(mimeType, "excel"):
		return ".xls"
	case strings.Contains(mimeType, "doc"):
		if strings.Contains(mimeType, "docx") {
			return ".docx"
		}
		return ".doc"
	}
	if fallback != "" {
		return fallback
	}
	return ".bin"
}

// UploadToS3 uploads file to S3 and returns the key
func (m *S3Manager) UploadToS3(ctx context.Context, userID string, key string, data []byte, mimeType string) error {
	client, config, ok := m.GetClient(userID)
	if !ok {
		// Try lazy init from DB if available (handles reconnect-after-restart)
		if m.EnsureClientFromDB(userID) {
			client, config, ok = m.GetClient(userID)
		}
		if !ok {
			return fmt.Errorf("S3 client not initialized for user %s", userID)
		}
	}

	// Set content type and cache headers for preview
	contentType := mimeType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Calculate expiration time based on retention days
	var expires *time.Time
	if config.RetentionDays > 0 {
		expirationTime := time.Now().Add(time.Duration(config.RetentionDays) * 24 * time.Hour)
		expires = &expirationTime
	}

	input := &s3.PutObjectInput{
		Bucket:       aws.String(config.Bucket),
		Key:          aws.String(key),
		Body:         bytes.NewReader(data),
		ContentType:  aws.String(contentType),
		CacheControl: aws.String("public, max-age=3600"),
	}

	if expires != nil {
		input.Expires = expires
	}

	// Add content disposition for inline preview
	if strings.HasPrefix(mimeType, "image/") || strings.HasPrefix(mimeType, "video/") || mimeType == "application/pdf" {
		input.ContentDisposition = aws.String("inline")
	}

	_, err := client.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to upload to S3: %w", err)
	}

	return nil
}

// GetPublicURL generates public URL for S3 object
func (m *S3Manager) GetPublicURL(userID, key string) string {
	_, config, ok := m.GetClient(userID)
	if !ok {
		return ""
	}

	return buildS3PublicURL(config.Endpoint, config.Region, config.Bucket, config.PublicURL, config.PathStyle, key)
}

// buildS3PublicURL monta a URL pública de um objeto. É a regra do slot padrão, reaproveitada
// pelo slot do integrador (customS3PublicURL).
func buildS3PublicURL(endpoint, region, bucket, publicURL string, pathStyle bool, key string) string {
	// Use custom public URL if configured (e.g. CloudFront). Bucket is not appended;
	// for backends that need it (e.g. MinIO), include the bucket in s3_public_url.
	if publicURL != "" {
		return fmt.Sprintf("%s/%s", strings.TrimRight(publicURL, "/"), key)
	}

	// Generate standard S3 URL
	if pathStyle {
		return fmt.Sprintf("%s/%s/%s",
			strings.TrimRight(endpoint, "/"),
			bucket,
			key)
	}

	// Virtual hosted-style URL
	if strings.Contains(endpoint, "amazonaws.com") {
		return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
			bucket,
			region,
			key)
	}

	// For other S3-compatible services
	host := strings.TrimPrefix(endpoint, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	return fmt.Sprintf("https://%s.%s/%s", bucket, host, key)
}

// TestConnection tests S3 connection
func (m *S3Manager) TestConnection(ctx context.Context, userID string) error {
	client, config, ok := m.GetClient(userID)
	if !ok {
		return fmt.Errorf("S3 client not initialized for user %s", userID)
	}

	// Try to list objects with max 1 result
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(config.Bucket),
		MaxKeys: aws.Int32(1),
	}

	_, err := client.ListObjectsV2(ctx, input)
	return err
}

// ProcessMediaForS3 handles the complete media upload process
func (m *S3Manager) ProcessMediaForS3(ctx context.Context, userID, contactJID, messageID string,
	data []byte, mimeType string, fileName string, isIncoming bool) (map[string]interface{}, error) {

	// Generate S3 key
	key := m.GenerateS3Key(userID, contactJID, messageID, mimeType, isIncoming)

	// Upload to S3
	err := m.UploadToS3(ctx, userID, key, data, mimeType)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Generate public URL
	publicURL := m.GetPublicURL(userID, key)

	// Read the bucket through GetClient, which acquires the read lock — this
	// avoids racing with a concurrent reconfigure/removal of the configs map and
	// the nil deref the previous unlocked read could hit.
	bucket := ""
	if _, config, ok := m.GetClient(userID); ok && config != nil {
		bucket = config.Bucket
	}

	// Return S3 metadata
	s3Data := map[string]interface{}{
		"url":      publicURL,
		"key":      key,
		"bucket":   bucket,
		"size":     len(data),
		"mimeType": mimeType,
		"fileName": fileName,
	}

	return s3Data, nil
}

// DeleteAllUserObjects deletes all user files from S3
func (m *S3Manager) DeleteAllUserObjects(ctx context.Context, userID string) error {
	client, config, ok := m.GetClient(userID)
	if !ok {
		return fmt.Errorf("S3 client not initialized for user %s", userID)
	}

	prefix := fmt.Sprintf("users/%s/", userID)
	var toDelete []types.ObjectIdentifier
	var continuationToken *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(config.Bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: continuationToken,
		}
		output, err := client.ListObjectsV2(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to list objects for user %s: %w", userID, err)
		}

		for _, obj := range output.Contents {
			toDelete = append(toDelete, types.ObjectIdentifier{Key: obj.Key})
			// Delete in batches of 1000 (S3 limit)
			if len(toDelete) == 1000 {
				_, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: aws.String(config.Bucket),
					Delete: &types.Delete{Objects: toDelete},
				})
				if err != nil {
					return fmt.Errorf("failed to delete objects for user %s: %w", userID, err)
				}
				toDelete = nil
			}
		}

		if output.IsTruncated != nil && *output.IsTruncated && output.NextContinuationToken != nil {
			continuationToken = output.NextContinuationToken
		} else {
			break
		}
	}

	// Delete any remaining objects
	if len(toDelete) > 0 {
		_, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(config.Bucket),
			Delete: &types.Delete{Objects: toDelete},
		})
		if err != nil {
			return fmt.Errorf("failed to delete objects for user %s: %w", userID, err)
		}
	}

	log.Info().Str("userID", userID).Msg("all user files removed from S3")
	return nil
}

// ---------------------------------------------------------------------------------------------
// Segundo slot: storage próprio do integrador (feature 028, US2)
//
// O manager cadastra o slot por PUT /admin/users/{id}/custom-s3. A mídia recebida pelo `device`
// tenta o slot do integrador primeiro; na falha, no prazo estourado ou com o disjuntor aberto,
// vai para o slot padrão. O payload interno ganha `s3.storage` e `s3.customError` só quando o
// slot do integrador existe (contracts/internal-apis.md).
// ---------------------------------------------------------------------------------------------

const (
	// customS3DefaultTimeout é o prazo padrão de cada gravação no storage do integrador. O
	// SC-005 admite 5 s de atraso; o segundo de folga cobre o disjuntor e o registro da falha.
	customS3DefaultTimeout = 4000 * time.Millisecond
	// customS3BreakerWindow é o tempo em que o slot do integrador não é tentado depois de uma
	// falha. Passado o prazo, a próxima mídia serve de sonda.
	customS3BreakerWindow = 60 * time.Second
	// customS3MissingTTL limita por quanto tempo o "não há slot" lido do banco fica em memória.
	customS3MissingTTL = 60 * time.Second

	customS3StorageCustom  = "custom"
	customS3StorageDefault = "default"

	// Motivos de falha; os mesmos de InstanceStorageFailureReason no manager.
	customS3ReasonAccessDenied = "ACCESS_DENIED"
	customS3ReasonNotFound     = "NOT_FOUND"
	customS3ReasonTimeout      = "TIMEOUT"
	customS3ReasonUnreachable  = "UNREACHABLE"
	customS3ReasonTooLarge     = "TOO_LARGE"
	customS3ReasonUnknown      = "UNKNOWN"
)

// customS3Timeout é o prazo em uso. main.go troca o padrão por CUSTOM_S3_TIMEOUT_MS na subida.
var customS3Timeout = customS3DefaultTimeout

// customS3SafeHTTPClient é o cliente anti-SSRF de main.go, compartilhado pelos clientes S3 dos
// integradores. Ele resolve o host a cada conexão e recusa endereço privado, loopback,
// link-local e CGNAT, o que cobre a troca de DNS depois do cadastro.
var customS3SafeHTTPClient = newSafeHTTPClient()

// CustomS3Config é o slot do storage próprio de um usuário.
type CustomS3Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	PathStyle bool
	PublicURL string
	// KeyPrefix é o prefixo completo da chave, já com `media/{instanceId}/`.
	KeyPrefix string
	AccessKey string
	SecretKey string
}

// LogFields devolve o slot sem as credenciais. AccessKey e SecretKey NUNCA entram em log, em
// erro devolvido ou em resposta HTTP; quem loga o slot MUST usar este método.
func (c *CustomS3Config) LogFields() map[string]interface{} {
	if c == nil {
		return nil
	}
	return map[string]interface{}{
		"endpoint":   c.Endpoint,
		"region":     c.Region,
		"bucket":     c.Bucket,
		"path_style": c.PathStyle,
		"public_url": c.PublicURL,
		"key_prefix": c.KeyPrefix,
	}
}

type customS3Slot struct {
	client *s3.Client
	config *CustomS3Config
}

type customS3Breaker struct {
	openUntil time.Time
	reason    string
}

// customS3PublicURL monta a URL do objeto no storage do integrador, com a regra do slot padrão.
func customS3PublicURL(cfg *CustomS3Config, key string) string {
	return buildS3PublicURL(cfg.Endpoint, cfg.Region, cfg.Bucket, cfg.PublicURL, cfg.PathStyle, key)
}

func (m *S3Manager) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *S3Manager) customS3Timeout() time.Duration {
	if m.customTimeout > 0 {
		return m.customTimeout
	}
	return customS3Timeout
}

// ensureCustomMapsLocked cobre o S3Manager montado sem newS3Manager. Exige m.mu travado.
func (m *S3Manager) ensureCustomMapsLocked() {
	if m.customSlots == nil {
		m.customSlots = make(map[string]*customS3Slot)
	}
	if m.customMissing == nil {
		m.customMissing = make(map[string]time.Time)
	}
	if m.breakers == nil {
		m.breakers = make(map[string]customS3Breaker)
	}
}

// newCustomS3Client cria o cliente do integrador: cliente HTTP anti-SSRF, sem retentativa e
// com checksum só quando a operação exige, para aceitar provedores compatíveis com S3.
func (m *S3Manager) newCustomS3Client(cfg *CustomS3Config) *s3.Client {
	httpClient := m.customHTTPClient
	if httpClient == nil {
		httpClient = customS3SafeHTTPClient
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	return s3.New(s3.Options{
		Region:                     region,
		Credentials:                credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		BaseEndpoint:               aws.String(cfg.Endpoint),
		UsePathStyle:               cfg.PathStyle,
		HTTPClient:                 httpClient,
		Retryer:                    aws.NopRetryer{},
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
}

// SetCustomSlot grava o slot do integrador em memória e recria o cliente. Um slot novo começa
// com o disjuntor fechado.
func (m *S3Manager) SetCustomSlot(userID string, cfg *CustomS3Config) error {
	if cfg == nil || cfg.Endpoint == "" || cfg.Bucket == "" {
		return errors.New("custom S3 slot requires endpoint and bucket")
	}
	c := *cfg
	slot := &customS3Slot{client: m.newCustomS3Client(&c), config: &c}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCustomMapsLocked()
	m.customSlots[userID] = slot
	delete(m.customMissing, userID)
	delete(m.breakers, userID)
	return nil
}

// RemoveCustomSlot apaga o slot do integrador da memória.
func (m *S3Manager) RemoveCustomSlot(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCustomMapsLocked()
	delete(m.customSlots, userID)
	delete(m.breakers, userID)
	m.customMissing[userID] = m.clock().Add(customS3MissingTTL)
}

// HasCustomSlot informa se o usuário tem slot do integrador (em memória ou no banco).
func (m *S3Manager) HasCustomSlot(userID string) bool {
	_, ok := m.getCustomSlot(userID)
	return ok
}

// customSlotConfig devolve uma cópia do slot do integrador, carregando do banco se preciso.
func (m *S3Manager) customSlotConfig(userID string) (CustomS3Config, bool) {
	slot, ok := m.getCustomSlot(userID)
	if !ok {
		return CustomS3Config{}, false
	}
	return *slot.config, true
}

// getCustomSlot devolve o slot em memória ou o carrega do banco (reinício do processo). A
// ausência fica em memória por customS3MissingTTL para não consultar o banco a cada mídia.
func (m *S3Manager) getCustomSlot(userID string) (*customS3Slot, bool) {
	now := m.clock()
	m.mu.RLock()
	slot, ok := m.customSlots[userID]
	missingUntil, missing := m.customMissing[userID]
	db := m.db
	m.mu.RUnlock()
	if ok {
		return slot, true
	}
	if db == nil || (missing && now.Before(missingUntil)) {
		return nil, false
	}

	cfg, err := loadCustomS3FromDB(db, userID)
	if err != nil {
		// O erro de leitura ou de decifra não carrega credencial.
		log.Warn().Err(err).Str("userID", userID).Msg("falha ao carregar o storage próprio do banco; usando só o slot padrão")
	}
	if cfg == nil {
		m.mu.Lock()
		m.ensureCustomMapsLocked()
		m.customMissing[userID] = now.Add(customS3MissingTTL)
		m.mu.Unlock()
		return nil, false
	}

	newSlot := &customS3Slot{client: m.newCustomS3Client(cfg), config: cfg}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCustomMapsLocked()
	// Um PUT concorrente vence a leitura do banco, que pode estar defasada.
	if current, exists := m.customSlots[userID]; exists {
		return current, true
	}
	m.customSlots[userID] = newSlot
	delete(m.customMissing, userID)
	return newSlot, true
}

// loadCustomS3FromDB lê e decifra o slot do integrador. Devolve nil sem erro quando não há slot.
func loadCustomS3FromDB(db *sqlx.DB, userID string) (*CustomS3Config, error) {
	var row struct {
		Enabled   bool   `db:"custom_s3_enabled"`
		Endpoint  string `db:"custom_s3_endpoint"`
		Region    string `db:"custom_s3_region"`
		Bucket    string `db:"custom_s3_bucket"`
		PathStyle bool   `db:"custom_s3_path_style"`
		PublicURL string `db:"custom_s3_public_url"`
		KeyPrefix string `db:"custom_s3_key_prefix"`
		AccessKey []byte `db:"custom_s3_access_key"`
		SecretKey []byte `db:"custom_s3_secret_key"`
	}
	query := db.Rebind(`SELECT COALESCE(custom_s3_enabled, false) AS custom_s3_enabled,
		COALESCE(custom_s3_endpoint, '') AS custom_s3_endpoint,
		COALESCE(custom_s3_region, '') AS custom_s3_region,
		COALESCE(custom_s3_bucket, '') AS custom_s3_bucket,
		COALESCE(custom_s3_path_style, false) AS custom_s3_path_style,
		COALESCE(custom_s3_public_url, '') AS custom_s3_public_url,
		COALESCE(custom_s3_key_prefix, '') AS custom_s3_key_prefix,
		custom_s3_access_key, custom_s3_secret_key
		FROM users WHERE id = $1`)
	if err := db.Get(&row, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom S3 slot: %w", err)
	}
	if !row.Enabled || row.Endpoint == "" || row.Bucket == "" {
		return nil, nil
	}
	accessKey, err := decryptHMACKey(row.AccessKey)
	if err != nil {
		return nil, errors.New("decrypt custom S3 access key failed")
	}
	secretKey, err := decryptHMACKey(row.SecretKey)
	if err != nil {
		return nil, errors.New("decrypt custom S3 secret key failed")
	}
	return &CustomS3Config{
		Endpoint:  row.Endpoint,
		Region:    row.Region,
		Bucket:    row.Bucket,
		PathStyle: row.PathStyle,
		PublicURL: row.PublicURL,
		KeyPrefix: row.KeyPrefix,
		AccessKey: accessKey,
		SecretKey: secretKey,
	}, nil
}

// breakerOpen informa se o disjuntor do usuário está aberto e o motivo da falha que o abriu.
func (m *S3Manager) breakerOpen(userID string) (bool, string) {
	now := m.clock()
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.breakers[userID]
	if !ok || !now.Before(b.openUntil) {
		return false, ""
	}
	return true, b.reason
}

func (m *S3Manager) openBreaker(userID, reason string) {
	until := m.clock().Add(customS3BreakerWindow)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureCustomMapsLocked()
	m.breakers[userID] = customS3Breaker{openUntil: until, reason: reason}
}

func (m *S3Manager) closeBreaker(userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.breakers, userID)
}

// StoreMedia grava a mídia no slot do integrador e, se ele falhar, no slot padrão.
//
// Sem slot do integrador, devolve o mesmo que ProcessMediaForS3. Com ele, o resultado ganha
// `storage` ("custom" ou "default") e, quando a mídia foi para o slot padrão, `customError`
// com o motivo. Com o disjuntor aberto, o slot do integrador não é tentado, e `customError`
// repete o motivo da falha que o abriu.
func (m *S3Manager) StoreMedia(ctx context.Context, userID, contactJID, messageID string,
	data []byte, mimeType string, fileName string, isIncoming bool) (map[string]interface{}, error) {

	slot, hasCustom := m.getCustomSlot(userID)
	reason := ""
	if hasCustom {
		if open, last := m.breakerOpen(userID); open {
			reason = last
		} else {
			res, failReason := m.uploadToCustom(ctx, userID, slot, messageID, data, mimeType, fileName)
			if failReason == "" {
				return res, nil
			}
			reason = failReason
		}
	}

	s3Data, err := m.ProcessMediaForS3(ctx, userID, contactJID, messageID, data, mimeType, fileName, isIncoming)
	if err != nil {
		return nil, err
	}
	if hasCustom {
		s3Data["storage"] = customS3StorageDefault
		s3Data["customError"] = map[string]string{"reason": reason}
	}
	return s3Data, nil
}

// uploadToCustom faz uma única tentativa no slot do integrador, dentro do prazo. Devolve o
// resultado ou o motivo da falha; a falha arma o disjuntor e o sucesso o fecha.
func (m *S3Manager) uploadToCustom(ctx context.Context, userID string, slot *customS3Slot,
	messageID string, data []byte, mimeType, fileName string) (map[string]interface{}, string) {

	cfg := slot.config
	key := fmt.Sprintf("%s%d-%s%s", cfg.KeyPrefix, m.clock().UnixMilli(), messageID,
		s3ExtensionForMime(mimeType, filepath.Ext(fileName)))

	contentType := mimeType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	input := &s3.PutObjectInput{
		Bucket:        aws.String(cfg.Bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
		ContentType:   aws.String(contentType),
	}
	if strings.HasPrefix(mimeType, "image/") || strings.HasPrefix(mimeType, "video/") || mimeType == "application/pdf" {
		input.ContentDisposition = aws.String("inline")
	}

	cctx, cancel := context.WithTimeout(ctx, m.customS3Timeout())
	defer cancel()
	if _, err := slot.client.PutObject(cctx, input); err != nil {
		reason := classifyCustomS3Error(cctx, err)
		m.openBreaker(userID, reason)
		// Só o motivo, o código e o status do provedor: a mensagem do SDK não entra no log.
		ev := log.Warn().Str("userID", userID).Str("bucket", cfg.Bucket).Str("reason", reason)
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			ev = ev.Str("providerCode", apiErr.ErrorCode())
		}
		var statusErr interface{ HTTPStatusCode() int }
		if errors.As(err, &statusErr) {
			ev = ev.Int("httpStatus", statusErr.HTTPStatusCode())
		}
		ev.Msg("falha ao gravar mídia no storage próprio; usando o slot padrão")
		return nil, reason
	}
	m.closeBreaker(userID)

	return map[string]interface{}{
		"url":      customS3PublicURL(cfg, key),
		"key":      key,
		"bucket":   cfg.Bucket,
		"size":     len(data),
		"mimeType": mimeType,
		"fileName": fileName,
		"storage":  customS3StorageCustom,
	}, ""
}

// classifyCustomS3Error traduz o erro do provedor para os motivos do contrato com o manager.
func classifyCustomS3Error(ctx context.Context, err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return customS3ReasonTimeout
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "Forbidden", "InvalidAccessKeyId", "SignatureDoesNotMatch",
			"AllAccessDisabled", "AccountProblem", "InvalidToken", "ExpiredToken":
			return customS3ReasonAccessDenied
		case "NoSuchBucket", "NotFound", "NoSuchKey":
			return customS3ReasonNotFound
		case "EntityTooLarge", "RequestEntityTooLarge", "MaxMessageLengthExceeded":
			return customS3ReasonTooLarge
		}
	}

	var statusErr interface{ HTTPStatusCode() int }
	if errors.As(err, &statusErr) {
		switch statusErr.HTTPStatusCode() {
		case http.StatusUnauthorized, http.StatusForbidden:
			return customS3ReasonAccessDenied
		case http.StatusNotFound:
			return customS3ReasonNotFound
		case http.StatusRequestEntityTooLarge:
			return customS3ReasonTooLarge
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return customS3ReasonTimeout
	}

	// Pedido que não saiu: conexão recusada, DNS, endereço recusado pelo anti-SSRF.
	var sendErr *smithyhttp.RequestSendError
	var dnsErr *net.DNSError
	var opErr *net.OpError
	if errors.As(err, &sendErr) || errors.As(err, &dnsErr) || errors.As(err, &opErr) {
		return customS3ReasonUnreachable
	}

	return customS3ReasonUnknown
}
