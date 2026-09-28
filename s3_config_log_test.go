package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// FR-013a / Principle VI (023-storage-r2): the S3 secret and access keys MUST NOT reach
// any log, at any level. AddUser and EditUser used to log the raw S3Config at Info, and
// the raw user struct (S3Config included) at Debug — both leaked SecretKey and AccessKey
// in clear text on every instance creation and edit. This test locks the fix: LogFields()
// is what AddUser/EditUser now pass to the logger, and it must never surface either key,
// regardless of log level.
func TestS3ConfigLogFieldsOmitsCredentials(t *testing.T) {
	const secretKey = "super-secret-r2-key-must-never-log"
	const accessKey = "AKIA-must-never-log-either"

	cfg := &S3Config{
		Enabled:       true,
		Endpoint:      "https://acc.r2.cloudflarestorage.com",
		Region:        "auto",
		Bucket:        "zapperhub-files",
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		PathStyle:     true,
		PublicURL:     "https://storage.zapperhub.com",
		MediaDelivery: "s3",
		RetentionDays: 7,
	}

	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	for _, level := range []func() *zerolog.Event{logger.Info, logger.Debug, logger.Trace, logger.Warn, logger.Error} {
		buf.Reset()
		level().Interface("s3Config", cfg.LogFields()).Msg("Received values for proxyConfig and s3Config")

		output := buf.String()
		if strings.Contains(output, secretKey) {
			t.Fatalf("secretKey vazou no log (nível testado): %s", output)
		}
		if strings.Contains(output, accessKey) {
			t.Fatalf("accessKey vazou no log (nível testado): %s", output)
		}
	}
}

// Trava a regressão que este teste existe para prevenir: logar o struct bruto,
// como AddUser/EditUser faziam antes da correção, vaza as duas credenciais.
// Serve de documentação viva de por que LogFields() é obrigatório.
func TestRawS3ConfigWouldLeakCredentials(t *testing.T) {
	const secretKey = "super-secret-r2-key-must-never-log"

	cfg := &S3Config{SecretKey: secretKey, AccessKey: "AKIA123"}

	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	logger.Info().Interface("s3Config", cfg).Msg("raw, do not do this")

	if !strings.Contains(buf.String(), secretKey) {
		t.Fatal("esperava que o log bruto vazasse o segredo — se não vaza mais, o teste de regressão perdeu sentido e pode ser removido")
	}
}

func TestS3ConfigLogFieldsHandlesNil(t *testing.T) {
	var cfg *S3Config

	if fields := cfg.LogFields(); fields != nil {
		t.Fatalf("esperava nil para um S3Config nulo (instância sem armazenamento), obteve %v", fields)
	}
}
