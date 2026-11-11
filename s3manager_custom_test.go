package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Feature 028, US2 (T036): segundo slot de S3 por usuário, o storage próprio do integrador.
// Estes testes cobrem a gravação no slot do integrador, o fallback para o slot padrão, o
// disjuntor de 60 s, o prazo (SC-005), o cliente HTTP anti-SSRF e a cifra das credenciais.

const (
	customTestAccessKey = "AKIA-INTEGRADOR-NUNCA-NO-LOG"
	customTestSecretKey = "segredo-do-integrador-nunca-no-log"
	customTestPrefix    = "zapper/media/inst-1/"
	customTestUser      = "u-custom-1"
	customTestMessageID = "3EB0ABCDEF123456"
)

// fakeS3 é um servidor S3 mínimo: aceita PUT e registra o caminho, ou responde com o erro
// configurado, ou não responde até o teste terminar.
type fakeS3 struct {
	srv     *httptest.Server
	mu      sync.Mutex
	paths   []string
	status  int
	code    string
	hang    bool
	release chan struct{}
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{status: http.StatusOK, release: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		status, code, hang := f.status, f.code, f.hang
		f.mu.Unlock()
		if hang {
			select {
			case <-r.Context().Done():
			case <-f.release:
			}
			return
		}
		if status == http.StatusOK {
			w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>falha simulada</Message><RequestId>req-1</RequestId></Error>`, code)
	}))
	t.Cleanup(func() {
		close(f.release)
		f.srv.Close()
	})
	return f
}

func (f *fakeS3) set(status int, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.code = status, code
}

func (f *fakeS3) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

// newCustomTestManager monta um S3Manager com o slot padrão apontando para defaultSrv e,
// quando custom não é nil, o slot do integrador apontando para ele. O cliente HTTP do slot
// do integrador é trocado por um que alcança o loopback do httptest; o teste do cliente
// anti-SSRF não faz essa troca.
func newCustomTestManager(t *testing.T, defaultSrv, custom *fakeS3, clock *fakeClock) *S3Manager {
	t.Helper()
	m := newS3Manager()
	m.customHTTPClient = &http.Client{}
	if clock != nil {
		m.now = clock.Now
	}
	if err := m.InitializeS3Client(customTestUser, &S3Config{
		Enabled:   true,
		Endpoint:  defaultSrv.srv.URL,
		Region:    "us-east-1",
		Bucket:    "zapperhub-files",
		AccessKey: "zapper-access",
		SecretKey: "zapper-secret",
		PathStyle: true,
	}); err != nil {
		t.Fatalf("slot padrão: %v", err)
	}
	if custom != nil {
		if err := m.SetCustomSlot(customTestUser, &CustomS3Config{
			Endpoint:  custom.srv.URL,
			Region:    "us-east-1",
			Bucket:    "integrador",
			PathStyle: true,
			KeyPrefix: customTestPrefix,
			AccessKey: customTestAccessKey,
			SecretKey: customTestSecretKey,
		}); err != nil {
			t.Fatalf("slot do integrador: %v", err)
		}
	}
	return m
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// asJSON reduz o resultado ao que o manager recebe no webhook interno.
func asJSON(t *testing.T, v map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func storeTestMedia(t *testing.T, m *S3Manager) map[string]interface{} {
	t.Helper()
	res, err := m.StoreMedia(context.Background(), customTestUser, "5511999999999@s.whatsapp.net",
		customTestMessageID, []byte("conteudo-da-midia"), "image/jpeg", customTestMessageID+".jpg", true)
	if err != nil {
		t.Fatalf("StoreMedia: %v", err)
	}
	return asJSON(t, res)
}

func customErrorReason(res map[string]interface{}) string {
	ce, ok := res["customError"].(map[string]interface{})
	if !ok {
		return ""
	}
	r, _ := ce["reason"].(string)
	return r
}

func TestCustomS3SlotRecebeMidiaComChaveDoPrefixo(t *testing.T) {
	def, cus := newFakeS3(t), newFakeS3(t)
	clock := &fakeClock{t: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	m := newCustomTestManager(t, def, cus, clock)

	res := storeTestMedia(t, m)

	wantKey := fmt.Sprintf("%s%d-%s.jpg", customTestPrefix, clock.Now().UnixMilli(), customTestMessageID)
	if res["key"] != wantKey {
		t.Fatalf("key = %v, esperava %s", res["key"], wantKey)
	}
	if res["storage"] != "custom" {
		t.Fatalf("storage = %v, esperava custom", res["storage"])
	}
	if _, ok := res["customError"]; ok {
		t.Fatalf("customError não deveria vir no sucesso: %v", res["customError"])
	}
	if res["bucket"] != "integrador" {
		t.Fatalf("bucket = %v, esperava o do integrador", res["bucket"])
	}
	wantURL := cus.srv.URL + "/integrador/" + wantKey
	if res["url"] != wantURL {
		t.Fatalf("url = %v, esperava %s", res["url"], wantURL)
	}
	for _, k := range []string{"size", "mimeType", "fileName"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("campo %q do s3 sumiu do resultado", k)
		}
	}
	if got := cus.requests(); len(got) != 1 || got[0] != "PUT /integrador/"+wantKey {
		t.Fatalf("pedidos ao integrador = %v", got)
	}
	if got := def.requests(); len(got) != 0 {
		t.Fatalf("o slot padrão não deveria ser usado: %v", got)
	}
}

func TestCustomS3FalhaCaiNoSlotPadrao(t *testing.T) {
	cases := []struct {
		name   string
		status int
		code   string
		reason string
	}{
		{"acesso negado", http.StatusForbidden, "AccessDenied", customS3ReasonAccessDenied},
		{"bucket inexistente", http.StatusNotFound, "NoSuchBucket", customS3ReasonNotFound},
		{"arquivo grande demais", http.StatusBadRequest, "EntityTooLarge", customS3ReasonTooLarge},
		{"erro interno", http.StatusInternalServerError, "InternalError", customS3ReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, cus := newFakeS3(t), newFakeS3(t)
			cus.set(tc.status, tc.code)
			m := newCustomTestManager(t, def, cus, nil)

			res := storeTestMedia(t, m)

			if res["storage"] != "default" {
				t.Fatalf("storage = %v, esperava default", res["storage"])
			}
			if got := customErrorReason(res); got != tc.reason {
				t.Fatalf("customError.reason = %q, esperava %q", got, tc.reason)
			}
			if !strings.HasPrefix(res["url"].(string), def.srv.URL+"/zapperhub-files/users/") {
				t.Fatalf("url deveria ser do slot padrão: %v", res["url"])
			}
			if got := def.requests(); len(got) != 1 {
				t.Fatalf("esperava 1 gravação no slot padrão, houve %v", got)
			}
			// Sem retentativa no slot do integrador.
			if got := cus.requests(); len(got) != 1 {
				t.Fatalf("esperava 1 tentativa no integrador, houve %v", got)
			}
		})
	}

	t.Run("endereço inalcançável", func(t *testing.T) {
		def, cus := newFakeS3(t), newFakeS3(t)
		m := newCustomTestManager(t, def, cus, nil)
		cus.srv.Close() // conexão recusada

		res := storeTestMedia(t, m)
		if res["storage"] != "default" || customErrorReason(res) != customS3ReasonUnreachable {
			t.Fatalf("esperava default com UNREACHABLE, veio %v", res)
		}
	})
}

func TestCustomS3DisjuntorDe60s(t *testing.T) {
	def, cus := newFakeS3(t), newFakeS3(t)
	cus.set(http.StatusForbidden, "AccessDenied")
	clock := &fakeClock{t: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	m := newCustomTestManager(t, def, cus, clock)

	if res := storeTestMedia(t, m); customErrorReason(res) != customS3ReasonAccessDenied {
		t.Fatalf("primeira falha deveria trazer ACCESS_DENIED: %v", res)
	}

	// O integrador volta, mas o disjuntor segura as tentativas por 60 s.
	cus.set(http.StatusOK, "")
	clock.Advance(59 * time.Second)
	res := storeTestMedia(t, m)
	if res["storage"] != "default" {
		t.Fatalf("com o disjuntor aberto a mídia vai para o slot padrão: %v", res)
	}
	if customErrorReason(res) != customS3ReasonAccessDenied {
		t.Fatalf("com o disjuntor aberto o motivo da última falha continua no resultado: %v", res)
	}
	if got := cus.requests(); len(got) != 1 {
		t.Fatalf("o integrador não deveria ser tentado com o disjuntor aberto: %v", got)
	}

	// Passados 60 s, a próxima mídia serve de sonda.
	clock.Advance(1 * time.Second)
	res = storeTestMedia(t, m)
	if res["storage"] != "custom" {
		t.Fatalf("depois de 60 s o integrador deveria ser tentado de novo: %v", res)
	}
	if _, ok := res["customError"]; ok {
		t.Fatalf("customError não deveria vir depois da recuperação: %v", res)
	}
	if got := cus.requests(); len(got) != 2 {
		t.Fatalf("esperava 2 tentativas no integrador, houve %v", got)
	}
}

// SC-005: um storage do integrador que não responde acrescenta menos de 5 s ao evento, com o
// prazo padrão de CUSTOM_S3_TIMEOUT_MS.
func TestCustomS3PrazoAbaixoDe5s(t *testing.T) {
	if customS3Timeout != customS3DefaultTimeout || customS3DefaultTimeout != 4*time.Second {
		t.Fatalf("prazo padrão = %v (atual %v), esperava 4s", customS3DefaultTimeout, customS3Timeout)
	}
	def, cus := newFakeS3(t), newFakeS3(t)
	cus.mu.Lock()
	cus.hang = true
	cus.mu.Unlock()
	m := newCustomTestManager(t, def, cus, nil)

	start := time.Now()
	res := storeTestMedia(t, m)
	elapsed := time.Since(start)

	if elapsed >= 5*time.Second {
		t.Fatalf("atraso acrescentado = %v, o SC-005 admite menos de 5 s", elapsed)
	}
	if res["storage"] != "default" || customErrorReason(res) != customS3ReasonTimeout {
		t.Fatalf("esperava default com TIMEOUT, veio %v", res)
	}
}

// O slot do integrador usa o cliente HTTP anti-SSRF de main.go: endereço de loopback é recusado
// antes de qualquer conexão, e a mídia cai no slot padrão.
func TestCustomS3ClienteSeguroRecusaEnderecoPrivado(t *testing.T) {
	def, cus := newFakeS3(t), newFakeS3(t)
	m := newCustomTestManager(t, def, nil, nil)
	m.customHTTPClient = nil // volta ao cliente seguro
	if err := m.SetCustomSlot(customTestUser, &CustomS3Config{
		Endpoint: cus.srv.URL, Region: "us-east-1", Bucket: "integrador", PathStyle: true,
		KeyPrefix: customTestPrefix, AccessKey: customTestAccessKey, SecretKey: customTestSecretKey,
	}); err != nil {
		t.Fatalf("SetCustomSlot: %v", err)
	}

	res := storeTestMedia(t, m)
	if res["storage"] != "default" || customErrorReason(res) != customS3ReasonUnreachable {
		t.Fatalf("esperava default com UNREACHABLE, veio %v", res)
	}
	if got := cus.requests(); len(got) != 0 {
		t.Fatalf("o cliente seguro não deveria alcançar o loopback: %v", got)
	}
}

// Sem storage próprio cadastrado, o payload fica como era: sem storage e sem customError.
func TestCustomS3SemSlotNaoMandaCamposNovos(t *testing.T) {
	def := newFakeS3(t)
	m := newCustomTestManager(t, def, nil, nil)

	res := storeTestMedia(t, m)
	for _, k := range []string{"storage", "customError"} {
		if _, ok := res[k]; ok {
			t.Fatalf("campo %q não deveria vir sem slot do integrador: %v", k, res)
		}
	}
	for _, k := range []string{"url", "key", "bucket", "size", "mimeType", "fileName"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("campo %q do s3 sumiu: %v", k, res)
		}
	}
}

func TestCustomS3PublicURL(t *testing.T) {
	key := customTestPrefix + "1-ABC.jpg"
	cases := []struct {
		name string
		cfg  CustomS3Config
		want string
	}{
		{"public_url", CustomS3Config{Endpoint: "https://s3.example.com", Bucket: "b", PublicURL: "https://cdn.example.com/"}, "https://cdn.example.com/" + key},
		{"path style", CustomS3Config{Endpoint: "https://s3.example.com/", Bucket: "b", PathStyle: true}, "https://s3.example.com/b/" + key},
		{"virtual hosted", CustomS3Config{Endpoint: "https://s3.example.com", Bucket: "b"}, "https://b.s3.example.com/" + key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := customS3PublicURL(&tc.cfg, key); got != tc.want {
				t.Fatalf("url = %s, esperava %s", got, tc.want)
			}
		})
	}
}

// syncBuffer protege o buffer do log contra escrita concorrente.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prevLogger, prevLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf).Level(zerolog.TraceLevel)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})
	return buf
}

func withEncryptionKey(t *testing.T) {
	t.Helper()
	prev := *globalEncryptionKey
	*globalEncryptionKey = "0123456789abcdef0123456789abcdef"
	t.Cleanup(func() { *globalEncryptionKey = prev })
}

func assertNoCredential(t *testing.T, where, text string) {
	t.Helper()
	if strings.Contains(text, customTestAccessKey) || strings.Contains(text, customTestSecretKey) {
		t.Fatalf("credencial do integrador apareceu em %s: %s", where, text)
	}
}

// A rota administrativa grava o slot com as credenciais cifradas, não devolve credencial e não
// a escreve no log. O slot gravado é recarregado do banco por outro S3Manager (reinício).
func TestCustomS3RotaAdminCifraCredenciais(t *testing.T) {
	withEncryptionKey(t)
	s := makeTestServer(t)
	logs := captureLogs(t)
	t.Cleanup(func() { GetS3Manager().RemoveCustomSlot(customTestUser) })

	if _, err := s.db.Exec("INSERT INTO users (id, name, token) VALUES ($1, $2, $3)", customTestUser, "inst", "tok-custom"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	body := `{"endpoint":"https://s3.integrador.example.com","region":"us-east-1","bucket":"integrador",` +
		`"path_style":true,"public_url":"","key_prefix":"` + customTestPrefix + `",` +
		`"access_key":"` + customTestAccessKey + `","secret_key":"` + customTestSecretKey + `"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/users/"+customTestUser+"/custom-s3", strings.NewReader(body))
	req.Header.Set("Authorization", "test-admin-token")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, corpo %s", rec.Code, rec.Body.String())
	}
	assertNoCredential(t, "resposta do PUT", rec.Body.String())

	var row struct {
		Enabled   bool   `db:"custom_s3_enabled"`
		Bucket    string `db:"custom_s3_bucket"`
		KeyPrefix string `db:"custom_s3_key_prefix"`
		AccessKey []byte `db:"custom_s3_access_key"`
		SecretKey []byte `db:"custom_s3_secret_key"`
	}
	if err := s.db.Get(&row, "SELECT custom_s3_enabled, custom_s3_bucket, custom_s3_key_prefix, custom_s3_access_key, custom_s3_secret_key FROM users WHERE id = $1", customTestUser); err != nil {
		t.Fatalf("select: %v", err)
	}
	if !row.Enabled || row.Bucket != "integrador" || row.KeyPrefix != customTestPrefix {
		t.Fatalf("slot gravado errado: %+v", row)
	}
	if bytes.Contains(row.AccessKey, []byte(customTestAccessKey)) || bytes.Contains(row.SecretKey, []byte(customTestSecretKey)) {
		t.Fatal("credencial gravada em texto puro")
	}
	if got, err := decryptHMACKey(row.SecretKey); err != nil || got != customTestSecretKey {
		t.Fatalf("secret_key não decifra com a chave global: %q, %v", got, err)
	}
	if got, err := decryptHMACKey(row.AccessKey); err != nil || got != customTestAccessKey {
		t.Fatalf("access_key não decifra com a chave global: %q, %v", got, err)
	}
	if !GetS3Manager().HasCustomSlot(customTestUser) {
		t.Fatal("o PUT deveria recriar o cliente do slot")
	}

	// Outro processo (reinício) carrega o slot do banco e decifra as credenciais.
	fresh := newS3Manager()
	fresh.SetDB(s.db)
	cfg, ok := fresh.customSlotConfig(customTestUser)
	if !ok || cfg.SecretKey != customTestSecretKey || cfg.AccessKey != customTestAccessKey || cfg.KeyPrefix != customTestPrefix {
		t.Fatalf("slot recarregado do banco errado: ok=%v", ok)
	}

	// Uma falha no integrador também não escreve credencial no log.
	def, cus := newFakeS3(t), newFakeS3(t)
	cus.set(http.StatusForbidden, "SignatureDoesNotMatch")
	m := newCustomTestManager(t, def, cus, nil)
	if res := storeTestMedia(t, m); customErrorReason(res) != customS3ReasonAccessDenied {
		t.Fatalf("esperava ACCESS_DENIED: %v", res)
	}

	// O log capturado precisa ter as duas linhas, senão a checagem abaixo não prova nada.
	for _, want := range []string{"storage próprio configurado", "falha ao gravar mídia no storage próprio"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log sem %q; a captura não funcionou: %s", want, logs.String())
		}
	}
	assertNoCredential(t, "log", logs.String())

	// DELETE apaga o slot no banco e na memória.
	req = httptest.NewRequest(http.MethodDelete, "/admin/users/"+customTestUser+"/custom-s3", nil)
	req.Header.Set("Authorization", "test-admin-token")
	rec = httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, corpo %s", rec.Code, rec.Body.String())
	}
	if err := s.db.Get(&row, "SELECT custom_s3_enabled, custom_s3_bucket, custom_s3_key_prefix, custom_s3_access_key, custom_s3_secret_key FROM users WHERE id = $1", customTestUser); err != nil {
		t.Fatalf("select: %v", err)
	}
	if row.Enabled || len(row.AccessKey) != 0 || len(row.SecretKey) != 0 {
		t.Fatalf("DELETE deveria apagar o slot: %+v", row)
	}
	if GetS3Manager().HasCustomSlot(customTestUser) {
		t.Fatal("DELETE deveria remover o cliente do slot")
	}
}

func TestCustomS3RotaAdminValidaEntrada(t *testing.T) {
	withEncryptionKey(t)
	s := makeTestServer(t)
	if _, err := s.db.Exec("INSERT INTO users (id, name, token) VALUES ($1, $2, $3)", customTestUser, "inst", "tok-custom"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	cases := []struct {
		name, id, body string
		want           int
	}{
		{"usuário inexistente", "nao-existe", `{"endpoint":"https://s3.example.com","bucket":"b","key_prefix":"p/","access_key":"a","secret_key":"s"}`, http.StatusNotFound},
		{"sem bucket", customTestUser, `{"endpoint":"https://s3.example.com","key_prefix":"p/","access_key":"a","secret_key":"s"}`, http.StatusBadRequest},
		{"endpoint sem https", customTestUser, `{"endpoint":"http://s3.example.com","bucket":"b","key_prefix":"p/","access_key":"a","secret_key":"s"}`, http.StatusBadRequest},
		{"corpo inválido", customTestUser, `{`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/admin/users/"+tc.id+"/custom-s3", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "test-admin-token")
			rec := httptest.NewRecorder()
			s.router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, esperava %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/users/nao-existe/custom-s3", nil)
	req.Header.Set("Authorization", "test-admin-token")
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE de usuário inexistente = %d, esperava 404", rec.Code)
	}
}
