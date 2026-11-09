package main

import (
	"fmt"
	"os"

	"github.com/polymorfa/hypermeow/store"
	"github.com/rs/zerolog/log"
)

// applyWAVersionFromEnv troca a versão do WhatsApp anunciada pelo cliente quando
// WA_VERSION está definida (formato "2.3000.1053682356"). Sem a variável, vale a
// versão embutida no hypermeow. Chamar antes de criar qualquer cliente.
//
// O servidor do WhatsApp pode recusar recursos novos a um cliente com revisão
// muito antiga; este controle permite anunciar a revisão atual do WhatsApp Web
// sem recompilar.
func applyWAVersionFromEnv() {
	raw := os.Getenv("WA_VERSION")
	if raw == "" {
		return
	}
	version, err := parseWAVersion(raw)
	if err != nil {
		log.Warn().Err(err).Str("WA_VERSION", raw).Msg("WA_VERSION ignorada: formato inválido")
		return
	}
	store.SetWAVersion(version)
	log.Info().Str("version", version.String()).Msg("Versão do WhatsApp configurada por WA_VERSION")
}

func parseWAVersion(raw string) (store.WAVersionContainer, error) {
	version, err := store.ParseVersion(raw)
	if err != nil {
		return store.WAVersionContainer{}, fmt.Errorf("versão %q inválida: %w", raw, err)
	}
	if version.IsZero() {
		return store.WAVersionContainer{}, fmt.Errorf("versão %q é zero", raw)
	}
	return version, nil
}
