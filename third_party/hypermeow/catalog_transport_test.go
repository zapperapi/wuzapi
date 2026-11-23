package whatsmeow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/polymorfa/hypermeow/mex"
	"github.com/polymorfa/hypermeow/store"
	"github.com/polymorfa/hypermeow/types"
	waLog "github.com/polymorfa/hypermeow/util/log"
)

// As consultas de catálogo vão por HTTP para graph.whatsapp.com/graphql/catalog, como no
// cliente oficial. Pelo IQ w:mex o servidor devolve 400.
func TestCatalogQueriesUseCatalogGraphQLEndpoint(t *testing.T) {
	own := types.NewJID("15550001111", types.DefaultUserServer)
	business := types.NewJID("15550002222", types.DefaultUserServer)
	client := NewClient(&store.Device{ID: &own}, waLog.Noop)
	seen := map[string]bool{}
	client.mediaHTTP = &http.Client{Transport: merchantComplianceRoundTripper(func(request *http.Request) (*http.Response, error) {
		var body struct {
			AccessToken string         `json:"access_token"`
			DocumentID  string         `json:"doc_id"`
			Variables   map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		if request.URL.String() != businessCatalogGraphQLEndpoint || body.AccessToken != businessCatalogGraphQLAccessToken {
			return nil, fmt.Errorf("unexpected catalog request: %s", request.URL)
		}
		encoded, _ := json.Marshal(body.Variables)
		if bytes.Contains(encoded, []byte("variant_info_fields")) {
			return nil, fmt.Errorf("variant_info_fields must not be sent: %s", encoded)
		}
		seen[body.DocumentID] = true
		payloads := map[mex.OperationName]string{
			mex.QueryCatalog:                 `{"data":{"xwa_product_catalog_get_product_catalog":{"product_catalog":{"products":[],"paging":{}}}}}`,
			mex.QueryProductCollections:      `{"data":{"xwa_product_catalog_get_collections":{"collections":[]}}}`,
			mex.QueryCatalogProduct:          `{"errors":[{"message":"not found","code":2498053}]}`,
			mex.QueryProductSingleCollection: `{"errors":[{"message":"not found","code":2498052}]}`,
			mex.QueryProductListCatalog:      `{"errors":[{"message":"not found","code":2498052}]}`,
		}
		for name, payload := range payloads {
			if operation, _ := mex.Lookup(name); operation.DocumentID == body.DocumentID {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewBufferString(payload))}, nil
			}
		}
		return nil, fmt.Errorf("unexpected document ID %q", body.DocumentID)
	})}

	ctx := context.Background()
	if _, err := client.GetCatalog(ctx, business, GetCatalogParams{}); err != nil {
		t.Fatalf("GetCatalog: %v", err)
	}
	if _, err := client.GetProductCollections(ctx, business, GetCollectionsParams{}); err != nil {
		t.Fatalf("GetProductCollections: %v", err)
	}
	if _, err := client.GetCatalogProduct(ctx, business, "1234567890123456"); err == nil {
		t.Fatal("GetCatalogProduct: expected the server error")
	}
	if _, err := client.GetProductCollection(ctx, business, "1234567890123456", GetCatalogParams{}); err == nil {
		t.Fatal("GetProductCollection: expected the server error")
	}
	if _, err := client.GetCatalogProducts(ctx, business, []string{"1234567890123456"}); err == nil {
		t.Fatal("GetCatalogProducts: expected the server error")
	}
	for _, name := range []mex.OperationName{mex.QueryCatalog, mex.QueryCatalogProduct, mex.QueryProductCollections, mex.QueryProductSingleCollection, mex.QueryProductListCatalog} {
		operation, _ := mex.Lookup(name)
		if !seen[operation.DocumentID] {
			t.Errorf("%s was not sent to the catalog endpoint", name)
		}
	}
}
