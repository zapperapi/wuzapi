// Copyright (c) 2026 Rajeh Taher
//
// Licensed under the MIT License. See LICENSE-MIT for details.

package mex

import "testing"

func TestCatalogBindingsMatchPinnedSpec(t *testing.T) {
	if SourceRevision != "74509efe262b37b26bed05486c9f4160db5e841b" {
		t.Fatalf("source revision = %q", SourceRevision)
	}
	tests := map[OperationName]string{
		DeleteNewsletter:             "30062808666639665",
		QueryCatalog:                 "29516483177936279",
		QueryCatalogProduct:          "28846496438335971",
		QueryProductCollections:      "29398139243143451",
		QueryProductListCatalog:      "29053768057577183",
		QueryProductSingleCollection: "40688642257401415",
		BizCreateOrder:               "26486627094287046",
		BizQueryOrder:                "26593811266898374",
	}
	for name, wantID := range tests {
		binding, ok := Lookup(name)
		if !ok || binding.DocumentID != wantID {
			t.Errorf("%s = %#v, %t; want document ID %s", name, binding, ok, wantID)
		}
	}
}

func TestLookupRejectsUnknownOperation(t *testing.T) {
	if _, ok := Lookup(OperationName("unknown")); ok {
		t.Fatal("unknown operation unexpectedly resolved")
	}
}
