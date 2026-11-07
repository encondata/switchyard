package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testUI() fstest.MapFS {
	return fstest.MapFS{
		"index.html":    {Data: []byte("<html>app</html>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestHealth(t *testing.T) {
	h := New(Options{Version: "1.2.3", UI: testUI()})
	rec := get(t, h, "/api/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" || body["version"] != "1.2.3" {
		t.Fatalf("body = %v", body)
	}
}

func TestUnknownAPIRouteIsJSON404(t *testing.T) {
	rec := get(t, New(Options{UI: testUI()}), "/api/nope")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestSPA(t *testing.T) {
	h := New(Options{UI: testUI()})
	cases := []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/", http.StatusOK, "app"},
		{"/hosts/42", http.StatusOK, "app"}, // client-side route
		{"/assets/app.js", http.StatusOK, "console.log"},
		{"/assets/missing.js", http.StatusNotFound, ""},
	}
	for _, c := range cases {
		rec := get(t, h, c.path)
		if rec.Code != c.wantCode {
			t.Errorf("%s: status = %d, want %d", c.path, rec.Code, c.wantCode)
		}
		if !strings.Contains(rec.Body.String(), c.wantBody) {
			t.Errorf("%s: body %q does not contain %q", c.path, rec.Body.String(), c.wantBody)
		}
	}
}

func TestNoUI(t *testing.T) {
	rec := get(t, New(Options{}), "/")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
