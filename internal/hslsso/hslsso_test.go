package hslsso

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"":                      "/",
		"/":                     "/",
		"/#/hosts/3":            "/#/hosts/3",
		"/a?b=c":                "/a?b=c",
		"//evil.example":        "/",
		"https://evil.example/": "/",
		"/\\evil":               "/",
		"/\tx":                  "/",
		"evil":                  "/",
	} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownRoles(t *testing.T) {
	got := KnownRoles([]string{"viewer", "nope", "admin"}, "admin", "editor", "viewer")
	if len(got) != 2 || got[0] != "admin" || got[1] != "viewer" {
		t.Fatalf("%v", got)
	}
	if KnownRoles(nil, "admin") != nil {
		t.Fatal("roles from nothing")
	}
}

func TestNewChecksConfig(t *testing.T) {
	good := Config{Issuer: "https://auth.example/realms/r", ClientID: "c", ClientSecret: "s", RedirectURL: "https://app.example/cb"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"issuer":   func(c *Config) { c.Issuer = "auth.example" },
		"secret":   func(c *Config) { c.ClientSecret = "" },
		"redirect": func(c *Config) { c.RedirectURL = "/cb" },
		"internal": func(c *Config) { c.InternalURL = "http://kc:8080/realms" },
	} {
		c := good
		change(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Discovery happens on first use, a failure is reported as ErrUnavailable, and it is retried.
func TestLazyDiscovery(t *testing.T) {
	up := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + "http://" + r.Host + `/realms/r","authorization_endpoint":"http://` + r.Host +
			`/auth","token_endpoint":"http://kc.public/token","jwks_uri":"http://kc.public/certs","end_session_endpoint":"http://kc.public/logout"}`))
	}))
	defer srv.Close()
	c, err := New(Config{Issuer: srv.URL + "/realms/r", ClientID: "c", ClientSecret: "s", RedirectURL: "http://app/cb"})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := NewFlow()
	if _, err := c.AuthURL(context.Background(), f, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	up = true
	if _, err := c.AuthURL(context.Background(), f, "login"); err != nil {
		t.Fatalf("not retried: %v", err)
	}
}

// With an internal URL, server-to-server endpoints move to it; browser ones stay public.
func TestInternalURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://auth.example/realms/r","authorization_endpoint":"https://auth.example/realms/r/auth",
			"token_endpoint":"https://auth.example/realms/r/token","jwks_uri":"https://auth.example/realms/r/certs",
			"end_session_endpoint":"https://auth.example/realms/r/logout"}`))
	}))
	defer srv.Close()
	c, err := New(Config{Issuer: "https://auth.example/realms/r", ClientID: "c", ClientSecret: "s",
		RedirectURL: "https://app.example/cb", InternalURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.provider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.oauth.Endpoint.TokenURL != srv.URL+"/realms/r/token" || p.oauth.Endpoint.AuthURL != "https://auth.example/realms/r/auth" ||
		p.endSession != "https://auth.example/realms/r/logout" {
		t.Fatalf("endpoints: %+v %s", p.oauth.Endpoint, p.endSession)
	}
}
