package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_valid(t *testing.T) {
	content := `
default_connection: prod
global:
  emojis: false
  colors: true
  limit: 50
  exportdir: /tmp/out
connections:
  - name: prod
    server: dc.example.com
    port: 636
    ldaps: true
    username: admin
    paging: 400
    ssh:
      host: bastion.example.com
      port: 2222
      agent: true
`
	f := writeTempFile(t, content)
	cfg, err := Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultConnection != "prod" {
		t.Errorf("DefaultConnection = %q, want %q", cfg.DefaultConnection, "prod")
	}
	if cfg.Global.Emojis {
		t.Error("Global.Emojis should be false")
	}
	if !cfg.Global.Colors {
		t.Error("Global.Colors should be true")
	}
	if cfg.Global.Limit != 50 {
		t.Errorf("Global.Limit = %d, want 50", cfg.Global.Limit)
	}
	if cfg.Global.ExportDir != "/tmp/out" {
		t.Errorf("Global.ExportDir = %q, want /tmp/out", cfg.Global.ExportDir)
	}
	if len(cfg.Connections) != 1 {
		t.Fatalf("len(Connections) = %d, want 1", len(cfg.Connections))
	}
	conn := cfg.Connections[0]
	if conn.Server != "dc.example.com" {
		t.Errorf("Server = %q", conn.Server)
	}
	if conn.Port != 636 {
		t.Errorf("Port = %d, want 636", conn.Port)
	}
	if !conn.Ldaps {
		t.Error("Ldaps should be true")
	}
	if conn.Paging != 400 {
		t.Errorf("Paging = %d, want 400", conn.Paging)
	}
	if conn.SSH.Host != "bastion.example.com" {
		t.Errorf("SSH.Host = %q", conn.SSH.Host)
	}
	if conn.SSH.Port != 2222 {
		t.Errorf("SSH.Port = %d, want 2222", conn.SSH.Port)
	}
	if !conn.SSH.Agent {
		t.Error("SSH.Agent should be true")
	}
}

func TestLoad_missingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_malformedYAML(t *testing.T) {
	f := writeTempFile(t, ":: invalid: yaml: {{")
	_, err := Load(f)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestLoad_defaultsApplied(t *testing.T) {
	// Empty global section — defaults should match cobra flag defaults.
	f := writeTempFile(t, "connections:\n  - name: a\n    server: s\n")
	cfg, err := Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	g := cfg.Global
	if !g.Emojis {
		t.Error("default Emojis should be true")
	}
	if !g.Colors {
		t.Error("default Colors should be true")
	}
	if !g.Format {
		t.Error("default Format should be true")
	}
	if !g.Expand {
		t.Error("default Expand should be true")
	}
	if !g.Cache {
		t.Error("default Cache should be true")
	}
	if g.Limit != 20 {
		t.Errorf("default Limit = %d, want 20", g.Limit)
	}
	if g.AttrSort != "none" {
		t.Errorf("default AttrSort = %q, want none", g.AttrSort)
	}
	if g.ExportDir != "data" {
		t.Errorf("default ExportDir = %q, want data", g.ExportDir)
	}
}

func TestFindConfigFile_cwdWins(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "godap.yaml")
	if err := os.WriteFile(cfgPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) })

	got, ok := FindConfigFile()
	if !ok {
		t.Fatal("FindConfigFile returned not-found")
	}
	if got != "godap.yaml" {
		t.Errorf("got %q, want %q", got, "godap.yaml")
	}
}

func TestFindConfigFile_notFound(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	origHome := os.Getenv("HOME")
	os.Chdir(dir)
	// Redirect HOME so the XDG config path resolves inside the empty temp dir.
	os.Setenv("HOME", dir)
	t.Cleanup(func() {
		os.Chdir(orig)
		os.Setenv("HOME", origHome)
	})

	_, ok := FindConfigFile()
	if ok {
		t.Error("expected not-found in empty temp dir")
	}
}

func TestConfig_FindConnection(t *testing.T) {
	cfg := &Config{
		Connections: []ConnectionConfig{
			{Name: "a", Server: "host-a"},
			{Name: "b", Server: "host-b"},
		},
	}
	conn := cfg.FindConnection("b")
	if conn == nil {
		t.Fatal("expected non-nil for name b")
	}
	if conn.Server != "host-b" {
		t.Errorf("Server = %q, want host-b", conn.Server)
	}
	if cfg.FindConnection("missing") != nil {
		t.Error("expected nil for missing name")
	}
}

func TestConfig_DefaultConn_explicit(t *testing.T) {
	cfg := &Config{
		DefaultConnection: "second",
		Connections: []ConnectionConfig{
			{Name: "first"},
			{Name: "second"},
		},
	}
	conn := cfg.DefaultConn()
	if conn == nil || conn.Name != "second" {
		t.Errorf("DefaultConn = %v, want second", conn)
	}
}

func TestConfig_DefaultConn_fallback(t *testing.T) {
	cfg := &Config{
		Connections: []ConnectionConfig{
			{Name: "only"},
		},
	}
	conn := cfg.DefaultConn()
	if conn == nil || conn.Name != "only" {
		t.Errorf("DefaultConn fallback = %v, want only", conn)
	}
}

func TestConfig_DefaultConn_empty(t *testing.T) {
	cfg := &Config{}
	if conn := cfg.DefaultConn(); conn != nil {
		t.Errorf("expected nil for empty connections, got %v", conn)
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "godap-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}
