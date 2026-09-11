package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// SSHTunnelConfig holds SSH tunnel parameters for a connection entry.
type SSHTunnelConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	User          string `yaml:"user"`
	Password      string `yaml:"password"`
	Passfile      string `yaml:"passfile"`
	Agent         bool   `yaml:"agent"`
	Key           string `yaml:"key"`
	KeyPassphrase string `yaml:"key_passphrase"`
	IgnoreHostKey bool   `yaml:"ignore_host_key"`
}

// ConnectionConfig holds all per-connection parameters.
type ConnectionConfig struct {
	Name     string `yaml:"name"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Ldaps    bool   `yaml:"ldaps"`
	Insecure bool   `yaml:"insecure"`
	Socks    string `yaml:"socks"`
	Timeout  int32  `yaml:"timeout"`
	Backend  string `yaml:"backend"`

	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Passfile string `yaml:"passfile"`
	Domain   string `yaml:"domain"`
	Hash     string `yaml:"hash"`
	Hashfile string `yaml:"hashfile"`
	Kerberos bool   `yaml:"kerberos"`
	Kdc      string `yaml:"kdc"`
	Crt      string `yaml:"crt"`
	Key      string `yaml:"key"`
	Pfx      string `yaml:"pfx"`

	RootDN  string `yaml:"root_dn"`
	Filter  string `yaml:"filter"`
	Paging  uint32 `yaml:"paging"`
	Schema  bool   `yaml:"schema"`
	Deleted bool   `yaml:"deleted"`

	SSH SSHTunnelConfig `yaml:"ssh"`
}

// GlobalConfig holds TUI behavior settings that apply across all connections.
type GlobalConfig struct {
	Emojis    bool   `yaml:"emojis"`
	Colors    bool   `yaml:"colors"`
	Format    bool   `yaml:"format"`
	Expand    bool   `yaml:"expand"`
	Limit     int    `yaml:"limit"`
	Cache     bool   `yaml:"cache"`
	AttrSort  string `yaml:"attrsort"`
	TimeFmt   string `yaml:"timefmt"`
	Offset    int    `yaml:"offset"`
	ExportDir string `yaml:"exportdir"`
	DebugLog  string `yaml:"debug_log"`
}

// Config is the top-level config file structure.
type Config struct {
	DefaultConnection string             `yaml:"default_connection"`
	Global            GlobalConfig       `yaml:"global"`
	Connections       []ConnectionConfig `yaml:"connections"`
}

// Load reads and parses a YAML config file at path. Global fields are
// pre-initialized to the same defaults as the cobra flags so that omitting
// a field in the file is equivalent to not having a config file at all.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	cfg := Config{
		Global: GlobalConfig{
			Emojis:    true,
			Colors:    true,
			Format:    true,
			Expand:    true,
			Limit:     20,
			Cache:     true,
			AttrSort:  "none",
			ExportDir: "data",
		},
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	return &cfg, nil
}

// FindConfigFile searches standard config locations in precedence order and
// returns the first path that exists. Returns ("", false) if none found.
func FindConfigFile() (string, bool) {
	for _, p := range configFileCandidates() {
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}

func configFileCandidates() []string {
	paths := []string{"godap.yaml"}

	var userCfg string
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			userCfg = filepath.Join(appdata, "godap", "config.yaml")
		}
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			userCfg = filepath.Join(home, ".config", "godap", "config.yaml")
		}
	}
	if userCfg != "" {
		paths = append(paths, userCfg)
	}
	return paths
}

// FindConnection looks up a connection by name. Returns nil if not found.
func (c *Config) FindConnection(name string) *ConnectionConfig {
	for i := range c.Connections {
		if c.Connections[i].Name == name {
			return &c.Connections[i]
		}
	}
	return nil
}

// DefaultConn returns the connection to use based on default_connection and
// the order of the connections list. Returns nil if no connections exist.
func (c *Config) DefaultConn() *ConnectionConfig {
	if len(c.Connections) == 0 {
		return nil
	}
	if c.DefaultConnection != "" {
		if conn := c.FindConnection(c.DefaultConnection); conn != nil {
			return conn
		}
	}
	return &c.Connections[0]
}

// SampleConfig is a fully documented sample configuration file printed by
// the `init-config` subcommand.
const SampleConfig = `# godap configuration file
#
# Locations (first found wins):
#   ./godap.yaml                         current directory
#   ~/.config/godap/config.yaml          Linux/macOS user config
#   %APPDATA%\godap\config.yaml          Windows user config
#
# Generate this file:
#   godap init-config > ~/.config/godap/config.yaml

# default_connection names the connection to use when --connection is not
# given on the command line. If omitted, the first entry in connections is used.
default_connection: my-server

# global contains TUI behavior settings that apply to all connections.
global:
  emojis: true        # prefix objects with emojis
  colors: true        # colorize objects in the tree
  format: true        # format attributes into human-readable values
  expand: true        # expand multi-value attributes
  limit: 20           # max attribute values shown when expand is true
  cache: true         # keep loaded entries in memory (no re-query)
  attrsort: none      # sort attributes by name: none, asc, or desc
  timefmt: ""         # timestamp format: EU (default), US, ISO8601, or Go layout
  offset: 0           # hours to add to formatted timestamps
  exportdir: data     # directory for Ctrl+S exports
  debug_log: ""       # path to debug log file (empty = disabled)

connections:
  - name: my-server
    # Server address. Can also be given as the first positional argument on the
    # command line, which takes precedence over this value.
    server: dc01.corp.example.com

    port: 0           # 0 = auto (389 for plain LDAP, 636 for LDAPS)
    ldaps: false      # use LDAPS for the initial connection
    insecure: false   # skip TLS certificate verification (LDAPS/StartTLS)
    socks: ""         # SOCKS5 proxy address, e.g. socks5://127.0.0.1:1080
    timeout: 10       # connection timeout in seconds
    backend: msad     # LDAP backend: msad (Microsoft AD), basic, or auto

    # Authentication — use exactly one of the following credential methods,
    # or omit all for an anonymous bind.
    username: CORP\jsmith
    # password: s3cr3t
    # WARNING: Storing passwords in config files is a security risk.
    # Use passfile, the GODAP_PASSWD environment variable, or interactive
    # prompting (omit both password and passfile when username is set).
    passfile: ""      # path to a file containing the password (or - for stdin)
    domain: CORP      # domain for NTLM / Kerberos authentication
    hash: ""          # NTLM hash (alternative to password)
    hashfile: ""      # path to a file containing the NTLM hash (or - for stdin)
    kerberos: false   # use Kerberos ticket from KRB5CCNAME env var
    kdc: ""           # KDC address (only if different from server)
    crt: ""           # path to certificate file for certificate-based bind
    key: ""           # path to private key file for certificate-based bind
    pfx: ""           # path to PFX/PKCS#12 file for certificate-based bind

    # Query defaults
    root_dn: ""                  # initial root DN (auto-detected when empty)
    filter: "(objectClass=*)"    # initial LDAP search filter
    paging: 800                  # paging size for LDAP queries
    schema: false                # load schema GUIDs from server at startup
    deleted: false               # include deleted objects in queries (msad only)

    # SSH tunnel — set host to enable the tunnel
    ssh:
      host: ""              # SSH server hostname or IP
      port: 22              # SSH server port
      user: ""              # SSH username (defaults to $USER when empty)
      # password: s3cr3t
      # WARNING: Storing passwords in config files is a security risk.
      passfile: ""          # path to SSH password file (or - for stdin)
      agent: false          # use SSH agent (mutually exclusive with key/password)
      key: ""               # path to SSH private key file
      key_passphrase: ""    # passphrase for the SSH private key
      ignore_host_key: false  # skip SSH host key verification (insecure)

  # Minimal second connection example
  - name: dev-ldap
    server: ldap.dev.internal
    port: 389
    backend: basic
    username: cn=admin,dc=dev,dc=internal
    root_dn: dc=dev,dc=internal
`
