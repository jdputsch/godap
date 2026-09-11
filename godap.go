package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Macmod/godap/v2/pkg/config"
	"github.com/Macmod/godap/v2/pkg/debug"
	"github.com/Macmod/godap/v2/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var acceptableAuthFlagSets = []map[string]bool{
	{"username": true},
	{"username": true, "password": true},
	{"username": true, "passfile": true},
	{"username": true, "hash": true},
	{"username": true, "hashfile": true},
	{"kerberos": true},
	{"crt": true, "key": true},
	{"pfx": true},
}

func validateFlagSet(cmd *cobra.Command) error {
	used := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) {
		used[f.Name] = true
	})

	matches := 0
	partials := 0

	for _, candidateSet := range acceptableAuthFlagSets {
		if containsAll(used, candidateSet) {
			if matches > 0 {
				return fmt.Errorf("Invalid authentication flags: mixed flags from multiple acceptable sets\nPlease use only one of {-u,-p},{-u,--passfile},{-u,-H},{-u,--hashfile},{-k},{--crt,--key},{--pfx}\nor none of these for anonymous binds.")
			}
			matches++
		} else if intersects(used, candidateSet) {
			partials++
		}
	}

	if matches == 0 && partials > 0 {
		return fmt.Errorf("Invalid authentication flags: missing required flags\nPlease use only one of {-u,-p},{-u,--passfile},{-u,-H},{-u,--hashfile},{-k},{--crt,--key},{--pfx}\nor none of these for anonymous binds.")
	}

	return nil
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, "--"+k)
	}
	return out
}

func containsAll(provided, required map[string]bool) bool {
	for k := range required {
		if !provided[k] {
			return false
		}
	}
	return true
}

func intersects(setA, setB map[string]bool) bool {
	for k := range setA {
		if setB[k] {
			return true
		}
	}
	return false
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "godap [server address | connection name]",
		Short: "A complete TUI for LDAP.",
		Long: `A complete TUI for LDAP.

The positional argument selects the server to connect to. When a config file
is present, it is first checked as a named connection; if no match is found it
is treated as a server address. Omit it entirely to use the default connection
from the config file.`,
		Args: cobra.RangeArgs(0, 1),
		Run: func(cmd *cobra.Command, args []string) {
			// Load config file and apply values for flags not explicitly set on CLI.
			var cfg *config.Config
			var cfgPath string
			if cmd.Flags().Changed("config") {
				cfgPath = tui.ConfigFile
			} else {
				cfgPath, _ = config.FindConfigFile()
			}
			if cfgPath != "" {
				var err error
				cfg, err = config.Load(cfgPath)
				if err != nil {
					log.Fatalf("Config file error: %v", err)
				}
				var conn *config.ConnectionConfig
				if cmd.Flags().Changed("connection") {
					conn = cfg.FindConnection(tui.ConnectionName)
					if conn == nil {
						log.Fatalf("Config: connection %q not found in %s", tui.ConnectionName, cfgPath)
					}
				} else if len(args) == 0 {
					conn = cfg.DefaultConn()
				}
				if conn != nil {
					applyConnectionConfig(cmd, conn)
				}
				applyGlobalConfig(cmd, &cfg.Global)
			}

			// Apply GODAP_PASSWD env var when no explicit password flag was provided.
			if !cmd.Flags().Changed("password") && !cmd.Flags().Changed("passfile") {
				if envPw := os.Getenv("GODAP_PASSWD"); envPw != "" {
					tui.LdapPassword = envPw
				}
			}

			err := validateFlagSet(cmd)
			if err != nil {
				log.Fatalf(fmt.Sprint(err))
			}

			// Prompt for LDAP password when username is set but no password method was provided.
			if tui.LdapUsername != "" &&
				tui.LdapPassword == "" &&
				tui.LdapPasswordFile == "" &&
				tui.NtlmHash == "" &&
				tui.NtlmHashFile == "" &&
				!tui.Kerberos &&
				tui.CertFile == "" &&
				tui.PfxFile == "" {
				fmt.Print("LDAP Password: ")
				passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					log.Fatalf("Failed to read password: %v", err)
				}
				tui.LdapPassword = string(passwordBytes)
			}

			if len(args) == 1 && !cmd.Flags().Changed("connection") {
				// When --connection was not explicitly set, check whether the positional
				// arg names a config connection; fall back to treating it as a server address.
				if cfg != nil {
					if conn := cfg.FindConnection(args[0]); conn != nil {
						applyConnectionConfig(cmd, conn)
					} else {
						tui.LdapServer = args[0]
					}
				} else {
					tui.LdapServer = args[0]
				}
			} else if tui.LdapServer == "" {
				log.Fatal("No server address provided. Specify a server address, a config connection name, or set a default connection in the config file.")
			}

			// Apply GODAP_SSH_PASSWORD env var when no explicit SSH password flag was provided.
			if !cmd.Flags().Changed("ssh-password") && !cmd.Flags().Changed("ssh-passfile") {
				if envPw := os.Getenv("GODAP_SSH_PASSWORD"); envPw != "" {
					tui.SSHTunnelPassword = envPw
				}
			}

			// --ssh-passfile: read password from file or prompt on "-".
			if cmd.Flags().Changed("ssh-passfile") {
				pw, err := tui.ReadFileOrStdin(tui.SSHTunnelPasswordFile, "SSH Password: ")
				if err != nil {
					log.Fatalf("Failed to read SSH password file: %v", err)
				}
				tui.SSHTunnelPassword = strings.TrimSpace(pw)
			}

			// Infer SSH auth method from flags; explicit --ssh-auth is honoured only as a fallback.
			sshAgentSet := tui.SSHTunnelAgentAuth
			sshKeySet := cmd.Flags().Changed("ssh-key") || tui.SSHTunnelKeyFile != ""
			sshPassSet := tui.SSHTunnelPassword != ""
			switch {
			case sshAgentSet && sshKeySet:
				log.Fatal("Conflicting SSH auth flags: --ssh-agent and --ssh-key cannot both be set")
			case sshAgentSet && sshPassSet:
				log.Fatal("Conflicting SSH auth flags: --ssh-agent and --ssh-password/--ssh-passfile cannot both be set")
			case sshKeySet && sshPassSet:
				log.Fatal("Conflicting SSH auth flags: --ssh-key and --ssh-password/--ssh-passfile cannot both be set")
			case sshAgentSet:
				tui.SSHTunnelAuthMethod = "agent"
			case sshKeySet:
				tui.SSHTunnelAuthMethod = "key"
			case sshPassSet:
				tui.SSHTunnelAuthMethod = "password"
			}

			if tui.LdapPort == 0 {
				if tui.Ldaps {
					tui.LdapPort = 636
				} else {
					tui.LdapPort = 389
				}
			}

			// A non-empty --ssh-host implicitly enables the tunnel.
			if tui.SSHTunnelHost != "" {
				tui.SSHTunnelEnabled = true
			}

			// Initialize debug log if requested.
			if tui.DebugLogPath != "" {
				if err := debug.Init(tui.DebugLogPath); err != nil {
					log.Printf("Warning: could not open debug log %q: %v", tui.DebugLogPath, err)
				} else {
					defer debug.Close()
				}
			}

			tui.SetupApp()
		},
	}

	rootCmd.Flags().IntVarP(&tui.LdapPort, "port", "P", 0, "LDAP server port")
	rootCmd.Flags().StringVarP(&tui.LdapUsername, "username", "u", "", "LDAP username")
	rootCmd.Flags().StringVarP(&tui.LdapPassword, "password", "p", "", "LDAP password")
	rootCmd.Flags().StringVarP(&tui.LdapPasswordFile, "passfile", "", "", "Path to a file containing the LDAP password (or - for stdin)")
	rootCmd.Flags().StringVarP(&tui.DomainName, "domain", "d", "", "Domain for NTLM / Kerberos authentication")
	rootCmd.Flags().StringVarP(&tui.NtlmHash, "hash", "H", "", "NTLM hash")
	rootCmd.Flags().BoolVarP(&tui.Kerberos, "kerberos", "k", false, "Use Kerberos ticket for authentication (CCACHE specified via KRB5CCNAME environment variable)")
	rootCmd.Flags().StringVarP(&tui.TargetSpn, "spn", "t", "", "Target SPN to use for Kerberos bind (usually ldap/dchostname)")
	rootCmd.Flags().StringVarP(&tui.NtlmHashFile, "hashfile", "", "", "Path to a file containing the NTLM hash (or - for stdin)")
	rootCmd.Flags().StringVarP(&tui.RootDN, "rootDN", "r", "", "Initial root DN")
	rootCmd.Flags().StringVarP(&tui.SearchFilter, "filter", "f", "(objectClass=*)", "Initial LDAP search filter")
	rootCmd.Flags().BoolVarP(&tui.Emojis, "emojis", "E", true, "Prefix objects with emojis")
	rootCmd.Flags().BoolVarP(&tui.Colors, "colors", "C", true, "Colorize objects")
	rootCmd.Flags().BoolVarP(&tui.FormatAttrs, "format", "F", true, "Format attributes into human-readable values")
	rootCmd.Flags().BoolVarP(&tui.ExpandAttrs, "expand", "A", true, "Expand multi-value attributes")
	rootCmd.Flags().IntVarP(&tui.AttrLimit, "limit", "L", 20, "Number of attribute values to render for multi-value attributes when -expand is set true")
	rootCmd.Flags().BoolVarP(&tui.CacheEntries, "cache", "M", true, "Keep loaded entries in memory while the program is open and don't query them again")
	rootCmd.Flags().BoolVarP(&tui.Deleted, "deleted", "D", false, "Include deleted objects in all queries performed")
	rootCmd.Flags().Int32VarP(&tui.Timeout, "timeout", "T", 10, "Timeout for LDAP connections in seconds")
	rootCmd.Flags().BoolVarP(&tui.LoadSchema, "schema", "s", false, "Load schema GUIDs from the LDAP server during initialization")
	rootCmd.Flags().Uint32VarP(&tui.PagingSize, "paging", "G", 800, "Default paging size for regular queries")
	rootCmd.Flags().BoolVarP(&tui.Insecure, "insecure", "I", false, "Skip TLS verification for LDAPS/StartTLS")
	rootCmd.Flags().BoolVarP(&tui.Ldaps, "ldaps", "S", false, "Use LDAPS for initial connection")
	rootCmd.Flags().StringVarP(&tui.SocksServer, "socks", "x", "", "Use a SOCKS proxy for initial connection")
	rootCmd.Flags().StringVarP(&tui.KdcHost, "kdc", "", "", "Address of the KDC to use with Kerberos authentication (optional: only if the KDC differs from the specified LDAP server)")
	rootCmd.Flags().StringVarP(&tui.TimeFormat, "timefmt", "", "", "Time format for LDAP timestamps")
	rootCmd.Flags().StringVarP(&tui.CertFile, "crt", "", "", "Path to a file containing the certificate to use for the bind")
	rootCmd.Flags().StringVarP(&tui.KeyFile, "key", "", "", "Path to a file containing the private key to use for the bind")
	rootCmd.Flags().StringVarP(&tui.PfxFile, "pfx", "", "", "Path to a file containing the PFX to use for the bind")
	rootCmd.Flags().StringVarP(&tui.AttrSort, "attrsort", "", "none", "Sort attributes by name (none, asc, desc)")
	rootCmd.Flags().IntVarP(&tui.TimeOffset, "offset", "", 0, "Offset in hours to apply to formatted timestamps")
	rootCmd.Flags().StringVarP(&tui.ExportDir, "exportdir", "", "data", "Custom directory to save godap exports taken with Ctrl+S")
	rootCmd.Flags().StringVarP(&tui.BackendFlavor, "backend", "b", "msad", "LDAP backend flavor (msad, basic or auto)")

	// SSH tunnel flags
	rootCmd.Flags().StringVar(&tui.SSHTunnelHost, "ssh-host", "", "SSH tunnel host (also enables the tunnel when non-empty)")
	rootCmd.Flags().IntVar(&tui.SSHTunnelPort, "ssh-port", 22, "SSH tunnel port")
	rootCmd.Flags().StringVar(&tui.SSHTunnelUser, "ssh-user", os.Getenv("USER"), "SSH tunnel username")
	rootCmd.Flags().StringVar(&tui.SSHTunnelAuthMethod, "ssh-auth", "password", "SSH auth method: password, key, or agent (deprecated: inferred automatically from other flags)")
	rootCmd.Flags().StringVar(&tui.SSHTunnelPassword, "ssh-password", "", "SSH tunnel password")
	rootCmd.Flags().StringVar(&tui.SSHTunnelPasswordFile, "ssh-passfile", "", "Path to a file containing the SSH tunnel password (or - for stdin)")
	rootCmd.Flags().BoolVar(&tui.SSHTunnelAgentAuth, "ssh-agent", false, "Use SSH agent for tunnel authentication")
	rootCmd.Flags().StringVar(&tui.SSHTunnelKeyFile, "ssh-key", "", "Path to SSH private key file")
	rootCmd.Flags().StringVar(&tui.SSHTunnelKeyPassphrase, "ssh-key-passphrase", "", "Passphrase for SSH private key")
	rootCmd.Flags().BoolVar(&tui.SSHTunnelInsecure, "ssh-ignore-host-key", false, "Skip SSH host key verification (insecure)")
	rootCmd.Flags().StringVar(&tui.DebugLogPath, "debug-log", "", "Path to debug log file")

	rootCmd.Flags().StringVarP(&tui.ConfigFile, "config", "c", "", "Path to config file (overrides auto-discovery)")
	rootCmd.Flags().StringVar(&tui.ConnectionName, "connection", "", "Named connection to use from config file (overrides default_connection)")

	initConfigCmd := &cobra.Command{
		Use:   "init-config",
		Short: "Print a documented sample config file",
		Long: "Print a documented sample config file to stdout or write it to a file.\n" +
			"Use this to bootstrap your godap configuration:\n\n" +
			"  godap init-config > ~/.config/godap/config.yaml",
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			output, _ := cmd.Flags().GetString("output")
			if output == "" || output == "-" {
				fmt.Print(config.SampleConfig)
				return
			}
			if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
				log.Fatalf("init-config: cannot create directory: %v", err)
			}
			if err := os.WriteFile(output, []byte(config.SampleConfig), 0600); err != nil {
				log.Fatalf("init-config: cannot write file: %v", err)
			}
			fmt.Fprintf(os.Stderr, "Config written to %s\n", output)
		},
	}
	initConfigCmd.Flags().String("output", "", "Write config to FILE instead of stdout (use - for stdout)")

	versionCmd := &cobra.Command{
		Use:                   "version",
		Short:                 "Print the version number of the application",
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(tui.GodapVer)
		},
	}

	rootCmd.AddCommand(initConfigCmd)
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

// applyConnectionConfig writes config connection values into tui globals for
// every connection-related flag that was not explicitly set on the CLI.
func applyConnectionConfig(cmd *cobra.Command, conn *config.ConnectionConfig) {
	if conn.Server != "" {
		tui.LdapServer = conn.Server
	}
	if !cmd.Flags().Changed("port") && conn.Port != 0 {
		tui.LdapPort = conn.Port
	}
	if !cmd.Flags().Changed("ldaps") && conn.Ldaps {
		tui.Ldaps = conn.Ldaps
	}
	if !cmd.Flags().Changed("insecure") && conn.Insecure {
		tui.Insecure = conn.Insecure
	}
	if !cmd.Flags().Changed("socks") && conn.Socks != "" {
		tui.SocksServer = conn.Socks
	}
	if !cmd.Flags().Changed("timeout") && conn.Timeout != 0 {
		tui.Timeout = conn.Timeout
	}
	if !cmd.Flags().Changed("backend") && conn.Backend != "" {
		tui.BackendFlavor = conn.Backend
	}
	if !cmd.Flags().Changed("username") && conn.Username != "" {
		tui.LdapUsername = conn.Username
	}
	if !cmd.Flags().Changed("password") && conn.Password != "" {
		tui.LdapPassword = conn.Password
	}
	if !cmd.Flags().Changed("passfile") && conn.Passfile != "" {
		tui.LdapPasswordFile = conn.Passfile
	}
	if !cmd.Flags().Changed("domain") && conn.Domain != "" {
		tui.DomainName = conn.Domain
	}
	if !cmd.Flags().Changed("hash") && conn.Hash != "" {
		tui.NtlmHash = conn.Hash
	}
	if !cmd.Flags().Changed("hashfile") && conn.Hashfile != "" {
		tui.NtlmHashFile = conn.Hashfile
	}
	if !cmd.Flags().Changed("kerberos") && conn.Kerberos {
		tui.Kerberos = conn.Kerberos
	}
	if !cmd.Flags().Changed("spn") && conn.Spn != "" {
		tui.TargetSpn = conn.Spn
	}
	if !cmd.Flags().Changed("kdc") && conn.Kdc != "" {
		tui.KdcHost = conn.Kdc
	}
	if !cmd.Flags().Changed("crt") && conn.Crt != "" {
		tui.CertFile = conn.Crt
	}
	if !cmd.Flags().Changed("key") && conn.Key != "" {
		tui.KeyFile = conn.Key
	}
	if !cmd.Flags().Changed("pfx") && conn.Pfx != "" {
		tui.PfxFile = conn.Pfx
	}
	if !cmd.Flags().Changed("rootDN") && conn.RootDN != "" {
		tui.RootDN = conn.RootDN
	}
	if !cmd.Flags().Changed("filter") && conn.Filter != "" {
		tui.SearchFilter = conn.Filter
	}
	if !cmd.Flags().Changed("paging") && conn.Paging != 0 {
		tui.PagingSize = conn.Paging
	}
	if !cmd.Flags().Changed("schema") && conn.Schema {
		tui.LoadSchema = conn.Schema
	}
	if !cmd.Flags().Changed("deleted") && conn.Deleted {
		tui.Deleted = conn.Deleted
	}
	if !cmd.Flags().Changed("ssh-host") && conn.SSH.Host != "" {
		tui.SSHTunnelHost = conn.SSH.Host
	}
	if !cmd.Flags().Changed("ssh-port") && conn.SSH.Port != 0 {
		tui.SSHTunnelPort = conn.SSH.Port
	}
	if !cmd.Flags().Changed("ssh-user") && conn.SSH.User != "" {
		tui.SSHTunnelUser = conn.SSH.User
	}
	if !cmd.Flags().Changed("ssh-password") && conn.SSH.Password != "" {
		tui.SSHTunnelPassword = conn.SSH.Password
	}
	if !cmd.Flags().Changed("ssh-passfile") && conn.SSH.Passfile != "" {
		tui.SSHTunnelPasswordFile = conn.SSH.Passfile
	}
	if !cmd.Flags().Changed("ssh-agent") && conn.SSH.Agent {
		tui.SSHTunnelAgentAuth = conn.SSH.Agent
	}
	if !cmd.Flags().Changed("ssh-key") && conn.SSH.Key != "" {
		tui.SSHTunnelKeyFile = conn.SSH.Key
	}
	if !cmd.Flags().Changed("ssh-key-passphrase") && conn.SSH.KeyPassphrase != "" {
		tui.SSHTunnelKeyPassphrase = conn.SSH.KeyPassphrase
	}
	if !cmd.Flags().Changed("ssh-ignore-host-key") && conn.SSH.IgnoreHostKey {
		tui.SSHTunnelInsecure = conn.SSH.IgnoreHostKey
	}
}

// applyGlobalConfig writes config global values into tui globals for every
// TUI-behavior flag that was not explicitly set on the CLI.
func applyGlobalConfig(cmd *cobra.Command, g *config.GlobalConfig) {
	if !cmd.Flags().Changed("emojis") {
		tui.Emojis = g.Emojis
	}
	if !cmd.Flags().Changed("colors") {
		tui.Colors = g.Colors
	}
	if !cmd.Flags().Changed("format") {
		tui.FormatAttrs = g.Format
	}
	if !cmd.Flags().Changed("expand") {
		tui.ExpandAttrs = g.Expand
	}
	if !cmd.Flags().Changed("limit") && g.Limit != 0 {
		tui.AttrLimit = g.Limit
	}
	if !cmd.Flags().Changed("cache") {
		tui.CacheEntries = g.Cache
	}
	if !cmd.Flags().Changed("attrsort") && g.AttrSort != "" {
		tui.AttrSort = g.AttrSort
	}
	if !cmd.Flags().Changed("timefmt") && g.TimeFmt != "" {
		tui.TimeFormat = g.TimeFmt
	}
	if !cmd.Flags().Changed("offset") && g.Offset != 0 {
		tui.TimeOffset = g.Offset
	}
	if !cmd.Flags().Changed("exportdir") && g.ExportDir != "" {
		tui.ExportDir = g.ExportDir
	}
	if !cmd.Flags().Changed("debug-log") && g.DebugLog != "" {
		tui.DebugLogPath = g.DebugLog
	}
}
