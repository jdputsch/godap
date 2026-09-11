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
	"golang.org/x/term"
)

// validateFlagSet checks the auth-related flags for known-nonsensical
// combinations. It intentionally does not try to enforce "exactly one
// acceptable set" via a flat list of disjoint flag-name sets (the
// pre-migration algorithm) - the new design has --kerberos legitimately
// combine with --password/--hash/--aes-key, which are supersets of each
// other in exactly the way that approach can't represent without producing
// false "mixed flags" errors. See resolveAuthMode below for the actual
// precedence resolution; this function only rejects combinations that can
// never resolve to anything sensible, regardless of precedence.
func validateFlagSet(cmd *cobra.Command) error {
	changed := func(name string) bool { return cmd.Flags().Changed(name) }

	hasCert := changed("crt") || changed("key") || changed("pfx")
	if changed("crt") != changed("key") {
		return fmt.Errorf("invalid authentication flags: --crt and --key must be given together")
	}
	if hasCert && changed("pfx") && (changed("crt") || changed("key")) {
		return fmt.Errorf("invalid authentication flags: --crt/--key and --pfx are mutually exclusive")
	}

	if changed("password") && changed("passfile") {
		return fmt.Errorf("invalid authentication flags: --password and --passfile are mutually exclusive")
	}
	if changed("hash") && changed("hashfile") {
		return fmt.Errorf("invalid authentication flags: --hash and --hashfile are mutually exclusive")
	}

	if changed("simple") {
		if changed("kerberos") || changed("hash") || changed("hashfile") || changed("aes-key") || hasCert {
			return fmt.Errorf("invalid authentication flags: --simple only makes sense with " +
				"-u/--username and -p/--password (or --passfile), not with --kerberos, --hash/--hashfile, " +
				"--aes-key, or a client certificate")
		}
	}

	if changed("aes-key") && !changed("kerberos") {
		return fmt.Errorf("invalid authentication flags: --aes-key requires -k/--kerberos")
	}

	credentialFlagsGiven := 0
	for _, name := range []string{"password", "passfile", "hash", "hashfile", "aes-key"} {
		if changed(name) {
			credentialFlagsGiven++
		}
	}
	if changed("kerberos") && credentialFlagsGiven > 1 {
		fmt.Fprintf(log.Writer(),
			"warning: multiple credential flags given with --kerberos; using precedence "+
				"aes-key > hash/hashfile > password/passfile > ccache (see resolveAuthMode)\n")
	}
	if !changed("kerberos") && (changed("password") || changed("passfile")) && (changed("hash") || changed("hashfile")) {
		fmt.Fprintf(log.Writer(),
			"warning: both a password and a hash given; using precedence hash/hashfile > password/passfile (NTLM)\n")
	}

	if (changed("password") || changed("passfile")) && !changed("username") {
		return fmt.Errorf("invalid authentication flags: -p/--password or --passfile requires -u/--username")
	}
	if (changed("hash") || changed("hashfile")) && !changed("username") {
		return fmt.Errorf("invalid authentication flags: -H/--hash or --hashfile requires -u/--username")
	}
	if changed("aes-key") && !changed("username") {
		return fmt.Errorf("invalid authentication flags: --aes-key requires -u/--username")
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "godap [server address | connection name]",
		Short: "A complete TUI for LDAP.",
		Long: `A complete TUI for LDAP.

The positional argument selects the server to connect to. When a config file
is present, it is first checked as a named connection; if no match is found it
is treated as a server address. Omit it entirely to use the default connection
from the config file, or rely on -d/--domain for DC auto-discovery.`,
		Args: cobra.RangeArgs(0, 1),
		Run: func(cmd *cobra.Command, args []string) {
			// Load config file and resolve connection — must happen before any env var,
			// prompt, or inference that depends on connection values.
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
				} else if len(args) == 1 {
					// Positional arg: try as a connection name first, fall back to server address.
					conn = cfg.FindConnection(args[0])
					if conn == nil {
						tui.LdapServer = args[0]
					}
				} else { // len(args) == 0
					conn = cfg.DefaultConn()
				}
				if conn != nil {
					applyConnectionConfig(cmd, conn)
				}
				applyGlobalConfig(cmd, &cfg.Global)
			} else if len(args) == 1 {
				// No config file: positional arg is a server address.
				tui.LdapServer = args[0]
			}

			if tui.LdapServer == "" && tui.DomainName == "" && !domainInUsername(tui.LdapUsername) {
				log.Fatalf("target host is required (or -d/--domain / a domain-qualified -u/--username, " +
					"to discover a domain controller automatically)")
			}

			// Apply GODAP_PASSWD env var when no explicit password flag was provided.
			if !cmd.Flags().Changed("password") && !cmd.Flags().Changed("passfile") {
				if envPw := os.Getenv("GODAP_PASSWD"); envPw != "" {
					tui.LdapPassword = envPw
					tui.LdapPasswordFile = "" // env var supersedes config passfile
				}
			}

			if err := validateFlagSet(cmd); err != nil {
				log.Fatal(err)
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

			// Apply GODAP_SSH_PASSWORD env var when no explicit SSH password flag was provided.
			if !cmd.Flags().Changed("ssh-password") && !cmd.Flags().Changed("ssh-passfile") {
				if envPw := os.Getenv("GODAP_SSH_PASSWORD"); envPw != "" {
					tui.SSHTunnelPassword = envPw
				}
			}

			// Read SSH passfile from CLI flag or config-supplied path.
			if cmd.Flags().Changed("ssh-passfile") || tui.SSHTunnelPasswordFile != "" {
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
	rootCmd.Flags().StringVarP(&tui.DomainName, "domain", "d", "", "Domain for NTLM / Kerberos authentication, or for DC discovery when the target is omitted")
	rootCmd.Flags().StringVarP(&tui.NtlmHash, "hash", "H", "", "NTLM hash")
	rootCmd.Flags().StringVarP(&tui.AESKey, "aes-key", "", "", "Kerberos AES128/AES256 key (hex-encoded); requires --kerberos")
	rootCmd.Flags().BoolVarP(&tui.SimpleBind, "simple", "", false, "Force a simple LDAP bind for -u/-p instead of the default NTLM")
	rootCmd.Flags().BoolVarP(&tui.Kerberos, "kerberos", "k", false, "Use Kerberos authentication - combine with -p/-H/--aes-key for AS-REQ, --crt/--key/--pfx for PKINIT, or alone for CCACHE (via KRB5CCNAME)")
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
	rootCmd.Flags().StringVarP(&tui.SocksServer, "socks", "x", "", "Use a SOCKS proxy for the LDAP connection and all Kerberos KDC traffic")
	rootCmd.Flags().StringVarP(&tui.KdcHost, "kdc", "", "", "Address of the KDC to use with Kerberos authentication (optional: only if the KDC differs from the specified LDAP server)")
	rootCmd.Flags().StringVarP(&tui.CustomDNS, "dns", "", "", "Custom DNS resolver IP[:port] for DC discovery and SPN/hostname lookups")
	rootCmd.Flags().BoolVarP(&tui.ForceDNSTCP, "dns-tcp", "", false, "Force DNS queries over TCP instead of UDP")
	rootCmd.Flags().BoolVarP(&tui.NoProxyDNS, "no-proxy-dns", "", false, "Do not route DNS queries through the SOCKS5 proxy (only relevant with -x/--socks)")
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

// domainInUsername reports whether u already carries a domain (user@domain or
// DOMAIN\user), which is enough to attempt DC discovery even without -d.
func domainInUsername(u string) bool {
	for _, r := range u {
		if r == '@' || r == '\\' {
			return true
		}
	}
	return false
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
