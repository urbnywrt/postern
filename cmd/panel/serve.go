package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/urbnywrt/postern/internal/panel/auth"
	"github.com/urbnywrt/postern/internal/panel/nodes"
	"github.com/urbnywrt/postern/internal/panel/selfupdate"
	"github.com/urbnywrt/postern/internal/panel/server"
	"github.com/urbnywrt/postern/internal/version"
)

// The environment of the serve command. An empty value is as good as none, since
// docker compose passes a variable that was not set as an empty one.
const (
	envData      = "POSTERN_DATA"            // the data directory: the database, backups, downloaded engines
	envKeys      = "POSTERN_KEYS"            // the directory of the master key
	envListen    = "POSTERN_LISTEN"          // the address to listen on
	envProxies   = "POSTERN_TRUSTED_PROXIES" // the peers whose X-Forwarded-For and X-Forwarded-Proto are believed
	envHealthy   = "POSTERN_HEALTHY_FILE"    // the marker for deploy/panel/launcher.sh
	envNodeKit   = "POSTERN_NODE_KIT_DIR"    // the node kit that the panel serves for manual installs
	envGeoIP     = "POSTERN_GEOIP_BASE_URL"  // where the country database is downloaded from, instead of DB-IP
	envPublic    = "POSTERN_PUBLIC_PAGE"     // "off" serves the admin on every host and the public page on none
	envGitHub    = "POSTERN_GITHUB_API"      // the API of GitHub that the release catalog polls; its default when empty
	envNodeImage = "POSTERN_NODE_IMAGE"      // the node image of the one-command install; version.NodeImage when empty
	defaultData  = "/data"
	defaultKeys  = "/keys"
)

// configFromEnv reads the configuration of the panel from the environment, as
// getenv gives it. Defaults are those of the Docker image.
func configFromEnv(getenv func(string) string) (server.Config, error) {
	value := func(name, fallback string) string {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return v
		}
		return fallback
	}
	cfg := server.Config{
		DataDir:     value(envData, defaultData),
		KeysDir:     value(envKeys, defaultKeys),
		Listen:      value(envListen, server.DefaultListen),
		HealthyFile: value(envHealthy, ""),
		NodeKitDir:  value(envNodeKit, nodes.DefaultKitDir),

		GeoIPBaseURL: value(envGeoIP, ""),
		ReleasesAPI:  value(envGitHub, ""),
	}

	if err := checkListen(cfg.Listen); err != nil {
		return server.Config{}, fmt.Errorf("%s=%q: %w", envListen, cfg.Listen, err)
	}
	image, err := nodeImageFromEnv(value(envNodeImage, ""))
	if err != nil {
		return server.Config{}, err
	}
	cfg.NodeImage = image
	if err := checkBaseURL(cfg.GeoIPBaseURL); err != nil {
		return server.Config{}, fmt.Errorf("%s=%q: %w", envGeoIP, shownBase(cfg.GeoIPBaseURL), err)
	}
	switch public := strings.ToLower(value(envPublic, "on")); public {
	case "on":
	case "off":
		cfg.PublicPageOff = true
	default:
		return server.Config{}, fmt.Errorf("%s=%q: it must be on or off", envPublic, public)
	}

	// A list of nothing but separators says nothing, and is the default.
	list := value(envProxies, auth.DefaultTrustedProxies)
	proxies, err := auth.ParseTrustedProxies(list)
	if err != nil {
		return server.Config{}, fmt.Errorf("%s: %w", envProxies, err)
	}
	if len(proxies) == 0 {
		proxies, _ = auth.ParseTrustedProxies(auth.DefaultTrustedProxies)
	}
	cfg.TrustedProxies = proxies
	return cfg, nil
}

// nodeImageFromEnv is the node image that the panel installs nodes from:
// POSTERN_NODE_IMAGE, given as env, or else the default of the build,
// version.NodeImage, resolved with the version of the panel
// (nodes.ResolveNodeImage). Empty means none. A reference that is not one is
// an error, which names POSTERN_NODE_IMAGE either way. A reference without a
// tag in a build whose version cannot be a tag is none: runServe warns of it
// (warnNodeImage).
func nodeImageFromEnv(env string) (string, error) {
	ref := configuredNodeImage(env)
	image, err := nodes.ResolveNodeImage(ref, version.Version)
	switch {
	case err != nil && env != "":
		return "", fmt.Errorf("%s=%q: %w", envNodeImage, env, err)
	case err != nil:
		return "", fmt.Errorf("the node image of this build, %q: %w; set %s to one that is", ref, err, envNodeImage)
	}
	return image, nil
}

// configuredNodeImage is the node image reference as it is configured:
// POSTERN_NODE_IMAGE, given as env, or else the default of the build.
func configuredNodeImage(env string) string {
	if env != "" {
		return env
	}
	return strings.TrimSpace(version.NodeImage)
}

// warnNodeImage logs, once at the start, that the configured node image has no
// tag and the version of the panel cannot be one, so that the panel offers no
// one-command install of nodes.
func warnNodeImage(log *slog.Logger, env string) {
	if ref := configuredNodeImage(env); nodes.NodeImageNeedsTag(ref, version.Version) {
		log.Warn("no one-command install of nodes: the node image has no tag and the version of the panel cannot be one; set "+
			envNodeImage+" to the image with an explicit tag", "image", ref, "version", version.Version)
	}
}

// checkListen reports what is wrong with an address to listen on: it is host:port
// or :port, with a port from 0 to 65535 written in digits.
func checkListen(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("it must be host:port, or :port to listen on every interface: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || strings.TrimLeft(port, "0123456789") != "" {
		return fmt.Errorf("the port must be a number from 0 to 65535")
	}
	return nil
}

// checkBaseURL reports what is wrong with the address that the country database
// is downloaded from: it is the address of a directory that the files are in,
// http or https, and it carries no user name or password (the address is kept
// in the open and shows in messages; a mirror that asks for a secret is asked
// for it some other way). Empty is the address of DB-IP. What it says never
// repeats the address: see shownBase.
func checkBaseURL(base string) error {
	if base == "" {
		return nil
	}
	u, err := url.Parse(base)
	if err != nil {
		var bad *url.Error
		if errors.As(err, &bad) {
			err = bad.Err // the reason, without the address
		}
		return fmt.Errorf("it must be an http:// or https:// address: %w", err)
	}
	if u.User != nil {
		return errors.New("it must not carry a user name or password")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("it must be an http:// or https:// address of the directory that the files are in")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("it must be the address of a directory, with no query and no fragment")
	}
	return nil
}

// shownBase is the address as a message may repeat it: as it is, unless it may
// carry a user name or a password (an "@" in it, or a user in what is read of it)
// or cannot be read, when it is left out.
func shownBase(base string) string {
	if u, err := url.Parse(base); err != nil || u.User != nil || strings.Contains(base, "@") {
		return "(the address is left out: it may carry a user name or a password)"
	}
	return base
}

// runServe is the serve command: it runs the panel until ctx is done, which is
// when the process is told to stop, and returns the exit status of the process:
// 0 after a stop that was asked for, 1 when the panel could not start or had to
// stop, 2 for arguments or a configuration that cannot be used, and 75
// (selfupdate.ExitRestart) when the panel installed a new version of itself, or
// found a newer image binary than the one it runs from the data volume: the
// launcher then starts what bin/current says.
//
// Before the database is opened, selfupdate.Recover settles what the last
// update left: after a rollback by the launcher it puts the snapshot of the
// database back when the failed version migrated it.
//
// What the panel has to say to the operator goes to stdout (the URL of the first
// setup), the log, one line per record and never a secret, to stderr.
func runServe(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		_, _ = fmt.Fprint(stderr, "postern-panel: serve takes no arguments; it is configured by environment variables\n\n")
		usage(stderr)
		return 2
	}
	cfg, err := configFromEnv(getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-panel: %v\n", err)
		return 2
	}

	log := slog.New(slog.NewTextHandler(stderr, nil))
	// The store logs through the default logger.
	previous := slog.Default()
	slog.SetDefault(log)
	defer slog.SetDefault(previous)
	cfg.Log = log
	warnNodeImage(log, strings.TrimSpace(getenv(envNodeImage)))
	cfg.Out = stdout

	log.Info("postern-panel is starting", "version", version.String(),
		"data", cfg.DataDir, "keys", cfg.KeysDir, "listen", cfg.Listen, "trusted_proxies", fmt.Sprint(cfg.TrustedProxies))
	recovered, err := selfupdate.Recover(cfg.DataDir, version.Version, log)
	if errors.Is(err, selfupdate.ErrRestart) {
		return selfupdate.ExitRestart
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-panel: %v\n", err)
		return 1
	}
	cfg.Recovered = recovered
	srv, err := server.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "postern-panel: %v\n", err)
		return 1
	}
	if err := srv.ListenAndServe(ctx); err != nil {
		if errors.Is(err, selfupdate.ErrRestart) {
			log.Info("postern-panel exits to restart into its new version", "status", selfupdate.ExitRestart, "detail", err.Error())
			return selfupdate.ExitRestart
		}
		_, _ = fmt.Fprintf(stderr, "postern-panel: %v\n", err)
		return 1
	}
	return 0
}
