package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const version = "0.1.0-phase1"

func usage() {
	fmt.Printf(`WAMB %s — Win Anti Malware Blocker (ClamAV manager)

Usage:
  wamb init [--config PATH]            write a default config file
  wamb scan [FOLDER...] [options]      scan folders (default: config targets)
  wamb watch [--config PATH]           lightweight real-time scan of changed files
  wamb update [--config PATH]          update signatures (freshclam)
  wamb quarantine list                 list quarantined files
  wamb quarantine restore <id>         restore a quarantined file
  wamb serve [--config PATH]           resident mode: watcher + self-scheduler
  wamb service install|uninstall|start|stop|status [--config PATH]
                                       manage the WAMB Windows service (admin)
  wamb task install [--user] [--config PATH]
  wamb task uninstall                  Task Scheduler insurance jobs (daily
                                       update + scan; SYSTEM unless --user)
  wamb version

Scan options:
  --config PATH          config file (default: %%LOCALAPPDATA%%\WAMB\config.json)
  --level 1|2|3          detection sensitivity (default: config value)
  --exclude-file PATH    never scan this file (repeatable)
  --exclude-dir PATH     never scan this folder (repeatable)
  --quarantine           move detections into the quarantine folder
  --quarantine-dir PATH  quarantine folder (default: config value)
  --notify               notify on detection (Discord webhook, if configured)
  --no-notify            never notify for this run
  --changed              scan only files changed since the last recorded state

Browser cookie/login stores are always covered and cannot be excluded.
Exit codes: 0 = clean, 1 = detections found, 2 = error.
`, version)
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "watch":
		err = cmdWatch(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "quarantine":
		err = cmdQuarantine(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "service":
		err = cmdService(os.Args[2:])
	case "task":
		err = cmdTask(os.Args[2:])
	case "version":
		fmt.Println("WAMB", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wamb:", err)
		os.Exit(2)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file path")
	fs.Parse(args)
	path := configPath(*cfgPath)
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	if err := cfg.Save(path); err != nil {
		return err
	}
	fmt.Println("config written:", path)
	return nil
}

func loadCfg(flagVal string) (*Config, string, error) {
	path := configPath(flagVal)
	cfg, err := LoadConfig(path)
	return cfg, path, err
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "", "")
	level := fs.Int("level", 0, "")
	var exFiles, exDirs multiFlag
	fs.Var(&exFiles, "exclude-file", "")
	fs.Var(&exDirs, "exclude-dir", "")
	quar := fs.Bool("quarantine", false, "")
	quarDir := fs.String("quarantine-dir", "", "")
	notify := fs.Bool("notify", false, "")
	noNotify := fs.Bool("no-notify", false, "")
	changed := fs.Bool("changed", false, "")
	fs.Parse(args)

	cfg, _, err := loadCfg(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wamb:", err)
		return 2
	}
	if *level != 0 {
		if *level < 1 || *level > 3 {
			fmt.Fprintln(os.Stderr, "wamb: --level must be 1..3")
			return 2
		}
		cfg.Level = *level
	}
	cfg.ExcludeFiles = append(cfg.ExcludeFiles, exFiles...)
	cfg.ExcludeDirs = append(cfg.ExcludeDirs, exDirs...)
	if *quarDir != "" {
		cfg.QuarantineDir = *quarDir
	}
	notifyWanted := true
	if *noNotify {
		notifyWanted = false
	}
	if *notify {
		cfg.NotifyOnDetect = true
		notifyWanted = true
	}

	targets := fs.Args()
	if len(targets) == 0 {
		targets = cfg.effectiveTargets()
	}

	release, err := acquireLock(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wamb:", err)
		return 2
	}
	defer release()

	protected := effectiveProtected()
	var rep *Report
	if *changed {
		rep = scanChanged(cfg, targets, protected)
		if rep == nil {
			return 2
		}
	} else {
		rep, err = executeScan(cfg, scanOptions{Targets: targets, Mode: "scan"})
		if err != nil {
			fmt.Fprintln(os.Stderr, "wamb:", err)
			return 2
		}
		if cookies := protectedCookieFiles(protected); len(cookies) > 0 {
			if extra, err := executeScan(cfg, scanOptions{FileList: cookies, Mode: "scan"}); err == nil {
				mergeReport(rep, extra)
			}
		}
		refreshHistory(cfg, targets, protected)
	}

	postProcess(cfg, rep, *quar, notifyWanted)
	printSummary(rep)
	if len(rep.Detections) > 0 {
		return 1
	}
	return 0
}

// scanChanged implements the change-history scan: only files whose size or
// mtime differs from the recorded state are scanned (cookie stores included).
func scanChanged(cfg *Config, targets, protected []string) *Report {
	hist := LoadHistory(cfg.stateFile())
	cur := collectCurrent(cfg, targets, protected)
	for _, cf := range protectedCookieFiles(protected) {
		if st, err := os.Stat(cf); err == nil {
			cur[cf] = FileState{Size: st.Size(), Mtime: st.ModTime().UnixNano()}
		}
	}
	changed := ChangedFiles(hist, cur)
	// New baseline: keep entries outside the scanned targets, replace the rest.
	merged := map[string]FileState{}
	for p, st := range hist.Files {
		merged[p] = st
	}
	for p, st := range cur {
		merged[p] = st
	}
	hist.Files = merged
	_ = hist.Save(cfg.stateFile())

	if len(changed) == 0 {
		rep := &Report{ID: newReportID(time.Now()), Mode: "changed", Level: cfg.Level, Targets: targets}
		rep.StartedAt, rep.EndedAt = time.Now(), time.Now()
		fmt.Println("no changed files since the last recorded state")
		return rep
	}
	rep, err := executeScan(cfg, scanOptions{FileList: changed, Mode: "changed"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "wamb:", err)
		return nil
	}
	return rep
}

// refreshHistory records the current state of the targets after a full scan,
// so a later --changed run has a baseline.
func refreshHistory(cfg *Config, targets, protected []string) {
	hist := LoadHistory(cfg.stateFile())
	cur := collectCurrent(cfg, targets, protected)
	for p, st := range cur {
		hist.Files[p] = st
	}
	_ = hist.Save(cfg.stateFile())
}

func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	cfgPath := fs.String("config", "", "")
	fs.Parse(args)
	cfg, _, err := loadCfg(*cfgPath)
	if err != nil {
		return err
	}
	release, err := acquireLock(cfg)
	if err != nil {
		return err
	}
	defer release()
	return runWatch(cfg)
}

func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	cfgPath := fs.String("config", "", "")
	fs.Parse(args)
	cfg, _, err := loadCfg(*cfgPath)
	if err != nil {
		return err
	}
	release, err := acquireLock(cfg)
	if err != nil {
		return err
	}
	defer release()
	out, err := runUpdate(cfg)
	fmt.Print(out)
	return err
}

func cmdQuarantine(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wamb quarantine list|restore <id> [--config PATH]")
	}
	sub := args[0]
	rest := args[1:]
	cfgPath := ""
	for i := 0; i+1 < len(rest); i++ {
		if rest[i] == "--config" {
			cfgPath = rest[i+1]
		}
	}
	cfg, _, err := loadCfg(cfgPath)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		items, err := ListQuarantine(cfg)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			fmt.Println("quarantine is empty")
			return nil
		}
		for _, m := range items {
			fmt.Printf("%s  %s\n    from: %s\n    sig:  %s  sha256: %s\n",
				m.ID, m.QuarantinedAt.Format("2006-01-02 15:04"), m.OriginalPath, m.Signature, m.SHA256[:16]+"…")
		}
		return nil
	case "restore":
		if len(rest) < 1 {
			return fmt.Errorf("usage: wamb quarantine restore <id>")
		}
		id := rest[0]
		if strings.ContainsAny(id, `/\`) || strings.Contains(id, "..") {
			return fmt.Errorf("invalid quarantine id")
		}
		if err := RestoreQuarantine(cfg, filepath.Clean(id)); err != nil {
			return err
		}
		fmt.Println("restored:", id)
		return nil
	}
	return fmt.Errorf("unknown quarantine subcommand: %s", sub)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "")
	asService := fs.Bool("service", false, "")
	fs.Parse(args)
	path := configPath(*cfgPath)
	if *asService || isWindowsService() {
		return runWindowsService(path)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runServe(cfg, ctx, "")
}

func cmdService(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wamb service install|uninstall|start|stop|status [--config PATH]")
	}
	sub := args[0]
	cfgPath := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--config" {
			cfgPath = args[i+1]
		}
	}
	path := configPath(cfgPath)
	switch sub {
	case "install":
		if err := installService(path); err != nil {
			return err
		}
		fmt.Println("service installed (start it with: wamb service start)")
		return nil
	case "uninstall":
		if err := uninstallService(); err != nil {
			return err
		}
		fmt.Println("service removed")
		return nil
	case "start":
		if err := startService(); err != nil {
			return err
		}
		fmt.Println("service started")
		return nil
	case "stop":
		if err := stopService(); err != nil {
			return err
		}
		fmt.Println("service stopped")
		return nil
	case "status":
		st, err := statusService()
		if err != nil {
			return err
		}
		fmt.Println("WAMB service:", st)
		return nil
	}
	return fmt.Errorf("unknown service subcommand: %s", sub)
}

func cmdTask(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: wamb task install [--user] [--config PATH] | wamb task uninstall")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("task install", flag.ExitOnError)
		cfgPath := fs.String("config", "", "")
		userMode := fs.Bool("user", false, "")
		fs.Parse(args[1:])
		path := configPath(*cfgPath)
		cfg, err := LoadConfig(path)
		if err != nil {
			return err
		}
		if err := installTasks(cfg, path, !*userMode); err != nil {
			return err
		}
		fmt.Println("tasks registered: WAMB Update", cfg.ScheduleUpdate, "/ WAMB Scan", cfg.ScheduleScan)
		return nil
	case "uninstall":
		if err := uninstallTasks(); err != nil {
			return err
		}
		fmt.Println("tasks removed")
		return nil
	}
	return fmt.Errorf("unknown task subcommand: %s", args[0])
}

func printSummary(rep *Report) {
	fmt.Printf("scan %s (%s): %d file(s) scanned, %d detection(s)\n",
		rep.ID, rep.Mode, rep.ScannedFiles, len(rep.Detections))
	for _, d := range rep.Detections {
		fmt.Printf("  FOUND %s (%s)\n", d.Path, d.Signature)
	}
	for _, q := range rep.Quarantined {
		fmt.Println("  quarantined:", q)
	}
	for _, w := range rep.Warnings {
		fmt.Println("  warning:", w)
	}
}
