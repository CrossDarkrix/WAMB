<div align="center">
	<img width="150px" height="150px" alt="WAMB" src="https://raw.githubusercontent.com/CrossDarkrix/WAMB/master/WAMB.png">
</div>

English | [日本語](README_ja.md)

# WAMB — Win Anti Malware Blocker

A lightweight malware-defense manager for Windows built around ClamAV (written in Go, single exe).
It does not replace always-on Defender — it is a second-opinion layer that sits on top of it.

## Features

- **Detection-only by default** — never auto-deletes. Quarantine happens only through an explicit command
- **No clamd** — clamscan is launched per scan, so there is no resident memory footprint
- **Browser cookie / login stores are always monitored** — they cannot be excluded (they are what stealers actually go after)
- **Real-time watch** — detects and scans changes in Downloads / Desktop / browser profiles
- **Changed-files scan** — keeps a size/mtime history and rescans only what changed
- **Resident mode (serve)** — watch plus a self-scheduler (daily signature updates and scans)
- **Windows service** — runs as LocalSystem and automatically expands coverage to every user profile
- **Task Scheduler fallback** — daily jobs keep running even if the service dies
- **Notifications** — Discord webhook plus JSON reports (mirrored to a folder of your choice)
- **Sensitivity levels 1–3** — mapped to clamscan options, with exclusions to keep dev folders quiet

## Requirements

- Windows 10 / 11 (x64)
- [ClamAV for Windows](https://www.clamav.net/downloads) (the portable build is fine; run freshclam once to fetch the databases)

## Build

Bootstrap script (installs Git / Go with winget, then builds.
Add `-WithClamAV` to also fetch ClamAV and its signature databases and generate a starter config):

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1 [-WithClamAV] [-WithABA]
```

With `-WithABA`, the stealer tripwire [a-better-antivirus](https://github.com/vulnix0x4/a-better-antivirus)
— which WAMB is designed to coexist with — is also built from source and installed, and clamscan is
registered in ABA's ignore list. A scanner reads every file by design, which otherwise looks
exactly like a stealer sweep to ABA.

Manual build:

```powershell
go build -o wamb.exe .
```

## Usage (excerpt)

```
wamb scan [folders...] [--level 1-3] [--changed] [--quarantine]
wamb watch                 real-time monitoring
wamb serve                 resident mode (watch + daily scheduler)
wamb update                update signatures
wamb quarantine list|restore <id>
wamb service install|start|stop|status
wamb task install [--user]|uninstall
```

The config lives at `%LOCALAPPDATA%\WAMB\config.json` (when running as a service, pass any path with `--config`).

For design details, see [DESIGN_ja.md](DESIGN_ja.md) (in Japanese).

## License

MIT License — Copyright (c) 2026 CrossDarkrix

ClamAV itself is not included (it is invoked as an external program only).
