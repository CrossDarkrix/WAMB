//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "WAMB"

type svcHandler struct{ cfgPath string }

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	cfg, err := LoadConfig(h.cfgPath)
	if err != nil {
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		logFile := cfg.BaseDir + `\serve.log`
		_ = runServe(cfg, ctx, logFile)
		close(done)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			<-done
			return false, 0
		case svc.Interrogate:
			changes <- c.CurrentStatus
		}
	}
	cancel()
	return false, 0
}

func isWindowsService() bool {
	in, _ := svc.IsWindowsService()
	return in
}

func runWindowsService(cfgPath string) error {
	return svc.Run(serviceName, &svcHandler{cfgPath: cfgPath})
}

func exePath() (string, error) { return os.Executable() }

func installService(cfgPath string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}
	exe, err := exePath()
	if err != nil {
		return err
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "WAMB — Win Anti Malware Blocker",
		Description: "ClamAV manager: scheduled scans, signature updates, real-time watch.",
		StartType:   mgr.StartAutomatic,
	}, "serve", "--config", cfgPath, "--service")
	if err != nil {
		return err
	}
	defer s.Close()
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	time.Sleep(500 * time.Millisecond)
	return s.Delete()
}

func startService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func stopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}

func statusService() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		// mgr.Connect asks for full SCM access, which standard users lack.
		// Fall back to sc.exe, which can query as a normal user.
		out, qerr := exec.Command("sc.exe", "query", serviceName).CombinedOutput()
		s := string(out)
		if qerr != nil || strings.Contains(s, "1060") {
			return "not installed", nil
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "STATE") {
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					return strings.ToLower(parts[3]), nil
				}
			}
		}
		return "installed (state unknown without elevation)", nil
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return "not installed", nil
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", err
	}
	names := map[svc.State]string{
		svc.Stopped:         "stopped",
		svc.StartPending:    "start pending",
		svc.StopPending:     "stop pending",
		svc.Running:         "running",
		svc.ContinuePending: "continue pending",
		svc.PausePending:    "pause pending",
		svc.Paused:          "paused",
	}
	if n, ok := names[st.State]; ok {
		return n, nil
	}
	return fmt.Sprintf("state %d", st.State), nil
}
