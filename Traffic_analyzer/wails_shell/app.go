package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type TerminalEntry struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Line      string `json:"line"`
}

type TerminalInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Host        string `json:"host,omitempty"`
	Connected   bool   `json:"connected"`
	Interactive bool   `json:"interactive"`
}

type ManagedTerminal struct {
	Info TerminalInfo
	Logs []TerminalEntry

	Client  *ssh.Client
	Session *ssh.Session
	Cmd     *exec.Cmd
	Stdin   io.WriteCloser
}

type captureInterfaceRaw struct {
	Index       int      `json:"Index"`
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	IPs         []string `json:"IPs"`
}

type CaptureInterface struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPs         []string `json:"ips"`
	Status      string   `json:"status,omitempty"`
	Speed       string   `json:"speed,omitempty"`
	Display     string   `json:"display"`
}

type winAdapterMeta struct {
	Name                 string `json:"Name"`
	InterfaceDescription string `json:"InterfaceDescription"`
	Status               string `json:"Status"`
	LinkSpeed            string `json:"LinkSpeed"`
}

type App struct {
	ctx context.Context

	mu sync.Mutex

	repoRoot string
	taRoot   string
	dataDir  string

	backendCmd *exec.Cmd
	captureCmd *exec.Cmd

	selectedCaptureIfaceIndex int
	selectedCaptureIfaceName  string

	terminals map[string]*ManagedTerminal
	nextTerm  int
}

func NewApp() *App {
	return &App{
		terminals:                 make(map[string]*ManagedTerminal),
		nextTerm:                  1,
		selectedCaptureIfaceIndex: -1,
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.repoRoot, a.taRoot = resolveProjectPaths()
	a.dataDir = resolveDataDir(a.taRoot)
	a.selectedCaptureIfaceIndex = -1

	a.appendSystemLog("project_root=" + a.repoRoot)
	a.appendSystemLog("ta_root=" + a.taRoot)
	a.appendSystemLog("data_dir=" + a.dataDir)

	a.ensureDefaultLocalTerminal()
}

func (a *App) shutdown(ctx context.Context) {
	a.StopEmbeddedStack()
	a.StopCapture()
	a.mu.Lock()
	ids := make([]string, 0, len(a.terminals))
	for id := range a.terminals {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	for _, id := range ids {
		a.closeTerminalResources(id)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func resolveProjectPaths() (string, string) {
	if envRoot := strings.TrimSpace(os.Getenv("TA_PROJECT_ROOT")); envRoot != "" {
		if pathExists(filepath.Join(envRoot, "Traffic_analyzer", "main.py")) {
			return envRoot, filepath.Join(envRoot, "Traffic_analyzer")
		}
		if pathExists(filepath.Join(envRoot, "main.py")) && pathExists(filepath.Join(envRoot, "core")) {
			return filepath.Dir(envRoot), envRoot
		}
	}

	candidates := make([]string, 0)
	if exePath, err := os.Executable(); err == nil {
		d := filepath.Dir(exePath)
		for i := 0; i < 10; i++ {
			candidates = append(candidates, d)
			next := filepath.Dir(d)
			if next == d {
				break
			}
			d = next
		}
	}
	if wd, err := os.Getwd(); err == nil {
		d := wd
		for i := 0; i < 10; i++ {
			candidates = append(candidates, d)
			next := filepath.Dir(d)
			if next == d {
				break
			}
			d = next
		}
	}

	for _, c := range candidates {
		if pathExists(filepath.Join(c, "Traffic_analyzer", "main.py")) {
			return c, filepath.Join(c, "Traffic_analyzer")
		}
		if pathExists(filepath.Join(c, "main.py")) && pathExists(filepath.Join(c, "core")) {
			return filepath.Dir(c), c
		}
	}

	wd, _ := os.Getwd()
	return wd, filepath.Join(wd, "Traffic_analyzer")
}

func resolveDataDir(taRoot string) string {
	envData := strings.TrimSpace(os.Getenv("TRAFFIC_ANALYZER_DATA_DIR"))
	if envData != "" {
		_ = os.MkdirAll(envData, 0o755)
		return envData
	}

	defaultData := filepath.Join(taRoot, "data")
	if pathExists(defaultData) {
		_ = os.MkdirAll(defaultData, 0o755)
		return defaultData
	}

	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = os.TempDir()
	}
	fallback := filepath.Join(cfgDir, "traffic-analyzer", "data")
	_ = os.MkdirAll(fallback, 0o755)
	return fallback
}

func decodeOutput(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	if utf8.Valid(raw) {
		return string(raw)
	}
	decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(raw)
	if err == nil && utf8.Valid(decoded) {
		return string(decoded)
	}
	return string(raw)
}

func processRunning(cmd *exec.Cmd) bool {
	if cmd == nil || cmd.Process == nil {
		return false
	}
	if cmd.ProcessState == nil {
		return true
	}
	return !cmd.ProcessState.Exited()
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}

func waitHTTP(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return true
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
	return false
}

func findPythonCommand() ([]string, error) {
	if envPy := strings.TrimSpace(os.Getenv("TA_PYTHON")); envPy != "" {
		if _, err := exec.LookPath(envPy); err == nil {
			return []string{envPy}, nil
		}
	}

	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("py"); err == nil {
			return []string{"py", "-3"}, nil
		}
	}
	for _, c := range []string{"python3", "python"} {
		if _, err := exec.LookPath(c); err == nil {
			return []string{c}, nil
		}
	}
	return nil, fmt.Errorf("python runtime not found; set TA_PYTHON")
}

func (a *App) appendTerminalLog(termID string, source string, line string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	term, ok := a.terminals[termID]
	if !ok {
		return
	}
	term.Logs = append(term.Logs, TerminalEntry{
		Timestamp: time.Now().Format("15:04:05"),
		Source:    source,
		Line:      line,
	})
	if len(term.Logs) > 800 {
		term.Logs = term.Logs[len(term.Logs)-800:]
	}
}

func (a *App) appendSystemLog(line string) {
	a.ensureDefaultLocalTerminal()
	a.appendTerminalLog("local-default", "system", line)
}

func (a *App) streamReader(termID string, source string, reader io.Reader) {
	buf := bufio.NewReader(reader)
	for {
		line, err := buf.ReadBytes('\n')
		if len(line) > 0 {
			text := strings.TrimRight(decodeOutput(line), "\r\n")
			if text != "" {
				a.appendTerminalLog(termID, source, text)
			}
		}
		if err != nil {
			if err != io.EOF {
				a.appendTerminalLog(termID, "system", fmt.Sprintf("stream read error: %v", err))
			}
			return
		}
	}
}

func (a *App) closeTerminalResources(id string) {
	a.mu.Lock()
	term, ok := a.terminals[id]
	if !ok {
		a.mu.Unlock()
		return
	}
	stdin := term.Stdin
	session := term.Session
	client := term.Client
	cmd := term.Cmd
	term.Stdin = nil
	term.Session = nil
	term.Client = nil
	term.Cmd = nil
	term.Info.Connected = false
	a.mu.Unlock()

	if stdin != nil {
		_ = stdin.Close()
	}
	if session != nil {
		_ = session.Close()
	}
	if client != nil {
		_ = client.Close()
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func (a *App) createTerminal(id string, name string, terminalType string, host string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.terminals[id] = &ManagedTerminal{
		Info: TerminalInfo{
			ID:          id,
			Name:        name,
			Type:        terminalType,
			Host:        host,
			Connected:   false,
			Interactive: true,
		},
		Logs: make([]TerminalEntry, 0, 300),
	}
}

func (a *App) startLocalShell(termID string) error {
	a.mu.Lock()
	term, ok := a.terminals[termID]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("terminal not found")
	}
	if term.Stdin != nil && processRunning(term.Cmd) {
		term.Info.Connected = true
		a.mu.Unlock()
		return nil
	}
	a.mu.Unlock()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoLogo", "-NoProfile")
	} else {
		cmd = exec.Command("bash")
	}
	cmd.Dir = a.repoRoot

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	a.mu.Lock()
	term, ok = a.terminals[termID]
	if ok {
		term.Cmd = cmd
		term.Stdin = stdin
		term.Info.Connected = true
	}
	a.mu.Unlock()

	go a.streamReader(termID, "local", stdout)
	go a.streamReader(termID, "local", stderr)
	go func() {
		err := cmd.Wait()
		if err != nil {
			a.appendTerminalLog(termID, "system", "local shell closed: "+err.Error())
		} else {
			a.appendTerminalLog(termID, "system", "local shell closed")
		}
		a.mu.Lock()
		if t, exists := a.terminals[termID]; exists {
			t.Info.Connected = false
			t.Stdin = nil
			t.Cmd = nil
		}
		a.mu.Unlock()
	}()

	if runtime.GOOS == "windows" {
		_, _ = io.WriteString(stdin, "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); chcp 65001 > $null\r\n")
	}
	return nil
}

func (a *App) startSSHShell(termID string, client *ssh.Client) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 42, 160, modes); err != nil {
		_ = session.Close()
		return err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return err
	}

	if err := session.Shell(); err != nil {
		_ = session.Close()
		return err
	}

	a.mu.Lock()
	if term, exists := a.terminals[termID]; exists {
		term.Session = session
		term.Stdin = stdin
		term.Info.Connected = true
	}
	a.mu.Unlock()

	go a.streamReader(termID, "ssh", stdout)
	go a.streamReader(termID, "ssh", stderr)
	go func() {
		err := session.Wait()
		if err != nil {
			a.appendTerminalLog(termID, "system", "ssh shell closed: "+err.Error())
		} else {
			a.appendTerminalLog(termID, "system", "ssh shell closed")
		}
		a.mu.Lock()
		if t, exists := a.terminals[termID]; exists {
			t.Info.Connected = false
			t.Stdin = nil
			t.Session = nil
		}
		a.mu.Unlock()
	}()
	return nil
}

func (a *App) ensureDefaultLocalTerminal() {
	a.mu.Lock()
	_, ok := a.terminals["local-default"]
	a.mu.Unlock()
	if !ok {
		a.createTerminal("local-default", "Local", "local", "")
	}
	if err := a.startLocalShell("local-default"); err != nil {
		a.appendTerminalLog("local-default", "system", "start local shell failed: "+err.Error())
	}
}

func (a *App) startCmdWithLog(termID string, cmd *exec.Cmd, source string) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	go a.streamReader(termID, source, stdout)
	go a.streamReader(termID, source, stderr)
	return nil
}

func (a *App) startBackend() error {
	if processRunning(a.backendCmd) {
		return nil
	}

	py, err := findPythonCommand()
	if err != nil {
		return err
	}

	args := append(py[1:], "-m", "uvicorn", "Traffic_analyzer.main:app", "--host", "127.0.0.1", "--port", "8000")
	cmd := exec.Command(py[0], args...)
	cmd.Dir = a.repoRoot
	cmd.Env = append(os.Environ(),
		"TRAFFIC_ANALYZER_DATA_DIR="+a.dataDir,
		"PYTHONPATH="+a.repoRoot,
	)

	if err := a.startCmdWithLog("local-default", cmd, "backend"); err != nil {
		return err
	}
	a.backendCmd = cmd
	return nil
}

func (a *App) goCaptureRoot() string {
	return filepath.Join(a.taRoot, "go_capture")
}

func readWindowsAdapterMeta() map[string]winAdapterMeta {
	if runtime.GOOS != "windows" {
		return map[string]winAdapterMeta{}
	}
	cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed | ConvertTo-Json -Compress")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return map[string]winAdapterMeta{}
	}
	text := strings.TrimSpace(decodeOutput(out))
	if text == "" {
		return map[string]winAdapterMeta{}
	}

	mapping := map[string]winAdapterMeta{}
	var arr []winAdapterMeta
	if err := json.Unmarshal([]byte(text), &arr); err == nil {
		for _, item := range arr {
			key := strings.ToLower(strings.TrimSpace(item.InterfaceDescription))
			if key != "" {
				mapping[key] = item
			}
		}
		return mapping
	}

	var one winAdapterMeta
	if err := json.Unmarshal([]byte(text), &one); err == nil {
		key := strings.ToLower(strings.TrimSpace(one.InterfaceDescription))
		if key != "" {
			mapping[key] = one
		}
	}
	return mapping
}

func (a *App) ListCaptureInterfaces() ([]CaptureInterface, error) {
	goCaptureRoot := a.goCaptureRoot()
	if !pathExists(goCaptureRoot) {
		return nil, fmt.Errorf("go_capture path not found: %s", goCaptureRoot)
	}

	cmd := exec.Command("go", "run", ".", "-list-ifaces", "-json")
	cmd.Dir = goCaptureRoot
	cmd.Env = append(os.Environ(), "TRAFFIC_ANALYZER_DATA_DIR="+a.dataDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list interfaces failed: %v: %s", err, strings.TrimSpace(decodeOutput(out)))
	}

	var rawItems []captureInterfaceRaw
	if err := json.Unmarshal([]byte(strings.TrimSpace(decodeOutput(out))), &rawItems); err != nil {
		return nil, fmt.Errorf("invalid interface json: %v", err)
	}

	metaByDesc := readWindowsAdapterMeta()
	items := make([]CaptureInterface, 0, len(rawItems))
	for _, r := range rawItems {
		item := CaptureInterface{
			Index:       r.Index,
			Name:        r.Name,
			Description: strings.TrimSpace(r.Description),
			IPs:         r.IPs,
		}
		if item.Description == "" {
			item.Description = "未识别网卡描述"
		}
		if meta, ok := metaByDesc[strings.ToLower(item.Description)]; ok {
			item.Status = strings.TrimSpace(meta.Status)
			item.Speed = strings.TrimSpace(meta.LinkSpeed)
		}
		display := item.Description
		if item.Status != "" {
			display += " | " + item.Status
		}
		if item.Speed != "" {
			display += " | " + item.Speed
		}
		item.Display = display
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Index < items[j].Index })
	return items, nil
}

func (a *App) SetCaptureInterface(ifaceIndex int, ifaceName string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.selectedCaptureIfaceIndex = ifaceIndex
	a.selectedCaptureIfaceName = strings.TrimSpace(ifaceName)
	return map[string]any{
		"capture_iface_index": a.selectedCaptureIfaceIndex,
		"capture_iface_name":  a.selectedCaptureIfaceName,
	}
}

func (a *App) startCapture(ifaceIndex int, ifaceName string) error {
	if processRunning(a.captureCmd) {
		return nil
	}

	goCaptureRoot := a.goCaptureRoot()
	if !pathExists(goCaptureRoot) {
		return fmt.Errorf("go_capture path not found: %s", goCaptureRoot)
	}

	args := []string{"run", "."}
	if ifaceIndex >= 0 {
		args = append(args, "-iface-index", strconv.Itoa(ifaceIndex))
	} else if strings.TrimSpace(ifaceName) != "" {
		args = append(args, "-iface", strings.TrimSpace(ifaceName))
	}

	cmd := exec.Command("go", args...)
	cmd.Dir = goCaptureRoot
	cmd.Env = append(os.Environ(), "TRAFFIC_ANALYZER_DATA_DIR="+a.dataDir)

	if err := a.startCmdWithLog("local-default", cmd, "capture"); err != nil {
		return err
	}
	a.captureCmd = cmd

	a.mu.Lock()
	a.selectedCaptureIfaceIndex = ifaceIndex
	a.selectedCaptureIfaceName = strings.TrimSpace(ifaceName)
	a.mu.Unlock()

	return nil
}

func (a *App) StartEmbeddedStack() (map[string]any, error) {
	if err := a.startBackend(); err != nil {
		a.appendSystemLog("start backend failed: " + err.Error())
		return nil, err
	}

	ready := waitHTTP("http://127.0.0.1:8000/health", 20*time.Second)
	if ready {
		a.appendSystemLog("backend ready")
	}

	return map[string]any{
		"backend_running":  processRunning(a.backendCmd),
		"frontend_running": true,
		"backend_ready":    ready,
		"frontend_ready":   true,
		"project_root":     a.repoRoot,
		"data_dir":         a.dataDir,
	}, nil
}

func (a *App) StopEmbeddedStack() map[string]any {
	stopProcess(a.backendCmd)
	a.backendCmd = nil
	a.appendSystemLog("backend stopped")
	return map[string]any{"backend_running": false, "frontend_running": true}
}

func (a *App) StartCapture() (map[string]any, error) {
	a.mu.Lock()
	ifaceIndex := a.selectedCaptureIfaceIndex
	ifaceName := a.selectedCaptureIfaceName
	a.mu.Unlock()
	if err := a.startCapture(ifaceIndex, ifaceName); err != nil {
		a.appendSystemLog("start capture failed: " + err.Error())
		return nil, err
	}
	a.appendSystemLog("capture started")
	return map[string]any{"capture_running": processRunning(a.captureCmd)}, nil
}

func (a *App) StartCaptureWithInterface(ifaceIndex int, ifaceName string) (map[string]any, error) {
	if err := a.startCapture(ifaceIndex, ifaceName); err != nil {
		a.appendSystemLog("start capture failed: " + err.Error())
		return nil, err
	}
	a.appendSystemLog("capture started")
	return map[string]any{
		"capture_running":     processRunning(a.captureCmd),
		"capture_iface_index": ifaceIndex,
		"capture_iface_name":  strings.TrimSpace(ifaceName),
	}, nil
}

func (a *App) StopCapture() map[string]any {
	stopProcess(a.captureCmd)
	a.captureCmd = nil
	a.appendSystemLog("capture stopped")
	return map[string]any{"capture_running": false}
}

func (a *App) ServiceStatus() map[string]any {
	a.mu.Lock()
	ifaceIndex := a.selectedCaptureIfaceIndex
	ifaceName := a.selectedCaptureIfaceName
	a.mu.Unlock()
	return map[string]any{
		"project_root":        a.repoRoot,
		"traffic_root":        a.taRoot,
		"data_dir":            a.dataDir,
		"backend_running":     processRunning(a.backendCmd),
		"frontend_running":    true,
		"capture_running":     processRunning(a.captureCmd),
		"capture_iface_index": ifaceIndex,
		"capture_iface_name":  ifaceName,
	}
}

func (a *App) ListTerminals() []TerminalInfo {
	a.mu.Lock()
	defer a.mu.Unlock()

	items := make([]TerminalInfo, 0, len(a.terminals))
	for _, t := range a.terminals {
		items = append(items, t.Info)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (a *App) CreateLocalTerminal(name string) (TerminalInfo, error) {
	a.ensureDefaultLocalTerminal()
	if strings.TrimSpace(name) == "" {
		name = "Local"
	}
	a.mu.Lock()
	id := fmt.Sprintf("local-%d", a.nextTerm)
	a.nextTerm++
	a.mu.Unlock()

	a.createTerminal(id, name, "local", "")
	if err := a.startLocalShell(id); err != nil {
		return TerminalInfo{}, err
	}
	a.appendTerminalLog(id, "system", "interactive local shell ready")

	a.mu.Lock()
	info := a.terminals[id].Info
	a.mu.Unlock()
	return info, nil
}

func (a *App) CreateSSHTerminal(host string, port int, username string, password string, name string) (TerminalInfo, error) {
	if strings.TrimSpace(host) == "" || strings.TrimSpace(username) == "" {
		return TerminalInfo{}, fmt.Errorf("host and username are required")
	}
	if port <= 0 {
		port = 22
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("SSH %s@%s", username, host)
	}

	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return TerminalInfo{}, err
	}

	a.mu.Lock()
	id := fmt.Sprintf("ssh-%d", a.nextTerm)
	a.nextTerm++
	a.mu.Unlock()

	a.createTerminal(id, name, "ssh", addr)
	a.mu.Lock()
	if t, ok := a.terminals[id]; ok {
		t.Client = client
	}
	a.mu.Unlock()

	if err := a.startSSHShell(id, client); err != nil {
		a.closeTerminalResources(id)
		return TerminalInfo{}, err
	}
	a.appendTerminalLog(id, "system", "ssh interactive shell connected: "+addr)

	a.mu.Lock()
	info := a.terminals[id].Info
	a.mu.Unlock()
	return info, nil
}

func (a *App) CloseTerminal(id string) bool {
	if id == "local-default" {
		return false
	}
	a.closeTerminalResources(id)
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.terminals[id]; !ok {
		return false
	}
	delete(a.terminals, id)
	return true
}

func (a *App) GetTerminalLogsByID(id string, limit int) []TerminalEntry {
	a.mu.Lock()
	defer a.mu.Unlock()

	t, ok := a.terminals[id]
	if !ok {
		return []TerminalEntry{}
	}

	if limit <= 0 || limit >= len(t.Logs) {
		out := make([]TerminalEntry, len(t.Logs))
		copy(out, t.Logs)
		return out
	}

	start := len(t.Logs) - limit
	out := make([]TerminalEntry, len(t.Logs[start:]))
	copy(out, t.Logs[start:])
	return out
}

func (a *App) ClearTerminalLogsByID(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.terminals[id]
	if !ok {
		return false
	}
	t.Logs = make([]TerminalEntry, 0, 300)
	return true
}

func (a *App) writeToTerminal(termID string, text string) error {
	a.mu.Lock()
	term, ok := a.terminals[termID]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("terminal not found")
	}
	stdin := term.Stdin
	termType := term.Info.Type
	connected := term.Info.Connected
	client := term.Client
	a.mu.Unlock()

	if !connected || stdin == nil {
		if termType == "local" {
			if err := a.startLocalShell(termID); err != nil {
				return err
			}
			a.mu.Lock()
			stdin = a.terminals[termID].Stdin
			a.mu.Unlock()
		}
	}

	if stdin == nil {
		return fmt.Errorf("terminal input unavailable")
	}

	if termType == "ssh" && client == nil {
		return fmt.Errorf("ssh disconnected")
	}

	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	_, err := io.WriteString(stdin, text)
	return err
}

func (a *App) ExecuteTerminalCommandByID(id string, command string) string {
	cmdText := strings.TrimSpace(command)
	if cmdText == "" {
		return "empty command"
	}

	a.appendTerminalLog(id, "input", cmdText)
	if err := a.writeToTerminal(id, cmdText); err != nil {
		a.appendTerminalLog(id, "system", "execute error: "+err.Error())
		return "error"
	}
	return "sent"
}

func (a *App) GetTerminalLogs(limit int) []TerminalEntry {
	return a.GetTerminalLogsByID("local-default", limit)
}

func (a *App) ClearTerminalLogs() bool {
	return a.ClearTerminalLogsByID("local-default")
}

func (a *App) ExecuteTerminalCommand(command string) string {
	return a.ExecuteTerminalCommandByID("local-default", command)
}
