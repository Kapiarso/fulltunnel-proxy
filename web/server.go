package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"socks_connector/core"
	"socks_connector/core/config"
	"socks_connector/core/logger"

	"golang.org/x/net/websocket"
)

// Server provides the REST API and WebSocket streaming for GUI/Web dashboards
type Server struct {
	engine   *core.Engine
	port     int
	server   *http.Server
	clients  map[*websocket.Conn]bool
	clientMu sync.Mutex
}

func NewServer(engine *core.Engine, port int) *Server {
	if port <= 0 {
		port = 28888
	}
	return &Server{
		engine:  engine,
		port:    port,
		clients: make(map[*websocket.Conn]bool),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// REST API Routes
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/connect", s.handleConnect)
	mux.HandleFunc("/api/connect/quick", s.handleQuickConnect)
	mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/profile/select", s.handleProfileSelect)
	mux.HandleFunc("/api/profile/save", s.handleProfileSave)
	mux.HandleFunc("/api/profile/delete", s.handleProfileDelete)
	mux.HandleFunc("/api/ip", s.handleCheckIP)
	mux.HandleFunc("/api/speedtest", s.handleSpeedtest)
	mux.HandleFunc("/api/benchmark", s.handleBenchmark)
	mux.HandleFunc("/api/server/start", s.handleServerStart)
	mux.HandleFunc("/api/server/stop", s.handleServerStop)
	mux.HandleFunc("/api/server/status", s.handleServerStatus)

	// WebSocket Live Stream
	mux.Handle("/api/ws", websocket.Handler(s.handleWS))
	mux.Handle("/ws", websocket.Handler(s.handleWS))

	// Embedded Static UI Assets & Templates
	mux.Handle("/static/", http.FileServer(http.FS(StaticFS)))
	mux.HandleFunc("/", s.handleIndex)

	s.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler: mux,
	}

	go s.broadcastLoop()

	return s.server.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state, errMsg := s.engine.GetState()
	stats := s.engine.GetStats()
	cfg := s.engine.GetConfig()

	resp := map[string]any{
		"state":          state,
		"error":          errMsg,
		"stats":          stats,
		"active_profile": cfg.GetActiveProfile(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state, _ := s.engine.GetState()
	if state != core.StateDisconnected {
		_ = s.engine.Stop()
		time.Sleep(150 * time.Millisecond)
	}

	if err := s.engine.Start(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "state": "error"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "connected", "state": "connected"})
}

func (s *Server) handleQuickConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		ProxyString string `json:"proxy_string"`
		Type        string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	profile, err := config.ParseProxyString(body.ProxyString, config.ProxyType(body.Type))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	cfg := s.engine.GetConfig()
	profile.Name = fmt.Sprintf("Proxy %s:%d", profile.Host, profile.Port)
	cfg.Profiles = append([]config.Profile{*profile}, cfg.Profiles...)
	cfg.ActiveProfileID = profile.ID
	_ = cfg.Save()

	state, _ := s.engine.GetState()
	if state != core.StateDisconnected {
		_ = s.engine.Stop()
		time.Sleep(150 * time.Millisecond)
	}

	if err := s.engine.Start(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "state": "error"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "connected", "state": "connected", "profile": profile})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_ = s.engine.Stop()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "disconnected", "state": "disconnected"})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.GetConfig()

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == http.MethodPost {
		var newCfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*cfg = newCfg
		_ = cfg.Save()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleProfileSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.engine.GetConfig()
	cfg.ActiveProfileID = body.ID
	_ = cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "active_profile": cfg.GetActiveProfile()})
}

func (s *Server) handleProfileSave(w http.ResponseWriter, r *http.Request) {
	var profile config.Profile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if profile.ID == "" {
		profile.ID = fmt.Sprintf("prof-%d", time.Now().UnixNano())
	}

	cfg := s.engine.GetConfig()
	found := false
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == profile.ID {
			cfg.Profiles[i] = profile
			found = true
			break
		}
	}
	if !found {
		cfg.Profiles = append(cfg.Profiles, profile)
	}
	if cfg.ActiveProfileID == "" {
		cfg.ActiveProfileID = profile.ID
	}
	_ = cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "profile": profile})
}

func (s *Server) handleProfileDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cfg := s.engine.GetConfig()
	newProfiles := make([]config.Profile, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		if p.ID != body.ID {
			newProfiles = append(newProfiles, p)
		}
	}
	cfg.Profiles = newProfiles
	if cfg.ActiveProfileID == body.ID && len(cfg.Profiles) > 0 {
		cfg.ActiveProfileID = cfg.Profiles[0].ID
	}
	_ = cfg.Save()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleCheckIP(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		http.Error(w, fmt.Sprintf("IP check failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) handleWS(ws *websocket.Conn) {
	s.clientMu.Lock()
	s.clients[ws] = true
	s.clientMu.Unlock()

	defer func() {
		s.clientMu.Lock()
		delete(s.clients, ws)
		s.clientMu.Unlock()
		_ = ws.Close()
	}()

	// Keep alive
	buf := make([]byte, 128)
	for {
		if _, err := ws.Read(buf); err != nil {
			break
		}
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := logger.GlobalLogger.GetLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Server) broadcastLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		s.clientMu.Lock()
		clientCount := len(s.clients)
		s.clientMu.Unlock()

		if clientCount == 0 {
			continue
		}

		state, errMsg := s.engine.GetState()
		stats := s.engine.GetStats()
		cfg := s.engine.GetConfig()
		logs := logger.GlobalLogger.GetLogs()

		payload, err := json.Marshal(map[string]any{
			"state":          state,
			"error":          errMsg,
			"stats":          stats,
			"active_profile": cfg.GetActiveProfile(),
			"profiles":       cfg.Profiles,
			"logs":           logs,
		})
		if err != nil {
			continue
		}

		s.clientMu.Lock()
		for ws := range s.clients {
			_ = websocket.Message.Send(ws, string(payload))
		}
		s.clientMu.Unlock()
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(IndexHTML))
}

func (s *Server) handleSpeedtest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	testURL := "https://speed.cloudflare.com/__down?bytes=10485760"
	client := &http.Client{Timeout: 15 * time.Second}

	start := time.Now()
	resp, err := client.Get(testURL)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	dur := time.Since(start)

	mbps := float64(n*8) / (dur.Seconds() * 1000 * 1000)
	mbs := float64(n) / (dur.Seconds() * 1024 * 1024)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":       true,
		"bytes":         n,
		"duration_ms":   dur.Milliseconds(),
		"speed_mbps":    fmt.Sprintf("%.2f", mbps),
		"speed_mbs":     fmt.Sprintf("%.2f", mbs),
		"download_mbps": mbps,
	})
}

func (s *Server) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	comp, err := s.engine.RunSpeedComparison("")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"comparison": comp,
	})
}

func (s *Server) handleServerStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Port       int    `json:"port"`
		OutboundIP string `json:"outbound_ip"`
		Username   string `json:"username"`
		Password   string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Port <= 0 {
		body.Port = 10800
	}

	err := s.engine.StartLocalProxyServer(body.Port, body.OutboundIP, body.Username, body.Password)
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"message": fmt.Sprintf("SOCKS5 Server running on 0.0.0.0:%d", body.Port),
		"status":  s.engine.GetLocalProxyStatus(),
	})
}

func (s *Server) handleServerStop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := s.engine.StopLocalProxyServer()
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"status":  s.engine.GetLocalProxyStatus(),
	})
}

func (s *Server) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.engine.GetLocalProxyStatus())
}

