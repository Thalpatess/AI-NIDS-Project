package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Alert struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Classification string    `json:"classification"`
	Severity       string    `json:"severity"`
	Score          float64   `json:"score"`
	Message        string    `json:"message"`
	FlowID         string    `json:"flow_id"`
	SrcIP          string    `json:"src_ip"`
	DstIP          string    `json:"dst_ip"`
	DstPort        uint16    `json:"dst_port"`
	CreatedAt      time.Time `json:"created_at"`
}

type SIEMExport struct {
	Timestamp       time.Time `json:"@timestamp"`
	EventType       string    `json:"event.type"`
	EventSeverity   string    `json:"event.severity"`
	EventCategory   string    `json:"event.category"`
	SourceIP        string    `json:"source.ip"`
	DestinationIP   string    `json:"destination.ip"`
	DestinationPort int       `json:"destination.port"`
	RiskScore       float64   `json:"risk.score"`
	ThreatType      string    `json:"threat.type"`
	NIDSAlert       Alert     `json:"nids.alert"`
}

type Server struct {
	mu     sync.RWMutex
	alerts []Alert
}

func NewServer() *Server {
	s := &Server{}
	s.alerts = []Alert{
		{
			ID:             "alert-001",
			Type:           "port_scan",
			Classification: "reconnaissance",
			Severity:       "high",
			Score:          88.5,
			Message:        "Port scan pattern detected from suspicious source",
			FlowID:         "192.168.1.100:54321->10.0.0.8:443|tcp",
			SrcIP:          "192.168.1.100",
			DstIP:          "10.0.0.8",
			DstPort:        443,
			CreatedAt:      time.Now().UTC().Add(-2 * time.Minute),
		},
		{
			ID:             "alert-002",
			Type:           "data_exfiltration",
			Classification: "data_theft",
			Severity:       "critical",
			Score:          96.1,
			Message:        "Abnormal data transfer volume detected to external network",
			FlowID:         "10.0.0.50:80->203.0.113.7:443|tcp",
			SrcIP:          "10.0.0.50",
			DstIP:          "203.0.113.7",
			DstPort:        443,
			CreatedAt:      time.Now().UTC().Add(-5 * time.Minute),
		},
		{
			ID:             "alert-003",
			Type:           "high_packet_rate",
			Classification: "denial_of_service",
			Severity:       "high",
			Score:          75.3,
			Message:        "Potential DoS attack - abnormally high packet rate",
			FlowID:         "10.0.0.15:5000->10.0.0.200:80|tcp",
			SrcIP:          "10.0.0.15",
			DstIP:          "10.0.0.200",
			DstPort:        80,
			CreatedAt:      time.Now().UTC().Add(-10 * time.Minute),
		},
	}
	return s
}

func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/summary", s.handleSummary)
	mux.HandleFunc("/api/alerts/export", s.handleSIEMExport)
	mux.HandleFunc("/api/alerts/classify", s.handleClassify)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "nids-api",
		"version": "1.0",
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	defer s.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(s.alerts)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.alerts)
	critical := 0
	high := 0
	medium := 0
	classificationCount := make(map[string]int)
	highestScore := 0.0

	for _, a := range s.alerts {
		switch a.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
		classificationCount[a.Classification]++
		if a.Score > highestScore {
			highestScore = a.Score
		}
	}

	summary := map[string]interface{}{
		"total_alerts":      total,
		"critical":          critical,
		"high":              high,
		"medium":            medium,
		"highest_score":     highestScore,
		"classifications":   classificationCount,
		"last_updated":      time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleSIEMExport(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=nids-alerts-siem.json")

	exports := make([]SIEMExport, len(s.alerts))
	for i, alert := range s.alerts {
		exports[i] = SIEMExport{
			Timestamp:       alert.CreatedAt,
			EventType:       "detection",
			EventSeverity:   alert.Severity,
			EventCategory:   alert.Classification,
			SourceIP:        alert.SrcIP,
			DestinationIP:   alert.DstIP,
			DestinationPort: int(alert.DstPort),
			RiskScore:       alert.Score,
			ThreatType:      alert.Type,
			NIDSAlert:       alert,
		}
	}

	_ = json.NewEncoder(w).Encode(exports)
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	classification := classifyThreat(req)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"classification": classification,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

func classifyThreat(features map[string]interface{}) string {
	// Simple threat classification based on features
	if synCount, ok := features["syn_count"]; ok {
		if v, ok := synCount.(float64); ok && v > 5 {
			return "reconnaissance"
		}
	}

	if byteRate, ok := features["byte_rate"]; ok {
		if v, ok := byteRate.(float64); ok && v > 1000000 {
			return "data_theft"
		}
	}

	if packetRate, ok := features["packet_rate"]; ok {
		if v, ok := packetRate.(float64); ok && v > 100 {
			return "denial_of_service"
		}
	}

	return "anomalous_behavior"
}

func (s *Server) AddAlert(alert Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append([]Alert{alert}, s.alerts...)
	if len(s.alerts) > 1000 {
		s.alerts = s.alerts[:1000]
	}
}

func StartServer(addr string) error {
	mux := http.NewServeMux()
	srv := NewServer()
	srv.RegisterRoutes(mux)
	fmt.Printf("Starting NIDS API on %s\n", addr)
	return http.ListenAndServe(addr, mux)
}