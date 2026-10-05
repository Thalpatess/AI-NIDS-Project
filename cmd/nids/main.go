package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	packetsSeen = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nids_packets_seen_total",
		Help: "Total packets processed by the NIDS capture service",
	})
	flowsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "nids_active_flows",
		Help: "Number of active TCP/UDP flows currently tracked",
	})
	flowBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "nids_flow_bytes_total",
		Help: "Bytes processed per protocol",
	}, []string{"protocol"})
	packetLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "nids_packet_processing_seconds",
		Help: "Packet processing latency in seconds",
		Buckets: prometheus.DefBuckets,
	})
)

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

type FlowState struct {
	Key             FlowKey
	Start           time.Time
	LastSeen        time.Time
	PacketCount     int
	ByteCount       int
	ForwardPayload  int
	BackwardPayload int
	SynCount        int
	AckCount        int
	RstCount        int
	FinCount        int
	mu              sync.Mutex
}

func main() {
	iface := "eth0"
	if len(os.Args) > 1 {
		for i, arg := range os.Args {
			if arg == "--iface" && i+1 < len(os.Args) {
				iface = os.Args[i+1]
			}
		}
	}

	if err := runCapture(iface); err != nil {
		log.Fatalf("capture service failed: %v", err)
	}
}

func runCapture(iface string) error {
	defer prometheus.Unregister(packetLatency)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("find devices: %w", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no network devices found")
	}

	fmt.Printf("Available interfaces:\n")
	for _, dev := range devices {
		fmt.Printf(" - %s\n", dev.Name)
	}

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open %s: %w", iface, err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	start := time.Now()
	flows := make(map[string]*FlowState)

	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				return fmt.Errorf("capture channel closed")
			}
			if packet == nil {
				continue
			}

			startTs := time.Now()
			flow, okFlow := processPacket(packet)
			if okFlow {
				key := flowKeyToString(flow.Key)
				state, exists := flows[key]
				if !exists {
					state = &FlowState{Key: flow.Key, Start: time.Now(), LastSeen: time.Now()}
					flows[key] = state
				}
				state.mu.Lock()
				state.PacketCount++
				state.ByteCount += int(packet.Metadata().CaptureLength)
				state.LastSeen = time.Now()
				state.ForwardPayload += flow.ForwardPayload
				state.BackwardPayload += flow.BackwardPayload
				state.SynCount += flow.SynCount
				state.AckCount += flow.AckCount
				state.RstCount += flow.RstCount
				state.FinCount += flow.FinCount
				state.mu.Unlock()
			}

			packetsSeen.Inc()
			packetLatency.Observe(time.Since(startTs).Seconds())
			flowsActive.Set(float64(len(flows)))
			if time.Since(start) > 30*time.Second {
				for _, v := range flows {
					if time.Since(v.LastSeen) > 2*time.Minute {
						delete(flows, flowKeyToString(v.Key))
					}
				}
				start = time.Now()
			}
		}
	}
}

func processPacket(packet gopacket.Packet) (*FlowState, bool) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, false
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil, false
	}

	var proto string
	var srcPort, dstPort uint16
	payloadLen := len(packet.Data())

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok {
			proto = "tcp"
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
			payloadLen = len(tcp.Payload)
		}
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, ok := udpLayer.(*layers.UDP)
		if ok {
			proto = "udp"
			srcPort = uint16(udp.SrcPort)
			dstPort = uint16(udp.DstPort)
			payloadLen = len(udp.Payload)
		}
	}

	if proto == "" {
		return nil, false
	}

	flow := &FlowState{
		Key: FlowKey{
			SrcIP:   ip.SrcIP.String(),
			DstIP:   ip.DstIP.String(),
			SrcPort: srcPort,
			DstPort: dstPort,
			Proto:   proto,
		},
		Start:    time.Now(),
		LastSeen: time.Now(),
	}

	flow.ForwardPayload = payloadLen
	flow.ByteCount = payloadLen
	flow.PacketCount = 1

	if tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if ok {
			if tcp.SYN && !tcp.ACK {
				flow.SynCount = 1
			}
			if tcp.ACK {
				flow.AckCount = 1
			}
			if tcp.RST {
				flow.RstCount = 1
			}
			if tcp.FIN {
				flow.FinCount = 1
			}
		}
	}

	flowBytes.WithLabelValues(proto).Add(float64(payloadLen))
	return flow, true
}

func flowKeyToString(key FlowKey) string {
	return strings.Join([]string{
		key.SrcIP,
		key.DstIP,
		strconv.Itoa(int(key.SrcPort)),
		strconv.Itoa(int(key.DstPort)),
		key.Proto,
	}, "|")
}

func emitJSONMetrics() {
	payload, _ := json.Marshal(map[string]string{"status": "ok"})
	_ = payload
}
