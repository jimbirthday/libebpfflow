// ebpflowexport.go
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpf_flow "./go"
)

var gRUNNING bool = true
var gLogLevel int = 0 // 0: no logs, 1: errors only, 2: info, 3: debug

// 连接信息结构
type ConnectionInfo struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	BytesIn  uint64
	BytesOut uint64
	PktsIn   uint64
	PktsOut  uint64
	LastSeen time.Time
}

// 进程信息结构
type ProcessInfo struct {
	PID         uint32
	Name        string
	Path        string
	IsDocker    bool
	ContainerID string
}

// 进程流量统计结构
type ProcessStats struct {
	TotalBytesIn  uint64
	TotalBytesOut uint64
	TotalPktsIn   uint64
	TotalPktsOut  uint64
	LastSeen      time.Time
	StartTime     time.Time
	Connections   map[string]*ConnectionInfo
	ProcessInfo   ProcessInfo
}

// 总体网络事件统计结构
type NetworkEventStats struct {
	TCPStats struct {
		SendBytes uint64
		RecvBytes uint64
		SendPkts  uint64
		RecvPkts  uint64
	}
	UDPStats struct {
		SendBytes uint64
		RecvBytes uint64
		SendPkts  uint64
		RecvPkts  uint64
	}
	LastSeen time.Time
}

// 时间间隔统计结构
type IntervalStats struct {
	ProcessStats map[string]*ProcessStats
	NetworkStats *NetworkEventStats
	StartTime    time.Time
	EndTime      time.Time
	LastStats    map[string]*ProcessStats // 添加上一个间隔的统计
}

type TrafficTracker struct {
	processStats  map[string]*ProcessStats
	networkStats  *NetworkEventStats
	intervalStats *IntervalStats
	mu            sync.RWMutex
	connTimeout   time.Duration // 添加连接超时时间配置
}

func NewTrafficTracker() *TrafficTracker {
	return &TrafficTracker{
		processStats: make(map[string]*ProcessStats),
		networkStats: &NetworkEventStats{},
		intervalStats: &IntervalStats{
			ProcessStats: make(map[string]*ProcessStats),
			NetworkStats: &NetworkEventStats{},
			StartTime:    time.Now(),
			LastStats:    make(map[string]*ProcessStats),
		},
		connTimeout: 30 * time.Second, // 默认30秒超时
	}
}

func getConnectionKey(saddr, daddr net.IP, sport, dport uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", saddr.String(), sport, daddr.String(), dport)
}

// 获取进程标识符
func getProcessIdentifier(proc ebpf_flow.TaskInfo) string {
	// 如果是Docker容器，使用容器ID
	if proc.Full_Task_Path != "" && strings.Contains(proc.Full_Task_Path, "docker") {
		containerID := extractContainerID(proc.Full_Task_Path)
		return fmt.Sprintf("docker:%s:%s", containerID, proc.Task)
	}

	// 如果不是容器，使用进程名和PID
	return fmt.Sprintf("host:%s:%d", proc.Task, proc.Pid)
}

// 从Docker路径中提取容器ID
func extractContainerID(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if len(part) == 64 && !strings.Contains(part, ".") {
			return part
		}
	}
	return "unknown"
}

func (tt *TrafficTracker) updateStats(event ebpf_flow.EBPFevent) {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	// 更新累计统计
	processID := getProcessIdentifier(event.Proc)
	stats, exists := tt.processStats[processID]
	if !exists {
		containerID := ""
		if strings.Contains(event.Proc.Full_Task_Path, "docker") {
			containerID = extractContainerID(event.Proc.Full_Task_Path)
		}

		stats = &ProcessStats{
			StartTime:   time.Now(),
			Connections: make(map[string]*ConnectionInfo),
			ProcessInfo: ProcessInfo{
				PID:         event.Proc.Pid,
				Name:        event.Proc.Task,
				Path:        event.Proc.Full_Task_Path,
				IsDocker:    strings.Contains(event.Proc.Full_Task_Path, "docker"),
				ContainerID: containerID,
			},
		}
		tt.processStats[processID] = stats
	}

	// 更新间隔统计
	intervalStats, exists := tt.intervalStats.ProcessStats[processID]
	if !exists {
		containerID := ""
		if strings.Contains(event.Proc.Full_Task_Path, "docker") {
			containerID = extractContainerID(event.Proc.Full_Task_Path)
		}

		intervalStats = &ProcessStats{
			StartTime:   time.Now(),
			Connections: make(map[string]*ConnectionInfo),
			ProcessInfo: ProcessInfo{
				PID:         event.Proc.Pid,
				Name:        event.Proc.Task,
				Path:        event.Proc.Full_Task_Path,
				IsDocker:    strings.Contains(event.Proc.Full_Task_Path, "docker"),
				ContainerID: containerID,
			},
		}
		tt.intervalStats.ProcessStats[processID] = intervalStats
	}

	// 更新连接信息
	connKey := getConnectionKey(event.Saddr, event.Daddr, event.Sport, event.Dport)

	// 更新累计统计的连接
	conn, exists := stats.Connections[connKey]
	if !exists {
		conn = &ConnectionInfo{
			SrcIP:   event.Saddr,
			DstIP:   event.Daddr,
			SrcPort: event.Sport,
			DstPort: event.Dport,
		}
		stats.Connections[connKey] = conn
	}

	// 更新间隔统计的连接
	intervalConn, exists := intervalStats.Connections[connKey]
	if !exists {
		intervalConn = &ConnectionInfo{
			SrcIP:   event.Saddr,
			DstIP:   event.Daddr,
			SrcPort: event.Sport,
			DstPort: event.Dport,
		}
		intervalStats.Connections[connKey] = intervalConn
	}

	// 更新统计信息
	switch event.EType {
	case 600: // eTCP_SEND
		conn.PktsOut++
		conn.BytesOut += uint64(event.Len)
		stats.TotalPktsOut++
		stats.TotalBytesOut += uint64(event.Len)
		tt.networkStats.TCPStats.SendBytes += uint64(event.Len)
		tt.networkStats.TCPStats.SendPkts++

		intervalConn.PktsOut++
		intervalConn.BytesOut += uint64(event.Len)
		intervalStats.TotalPktsOut++
		intervalStats.TotalBytesOut += uint64(event.Len)
		tt.intervalStats.NetworkStats.TCPStats.SendBytes += uint64(event.Len)
		tt.intervalStats.NetworkStats.TCPStats.SendPkts++

	case 601: // eTCP_RECV
		conn.PktsIn++
		conn.BytesIn += uint64(event.Len)
		stats.TotalPktsIn++
		stats.TotalBytesIn += uint64(event.Len)
		tt.networkStats.TCPStats.RecvBytes += uint64(event.Len)
		tt.networkStats.TCPStats.RecvPkts++

		intervalConn.PktsIn++
		intervalConn.BytesIn += uint64(event.Len)
		intervalStats.TotalPktsIn++
		intervalStats.TotalBytesIn += uint64(event.Len)
		tt.intervalStats.NetworkStats.TCPStats.RecvBytes += uint64(event.Len)
		tt.intervalStats.NetworkStats.TCPStats.RecvPkts++

	case 700: // eUDP_SEND
		conn.PktsOut++
		conn.BytesOut += uint64(event.Len)
		stats.TotalPktsOut++
		stats.TotalBytesOut += uint64(event.Len)
		tt.networkStats.UDPStats.SendBytes += uint64(event.Len)
		tt.networkStats.UDPStats.SendPkts++

		intervalConn.PktsOut++
		intervalConn.BytesOut += uint64(event.Len)
		intervalStats.TotalPktsOut++
		intervalStats.TotalBytesOut += uint64(event.Len)
		tt.intervalStats.NetworkStats.UDPStats.SendBytes += uint64(event.Len)
		tt.intervalStats.NetworkStats.UDPStats.SendPkts++

	case 701: // eUDP_RECV
		conn.PktsIn++
		conn.BytesIn += uint64(event.Len)
		stats.TotalPktsIn++
		stats.TotalBytesIn += uint64(event.Len)
		tt.networkStats.UDPStats.RecvBytes += uint64(event.Len)
		tt.networkStats.UDPStats.RecvPkts++

		intervalConn.PktsIn++
		intervalConn.BytesIn += uint64(event.Len)
		intervalStats.TotalPktsIn++
		intervalStats.TotalBytesIn += uint64(event.Len)
		tt.intervalStats.NetworkStats.UDPStats.RecvBytes += uint64(event.Len)
		tt.intervalStats.NetworkStats.UDPStats.RecvPkts++
	}

	conn.LastSeen = time.Now()
	stats.LastSeen = time.Now()
	tt.networkStats.LastSeen = time.Now()

	intervalConn.LastSeen = time.Now()
	intervalStats.LastSeen = time.Now()
	tt.intervalStats.NetworkStats.LastSeen = time.Now()
}

// 清理不活跃的连接
func (tt *TrafficTracker) cleanupInactiveConnections() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now()
	for _, stats := range tt.processStats {
		for connKey, conn := range stats.Connections {
			if now.Sub(conn.LastSeen) > tt.connTimeout {
				delete(stats.Connections, connKey)
			}
		}
	}

	// 清理间隔统计中的不活跃连接
	for _, stats := range tt.intervalStats.ProcessStats {
		for connKey, conn := range stats.Connections {
			if now.Sub(conn.LastSeen) > tt.connTimeout {
				delete(stats.Connections, connKey)
			}
		}
	}
}

func (tt *TrafficTracker) writeStatsToFile(filename string, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to file %s: %v", filename, err)
	}
	return nil
}

func (tt *TrafficTracker) formatStatsForFile() (string, string) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	var cumulativeContent, intervalContent strings.Builder
	now := time.Now()

	// Format interval stats (only network traffic for current interval)
	intervalContent.WriteString(fmt.Sprintf("\n==========================================\n"))
	intervalContent.WriteString(fmt.Sprintf("INTERVAL NETWORK TRAFFIC STATISTICS\n"))
	intervalContent.WriteString(fmt.Sprintf("Period: %v - %v\n",
		tt.intervalStats.StartTime.Format(time.RFC3339),
		now.Format(time.RFC3339)))
	intervalContent.WriteString("==========================================\n\n")

	// Overall network stats for current interval
	if tt.intervalStats.NetworkStats != nil {
		intervalContent.WriteString("NETWORK STATISTICS\n")
		intervalContent.WriteString("-----------------\n")
		intervalContent.WriteString("TCP Traffic:\n")
		intervalContent.WriteString(fmt.Sprintf("  Outbound: %d bytes (%d packets)\n", tt.intervalStats.NetworkStats.TCPStats.SendBytes, tt.intervalStats.NetworkStats.TCPStats.SendPkts))
		intervalContent.WriteString(fmt.Sprintf("  Inbound:  %d bytes (%d packets)\n", tt.intervalStats.NetworkStats.TCPStats.RecvBytes, tt.intervalStats.NetworkStats.TCPStats.RecvPkts))
		intervalContent.WriteString("UDP Traffic:\n")
		intervalContent.WriteString(fmt.Sprintf("  Outbound: %d bytes (%d packets)\n", tt.intervalStats.NetworkStats.UDPStats.SendBytes, tt.intervalStats.NetworkStats.UDPStats.SendPkts))
		intervalContent.WriteString(fmt.Sprintf("  Inbound:  %d bytes (%d packets)\n", tt.intervalStats.NetworkStats.UDPStats.RecvBytes, tt.intervalStats.NetworkStats.UDPStats.RecvPkts))
	}

	// Format cumulative stats (all historical data)
	cumulativeContent.WriteString(fmt.Sprintf("\n==========================================\n"))
	cumulativeContent.WriteString(fmt.Sprintf("CUMULATIVE TRAFFIC STATISTICS\n"))
	cumulativeContent.WriteString(fmt.Sprintf("Generated at: %v\n", now.Format(time.RFC3339)))
	cumulativeContent.WriteString("==========================================\n\n")

	// Overall network stats (all time)
	if tt.networkStats != nil {
		cumulativeContent.WriteString("NETWORK STATISTICS\n")
		cumulativeContent.WriteString("-----------------\n")
		cumulativeContent.WriteString("TCP Traffic:\n")
		cumulativeContent.WriteString(fmt.Sprintf("  Outbound: %d bytes (%d packets)\n", tt.networkStats.TCPStats.SendBytes, tt.networkStats.TCPStats.SendPkts))
		cumulativeContent.WriteString(fmt.Sprintf("  Inbound:  %d bytes (%d packets)\n", tt.networkStats.TCPStats.RecvBytes, tt.networkStats.TCPStats.RecvPkts))
		cumulativeContent.WriteString("UDP Traffic:\n")
		cumulativeContent.WriteString(fmt.Sprintf("  Outbound: %d bytes (%d packets)\n", tt.networkStats.UDPStats.SendBytes, tt.networkStats.UDPStats.SendPkts))
		cumulativeContent.WriteString(fmt.Sprintf("  Inbound:  %d bytes (%d packets)\n\n", tt.networkStats.UDPStats.RecvBytes, tt.networkStats.UDPStats.RecvPkts))
	}

	// Process stats (all time)
	cumulativeContent.WriteString("PROCESS STATISTICS\n")
	cumulativeContent.WriteString("-----------------\n")
	for processID, stats := range tt.processStats {
		cumulativeContent.WriteString(fmt.Sprintf("\nProcess: %s\n", processID))
		if stats.ProcessInfo.IsDocker {
			cumulativeContent.WriteString("  Type: Docker Container\n")
			cumulativeContent.WriteString(fmt.Sprintf("  Container ID: %s\n", stats.ProcessInfo.ContainerID))
		} else {
			cumulativeContent.WriteString("  Type: Host Process\n")
		}
		cumulativeContent.WriteString(fmt.Sprintf("  PID: %d\n", stats.ProcessInfo.PID))
		cumulativeContent.WriteString(fmt.Sprintf("  Name: %s\n", stats.ProcessInfo.Name))
		cumulativeContent.WriteString(fmt.Sprintf("  Running Time: %v\n", time.Since(stats.StartTime).Round(time.Second)))
		cumulativeContent.WriteString("  Traffic:\n")
		cumulativeContent.WriteString(fmt.Sprintf("    Inbound:  %d bytes (%d packets)\n", stats.TotalBytesIn, stats.TotalPktsIn))
		cumulativeContent.WriteString(fmt.Sprintf("    Outbound: %d bytes (%d packets)\n", stats.TotalBytesOut, stats.TotalPktsOut))

		// All active connections
		if len(stats.Connections) > 0 {
			cumulativeContent.WriteString("  Active Connections:\n")
			for _, conn := range stats.Connections {
				if conn == nil {
					continue
				}
				cumulativeContent.WriteString(fmt.Sprintf("    %s:%d -> %s:%d\n",
					conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort))
				cumulativeContent.WriteString(fmt.Sprintf("      Inbound:  %d bytes (%d packets)\n", conn.BytesIn, conn.PktsIn))
				cumulativeContent.WriteString(fmt.Sprintf("      Outbound: %d bytes (%d packets)\n", conn.BytesOut, conn.PktsOut))
				cumulativeContent.WriteString(fmt.Sprintf("      Last Seen: %s\n", conn.LastSeen.Format(time.RFC3339)))
			}
		}
		cumulativeContent.WriteString("-----------------\n")
	}

	return cumulativeContent.String(), intervalContent.String()
}

func (tt *TrafficTracker) printStats() {
	// 先清理不活跃的连接
	tt.cleanupInactiveConnections()

	// 格式化统计数据
	cumulativeContent, intervalContent := tt.formatStatsForFile()

	// 写入文件
	if err := tt.writeStatsToFile("cumulative_stats.log", cumulativeContent); err != nil {
		fmt.Printf("Error writing cumulative stats: %v\n", err)
	}
	if err := tt.writeStatsToFile("interval_stats.log", intervalContent); err != nil {
		fmt.Printf("Error writing interval stats: %v\n", err)
	}

	// 打印到控制台
	fmt.Print(cumulativeContent)
	fmt.Print(intervalContent)

	// 重置间隔统计
	tt.resetIntervalStats()
}

func (tt *TrafficTracker) resetIntervalStats() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	// Create a new map for last stats
	lastStats := make(map[string]*ProcessStats)

	// Safely copy the current stats
	for k, v := range tt.intervalStats.ProcessStats {
		// Create deep copy
		lastStat := &ProcessStats{
			TotalBytesIn:  v.TotalBytesIn,
			TotalBytesOut: v.TotalBytesOut,
			TotalPktsIn:   v.TotalPktsIn,
			TotalPktsOut:  v.TotalPktsOut,
			LastSeen:      v.LastSeen,
			StartTime:     v.StartTime,
			Connections:   make(map[string]*ConnectionInfo),
			ProcessInfo:   v.ProcessInfo,
		}
		// Copy connections
		for connKey, conn := range v.Connections {
			lastStat.Connections[connKey] = &ConnectionInfo{
				SrcIP:    conn.SrcIP,
				DstIP:    conn.DstIP,
				SrcPort:  conn.SrcPort,
				DstPort:  conn.DstPort,
				BytesIn:  conn.BytesIn,
				BytesOut: conn.BytesOut,
				PktsIn:   conn.PktsIn,
				PktsOut:  conn.PktsOut,
				LastSeen: conn.LastSeen,
			}
		}
		lastStats[k] = lastStat
	}

	// Reset current interval stats with new map
	tt.intervalStats = &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats),
		NetworkStats: &NetworkEventStats{},
		StartTime:    time.Now(),
		LastStats:    lastStats,
	}
}

func main() {
	// 创建流量跟踪器
	trafficTracker := NewTrafficTracker()

	// 事件处理函数
	eventHandler := func(event ebpf_flow.EBPFevent) {
		trafficTracker.updateStats(event)
	}

	// 创建定时器，定期打印统计信息
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			trafficTracker.printStats()
		}
	}()

	// 初始化 ebpflow
	ebpf := ebpf_flow.NewEbpflow(eventHandler, 0)
	if gLogLevel > 1 {
		fmt.Println("Initialized")
	}

	// 处理中断信号
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		gRUNNING = false
	}()

	// 轮询事件
	for gRUNNING == true {
		ebpf.PollEvent(10)
	}

	// 清理资源
	ebpf.Close()
}
