// ebpflowexport.go
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpf_flow "./go"
)

var gRUNNING bool = true

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

// 流量统计文件结构
type TrafficStatsFile struct {
	Date      string `json:"date"`
	Timestamp string `json:"timestamp"`
	Period    struct {
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
	} `json:"period"`
	TotalStats           *NetworkEventStats       `json:"total_stats"`
	IntervalStats        *NetworkEventStats       `json:"interval_stats"`
	ProcessStats         map[string]*ProcessStats `json:"process_stats"`
	ProcessIntervalStats map[string]*ProcessStats `json:"process_interval_stats"`
}

// 文件存储管理器
type FileStorageManager struct {
	baseDir          string
	totalStatsFile   *os.File
	processStatsFile *os.File
	currentDate      string
	mu               sync.Mutex
	writeChan        chan *TrafficStatsFile
}

func NewFileStorageManager(baseDir string) *FileStorageManager {
	fsm := &FileStorageManager{
		baseDir:   baseDir,
		writeChan: make(chan *TrafficStatsFile, 100), // 缓冲通道，避免阻塞
	}

	// 确保目录存在
	os.MkdirAll(baseDir, 0755)

	// 启动异步写入协程
	go fsm.asyncWriter()

	return fsm
}

func (fsm *FileStorageManager) asyncWriter() {
	for stats := range fsm.writeChan {
		fsm.writeStatsToFile(stats)
	}
}

func (fsm *FileStorageManager) writeStatsToFile(stats *TrafficStatsFile) {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()

	// 检查是否需要切换文件
	if fsm.currentDate != stats.Date {
		fsm.rotateFiles(stats.Date)
	}

	// 序列化数据
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling stats: %v\n", err)
		return
	}

	// 写入总流量统计
	if fsm.totalStatsFile != nil {
		if _, err := fsm.totalStatsFile.Write(append(data, '\n')); err != nil {
			fmt.Printf("Error writing total stats: %v\n", err)
		}
	}

	// 写入进程流量统计
	if fsm.processStatsFile != nil {
		if _, err := fsm.processStatsFile.Write(append(data, '\n')); err != nil {
			fmt.Printf("Error writing process stats: %v\n", err)
		}
	}
}

func (fsm *FileStorageManager) rotateFiles(date string) {
	// 关闭旧文件
	if fsm.totalStatsFile != nil {
		fsm.totalStatsFile.Close()
	}
	if fsm.processStatsFile != nil {
		fsm.processStatsFile.Close()
	}

	// 创建新文件
	totalStatsPath := filepath.Join(fsm.baseDir, fmt.Sprintf("total_stats_%s.json", date))
	processStatsPath := filepath.Join(fsm.baseDir, fmt.Sprintf("process_stats_%s.json", date))

	var err error
	fsm.totalStatsFile, err = os.OpenFile(totalStatsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening total stats file: %v\n", err)
	}

	fsm.processStatsFile, err = os.OpenFile(processStatsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening process stats file: %v\n", err)
	}

	fsm.currentDate = date
}

func (fsm *FileStorageManager) Close() {
	close(fsm.writeChan)
	if fsm.totalStatsFile != nil {
		fsm.totalStatsFile.Close()
	}
	if fsm.processStatsFile != nil {
		fsm.processStatsFile.Close()
	}
}

type TrafficTracker struct {
	processStats  map[string]*ProcessStats
	networkStats  *NetworkEventStats
	intervalStats *IntervalStats
	mu            sync.RWMutex
	connTimeout   time.Duration
	fileManager   *FileStorageManager
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
		connTimeout: 30 * time.Second,
		fileManager: NewFileStorageManager("./traffic_stats"),
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

func (tt *TrafficTracker) printStats() {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	// 清理不活跃的连接
	tt.cleanupInactiveConnections()

	// 准备写入文件的数据
	now := time.Now()
	stats := &TrafficStatsFile{
		Date:      now.Format("2006-01-02"),
		Timestamp: now.Format(time.RFC3339),
		Period: struct {
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
		}{
			StartTime: tt.intervalStats.StartTime.Format(time.RFC3339),
			EndTime:   now.Format(time.RFC3339),
		},
		TotalStats:           tt.networkStats,
		IntervalStats:        tt.intervalStats.NetworkStats,
		ProcessStats:         tt.processStats,
		ProcessIntervalStats: tt.intervalStats.ProcessStats,
	}

	// 异步写入文件
	select {
	case tt.fileManager.writeChan <- stats:
		// 成功发送到写入通道
	default:
		// 通道已满，记录错误
		fmt.Printf("Warning: Stats write channel is full, dropping stats\n")
	}

	fmt.Printf("\n==========================================\n")
	fmt.Printf("=== TRAFFIC STATISTICS ===\n")
	fmt.Printf("=== Period: %v - %v ===\n",
		tt.intervalStats.StartTime.Format(time.RFC3339),
		time.Now().Format(time.RFC3339))
	fmt.Printf("==========================================\n")

	// 打印总体网络统计
	if tt.networkStats != nil {
		tt.printNetworkStats(tt.networkStats, tt.intervalStats.NetworkStats)
	}

	// 打印进程统计
	fmt.Printf("\n--- Process Traffic Statistics ---\n")

	// 合并显示所有进程的统计信息
	allProcesses := make(map[string]bool)
	if tt.processStats != nil {
		for k := range tt.processStats {
			allProcesses[k] = true
		}
	}
	if tt.intervalStats != nil && tt.intervalStats.ProcessStats != nil {
		for k := range tt.intervalStats.ProcessStats {
			allProcesses[k] = true
		}
	}

	for processID := range allProcesses {
		cumulativeStats := tt.processStats[processID]
		var intervalStats, lastStats *ProcessStats
		if tt.intervalStats != nil {
			intervalStats = tt.intervalStats.ProcessStats[processID]
			lastStats = tt.intervalStats.LastStats[processID]
		}

		fmt.Printf("\nProcess: %s\n", processID)
		if cumulativeStats != nil {
			if cumulativeStats.ProcessInfo.IsDocker {
				fmt.Printf("  Type: Docker Container\n")
				fmt.Printf("  Container ID: %s\n", cumulativeStats.ProcessInfo.ContainerID)
			} else {
				fmt.Printf("  Type: Host Process\n")
			}
			fmt.Printf("  PID: %d\n", cumulativeStats.ProcessInfo.PID)
			fmt.Printf("  Name: %s\n", cumulativeStats.ProcessInfo.Name)
			fmt.Printf("  Duration: %v\n", time.Since(cumulativeStats.StartTime))

			// 累计统计
			fmt.Printf("  Cumulative Traffic:\n")
			fmt.Printf("    Bytes In:  %d (Packets: %d)\n", cumulativeStats.TotalBytesIn, cumulativeStats.TotalPktsIn)
			fmt.Printf("    Bytes Out: %d (Packets: %d)\n", cumulativeStats.TotalBytesOut, cumulativeStats.TotalPktsOut)
		}

		// 间隔统计
		if intervalStats != nil && lastStats != nil {
			// 计算当前间隔的统计值
			bytesInDiff := intervalStats.TotalBytesIn
			bytesOutDiff := intervalStats.TotalBytesOut
			pktsInDiff := intervalStats.TotalPktsIn
			pktsOutDiff := intervalStats.TotalPktsOut

			if bytesInDiff > 0 || bytesOutDiff > 0 || pktsInDiff > 0 || pktsOutDiff > 0 {
				fmt.Printf("  Interval Traffic:\n")
				fmt.Printf("    Bytes In:  %d (Packets: %d)\n", bytesInDiff, pktsInDiff)
				fmt.Printf("    Bytes Out: %d (Packets: %d)\n", bytesOutDiff, pktsOutDiff)
			}
		}

		// 显示活跃连接
		if cumulativeStats != nil && len(cumulativeStats.Connections) > 0 {
			fmt.Printf("\n  Active Connections:\n")
			for _, conn := range cumulativeStats.Connections {
				if conn == nil {
					continue
				}
				fmt.Printf("    %s:%d -> %s:%d\n",
					conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
				fmt.Printf("      Total Bytes In:  %d (Packets: %d)\n", conn.BytesIn, conn.PktsIn)
				fmt.Printf("      Total Bytes Out: %d (Packets: %d)\n", conn.BytesOut, conn.PktsOut)

				// 显示连接的变化
				if intervalStats != nil && lastStats != nil {
					connKey := getConnectionKey(conn.SrcIP, conn.DstIP, conn.SrcPort, conn.DstPort)
					if intervalConn, exists := intervalStats.Connections[connKey]; exists && intervalConn != nil {
						if lastConn, exists := lastStats.Connections[connKey]; exists && lastConn != nil {
							// 计算当前间隔的统计值
							bytesInDiff := intervalConn.BytesIn
							bytesOutDiff := intervalConn.BytesOut
							pktsInDiff := intervalConn.PktsIn
							pktsOutDiff := intervalConn.PktsOut

							if bytesInDiff > 0 || bytesOutDiff > 0 || pktsInDiff > 0 || pktsOutDiff > 0 {
								fmt.Printf("      Interval Bytes In:  %d (Packets: %d)\n", bytesInDiff, pktsInDiff)
								fmt.Printf("      Interval Bytes Out: %d (Packets: %d)\n", bytesOutDiff, pktsOutDiff)
							}
						}
					}
				}
				fmt.Printf("      Last Seen: %s\n", conn.LastSeen.Format(time.RFC3339))
			}
		}
		fmt.Printf("----------------------------\n")
	}

	// 重置间隔统计
	tt.resetIntervalStats()
}

func (tt *TrafficTracker) printNetworkStats(cumulativeStats, intervalStats *NetworkEventStats) {
	if cumulativeStats == nil {
		return
	}

	fmt.Printf("\n--- Overall Network Event Statistics ---\n")

	// 累计统计
	fmt.Printf("Cumulative Statistics:\n")
	fmt.Printf("TCP:\n")
	fmt.Printf("  Send: %d bytes (%d packets)\n", cumulativeStats.TCPStats.SendBytes, cumulativeStats.TCPStats.SendPkts)
	fmt.Printf("  Recv: %d bytes (%d packets)\n", cumulativeStats.TCPStats.RecvBytes, cumulativeStats.TCPStats.RecvPkts)
	fmt.Printf("UDP:\n")
	fmt.Printf("  Send: %d bytes (%d packets)\n", cumulativeStats.UDPStats.SendBytes, cumulativeStats.UDPStats.SendPkts)
	fmt.Printf("  Recv: %d bytes (%d packets)\n", cumulativeStats.UDPStats.RecvBytes, cumulativeStats.UDPStats.RecvPkts)

	// 间隔统计
	if intervalStats != nil {
		// 计算当前间隔的统计值
		tcpSendDiff := intervalStats.TCPStats.SendBytes
		tcpRecvDiff := intervalStats.TCPStats.RecvBytes
		tcpSendPktsDiff := intervalStats.TCPStats.SendPkts
		tcpRecvPktsDiff := intervalStats.TCPStats.RecvPkts

		udpSendDiff := intervalStats.UDPStats.SendBytes
		udpRecvDiff := intervalStats.UDPStats.RecvBytes
		udpSendPktsDiff := intervalStats.UDPStats.SendPkts
		udpRecvPktsDiff := intervalStats.UDPStats.RecvPkts

		if tcpSendDiff > 0 || tcpRecvDiff > 0 || udpSendDiff > 0 || udpRecvDiff > 0 {
			fmt.Printf("\nInterval Statistics:\n")
			fmt.Printf("TCP:\n")
			fmt.Printf("  Send: %d bytes (%d packets)\n", tcpSendDiff, tcpSendPktsDiff)
			fmt.Printf("  Recv: %d bytes (%d packets)\n", tcpRecvDiff, tcpRecvPktsDiff)
			fmt.Printf("UDP:\n")
			fmt.Printf("  Send: %d bytes (%d packets)\n", udpSendDiff, udpSendPktsDiff)
			fmt.Printf("  Recv: %d bytes (%d packets)\n", udpRecvDiff, udpRecvPktsDiff)
		}
	}

	fmt.Printf("\nLast Updated: %s\n", cumulativeStats.LastSeen.Format(time.RFC3339))
}

func (tt *TrafficTracker) resetIntervalStats() {
	// 保存当前统计作为下一个间隔的基准
	tt.intervalStats.LastStats = make(map[string]*ProcessStats)
	for k, v := range tt.intervalStats.ProcessStats {
		// 创建深拷贝
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
		// 复制连接信息
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
		tt.intervalStats.LastStats[k] = lastStat
	}

	// 重置当前间隔统计
	tt.intervalStats = &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats),
		NetworkStats: &NetworkEventStats{},
		StartTime:    time.Now(),
		LastStats:    tt.intervalStats.LastStats,
	}
}

func main() {
	// 创建流量跟踪器
	trafficTracker := NewTrafficTracker()
	defer trafficTracker.fileManager.Close()

	// 创建定时器，定期打印统计信息
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			trafficTracker.printStats()
		}
	}()

	// 事件处理函数
	eventHandler := func(event ebpf_flow.EBPFevent) {
		trafficTracker.updateStats(event)
	}

	// 初始化 ebpflow
	ebpf := ebpf_flow.NewEbpflow(eventHandler, 0)
	if ebpf == nil {
		fmt.Println("Error initializing ebpflow")
		return
	}
	fmt.Println("Initialized")

	// 处理中断信号
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		gRUNNING = false
		// 打印最终统计信息
		trafficTracker.printStats()
	}()

	// 轮询事件
	for gRUNNING {
		ebpf.PollEvent(10)
	}

	// 清理资源
	ebpf.Close()
}
