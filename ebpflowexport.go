// ebpflowexport.go
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpf_flow "./go"
)

var gRUNNING bool = true
var gLogLevel int = 0 // 0: no logs, 1: errors only, 2: info, 3: debug

// 添加配置常量
const (
	DefaultConnTimeout     = 30 * time.Second // 默认连接超时时间
	DefaultCleanupInterval = 5 * time.Minute  // 默认清理间隔
	MaxStoredProcesses     = 1000             // 最大存储进程数
	MaxStoredConnections   = 5000             // 每个进程最大存储连接数
	MaxStoredIntervals     = 24               // 最大存储间隔数
	LogFilePrefix          = "ebpflow_"       // 日志文件前缀
	LogFileSuffix          = ".log"           // 日志文件后缀
)

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

// 日志文件管理器
type LogFileManager struct {
	currentHour    int
	currentDate    string
	baseDir        string
	cumulativeFile *os.File
	intervalFile   *os.File
	mu             sync.Mutex
	bufferSize     int
}

func NewLogFileManager(baseDir string) *LogFileManager {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		fmt.Printf("Error creating log directory: %v\n", err)
		baseDir = "." // 如果创建目录失败，使用当前目录
	}

	return &LogFileManager{
		baseDir:     baseDir,
		currentHour: time.Now().Hour(),
		currentDate: time.Now().Format("2006-01-02"),
		bufferSize:  8192, // 8KB 缓冲区
	}
}

// 获取当前日志文件名
func (lfm *LogFileManager) getLogFileName(logType string) string {
	now := time.Now()
	return filepath.Join(lfm.baseDir, fmt.Sprintf("%s%s_%s_%02d%s",
		LogFilePrefix,
		logType,
		now.Format("2006-01-02"),
		now.Hour(),
		LogFileSuffix))
}

// 检查是否需要切换日志文件
func (lfm *LogFileManager) shouldRotate() bool {
	now := time.Now()
	return now.Hour() != lfm.currentHour || now.Format("2006-01-02") != lfm.currentDate
}

// 切换日志文件
func (lfm *LogFileManager) rotate() error {
	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	// 关闭当前文件
	if lfm.cumulativeFile != nil {
		lfm.cumulativeFile.Close()
	}
	if lfm.intervalFile != nil {
		lfm.intervalFile.Close()
	}

	// 更新当前时间
	now := time.Now()
	lfm.currentHour = now.Hour()
	lfm.currentDate = now.Format("2006-01-02")

	// 打开新的日志文件
	var err error
	lfm.cumulativeFile, err = os.OpenFile(
		lfm.getLogFileName("cumulative"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("failed to open cumulative log file: %v", err)
	}

	lfm.intervalFile, err = os.OpenFile(
		lfm.getLogFileName("interval"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		lfm.cumulativeFile.Close()
		return fmt.Errorf("failed to open interval log file: %v", err)
	}

	return nil
}

// 写入日志
func (lfm *LogFileManager) writeLog(logType string, content string) error {
	if lfm.shouldRotate() {
		if err := lfm.rotate(); err != nil {
			return err
		}
	}

	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	var file *os.File
	if logType == "cumulative" {
		file = lfm.cumulativeFile
	} else {
		file = lfm.intervalFile
	}

	// 使用缓冲写入
	writer := bufio.NewWriterSize(file, lfm.bufferSize)
	if _, err := writer.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to log file: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush log file: %v", err)
	}
	return nil
}

// 关闭日志文件
func (lfm *LogFileManager) close() {
	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	if lfm.cumulativeFile != nil {
		lfm.cumulativeFile.Close()
	}
	if lfm.intervalFile != nil {
		lfm.intervalFile.Close()
	}
}

type TrafficTracker struct {
	processStats  map[string]*ProcessStats
	networkStats  *NetworkEventStats
	intervalStats *IntervalStats
	mu            sync.RWMutex
	connTimeout   time.Duration
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	intervals     []*IntervalStats // 存储历史间隔数据
	logManager    *LogFileManager
}

func NewTrafficTracker() *TrafficTracker {
	tt := &TrafficTracker{
		processStats: make(map[string]*ProcessStats),
		networkStats: &NetworkEventStats{},
		intervalStats: &IntervalStats{
			ProcessStats: make(map[string]*ProcessStats),
			NetworkStats: &NetworkEventStats{},
			StartTime:    time.Now(),
			LastStats:    make(map[string]*ProcessStats),
		},
		connTimeout: DefaultConnTimeout,
		stopCleanup: make(chan struct{}),
		intervals:   make([]*IntervalStats, 0, MaxStoredIntervals),
		logManager:  NewLogFileManager("logs"), // 创建日志管理器
	}

	// 初始化日志文件
	if err := tt.logManager.rotate(); err != nil {
		fmt.Printf("Error initializing log files: %v\n", err)
	}

	tt.startCleanupRoutine()
	return tt
}

// 启动定期清理协程
func (tt *TrafficTracker) startCleanupRoutine() {
	tt.cleanupTicker = time.NewTicker(DefaultCleanupInterval)
	go func() {
		for {
			select {
			case <-tt.cleanupTicker.C:
				tt.cleanup()
			case <-tt.stopCleanup:
				tt.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// 清理过期和不必要的数据
func (tt *TrafficTracker) cleanup() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now()

	// 1. 清理过期连接
	for _, stats := range tt.processStats {
		// 清理过期连接
		for connKey, conn := range stats.Connections {
			if now.Sub(conn.LastSeen) > tt.connTimeout {
				delete(stats.Connections, connKey)
			}
		}

		// 如果连接数超过限制，删除最旧的连接
		if len(stats.Connections) > MaxStoredConnections {
			// 按最后访问时间排序
			type connWithTime struct {
				key string
				t   time.Time
			}
			conns := make([]connWithTime, 0, len(stats.Connections))
			for k, v := range stats.Connections {
				conns = append(conns, connWithTime{k, v.LastSeen})
			}
			sort.Slice(conns, func(i, j int) bool {
				return conns[i].t.Before(conns[j].t)
			})

			// 删除最旧的连接直到数量在限制内
			for i := 0; i < len(conns)-MaxStoredConnections; i++ {
				delete(stats.Connections, conns[i].key)
			}
		}
	}

	// 2. 清理过期进程
	if len(tt.processStats) > MaxStoredProcesses {
		// 按最后访问时间排序
		type procWithTime struct {
			key string
			t   time.Time
		}
		procs := make([]procWithTime, 0, len(tt.processStats))
		for k, v := range tt.processStats {
			procs = append(procs, procWithTime{k, v.LastSeen})
		}
		sort.Slice(procs, func(i, j int) bool {
			return procs[i].t.Before(procs[j].t)
		})

		// 删除最旧的进程直到数量在限制内
		for i := 0; i < len(procs)-MaxStoredProcesses; i++ {
			delete(tt.processStats, procs[i].key)
		}
	}

	// 3. 清理历史间隔数据
	if len(tt.intervals) > MaxStoredIntervals {
		tt.intervals = tt.intervals[len(tt.intervals)-MaxStoredIntervals:]
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

func (tt *TrafficTracker) writeStatsToFile(logType string, content string) error {
	return tt.logManager.writeLog(logType, content)
}

func (tt *TrafficTracker) formatStatsForFile() error {
	tt.mu.RLock()
	defer tt.mu.RUnlock()

	now := time.Now()

	// 写入间隔统计
	intervalContent := fmt.Sprintf("\n==========================================\n"+
		"INTERVAL NETWORK TRAFFIC STATISTICS\n"+
		"Period: %v - %v\n"+
		"==========================================\n\n",
		tt.intervalStats.StartTime.Format(time.RFC3339),
		now.Format(time.RFC3339))

	if err := tt.writeStatsToFile("interval", intervalContent); err != nil {
		return err
	}

	// 写入网络统计
	if tt.intervalStats.NetworkStats != nil {
		networkStats := fmt.Sprintf("NETWORK STATISTICS\n"+
			"-----------------\n"+
			"TCP Traffic:\n"+
			"  Outbound: %d bytes (%d packets)\n"+
			"  Inbound:  %d bytes (%d packets)\n"+
			"UDP Traffic:\n"+
			"  Outbound: %d bytes (%d packets)\n"+
			"  Inbound:  %d bytes (%d packets)\n",
			tt.intervalStats.NetworkStats.TCPStats.SendBytes,
			tt.intervalStats.NetworkStats.TCPStats.SendPkts,
			tt.intervalStats.NetworkStats.TCPStats.RecvBytes,
			tt.intervalStats.NetworkStats.TCPStats.RecvPkts,
			tt.intervalStats.NetworkStats.UDPStats.SendBytes,
			tt.intervalStats.NetworkStats.UDPStats.SendPkts,
			tt.intervalStats.NetworkStats.UDPStats.RecvBytes,
			tt.intervalStats.NetworkStats.UDPStats.RecvPkts)

		if err := tt.writeStatsToFile("interval", networkStats); err != nil {
			return err
		}
	}

	// 写入累计统计
	cumulativeContent := fmt.Sprintf("\n==========================================\n"+
		"CUMULATIVE TRAFFIC STATISTICS\n"+
		"Generated at: %v\n"+
		"==========================================\n\n",
		now.Format(time.RFC3339))

	if err := tt.writeStatsToFile("cumulative", cumulativeContent); err != nil {
		return err
	}

	// 写入网络统计
	if tt.networkStats != nil {
		networkStats := fmt.Sprintf("NETWORK STATISTICS\n"+
			"-----------------\n"+
			"TCP Traffic:\n"+
			"  Outbound: %d bytes (%d packets)\n"+
			"  Inbound:  %d bytes (%d packets)\n"+
			"UDP Traffic:\n"+
			"  Outbound: %d bytes (%d packets)\n"+
			"  Inbound:  %d bytes (%d packets)\n\n",
			tt.networkStats.TCPStats.SendBytes,
			tt.networkStats.TCPStats.SendPkts,
			tt.networkStats.TCPStats.RecvBytes,
			tt.networkStats.TCPStats.RecvPkts,
			tt.networkStats.UDPStats.SendBytes,
			tt.networkStats.UDPStats.SendPkts,
			tt.networkStats.UDPStats.RecvBytes,
			tt.networkStats.UDPStats.RecvPkts)

		if err := tt.writeStatsToFile("cumulative", networkStats); err != nil {
			return err
		}
	}

	// 写入进程统计
	if err := tt.writeStatsToFile("cumulative", "PROCESS STATISTICS\n-----------------\n"); err != nil {
		return err
	}

	for processID, stats := range tt.processStats {
		processHeader := fmt.Sprintf("\nProcess: %s\n", processID)
		if err := tt.writeStatsToFile("cumulative", processHeader); err != nil {
			return err
		}

		processInfo := fmt.Sprintf("  Type: %s\n"+
			"  PID: %d\n"+
			"  Name: %s\n"+
			"  Running Time: %v\n"+
			"  Traffic:\n"+
			"    Inbound:  %d bytes (%d packets)\n"+
			"    Outbound: %d bytes (%d packets)\n",
			func() string {
				if stats.ProcessInfo.IsDocker {
					return fmt.Sprintf("Docker Container\n  Container ID: %s", stats.ProcessInfo.ContainerID)
				}
				return "Host Process"
			}(),
			stats.ProcessInfo.PID,
			stats.ProcessInfo.Name,
			time.Since(stats.StartTime).Round(time.Second),
			stats.TotalBytesIn,
			stats.TotalPktsIn,
			stats.TotalBytesOut,
			stats.TotalPktsOut)

		if err := tt.writeStatsToFile("cumulative", processInfo); err != nil {
			return err
		}

		// 写入连接信息
		if len(stats.Connections) > 0 {
			if err := tt.writeStatsToFile("cumulative", "  Active Connections:\n"); err != nil {
				return err
			}

			for _, conn := range stats.Connections {
				if conn == nil {
					continue
				}
				connInfo := fmt.Sprintf("    %s:%d -> %s:%d\n"+
					"      Inbound:  %d bytes (%d packets)\n"+
					"      Outbound: %d bytes (%d packets)\n"+
					"      Last Seen: %s\n",
					conn.SrcIP, conn.SrcPort,
					conn.DstIP, conn.DstPort,
					conn.BytesIn, conn.PktsIn,
					conn.BytesOut, conn.PktsOut,
					conn.LastSeen.Format(time.RFC3339))

				if err := tt.writeStatsToFile("cumulative", connInfo); err != nil {
					return err
				}
			}
		}
		if err := tt.writeStatsToFile("cumulative", "-----------------\n"); err != nil {
			return err
		}
	}

	return nil
}

func (tt *TrafficTracker) printStats() {
	// 先清理不活跃的连接
	tt.cleanup()

	// 格式化并写入统计数据
	if err := tt.formatStatsForFile(); err != nil {
		fmt.Printf("Error writing stats: %v\n", err)
	}

	// 重置间隔统计
	tt.resetIntervalStats()
}

func (tt *TrafficTracker) resetIntervalStats() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	// 保存当前间隔到历史记录
	tt.intervals = append(tt.intervals, tt.intervalStats)
	if len(tt.intervals) > MaxStoredIntervals {
		tt.intervals = tt.intervals[1:]
	}

	// 创建新的间隔统计
	lastStats := make(map[string]*ProcessStats)
	for k, v := range tt.intervalStats.ProcessStats {
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

		// 只复制活跃的连接
		for connKey, conn := range v.Connections {
			if time.Since(conn.LastSeen) <= tt.connTimeout {
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
		}
		lastStats[k] = lastStat
	}

	tt.intervalStats = &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats),
		NetworkStats: &NetworkEventStats{},
		StartTime:    time.Now(),
		LastStats:    lastStats,
	}
}

func main() {
	trafficTracker := NewTrafficTracker()

	// 事件处理函数
	eventHandler := func(event ebpf_flow.EBPFevent) {
		trafficTracker.updateStats(event)
	}

	// 创建定时器，定期打印统计信息
	// 计算到下一个5秒整点的延迟
	now := time.Now()
	nextTick := now.Truncate(5 * time.Second).Add(5 * time.Second)
	initialDelay := nextTick.Sub(now)

	// 先等待到下一个5秒整点
	time.Sleep(initialDelay)

	// 然后开始5秒间隔的计时
	ticker := time.NewTicker(5 * time.Second)
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
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		gRUNNING = false
		// 停止清理协程
		close(trafficTracker.stopCleanup)
		// 最后一次清理
		trafficTracker.cleanup()
		// 关闭日志文件
		trafficTracker.logManager.close()
	}()

	// 轮询事件
	for gRUNNING == true {
		ebpf.PollEvent(10)
	}

	// 清理资源
	ebpf.Close()
}
