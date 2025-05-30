// ebpflowexport.go
//go:build cgo
// +build cgo

package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ebpf_flow "./go"
)

var gRUNNING bool = true
var gLogLevel int = 2 // 设置为debug级别

// 修改常量定义，增加更细粒度的控制
const (
	DefaultConnTimeout      = 30 * time.Second     // 默认连接超时时间
	DefaultCleanupInterval  = 1 * time.Minute      // 减少清理间隔到1分钟
	MaxStoredProcesses      = 500                  // 减少最大存储进程数到500
	MaxStoredConnections    = 2000                 // 减少每个进程最大存储连接数到2000
	MaxStoredIntervals      = 6                    // 减少存储的间隔数到6个（30分钟）
	LogFilePrefix           = "ebpflow_"           // 日志文件前缀
	LogFileSuffix           = ".log"               // 日志文件后缀
	MaxLogFileSize          = 50 * 1024 * 1024     // 减少最大日志文件大小到50MB
	LogBufferSize           = 16 * 1024            // 减少日志缓冲区大小到16KB
	EventBufferSize         = 1024 * 1024 * 2      // 减少到2MB
	EventBatchSize          = 1000                 // 减少批处理大小到1000
	EventProcessTimeoutMs   = 200                  // 处理超时时间
	EventProcessInterval    = 2 * time.Millisecond // 处理间隔
	MaxMemoryUsage          = 1024 * 1024 * 1024   // 1GB 最大内存使用
	MemoryWarningThreshold  = 768 * 1024 * 1024    // 768MB 内存警告阈值
	MemoryCriticalThreshold = 896 * 1024 * 1024    // 896MB 内存临界阈值

	// 新增常量
	NumWorkerGoroutines   = 8     // 减少工作协程数量到8
	EventQueueSize        = 50000 // 减少队列大小到5万
	EventDropThreshold    = 2000  // 减少丢弃阈值到2000
	EventProcessBatchSize = 1000  // 减少事件批处理大小到1000

	// 系统负载相关常量
	MaxSystemLoad     = 80.0                   // 最大系统负载百分比
	LoadCheckInterval = 5 * time.Second        // 负载检查间隔
	MinIdleTime       = 100 * time.Millisecond // 最小空闲时间

	// 事件过滤相关常量
	MinPacketSize    = 64                   // 最小数据包大小
	MaxPacketSize    = 1500                 // 最大数据包大小
	MinEventInterval = 1 * time.Millisecond // 最小事件间隔

	// 清理策略
	AggressiveCleanupThreshold = 768 * 1024 * 1024 // 768MB 触发激进清理
	EmergencyCleanupThreshold  = 896 * 1024 * 1024 // 896MB 触发紧急清理

	// 监控间隔
	MemoryCheckInterval = 15 * time.Second // 减少内存检查间隔到15秒
	CleanupInterval     = 30 * time.Second // 减少清理间隔到30秒

	// 日志文件配置
	LogFileMaxSize    = 50 * 1024 * 1024 // 50MB
	LogFileMaxAge     = 12 * time.Hour   // 12小时
	LogFileMaxBackups = 3                // 保留3个备份
	LogFileCompress   = true             // 压缩旧日志
	LogFileLocalTime  = true             // 使用本地时间
	LogFileBufferSize = 16 * 1024        // 16KB 缓冲区

	// 添加智能清理相关常量
	MinCleanupInterval    = 15 * time.Second // 最小清理间隔
	MaxCleanupInterval    = 2 * time.Minute  // 最大清理间隔
	CleanupIntervalStep   = 15 * time.Second // 清理间隔调整步长
	AdaptiveCleanupWindow = 5                // 自适应清理窗口大小

	// 事件类型常量
	eTCP_ACPT      = 100
	eTCP_CONN      = 101
	eTCP_RETR      = 200
	eUDP_RECV      = 210
	eUDP_SEND      = 211
	eTCP_CLOSE     = 300
	eTCP_CONN_FAIL = 500
	eTCP_SEND      = 600
	eTCP_RECV      = 601
)

// 新增事件优先级结构
type EventPriority int

const (
	PriorityHigh EventPriority = iota
	PriorityNormal
	PriorityLow
)

// 新增事件结构
type Event struct {
	Data     ebpf_flow.EBPFevent
	Priority EventPriority
	Time     time.Time
}

// 新增事件队列结构
type EventQueue struct {
	highPriority   chan Event
	normalPriority chan Event
	lowPriority    chan Event
	stop           chan struct{}
}

// 新增事件处理器结构
type EventProcessor struct {
	queues     []*EventQueue
	workers    []*EventWorker
	stop       chan struct{}
	wg         sync.WaitGroup
	stats      *EventStats
	memMonitor *MemoryMonitor
	tracker    *TrafficTracker
	procStats  *EventProcessingStats
}

// 新增事件工作器结构
type EventWorker struct {
	id        int
	queue     *EventQueue
	stop      chan struct{}
	stats     *EventStats
	processor *EventProcessor
}

// 连接信息结构
type ConnectionInfo struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	BytesIn  uint64
	BytesOut uint64
	PktsIn   uint32
	PktsOut  uint32
	LastSeen int64
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
	TotalPktsIn   uint32
	TotalPktsOut  uint32
	LastSeen      int64
	StartTime     int64
	Connections   map[string]*ConnectionInfo
	ProcessInfo   ProcessInfo
}

// 总体网络事件统计结构
type NetworkEventStats struct {
	TCPStats struct {
		SendBytes uint64
		RecvBytes uint64
		SendPkts  uint32
		RecvPkts  uint32
	}
	UDPStats struct {
		SendBytes uint64
		RecvBytes uint64
		SendPkts  uint32
		RecvPkts  uint32
	}
	LastSeen int64
}

// 时间间隔统计结构
type IntervalStats struct {
	ProcessStats map[string]*ProcessStats
	NetworkStats *NetworkEventStats
	StartTime    int64
	EndTime      int64
	LastStats    map[string]*ProcessStats
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
	currentSize    int64
	writer         *bufio.Writer
	backupCount    int
	lastRotate     int64
}

func NewLogFileManager(baseDir string) *LogFileManager {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		fmt.Printf("Error creating log directory: %v\n", err)
		baseDir = "." // 如果创建目录失败，使用当前目录
	}

	lfm := &LogFileManager{
		baseDir:     baseDir,
		currentHour: time.Now().Hour(),
		currentDate: time.Now().Format("2006-01-02"),
		bufferSize:  LogFileBufferSize,
		lastRotate:  time.Now().Unix(),
	}

	// 初始化文件
	if err := lfm.rotate(); err != nil {
		fmt.Printf("Error initializing log files: %v\n", err)
	}

	// 启动日志清理协程
	go lfm.startLogCleanup()

	return lfm
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

// 添加日志清理协程
func (lfm *LogFileManager) startLogCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lfm.cleanupOldLogs()
		}
	}
}

// 清理旧日志文件
func (lfm *LogFileManager) cleanupOldLogs() {
	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	// 获取所有日志文件
	files, err := filepath.Glob(filepath.Join(lfm.baseDir, LogFilePrefix+"*"+LogFileSuffix))
	if err != nil {
		return
	}

	// 按修改时间排序
	sort.Slice(files, func(i, j int) bool {
		info1, _ := os.Stat(files[i])
		info2, _ := os.Stat(files[j])
		return info1.ModTime().After(info2.ModTime())
	})

	// 删除超出备份数量的旧文件
	if len(files) > LogFileMaxBackups {
		for _, file := range files[LogFileMaxBackups:] {
			os.Remove(file)
		}
	}

	// 压缩旧日志文件
	if LogFileCompress {
		for _, file := range files {
			if !strings.HasSuffix(file, ".gz") {
				go lfm.compressLogFile(file)
			}
		}
	}
}

// 压缩日志文件
func (lfm *LogFileManager) compressLogFile(file string) {
	// 检查文件是否存在
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return
	}

	// 创建压缩文件
	gzFile := file + ".gz"
	gzWriter, err := os.Create(gzFile)
	if err != nil {
		return
	}
	defer gzWriter.Close()

	// 打开源文件
	srcFile, err := os.Open(file)
	if err != nil {
		return
	}
	defer srcFile.Close()

	// 创建gzip写入器
	gzipWriter := gzip.NewWriter(gzWriter)
	defer gzipWriter.Close()

	// 复制并压缩
	if _, err := io.Copy(gzipWriter, srcFile); err != nil {
		return
	}

	// 删除原文件
	os.Remove(file)
}

// 优化轮转检查
func (lfm *LogFileManager) shouldRotate() bool {
	now := time.Now()

	// 检查时间
	if now.Hour() != lfm.currentHour ||
		now.Format("2006-01-02") != lfm.currentDate {
		return true
	}

	// 检查文件大小
	if lfm.currentSize > LogFileMaxSize {
		return true
	}

	// 检查是否到达整点
	if now.Minute() == 0 && now.Second() == 0 {
		return true
	}

	return false
}

// 优化轮转方法
func (lfm *LogFileManager) rotate() error {
	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	// 关闭当前文件
	if lfm.cumulativeFile != nil {
		lfm.writer.Flush()
		lfm.cumulativeFile.Close()
	}
	if lfm.intervalFile != nil {
		lfm.intervalFile.Close()
	}

	// 更新当前时间
	now := time.Now()
	lfm.currentHour = now.Hour()
	lfm.currentDate = now.Format("2006-01-02")
	lfm.lastRotate = now.Unix()

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

	// 创建新的writer
	lfm.writer = bufio.NewWriterSize(lfm.cumulativeFile, lfm.bufferSize)
	lfm.currentSize = 0
	lfm.backupCount++

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
	var writer *bufio.Writer
	if logType == "cumulative" {
		file = lfm.cumulativeFile
		writer = lfm.writer
	} else {
		file = lfm.intervalFile
		writer = bufio.NewWriterSize(file, lfm.bufferSize)
	}

	// 检查文件大小
	if lfm.currentSize > MaxLogFileSize {
		if err := lfm.rotate(); err != nil {
			return err
		}
		if logType == "cumulative" {
			file = lfm.cumulativeFile
			writer = lfm.writer
		} else {
			file = lfm.intervalFile
			writer = bufio.NewWriterSize(file, lfm.bufferSize)
		}
	}

	// 使用缓冲写入
	if _, err := writer.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to log file: %v", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush log file: %v", err)
	}

	// 更新文件大小
	lfm.currentSize += int64(len(content))
	return nil
}

// 关闭日志文件
func (lfm *LogFileManager) close() {
	lfm.mu.Lock()
	defer lfm.mu.Unlock()

	if lfm.writer != nil {
		lfm.writer.Flush()
	}
	if lfm.cumulativeFile != nil {
		lfm.cumulativeFile.Close()
	}
	if lfm.intervalFile != nil {
		lfm.intervalFile.Close()
	}
}

// 添加事件统计结构
type EventStats struct {
	TotalEvents     uint64
	LostEvents      uint64
	ProcessedEvents uint64
	LastReport      time.Time
	mu              sync.Mutex
}

// 添加事件处理统计结构
type EventProcessingStats struct {
	TotalEvents     uint64
	ProcessedEvents uint64
	LostEvents      uint64
	ProcessingTime  time.Duration
	LastUpdate      time.Time
	mu              sync.Mutex
}

func (es *EventStats) Update(total, lost uint64) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.TotalEvents = total
	es.LostEvents = lost
	es.ProcessedEvents = total - lost
}

func (es *EventStats) GetStats() (uint64, uint64, uint64) {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.TotalEvents, es.LostEvents, es.ProcessedEvents
}

// 添加内存监控结构
type MemoryMonitor struct {
	lastCheck     int64
	lastCleanup   int64
	cleanupCount  int
	warningCount  int
	criticalCount int
	mu            sync.Mutex
}

// 添加内存监控方法
func (mm *MemoryMonitor) checkMemory() (bool, bool) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	mm.mu.Lock()
	defer mm.mu.Unlock()

	now := time.Now().Unix()
	mm.lastCheck = now

	// 检查是否需要清理
	needCleanup := false
	needEmergency := false

	// 使用更激进的内存阈值
	if m.Alloc > uint64(MemoryCriticalThreshold) {
		mm.criticalCount++
		needEmergency = true
		needCleanup = true
	} else if m.Alloc > uint64(MemoryWarningThreshold) {
		mm.warningCount++
		needCleanup = true
	}

	return needCleanup, needEmergency
}

// 添加智能清理结构
type AdaptiveCleanup struct {
	intervals    []time.Duration // 最近的清理间隔
	lastCleanup  int64           // 上次清理时间
	cleanupCount int             // 清理次数
	successCount int             // 成功清理次数
	mu           sync.Mutex
}

// 添加智能清理方法
func (ac *AdaptiveCleanup) updateInterval(success bool) time.Duration {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	now := time.Now().Unix()
	if ac.lastCleanup > 0 {
		interval := time.Duration(now-ac.lastCleanup) * time.Second
		ac.intervals = append(ac.intervals, interval)
		if len(ac.intervals) > AdaptiveCleanupWindow {
			ac.intervals = ac.intervals[1:]
		}
	}
	ac.lastCleanup = now

	if success {
		ac.successCount++
	}
	ac.cleanupCount++

	// 计算平均清理间隔
	var avgInterval time.Duration
	if len(ac.intervals) > 0 {
		var total time.Duration
		for _, interval := range ac.intervals {
			total += interval
		}
		avgInterval = total / time.Duration(len(ac.intervals))
	} else {
		avgInterval = DefaultCleanupInterval
	}

	// 根据清理成功率调整间隔
	successRate := float64(ac.successCount) / float64(ac.cleanupCount)
	if successRate > 0.8 {
		// 如果清理成功率高，增加间隔
		avgInterval += CleanupIntervalStep
	} else if successRate < 0.5 {
		// 如果清理成功率低，减少间隔
		avgInterval -= CleanupIntervalStep
	}

	// 确保间隔在合理范围内
	if avgInterval < MinCleanupInterval {
		avgInterval = MinCleanupInterval
	} else if avgInterval > MaxCleanupInterval {
		avgInterval = MaxCleanupInterval
	}

	return avgInterval
}

// 添加系统负载监控结构
type SystemLoadMonitor struct {
	lastCheck   time.Time
	currentLoad float64
	mu          sync.RWMutex
	stop        chan struct{}
}

// 添加事件过滤器结构
type EventFilter struct {
	lastEventTime time.Time
	mu            sync.Mutex
}

// 创建新的系统负载监控器
func NewSystemLoadMonitor() *SystemLoadMonitor {
	return &SystemLoadMonitor{
		lastCheck: time.Now(),
		stop:      make(chan struct{}),
	}
}

// 启动系统负载监控
func (slm *SystemLoadMonitor) Start() {
	go func() {
		ticker := time.NewTicker(LoadCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				slm.updateLoad()
			case <-slm.stop:
				return
			}
		}
	}()
}

// 更新系统负载
func (slm *SystemLoadMonitor) updateLoad() {
	// 读取系统负载
	load, err := getSystemLoad()
	if err != nil {
		return
	}

	slm.mu.Lock()
	slm.currentLoad = load
	slm.lastCheck = time.Now()
	slm.mu.Unlock()
}

// 获取当前系统负载
func (slm *SystemLoadMonitor) GetCurrentLoad() float64 {
	slm.mu.RLock()
	defer slm.mu.RUnlock()
	return slm.currentLoad
}

// 检查系统是否过载
func (slm *SystemLoadMonitor) IsOverloaded() bool {
	return slm.GetCurrentLoad() > MaxSystemLoad
}

// 停止监控
func (slm *SystemLoadMonitor) Stop() {
	close(slm.stop)
}

// 创建新的事件过滤器
func NewEventFilter() *EventFilter {
	return &EventFilter{
		lastEventTime: time.Now(),
	}
}

// 检查事件是否应该被过滤
func (ef *EventFilter) ShouldFilter(event ebpf_flow.EBPFevent) bool {
	ef.mu.Lock()
	defer ef.mu.Unlock()

	now := time.Now()

	// 检查事件间隔
	if now.Sub(ef.lastEventTime) < MinEventInterval {
		return true
	}

	// 检查数据包大小
	if event.Len < MinPacketSize || event.Len > MaxPacketSize {
		return true
	}

	ef.lastEventTime = now
	return false
}

type TrafficTracker struct {
	processStats  map[string]*ProcessStats
	networkStats  *NetworkEventStats
	intervalStats *IntervalStats
	mu            sync.RWMutex
	connTimeout   time.Duration
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
	intervals     []*IntervalStats
	logManager    *LogFileManager
	lastCleanup   int64
	memStats      struct {
		totalConnections int
		totalProcesses   int
		lastReport       int64
	}
	eventStats      *EventStats
	eventChan       chan ebpf_flow.EBPFevent
	eventStop       chan struct{}
	eventWg         sync.WaitGroup
	memMonitor      *MemoryMonitor
	adaptiveCleanup *AdaptiveCleanup
	eventProcessor  *EventProcessor
	loadMonitor     *SystemLoadMonitor
	eventFilter     *EventFilter
}

// 添加对象池来重用ConnectionInfo对象
var connectionInfoPool = sync.Pool{
	New: func() interface{} {
		return &ConnectionInfo{}
	},
}

// 获取ConnectionInfo对象
func getConnectionInfo() *ConnectionInfo {
	return connectionInfoPool.Get().(*ConnectionInfo)
}

// 归还ConnectionInfo对象
func putConnectionInfo(conn *ConnectionInfo) {
	// 重置对象状态
	conn.BytesIn = 0
	conn.BytesOut = 0
	conn.PktsIn = 0
	conn.PktsOut = 0
	conn.LastSeen = 0
	connectionInfoPool.Put(conn)
}

func NewTrafficTracker() *TrafficTracker {
	tt := &TrafficTracker{
		processStats: make(map[string]*ProcessStats), // 不预分配容量
		networkStats: &NetworkEventStats{},
		intervalStats: &IntervalStats{
			ProcessStats: make(map[string]*ProcessStats), // 不预分配容量
			NetworkStats: &NetworkEventStats{},
			StartTime:    time.Now().Unix(),
			LastStats:    make(map[string]*ProcessStats), // 不预分配容量
		},
		connTimeout: DefaultConnTimeout,
		stopCleanup: make(chan struct{}),
		intervals:   make([]*IntervalStats, 0, MaxStoredIntervals),
		logManager:  NewLogFileManager("logs"),
		lastCleanup: time.Now().Unix(),
		eventStats: &EventStats{
			LastReport: time.Now(),
		},
		eventChan:  make(chan ebpf_flow.EBPFevent, EventBufferSize),
		eventStop:  make(chan struct{}),
		memMonitor: &MemoryMonitor{},
		adaptiveCleanup: &AdaptiveCleanup{
			intervals: make([]time.Duration, 0, AdaptiveCleanupWindow),
		},
		loadMonitor: NewSystemLoadMonitor(),
		eventFilter: NewEventFilter(),
	}

	// 初始化事件处理器
	tt.eventProcessor = NewEventProcessor(NumWorkerGoroutines, tt)

	if err := tt.logManager.rotate(); err != nil {
		fmt.Printf("Error initializing log files: %v\n", err)
	}

	// 启动系统负载监控
	tt.loadMonitor.Start()

	tt.startCleanupRoutine()
	tt.startEventProcessor()
	tt.startMemoryMonitor()

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

// 启动事件处理协程
func (tt *TrafficTracker) startEventProcessor() {
	tt.eventWg.Add(1)
	go func() {
		defer tt.eventWg.Done()
		batch := make([]ebpf_flow.EBPFevent, 0, EventBatchSize)
		ticker := time.NewTicker(time.Millisecond * 100)
		defer ticker.Stop()

		// 添加内存监控
		memTicker := time.NewTicker(5 * time.Minute)
		defer memTicker.Stop()

		for {
			select {
			case <-tt.eventStop:
				// 处理剩余的事件
				if len(batch) > 0 {
					tt.processEventBatch(batch)
				}
				return
			case event := <-tt.eventChan:
				batch = append(batch, event)
				if len(batch) >= EventBatchSize {
					tt.processEventBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					tt.processEventBatch(batch)
					batch = batch[:0]
				}
			case <-memTicker.C:
				// 检查内存使用情况
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.Alloc > 1024*1024*1024 { // 如果内存使用超过1GB
					// 触发紧急清理
					tt.cleanup()
					// 强制GC
					runtime.GC()
				}
			}
		}
	}()
}

// 添加内存监控协程
func (tt *TrafficTracker) startMemoryMonitor() {
	go func() {
		ticker := time.NewTicker(MemoryCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				needCleanup, needEmergency := tt.memMonitor.checkMemory()
				if needCleanup {
					if needEmergency {
						tt.emergencyCleanup()
					} else {
						tt.cleanup()
					}
				}
			case <-tt.eventStop:
				return
			}
		}
	}()
}

// 清理过期和不必要的数据
func (tt *TrafficTracker) cleanup() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now().Unix()
	if now-tt.lastCleanup < int64(DefaultCleanupInterval.Seconds()) {
		return // 避免过于频繁的清理
	}

	// 记录清理前的内存使用
	var beforeMem runtime.MemStats
	runtime.ReadMemStats(&beforeMem)

	// 执行清理
	activeConnections := 0
	activeProcesses := 0

	// 1. 清理过期连接
	for pid, stats := range tt.processStats {
		// 清理过期连接
		for connKey, conn := range stats.Connections {
			if now-conn.LastSeen > int64(tt.connTimeout.Seconds()) {
				delete(stats.Connections, connKey)
				putConnectionInfo(conn) // 归还对象到对象池
				continue
			}
			activeConnections++
		}

		// 如果连接数超过限制，删除最旧的连接
		if len(stats.Connections) > MaxStoredConnections {
			conns := make([]struct {
				key string
				t   int64
			}, 0, len(stats.Connections))

			for k, v := range stats.Connections {
				conns = append(conns, struct {
					key string
					t   int64
				}{k, v.LastSeen})
			}

			sort.Slice(conns, func(i, j int) bool {
				return conns[i].t < conns[j].t
			})

			// 删除最旧的连接直到数量在限制内
			for i := 0; i < len(conns)-MaxStoredConnections; i++ {
				conn := stats.Connections[conns[i].key]
				delete(stats.Connections, conns[i].key)
				putConnectionInfo(conn) // 归还对象到对象池
			}
			activeConnections = len(stats.Connections)
		}

		// 如果进程没有活跃连接或超过最大存储时间，删除进程
		if len(stats.Connections) == 0 || now-stats.LastSeen > int64(tt.connTimeout.Seconds()*2) {
			delete(tt.processStats, pid)
			continue
		}
		activeProcesses++
	}

	// 2. 清理历史间隔数据
	if len(tt.intervals) > MaxStoredIntervals {
		tt.intervals = tt.intervals[len(tt.intervals)-MaxStoredIntervals:]
	}

	// 3. 强制GC
	runtime.GC()

	// 记录清理后的内存使用
	var afterMem runtime.MemStats
	runtime.ReadMemStats(&afterMem)

	// 计算内存释放量
	memoryFreed := beforeMem.Alloc - afterMem.Alloc
	cleanupSuccess := memoryFreed > 0

	// 更新清理间隔
	nextInterval := tt.adaptiveCleanup.updateInterval(cleanupSuccess)
	tt.cleanupTicker.Reset(nextInterval)

	// 更新统计
	tt.memStats.totalConnections = activeConnections
	tt.memStats.totalProcesses = activeProcesses
	tt.memStats.lastReport = now
	tt.lastCleanup = now

	// 如果距离上次报告超过30分钟，输出内存使用情况
	if now-tt.memStats.lastReport > 1800 {
		fmt.Printf("Memory stats - Active connections: %d, Active processes: %d, Alloc: %v MiB, Sys: %v MiB, Memory freed: %v MiB\n",
			tt.memStats.totalConnections, tt.memStats.totalProcesses,
			afterMem.Alloc/1024/1024, afterMem.Sys/1024/1024,
			memoryFreed/1024/1024)
	}
}

// 添加紧急清理方法
func (tt *TrafficTracker) emergencyCleanup() {
	tt.mu.Lock()
	defer tt.mu.Unlock()

	now := time.Now().Unix()

	// 1. 清理所有过期连接
	for pid, stats := range tt.processStats {
		// 清理过期连接
		for connKey, conn := range stats.Connections {
			if now-conn.LastSeen > int64(tt.connTimeout.Seconds()/2) { // 更激进的超时
				delete(stats.Connections, connKey)
				putConnectionInfo(conn) // 归还对象到对象池
			}
		}

		// 如果连接数超过限制的一半，删除最旧的连接
		if len(stats.Connections) > MaxStoredConnections/2 {
			conns := make([]struct {
				key string
				t   int64
			}, 0, len(stats.Connections))

			for k, v := range stats.Connections {
				conns = append(conns, struct {
					key string
					t   int64
				}{k, v.LastSeen})
			}

			sort.Slice(conns, func(i, j int) bool {
				return conns[i].t < conns[j].t
			})

			// 删除一半的连接
			for i := 0; i < len(conns)/2; i++ {
				conn := stats.Connections[conns[i].key]
				delete(stats.Connections, conns[i].key)
				putConnectionInfo(conn) // 归还对象到对象池
			}
		}

		// 如果进程没有活跃连接，立即删除
		if len(stats.Connections) == 0 {
			delete(tt.processStats, pid)
		}
	}

	// 2. 清理历史间隔数据
	if len(tt.intervals) > MaxStoredIntervals/2 {
		tt.intervals = tt.intervals[len(tt.intervals)-MaxStoredIntervals/2:]
	}

	// 3. 强制GC
	runtime.GC()
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

	now := time.Now().Unix()

	// 更新累计统计
	processID := getProcessIdentifier(event.Proc)
	stats, exists := tt.processStats[processID]
	if !exists {
		containerID := ""
		if strings.Contains(event.Proc.Full_Task_Path, "docker") {
			containerID = extractContainerID(event.Proc.Full_Task_Path)
		}

		stats = &ProcessStats{
			StartTime:   now,
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
			StartTime:   now,
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
		conn = getConnectionInfo()
		conn.SrcIP = event.Saddr
		conn.DstIP = event.Daddr
		conn.SrcPort = event.Sport
		conn.DstPort = event.Dport
		stats.Connections[connKey] = conn
	}

	// 更新间隔统计的连接
	intervalConn, exists := intervalStats.Connections[connKey]
	if !exists {
		intervalConn = getConnectionInfo()
		intervalConn.SrcIP = event.Saddr
		intervalConn.DstIP = event.Daddr
		intervalConn.SrcPort = event.Sport
		intervalConn.DstPort = event.Dport
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

	conn.LastSeen = now
	stats.LastSeen = now
	tt.networkStats.LastSeen = now

	intervalConn.LastSeen = now
	intervalStats.LastSeen = now
	tt.intervalStats.NetworkStats.LastSeen = now
}

func (tt *TrafficTracker) processEventBatch(events []ebpf_flow.EBPFevent) {
	type eventKey struct {
		pid     string
		connKey string
	}

	// 使用预分配的map来减少扩容
	updates := make(map[eventKey]*ConnectionInfo, len(events))

	now := time.Now().Unix()

	// 添加调试日志
	if gLogLevel > 2 {
		fmt.Printf("Processing batch of %d events\n", len(events))
	}

	for _, event := range events {
		processID := getProcessIdentifier(event.Proc)
		connKey := getConnectionKey(event.Saddr, event.Daddr, event.Sport, event.Dport)

		// 添加调试日志
		if gLogLevel > 2 {
			fmt.Printf("Event: Type=%d, Process=%s, Conn=%s, Len=%d\n",
				event.EType, processID, connKey, event.Len)
		}

		key := eventKey{pid: processID, connKey: connKey}
		conn, exists := updates[key]
		if !exists {
			conn = getConnectionInfo()
			conn.SrcIP = event.Saddr
			conn.DstIP = event.Daddr
			conn.SrcPort = event.Sport
			conn.DstPort = event.Dport
			updates[key] = conn
		}

		// 更新连接统计
		switch event.EType {
		case 600: // eTCP_SEND
			conn.PktsOut++
			conn.BytesOut += uint64(event.Len)
			tt.networkStats.TCPStats.SendBytes += uint64(event.Len)
			tt.networkStats.TCPStats.SendPkts++
		case 601: // eTCP_RECV
			conn.PktsIn++
			conn.BytesIn += uint64(event.Len)
			tt.networkStats.TCPStats.RecvBytes += uint64(event.Len)
			tt.networkStats.TCPStats.RecvPkts++
		case 700: // eUDP_SEND
			conn.PktsOut++
			conn.BytesOut += uint64(event.Len)
			tt.networkStats.UDPStats.SendBytes += uint64(event.Len)
			tt.networkStats.UDPStats.SendPkts++
		case 701: // eUDP_RECV
			conn.PktsIn++
			conn.BytesIn += uint64(event.Len)
			tt.networkStats.UDPStats.RecvBytes += uint64(event.Len)
			tt.networkStats.UDPStats.RecvPkts++
		}
		conn.LastSeen = now
	}

	// 批量更新到主数据结构
	tt.mu.Lock()
	defer tt.mu.Unlock()

	// 添加调试日志
	if gLogLevel > 2 {
		fmt.Printf("Updating %d connections\n", len(updates))
	}

	for key, conn := range updates {
		stats, exists := tt.processStats[key.pid]
		if !exists {
			// 从第一个事件中获取进程信息
			var procInfo ProcessInfo
			for _, event := range events {
				if getProcessIdentifier(event.Proc) == key.pid {
					containerID := ""
					if strings.Contains(event.Proc.Full_Task_Path, "docker") {
						containerID = extractContainerID(event.Proc.Full_Task_Path)
					}
					procInfo = ProcessInfo{
						PID:         event.Proc.Pid,
						Name:        event.Proc.Task,
						Path:        event.Proc.Full_Task_Path,
						IsDocker:    strings.Contains(event.Proc.Full_Task_Path, "docker"),
						ContainerID: containerID,
					}
					break
				}
			}

			stats = &ProcessStats{
				StartTime:   now,
				Connections: make(map[string]*ConnectionInfo, 16), // 预分配容量
				ProcessInfo: procInfo,
			}
			tt.processStats[key.pid] = stats

			// 添加调试日志
			if gLogLevel > 2 {
				fmt.Printf("Created new process stats for %s\n", key.pid)
			}
		}

		// 如果连接已存在，更新统计信息
		if existingConn, exists := stats.Connections[key.connKey]; exists {
			existingConn.BytesIn += conn.BytesIn
			existingConn.BytesOut += conn.BytesOut
			existingConn.PktsIn += conn.PktsIn
			existingConn.PktsOut += conn.PktsOut
			existingConn.LastSeen = now
			putConnectionInfo(conn) // 归还对象到对象池

			// 更新进程总统计
			stats.TotalBytesIn += conn.BytesIn
			stats.TotalBytesOut += conn.BytesOut
			stats.TotalPktsIn += conn.PktsIn
			stats.TotalPktsOut += conn.PktsOut

			// 添加调试日志
			if gLogLevel > 2 {
				fmt.Printf("Updated existing connection %s for process %s: BytesIn=%d, BytesOut=%d\n",
					key.connKey, key.pid, existingConn.BytesIn, existingConn.BytesOut)
			}
		} else {
			stats.Connections[key.connKey] = conn

			// 更新进程总统计
			stats.TotalBytesIn += conn.BytesIn
			stats.TotalBytesOut += conn.BytesOut
			stats.TotalPktsIn += conn.PktsIn
			stats.TotalPktsOut += conn.PktsOut

			// 添加调试日志
			if gLogLevel > 2 {
				fmt.Printf("Added new connection %s for process %s\n", key.connKey, key.pid)
			}
		}

		stats.LastSeen = now
	}

	// 更新网络统计的最后更新时间
	tt.networkStats.LastSeen = now
	tt.intervalStats.NetworkStats.LastSeen = now
}

func (tt *TrafficTracker) Stop() {
	// 先关闭事件处理
	close(tt.eventStop)
	tt.eventWg.Wait()
	close(tt.eventChan)

	// 停止清理协程
	close(tt.stopCleanup)
	if tt.cleanupTicker != nil {
		tt.cleanupTicker.Stop()
	}

	// 最后一次清理和统计
	tt.cleanup()
	tt.printStats()

	// 关闭日志文件
	tt.logManager.close()

	// 停止系统负载监控
	tt.loadMonitor.Stop()
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
		time.Unix(tt.intervalStats.StartTime, 0).Format(time.RFC3339),
		now.Format(time.RFC3339))

	if err := tt.writeStatsToFile("interval", intervalContent); err != nil {
		return err
	}

	// 写入网络统计
	if tt.intervalStats.NetworkStats != nil {
		networkStats := fmt.Sprintf("NETWORK STATISTICS\n"+
			"-----------------\n"+
			"TCP Traffic:\n"+
			"  Outbound: %d bytes (%d packets) [%.2f bytes/s]\n"+
			"  Inbound:  %d bytes (%d packets) [%.2f bytes/s]\n"+
			"UDP Traffic:\n"+
			"  Outbound: %d bytes (%d packets) [%.2f bytes/s]\n"+
			"  Inbound:  %d bytes (%d packets) [%.2f bytes/s]\n",
			tt.intervalStats.NetworkStats.TCPStats.SendBytes,
			tt.intervalStats.NetworkStats.TCPStats.SendPkts,
			float64(tt.intervalStats.NetworkStats.TCPStats.SendBytes)/60.0,
			tt.intervalStats.NetworkStats.TCPStats.RecvBytes,
			tt.intervalStats.NetworkStats.TCPStats.RecvPkts,
			float64(tt.intervalStats.NetworkStats.TCPStats.RecvBytes)/60.0,
			tt.intervalStats.NetworkStats.UDPStats.SendBytes,
			tt.intervalStats.NetworkStats.UDPStats.SendPkts,
			float64(tt.intervalStats.NetworkStats.UDPStats.SendBytes)/60.0,
			tt.intervalStats.NetworkStats.UDPStats.RecvBytes,
			tt.intervalStats.NetworkStats.UDPStats.RecvPkts,
			float64(tt.intervalStats.NetworkStats.UDPStats.RecvBytes)/60.0)

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
			"  Outbound: %d bytes (%d packets) [%.2f bytes/s]\n"+
			"  Inbound:  %d bytes (%d packets) [%.2f bytes/s]\n"+
			"UDP Traffic:\n"+
			"  Outbound: %d bytes (%d packets) [%.2f bytes/s]\n"+
			"  Inbound:  %d bytes (%d packets) [%.2f bytes/s]\n\n",
			tt.networkStats.TCPStats.SendBytes,
			tt.networkStats.TCPStats.SendPkts,
			float64(tt.networkStats.TCPStats.SendBytes)/60.0,
			tt.networkStats.TCPStats.RecvBytes,
			tt.networkStats.TCPStats.RecvPkts,
			float64(tt.networkStats.TCPStats.RecvBytes)/60.0,
			tt.networkStats.UDPStats.SendBytes,
			tt.networkStats.UDPStats.SendPkts,
			float64(tt.networkStats.UDPStats.SendBytes)/60.0,
			tt.networkStats.UDPStats.RecvBytes,
			tt.networkStats.UDPStats.RecvPkts,
			float64(tt.networkStats.UDPStats.RecvBytes)/60.0)

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
			"    Inbound:  %d bytes (%d packets) [%.2f bytes/s]\n"+
			"    Outbound: %d bytes (%d packets) [%.2f bytes/s]\n",
			func() string {
				if stats.ProcessInfo.IsDocker {
					return fmt.Sprintf("Docker Container\n  Container ID: %s", stats.ProcessInfo.ContainerID)
				}
				return "Host Process"
			}(),
			stats.ProcessInfo.PID,
			stats.ProcessInfo.Name,
			time.Since(time.Unix(stats.StartTime, 0)).Round(time.Second),
			stats.TotalBytesIn,
			stats.TotalPktsIn,
			float64(stats.TotalBytesIn)/60.0,
			stats.TotalBytesOut,
			stats.TotalPktsOut,
			float64(stats.TotalBytesOut)/60.0)

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
					time.Unix(conn.LastSeen, 0).Format(time.RFC3339))

				if err := tt.writeStatsToFile("cumulative", connInfo); err != nil {
					return err
				}
			}
		}
		if err := tt.writeStatsToFile("cumulative", "-----------------\n"); err != nil {
			return err
		}
	}

	// 在写入完所有日志后，清理累计统计数据和间隔统计数据
	tt.clearCumulativeStats()
	tt.clearIntervalStats()

	return nil
}

// 新增清理累计统计数据的方法
func (tt *TrafficTracker) clearCumulativeStats() {
	// 重置网络统计
	tt.networkStats = &NetworkEventStats{}

	// 清理进程统计
	for pid, stats := range tt.processStats {
		// 保留进程基本信息，但重置统计数据
		tt.processStats[pid] = &ProcessStats{
			StartTime:   stats.StartTime,
			Connections: make(map[string]*ConnectionInfo),
			ProcessInfo: stats.ProcessInfo,
		}
	}
}

// 新增清理间隔统计数据的方法
func (tt *TrafficTracker) clearIntervalStats() {
	now := time.Now().Unix()

	// 重置间隔统计
	tt.intervalStats = &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats),
		NetworkStats: &NetworkEventStats{},
		StartTime:    now,
		LastStats:    make(map[string]*ProcessStats),
	}
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

	now := time.Now().Unix()

	// 保存当前间隔到历史记录，但只保存必要的统计信息
	currentInterval := &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats),
		NetworkStats: tt.intervalStats.NetworkStats,
		StartTime:    tt.intervalStats.StartTime,
		EndTime:      now,
	}

	// 只复制活跃的进程统计
	for pid, stats := range tt.intervalStats.ProcessStats {
		if now-stats.LastSeen <= int64(tt.connTimeout.Seconds()) {
			currentInterval.ProcessStats[pid] = &ProcessStats{
				TotalBytesIn:  stats.TotalBytesIn,
				TotalBytesOut: stats.TotalBytesOut,
				TotalPktsIn:   stats.TotalPktsIn,
				TotalPktsOut:  stats.TotalPktsOut,
				LastSeen:      stats.LastSeen,
				StartTime:     stats.StartTime,
				ProcessInfo:   stats.ProcessInfo,
				// 不复制连接信息，减少内存使用
			}
		}
	}

	tt.intervals = append(tt.intervals, currentInterval)
	if len(tt.intervals) > MaxStoredIntervals {
		tt.intervals = tt.intervals[1:]
	}

	// 创建新的间隔统计，重用现有的 map
	tt.intervalStats = &IntervalStats{
		ProcessStats: make(map[string]*ProcessStats, MaxStoredProcesses),
		NetworkStats: &NetworkEventStats{},
		StartTime:    now,
		LastStats:    make(map[string]*ProcessStats, MaxStoredProcesses),
	}
}

// 新增事件队列方法
func NewEventQueue() *EventQueue {
	return &EventQueue{
		highPriority:   make(chan Event, EventQueueSize),
		normalPriority: make(chan Event, EventQueueSize),
		lowPriority:    make(chan Event, EventQueueSize),
		stop:           make(chan struct{}),
	}
}

// 新增事件处理器方法
func NewEventProcessor(numWorkers int, tracker *TrafficTracker) *EventProcessor {
	ep := &EventProcessor{
		queues:     make([]*EventQueue, numWorkers),
		workers:    make([]*EventWorker, numWorkers),
		stop:       make(chan struct{}),
		stats:      &EventStats{},
		memMonitor: &MemoryMonitor{},
		tracker:    tracker,
		procStats:  &EventProcessingStats{},
	}

	for i := 0; i < numWorkers; i++ {
		ep.queues[i] = NewEventQueue()
		ep.workers[i] = &EventWorker{
			id:        i,
			queue:     ep.queues[i],
			stop:      make(chan struct{}),
			stats:     ep.stats,
			processor: ep,
		}
		go ep.workers[i].start()
	}

	return ep
}

// 新增事件工作器方法
func (w *EventWorker) start() {
	batch := make([]Event, 0, EventProcessBatchSize)
	ticker := time.NewTicker(EventProcessInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stop:
			return
		case event := <-w.queue.highPriority:
			batch = append(batch, event)
		case event := <-w.queue.normalPriority:
			batch = append(batch, event)
		case event := <-w.queue.lowPriority:
			batch = append(batch, event)
		case <-ticker.C:
			if len(batch) > 0 {
				w.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (w *EventWorker) processBatch(events []Event) {
	start := time.Now()
	processed := uint64(0)
	lost := uint64(0)

	for _, event := range events {
		if w.processor != nil {
			w.processor.processEvent(event.Data)
			processed++
		} else {
			lost++
		}
	}

	// 更新统计信息
	processingTime := time.Since(start)
	w.processor.updateStats(processed, lost, processingTime)

	// 检查处理时间
	if processingTime > EventProcessTimeoutMs*time.Millisecond {
		w.stats.Update(0, uint64(len(events)))
	} else {
		w.stats.Update(processed, lost)
	}
}

// 更新事件处理逻辑
func (ep *EventProcessor) processEvent(event ebpf_flow.EBPFevent) {
	// 检查系统负载
	if ep.tracker.loadMonitor.IsOverloaded() {
		// 系统过载时，增加事件过滤
		if ep.tracker.eventFilter.ShouldFilter(event) {
			return
		}
	}

	start := time.Now()

	if ep.tracker != nil {
		ep.tracker.updateStats(event)
	}

	processingTime := time.Since(start)
	ep.updateStats(1, 0, processingTime)
}

func (ep *EventProcessor) updateStats(processed, lost uint64, processingTime time.Duration) {
	ep.procStats.mu.Lock()
	defer ep.procStats.mu.Unlock()

	ep.procStats.TotalEvents += processed + lost
	ep.procStats.ProcessedEvents += processed
	ep.procStats.LostEvents += lost
	ep.procStats.ProcessingTime += processingTime
	ep.procStats.LastUpdate = time.Now()
}

// 获取系统负载的辅助函数
func getSystemLoad() (float64, error) {
	// 在 Linux 系统上读取 /proc/loadavg
	content, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, err
	}

	// 解析负载值
	fields := strings.Fields(string(content))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid loadavg format")
	}

	load, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return load * 100, nil // 转换为百分比
}

func main() {
	fmt.Println("Starting initialization...")
	trafficTracker := NewTrafficTracker()
	fmt.Println("Traffic tracker initialized")

	// 事件处理函数
	eventHandler := func(event ebpf_flow.EBPFevent) {
		// 添加调试日志
		if gLogLevel > 2 {
			fmt.Printf("Received event: Type=%d, Process=%s, Len=%d\n",
				event.EType, event.Proc.Task, event.Len)
		}

		select {
		case trafficTracker.eventChan <- event:
			// 事件成功入队
			if gLogLevel > 2 {
				fmt.Printf("Event queued successfully\n")
			}
		default:
			// 通道已满，记录丢失的事件
			if gLogLevel > 0 {
				fmt.Printf("Event channel full, event dropped\n")
			}
		}
	}

	fmt.Println("Setting up timers...")
	// 创建定时器，定期打印统计信息
	// 计算到下一个1分钟整点的延迟
	now := time.Now()
	nextTick := now.Truncate(time.Minute).Add(time.Minute)
	initialDelay := nextTick.Sub(now)

	// 先等待到下一个1分钟整点
	fmt.Printf("Waiting %v for next minute mark...\n", initialDelay)
	time.Sleep(initialDelay)

	// 创建一个done通道用于优雅关闭
	done := make(chan struct{})

	// 然后开始1分钟间隔的计时
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				trafficTracker.printStats()
			case <-done:
				return
			}
		}
	}()
	fmt.Println("Timer setup completed")

	// 初始化 ebpflow
	fmt.Println("Initializing ebpflow...")
	ebpf := ebpf_flow.NewEbpflow(eventHandler, 0)
	if gLogLevel > 1 {
		fmt.Println("Ebpflow initialized")
	}

	// 处理中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 创建一个关闭通道
	shutdown := make(chan struct{})

	// 信号处理协程
	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal: %v\n", sig)
		gRUNNING = false

		// 通知所有组件开始关闭
		close(shutdown)

		// 停止 ebpflow
		fmt.Println("Stopping ebpflow...")
		ebpf.Close()

		// 停止 traffic tracker
		fmt.Println("Stopping traffic tracker...")
		trafficTracker.Stop()

		// 通知主循环可以退出了
		close(done)
	}()

	// 在信号处理协程中添加事件统计报告
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				total, lost, processed := trafficTracker.eventStats.GetStats()
				if lost > 0 {
					lossRate := float64(lost) / float64(total) * 100
					fmt.Printf("Event Statistics:\n"+
						"  Total Events: %d\n"+
						"  Processed Events: %d\n"+
						"  Lost Events: %d (%.2f%%)\n",
						total, processed, lost, lossRate)
				}
			case <-done:
				return
			}
		}
	}()

	// 主事件循环
	fmt.Println("Starting event polling...")
	for gRUNNING {
		select {
		case <-shutdown:
			// 收到关闭信号，退出循环
			gRUNNING = false
		default:
			// 轮询事件，但使用较短的超时时间
			ebpf.PollEvent(100)
			// 由于PollEvent没有返回值，我们不需要检查错误
		}
	}

	fmt.Println("Cleaning up resources...")

	// 等待所有组件完成清理
	<-done
	fmt.Println("Cleanup completed, exiting.")

	// 在清理资源时添加事件统计报告
	fmt.Println("Final Event Statistics:")
	total, lost, processed := trafficTracker.eventStats.GetStats()
	lossRate := float64(lost) / float64(total) * 100
	fmt.Printf("  Total Events: %d\n"+
		"  Processed Events: %d\n"+
		"  Lost Events: %d (%.2f%%)\n",
		total, processed, lost, lossRate)
}
