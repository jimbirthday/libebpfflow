package test

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const (
	NumTestConnections = 1000                  // 减少到1000个连接
	TestDuration       = 20 * time.Second      // 测试持续时间
	ReportInterval     = 5 * time.Second       // 报告间隔
	EventInterval      = 10 * time.Millisecond // 事件间隔缩短到10微秒
	MaxPacketSize      = 9000                  // 最大包大小
	NumWorkers         = 20                    // 减少到20个worker
	LocalPortStart     = 10000                 // 本地端口起始值
	LocalPortEnd       = 60000                 // 本地端口结束值
	TargetPort         = 8080                  // 目标端口
	TargetHost         = "127.0.0.1"           // 目标主机
	PacketsPerBatch    = 100                   // 每个worker每次发送100个包
)

// 端口管理器
type PortManager struct {
	mu    sync.Mutex
	ports map[int]bool
}

func NewPortManager() *PortManager {
	return &PortManager{
		ports: make(map[int]bool),
	}
}

func (pm *PortManager) GetPort() (int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 尝试最多100次找到可用端口
	for i := 0; i < 100; i++ {
		port := LocalPortStart + rand.Intn(LocalPortEnd-LocalPortStart)
		if !pm.ports[port] {
			pm.ports[port] = true
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports")
}

func (pm *PortManager) ReleasePort(port int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	delete(pm.ports, port)
}

// 测试连接信息
type TestConnection struct {
	conn     net.Conn
	udpConn  *net.UDPConn
	addr     *net.UDPAddr
	isTCP    bool
	workerID int
	port     int
	pm       *PortManager
}

// 测试服务器
type TestServer struct {
	tcpListener net.Listener
	udpConn     *net.UDPConn
	stop        chan struct{}
	wg          sync.WaitGroup
}

// 创建TCP连接
func createTCPConnection(workerID int, pm *PortManager) (*TestConnection, error) {
	port, err := pm.GetPort()
	if err != nil {
		return nil, err
	}

	localAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}
	remoteAddr := &net.TCPAddr{
		IP:   net.ParseIP(TargetHost),
		Port: TargetPort,
	}
	conn, err := net.DialTCP("tcp", localAddr, remoteAddr)
	if err != nil {
		pm.ReleasePort(port)
		return nil, err
	}
	return &TestConnection{
		conn:     conn,
		isTCP:    true,
		workerID: workerID,
		port:     port,
		pm:       pm,
	}, nil
}

// 创建UDP连接
func createUDPConnection(workerID int, pm *PortManager) (*TestConnection, error) {
	port, err := pm.GetPort()
	if err != nil {
		return nil, err
	}

	localAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: port,
	}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP(TargetHost),
		Port: TargetPort,
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		pm.ReleasePort(port)
		return nil, err
	}
	return &TestConnection{
		udpConn:  conn,
		addr:     remoteAddr,
		isTCP:    false,
		workerID: workerID,
		port:     port,
		pm:       pm,
	}, nil
}

// 创建测试连接
func createTestConnections(n int) []*TestConnection {
	conns := make([]*TestConnection, 0, n)
	pm := NewPortManager()

	for i := 0; i < n; i++ {
		workerID := i % NumWorkers
		var conn *TestConnection
		var err error

		// 交替创建TCP和UDP连接
		if i%2 == 0 {
			conn, err = createTCPConnection(workerID, pm)
		} else {
			conn, err = createUDPConnection(workerID, pm)
		}

		if err != nil {
			fmt.Printf("Failed to create connection %d: %v\n", i, err)
			continue
		}
		conns = append(conns, conn)
	}
	return conns
}

// 生成随机数据
func generateRandomData(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// 模拟流量
func simulateTraffic(t *testing.T, conns []*TestConnection, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	// 创建多个worker并发发送
	for i := 0; i < NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// 获取该worker的连接
			workerConns := make([]*TestConnection, 0)
			for _, conn := range conns {
				if conn.workerID == workerID {
					workerConns = append(workerConns, conn)
				}
			}

			if len(workerConns) == 0 {
				t.Logf("Worker %d has no connections\n", workerID)
				return
			}

			// 为每个连接创建缓冲区
			buffers := make([][]byte, len(workerConns))
			for i := range buffers {
				buffers[i] = make([]byte, MaxPacketSize)
			}

			for {
				select {
				case <-stop:
					return
				default:
					// 每个worker同时处理多个连接
					for j := 0; j < PacketsPerBatch; j++ {
						for connIdx, conn := range workerConns {
							// 生成随机大小的数据包
							packetSize := rand.Intn(MaxPacketSize-100) + 100 // 最小100字节
							rand.Read(buffers[connIdx][:packetSize])

							if conn.isTCP {
								// TCP发送
								_, err := conn.conn.Write(buffers[connIdx][:packetSize])
								if err != nil {
									t.Logf("TCP write error: %v\n", err)
									continue
								}
								// TCP接收
								_, err = conn.conn.Read(buffers[connIdx][:packetSize])
								if err != nil {
									t.Logf("TCP read error: %v\n", err)
									continue
								}
							} else {
								// UDP发送
								_, err := conn.udpConn.WriteTo(buffers[connIdx][:packetSize], conn.addr)
								if err != nil {
									t.Logf("UDP write error: %v\n", err)
									continue
								}
								// UDP接收
								_, _, err = conn.udpConn.ReadFrom(buffers[connIdx][:packetSize])
								if err != nil {
									t.Logf("UDP read error: %v\n", err)
									continue
								}
							}
						}
					}
					time.Sleep(EventInterval)
				}
			}
		}(i)
	}
}

// 清理连接
func cleanupConnections(conns []*TestConnection) {
	for _, conn := range conns {
		if conn.isTCP {
			conn.conn.Close()
		} else {
			conn.udpConn.Close()
		}
		conn.pm.ReleasePort(conn.port)
	}
}

// 监控内存使用
func monitorMemory(t *testing.T, stop chan struct{}) {
	var m runtime.MemStats
	ticker := time.NewTicker(ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			runtime.ReadMemStats(&m)
			t.Logf("\nMemory Stats:\n"+
				"Alloc = %v MiB\n"+
				"TotalAlloc = %v MiB\n"+
				"Sys = %v MiB\n"+
				"NumGC = %v\n"+
				"Goroutines = %v\n",
				m.Alloc/1024/1024,
				m.TotalAlloc/1024/1024,
				m.Sys/1024/1024,
				m.NumGC,
				runtime.NumGoroutine())
		}
	}
}

// 启动测试服务器
func startTestServer() (*TestServer, error) {
	server := &TestServer{
		stop: make(chan struct{}),
	}

	// 启动TCP服务器
	tcpAddr := &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: TargetPort,
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to start TCP server: %v", err)
	}
	server.tcpListener = listener

	// 启动UDP服务器
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: TargetPort,
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		server.tcpListener.Close()
		return nil, fmt.Errorf("failed to start UDP server: %v", err)
	}
	server.udpConn = udpConn

	// 启动TCP处理
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			select {
			case <-server.stop:
				return
			default:
				conn, err := server.tcpListener.Accept()
				if err != nil {
					continue
				}
				server.wg.Add(1)
				go func(c net.Conn) {
					defer server.wg.Done()
					defer c.Close()
					buf := make([]byte, MaxPacketSize)
					for {
						select {
						case <-server.stop:
							return
						default:
							n, err := c.Read(buf)
							if err != nil {
								return
							}
							// 回显数据
							_, err = c.Write(buf[:n])
							if err != nil {
								return
							}
						}
					}
				}(conn)
			}
		}
	}()

	// 启动UDP处理
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		buf := make([]byte, MaxPacketSize)
		for {
			select {
			case <-server.stop:
				return
			default:
				n, addr, err := server.udpConn.ReadFrom(buf)
				if err != nil {
					continue
				}
				// 回显数据
				_, err = server.udpConn.WriteTo(buf[:n], addr)
				if err != nil {
					continue
				}
			}
		}
	}()

	return server, nil
}

// 停止测试服务器
func (s *TestServer) Stop() {
	close(s.stop)
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	s.wg.Wait()
}

// 获取主程序路径
func getMainProgramPath() (string, error) {
	// 尝试多个可能的位置
	possiblePaths := []string{
		"go_ebpflowexport",                      // 当前目录
		"../go_ebpflowexport",                   // 上级目录
		filepath.Join("..", "go_ebpflowexport"), // 使用 filepath.Join 确保跨平台兼容
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			// 获取绝对路径
			absPath, err := filepath.Abs(path)
			if err == nil {
				return absPath, nil
			}
		}
	}

	return "", fmt.Errorf("could not find go_ebpflowexport executable in any of the expected locations")
}

// 启动主程序
func startMainProgram(t *testing.T) (*exec.Cmd, error) {
	mainPath, err := getMainProgramPath()
	if err != nil {
		return nil, fmt.Errorf("failed to find main program: %v", err)
	}

	t.Logf("Starting main program from: %s", mainPath)

	// 启动主程序
	cmd := exec.Command(mainPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start main program: %v", err)
	}

	// 等待一小段时间确保程序启动
	time.Sleep(5 * time.Second)

	return cmd, nil
}

// TestTrafficFlow 测试流量监控
func TestTrafficFlow(t *testing.T) {
	// 启动主程序
	mainCmd, err := startMainProgram(t)
	if err != nil {
		t.Fatalf("Failed to start main program: %v", err)
	}
	defer func() {
		if mainCmd.Process != nil {
			mainCmd.Process.Signal(os.Interrupt)
			mainCmd.Wait()
		}
	}()

	// 启动测试服务器
	server, err := startTestServer()
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Stop()

	// 设置随机种子
	rand.Seed(time.Now().UnixNano())

	// 创建停止通道
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 启动内存监控
	go monitorMemory(t, stop)

	// 创建测试连接
	t.Logf("Creating %d test connections...\n", NumTestConnections)
	conns := createTestConnections(NumTestConnections)
	t.Logf("Created %d test connections\n", len(conns))
	defer cleanupConnections(conns)

	// 启动流量模拟
	t.Logf("Starting %d traffic simulation workers...\n", NumWorkers)
	wg.Add(1)
	go simulateTraffic(t, conns, stop, &wg)

	// 等待测试时间
	t.Logf("Starting test for %v...\n", TestDuration)
	time.Sleep(TestDuration)

	// 停止流量模拟
	t.Log("Stopping traffic simulation...")
	close(stop)
	wg.Wait()

	t.Log("Test completed")
}

// TestMemoryLeak 测试内存泄漏
func TestMemoryLeak(t *testing.T) {
	// 启动主程序
	mainCmd, err := startMainProgram(t)
	if err != nil {
		t.Fatalf("Failed to start main program: %v", err)
	}
	defer func() {
		if mainCmd.Process != nil {
			mainCmd.Process.Signal(os.Interrupt)
			mainCmd.Wait()
		}
	}()

	// 启动测试服务器
	server, err := startTestServer()
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}
	defer server.Stop()

	// 设置随机种子
	rand.Seed(time.Now().UnixNano())

	// 创建停止通道
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 启动内存监控
	go monitorMemory(t, stop)

	// 创建测试连接
	t.Logf("Creating %d test connections...\n", NumTestConnections)
	conns := createTestConnections(NumTestConnections)
	t.Logf("Created %d test connections\n", len(conns))
	defer cleanupConnections(conns)

	// 启动流量模拟
	t.Logf("Starting %d traffic simulation workers...\n", NumWorkers)
	wg.Add(1)
	go simulateTraffic(t, conns, stop, &wg)

	// 等待测试时间
	t.Logf("Starting memory leak test for %v...\n", TestDuration)

	// 记录初始内存使用
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)
	initialAlloc := initialMem.Alloc
	t.Logf("Initial memory usage: %.2f MB\n", float64(initialAlloc)/1024/1024)

	// 等待测试时间
	time.Sleep(TestDuration)

	// 记录最终内存使用
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	finalAlloc := finalMem.Alloc
	t.Logf("Final memory usage: %.2f MB\n", float64(finalAlloc)/1024/1024)

	// 停止流量模拟
	t.Log("Stopping traffic simulation...")
	close(stop)
	wg.Wait()

	// 检查内存增长
	memoryGrowth := float64(finalAlloc-initialAlloc) / 1024 / 1024 // MB
	t.Logf("Memory growth: %.2f MB\n", memoryGrowth)

	// 如果内存增长超过200MB，认为存在内存泄漏
	if memoryGrowth > 200 {
		t.Errorf("Possible memory leak detected: memory growth %.2f MB exceeds 200 MB threshold", memoryGrowth)
	}

	t.Log("Memory leak test completed")
}
