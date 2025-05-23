// ebpflowexport.go
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	ebpf_flow "./go"
)

var gRUNNING bool = true

// TCP 连接跟踪结构
type TCPConnection struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	BytesIn  uint64
	BytesOut uint64
	PktsIn   uint64
	PktsOut  uint64
	LastSeen time.Time
	State    string
}

type ConnectionTracker struct {
	connections map[string]*TCPConnection
	mu          sync.RWMutex
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string]*TCPConnection),
	}
}

func (ct *ConnectionTracker) getKey(saddr, daddr net.IP, sport, dport uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", saddr.String(), sport, daddr.String(), dport)
}

func (ct *ConnectionTracker) updateConnection(event ebpf_flow.EBPFevent) {
	// fmt.Printf("updateConnection: %v\n", event, event.Proto, event.EType, event.Proc.Pid, event.Proc.Task, event.Proc.Full_Task_Path)

	if event.Proto != 6 { // 不是 TCP 协议
		return
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	key := ct.getKey(event.Saddr, event.Daddr, event.Sport, event.Dport)
	// fmt.Printf("key: %s\n", key)
	conn, exists := ct.connections[key]
	// fmt.Printf("conn: %v, exists: %v\n", conn, exists)
	// fmt.Printf("event.Len: %d\n", event.Len)
	if !exists {
		conn = &TCPConnection{
			SrcIP:    event.Saddr,
			DstIP:    event.Daddr,
			SrcPort:  event.Sport,
			DstPort:  event.Dport,
			LastSeen: time.Now(),
			State:    "NEW",
		}
		ct.connections[key] = conn
	}

	// 更新连接状态
	switch event.EType {
	case 101: // eTCP_CONN
		conn.State = "ESTABLISHED"
	case 300: // eTCP_CLOSE
		conn.State = "CLOSED"
	case 100: // eTCP_ACPT
		conn.State = "ESTABLISHED"
	case 600: // eTCP_SEND
		conn.PktsOut++
		conn.BytesOut += uint64(event.Len)
	case 601: // eTCP_RECV
		conn.PktsIn++
		conn.BytesIn += uint64(event.Len)
	}

	conn.LastSeen = time.Now()
}

func (ct *ConnectionTracker) printStats() {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	fmt.Printf("\n=== TCP Connection Statistics ===\n")
	for _, conn := range ct.connections {
		fmt.Printf("Connection: %s:%d -> %s:%d\n",
			conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort)
		fmt.Printf("  State:     %s\n", conn.State)
		fmt.Printf("  Bytes In:  %d (Packets: %d)\n", conn.BytesIn, conn.PktsIn)
		fmt.Printf("  Bytes Out: %d (Packets: %d)\n", conn.BytesOut, conn.PktsOut)
		fmt.Printf("  Last Seen: %s\n", conn.LastSeen.Format(time.RFC3339))
		fmt.Printf("----------------------------\n")
	}
}

func main() {
	// 创建连接跟踪器
	tracker := NewConnectionTracker()

	// 创建定时器，定期打印统计信息
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			tracker.printStats()
		}
	}()

	// 事件处理函数
	eventHandler := func(event ebpf_flow.EBPFevent) {
		// 更新连接统计
		tracker.updateConnection(event)

		// 只打印重要事件（连接建立、关闭、数据收发）
		if event.EType == 101 || event.EType == 300 || event.EType == 600 || event.EType == 601 {
			fmt.Printf("[pid:%d][uid:%d][task:%s][etype:%d][%s]",
				event.Proc.Pid, event.Proc.Uid, event.Proc.Task, event.EType, event.Ifname)
			fmt.Printf("[%s:%d <-> %s:%d]",
				event.Saddr.String(), event.Sport, event.Daddr.String(), event.Dport)
			if event.Len > 0 {
				fmt.Printf("[len:%d]", event.Len)
			}
			fmt.Printf("\n")
		}
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
		tracker.printStats()
	}()

	// 轮询事件
	for gRUNNING {
		ebpf.PollEvent(10)
	}

	// 清理资源
	ebpf.Close()
}
