package recon

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// port scan to check any oprn ports
var topPorts = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3000, 3306, 3389, 5173, 5900, 8080, 8443}

func ScanPorts(domain string, ports []int, timeout time.Duration) []int {
	if len(ports) == 0 {
		ports = topPorts
	}
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", domain, p), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}
