package scanner

import "sync"

type ScanResult struct {
	URL          string
	Vulnerable   bool
	Payload      string
	ResponseTime float64
	Details      string
}

type ScanConfig struct {
	URLs     []string
	Payloads []string
	Threads  int
	Timeout  int
	Cookie   string
	Headers  map[string]string
}

type Scanner interface {
	Scan(config ScanConfig) []ScanResult
}

// ResultProcessor is a helper to collect results safely
type ResultProcessor struct {
	Results []ScanResult
	Mu      sync.Mutex
}

func (rp *ResultProcessor) Add(result ScanResult) {
	rp.Mu.Lock()
	defer rp.Mu.Unlock()
	rp.Results = append(rp.Results, result)
}
