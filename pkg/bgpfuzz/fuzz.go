package bgpfuzz

// Fuzzer represents a fuzzer
type Fuzzer struct {
	target   string
	localASN uint16
	history  []byte
}

// New creates a new fuzzer
func New(target string, localASN uint16) *Fuzzer {
	return &Fuzzer{
		target:   target,
		localASN: localASN,
		history:  make([]byte, 0, 10000),
	}
}
