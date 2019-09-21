package main

import (
	"flag"
	"os"

	"github.com/bio-routing/bgpfuzz/pkg/bgpfuzz"
	log "github.com/sirupsen/logrus"
)

var (
	targetStr = flag.String("target", "", "IP-Address of peer")
	localASN  = flag.Uint("local_asn", 0, "Local ASN")
)

func main() {
	flag.Parse()

	f := bgpfuzz.New(*targetStr, uint16(*localASN))
	err := f.TestOpen()
	if err != nil {
		log.Errorf("OPEN tests failed: %v", err)
		os.Exit(1)
	}
}
