package bgpfuzz

import (
	"bytes"
	"fmt"
	"net"

	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/tflow2/convert"
)

const (
	openMsgType   = 1
	versionOffset = 0
)

var basicOpenMsg = []byte{
	4,    // Version
	0, 0, // ASN
	0, 0, // Hold Time
	192, 0, 2, 1, // BGP Identifier
	0, // Opt param len
}

func (f *Fuzzer) getValidOpenMsg() []byte {
	msg := make([]byte, 0, 10)
	copy(msg, basicOpenMsg)
	y := f.localASN % 256
	x := f.localASN - y
	msg[1] = uint8(x)
	msg[2] = uint8(y)
	return msg
}

func (f *Fuzzer) invalidVersionNumber() []byte {
	m := f.getValidOpenMsg()
	m[versionOffset] = 5

	return m
}

func (f *Fuzzer) invalidASN() []byte {
	m := f.getValidOpenMsg()
	m[1] = 0
	m[2] = 0

	return m
}

func (f *Fuzzer) invalidBGPIdentifier() []byte {
	m := f.getValidOpenMsg()
	m[5] = 0
	m[6] = 0
	m[7] = 0
	m[8] = 0

	return m
}

func (f *Fuzzer) invalidOptParmLen() []byte {
	m := f.getValidOpenMsg()
	m[9] = 10

	return m
}

// TestOpen performs tests around the BGP OPEN message
func (f *Fuzzer) TestOpen() error {
	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name:   "Invalid Version Number",
			packet: f.invalidVersionNumber(),
		},
		{
			name:   "Invalid ASN (0)",
			packet: f.invalidASN(),
		},
		{
			name:   "Invalid BGP Identifier",
			packet: f.invalidBGPIdentifier(),
		},
		{
			name:   "Invalid Opt. Param length",
			packet: f.invalidOptParmLen(),
		},
	}

	for _, test := range tests {
		f.history = make([]byte, 0, 10000)

		c, err := net.Dial("tcp", fmt.Sprintf("%s:179", f.target))
		if err != nil {
			return fmt.Errorf("dial failed for test %q: %v", test.name, err)
		}

		data, err := recvMsg(c)
		if err != nil {
			return fmt.Errorf("Unable receive message for test %q: %v", test.name, err)
		}

		msg, err := packet.Decode(bytes.NewBuffer(data), &packet.DecodeOptions{})
		if err != nil {
			return fmt.Errorf("Unable to decode message for test %q: %v", test.name, err)
		}

		hdr := getHeader()
		hdr[headerTypeOffset] = openMsgType

		l := convert.Uint16Byte(uint16(len(test.packet)))

		hdr[headerLengthOffset] = l[0]
		hdr[headerLengthOffset+1] = l[1]

		f.history = append(f.history, hdr...)
		_, err = c.Write(hdr)
		if err != nil {
			return fmt.Errorf("write failed for test %q: %v", test.name, err)
		}

		f.history = append(f.history, test.packet...)
		_, err = c.Write(test.packet)
		if err != nil {
			return fmt.Errorf("write failed for test %q: %v", test.name, err)
		}

		data, err = recvMsg(c)
		if err != nil {
			fmt.Printf("Test %q:\n", test.name)
			fmt.Printf("Read from socket failed after sending payload\n")
			fmt.Printf("Error: %v\n", err)
			fmt.Printf("Payload: %v\n", f.history)
			return nil
		}

		msg, err = packet.Decode(bytes.NewBuffer(data), &packet.DecodeOptions{})
		if err != nil {
			return fmt.Errorf("Unable to decode message for test %q: %v", test.name, err)
		}

		if msg.Header.Type != packet.NotificationMsg {
			fmt.Printf("Test %q:\n", test.name)
			fmt.Printf("Target did not send expected NOTIFICATION message\n")
			fmt.Printf("Payload: %v\n", f.history)
			return nil
		}

		fmt.Printf("Test %q successful\n", test.name)
	}

	return nil
}
