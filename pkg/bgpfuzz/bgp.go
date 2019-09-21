package bgpfuzz

import (
	"io"
	"net"

	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/pkg/errors"
)

var (
	header = []byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		0, 0, // Length
		0, // Type
	}

	headerLengthOffset = 16
	headerTypeOffset   = 18
)

func getHeader() []byte {
	ret := make([]byte, 0, 19)
	copy(ret, header)
	return ret
}

func recvMsg(c net.Conn) (msg []byte, err error) {
	buffer := make([]byte, packet.MaxLen)
	_, err = io.ReadFull(c, buffer[0:packet.MinLen])
	if err != nil {
		return nil, errors.Wrap(err, "Read failed")
	}

	l := int(buffer[16])*256 + int(buffer[17])
	toRead := l
	_, err = io.ReadFull(c, buffer[packet.MinLen:toRead])
	if err != nil {
		return nil, errors.Wrap(err, "Read failed")
	}

	return buffer, nil
}
