/**
* Homer Encapsulation Protocol v3
* Courtesy of Weave Communications, Inc (http://getweave.com/) under the ISC license (https://en.wikipedia.org/wiki/ISC_license)
**/

package hep

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/james4e/sipparser"
)

/*************************************
 Constants
*************************************/

// HEP ID
const (
	HEPID1 = 0x011002
	HEPID2 = 0x021002
	HEPID3 = 0x48455033
)

// Generic Chunk Types
const (
	_ = iota // Don't want to assign zero here, but want to implicitly repeat this expression after...
	IPProtocolFamily
	IPProtocolID
	IP4SourceAddress
	IP4DestinationAddress
	IP6SourceAddress
	IP6DestinationAddress
	SourcePort
	DestinationPort
	Timestamp
	TimestampMicro
	ProtocolType // Maps to Protocol Types below
	CaptureAgentID
	KeepAliveTimer
	AuthenticationKey
	PacketPayload
	CompressedPayload
	InternalC
)

var protocolFamilies []string
var vendors []string
var protocolTypes []string

func init() {

	// Protocol Family Types - HEP3 Spec does not list these values out. Took IPv4 from an example.
	protocolFamilies = []string{
		"?",
		"?",
		"IPv4"}

	// Initialize vendors
	vendors = []string{
		"None",
		"FreeSWITCH",
		"Kamailio",
		"OpenSIPS",
		"Asterisk",
		"Homer",
		"SipXecs",
	}

	// Initialize protocol types
	protocolTypes = []string{
		"Reserved",
		"SIP",
		"XMPP",
		"SDP",
		"RTP",
		"RTCP",
		"MGCP",
		"MEGACO",
		"M2UA",
		"M3UA",
		"IAX",
		"H322",
		"H321",
	}
}

// HepMsg represents a parsed HEP packet
type HepMsg struct {
	IPProtocolFamily      byte
	IPProtocolID          byte
	IP4SourceAddress      string
	IP4DestinationAddress string
	IP6SourceAddress      string
	IP6DestinationAddress string
	SourcePort            uint16
	DestinationPort       uint16
	Timestamp             uint32
	TimestampMicro        uint32
	ProtocolType          byte
	CaptureAgentID        uint16
	KeepAliveTimer        uint16
	AuthenticateKey       string
	Body                  string
	SipMsg                *sipparser.SipMsg
}

// NewHepMsg returns a parsed message object. Takes a byte slice.
func NewHepMsg(packet []byte) (hMsg *HepMsg, err error) {
	// 使用 defer 和 recover 捕获恐慌
	defer func() {
		if r := recover(); r != nil {
			// 恢复后记录错误
			// 这里可以根据需要做更多的日志记录或者错误处理
			if e, ok := r.(error); ok {
				err = e
			}
			// 如果是其他类型的panic，返回一个通用错误
			err = errors.New("Recovered from panic in HEP parsing")
		}
	}()

	newHepMsg := &HepMsg{}
	err = newHepMsg.parse(packet)
	if err != nil {
		return nil, err
	}
	return newHepMsg, nil
}

// 创建对象池来复用内存
var (
	// IP地址缓冲池
	ipBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 16) // IPv6最大长度
		},
	}

	// 通用缓冲池
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 0, 4096) // 4KB初始容量
		},
	}
)

func (hepMsg *HepMsg) parse(udpPacket []byte) error {
	switch udpPacket[0] {
	case 0x01:
		return hepMsg.parseHep1(udpPacket)
	case 0x02:
		return hepMsg.parseHep2(udpPacket)
	case 0x48:
		return hepMsg.parseHep3(udpPacket)
	default:
		err := errors.New("Not a valid HEP packet - HEP ID does not match spec")
		return err
	}
}

func (hepMsg *HepMsg) parseHep1(udpPacket []byte) error {
	//var err error
	if len(udpPacket) < 21 {
		return errors.New("Found HEP ID for HEP v1, but length of packet is too short to be HEP1 or is NAT keepalive")
	}
	packetLength := len(udpPacket)
	hepMsg.SourcePort = binary.BigEndian.Uint16(udpPacket[4:6])
	hepMsg.DestinationPort = binary.BigEndian.Uint16(udpPacket[6:8])
	hepMsg.IP4SourceAddress = net.IP(udpPacket[8:12]).String()
	hepMsg.IP4DestinationAddress = net.IP(udpPacket[12:16]).String()
	hepMsg.Body = string(udpPacket[16:])
	if len(udpPacket[16:packetLength-4]) > 1 {
		hepMsg.SipMsg = sipparser.ParseMsg(string(udpPacket[16:packetLength]))
		//hepMsg.SipMsg, err = sip.NewSipMsg(udpPacket[16 : packetLength-4])
		if hepMsg.SipMsg.Error != nil {
			return hepMsg.SipMsg.Error
		}
	} else {

	}

	return nil
}

func (hepMsg *HepMsg) parseHep2(udpPacket []byte) error {
	//var err error
	if len(udpPacket) < 31 {
		return errors.New("Found HEP ID for HEP v2, but length of packet is too short to be HEP2 or is NAT keepalive")
	}
	packetLength := len(udpPacket)
	hepMsg.SourcePort = binary.BigEndian.Uint16(udpPacket[4:6])
	hepMsg.DestinationPort = binary.BigEndian.Uint16(udpPacket[6:8])
	hepMsg.IP4SourceAddress = net.IP(udpPacket[8:12]).String()
	hepMsg.IP4DestinationAddress = net.IP(udpPacket[12:16]).String()
	hepMsg.Timestamp = binary.LittleEndian.Uint32(udpPacket[16:20])
	hepMsg.TimestampMicro = binary.LittleEndian.Uint32(udpPacket[20:24])
	hepMsg.CaptureAgentID = binary.BigEndian.Uint16(udpPacket[24:26])
	hepMsg.Body = string(udpPacket[28:])
	if len(udpPacket[28:packetLength-4]) > 1 {
		hepMsg.SipMsg = sipparser.ParseMsg(string(udpPacket[28:packetLength]))
		//hepMsg.SipMsg, err = sip.NewSipMsg(udpPacket[16 : packetLength-4])
		if hepMsg.SipMsg.Error != nil {
			return hepMsg.SipMsg.Error
		}
	}

	return nil
}

func (hepMsg *HepMsg) parseHep3(udpPacket []byte) error {
	if len(udpPacket) < 6 {
		return errors.New("HEP3 packet length is insufficient")
	}

	length := binary.BigEndian.Uint16(udpPacket[4:6])
	if uint16(len(udpPacket)) < length {
		return errors.New("HEP3 packet length is less than declared length")
	}

	currentByte := uint16(6)

	// 从对象池获取缓冲区
	payload := bufferPool.Get().([]byte)
	defer bufferPool.Put(payload) // 确保缓冲区返回池中

	ipBuf := ipBufferPool.Get().([]byte)
	defer ipBufferPool.Put(ipBuf) // 确保IP缓冲区返回池中

	for currentByte < length {
		if length-currentByte < 6 {
			return errors.New("Incomplete chunk header in HEP3 packet")
		}

		chunkType := binary.BigEndian.Uint16(udpPacket[currentByte+2 : currentByte+4])
		chunkLength := binary.BigEndian.Uint16(udpPacket[currentByte+4 : currentByte+6])

		if chunkLength < 6 {
			return errors.New("Invalid HEP3 chunk length")
		}

		if currentByte+chunkLength > length {
			return errors.New("HEP3 chunk exceeds packet boundary")
		}

		chunkBodyStart := currentByte + 6
		chunkBodyEnd := currentByte + chunkLength

		switch chunkType {
		case IPProtocolFamily:
			if chunkBodyEnd > chunkBodyStart {
				hepMsg.IPProtocolFamily = udpPacket[chunkBodyStart]
			}
		case IPProtocolID:
			if chunkBodyEnd > chunkBodyStart {
				hepMsg.IPProtocolID = udpPacket[chunkBodyStart]
			}
		case IP4SourceAddress, IP4DestinationAddress, IP6SourceAddress, IP6DestinationAddress:
			// 使用IP缓冲区
			n := copy(ipBuf, udpPacket[chunkBodyStart:chunkBodyEnd])
			ip := net.IP(ipBuf[:n])

			switch chunkType {
			case IP4SourceAddress:
				hepMsg.IP4SourceAddress = ip.String()
			case IP4DestinationAddress:
				hepMsg.IP4DestinationAddress = ip.String()
			case IP6SourceAddress:
				hepMsg.IP6SourceAddress = ip.String()
			case IP6DestinationAddress:
				hepMsg.IP6DestinationAddress = ip.String()
			}

		case SourcePort:
			if chunkBodyEnd-chunkBodyStart >= 2 {
				hepMsg.SourcePort = binary.BigEndian.Uint16(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case DestinationPort:
			if chunkBodyEnd-chunkBodyStart >= 2 {
				hepMsg.DestinationPort = binary.BigEndian.Uint16(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case Timestamp:
			if chunkBodyEnd-chunkBodyStart >= 4 {
				hepMsg.Timestamp = binary.BigEndian.Uint32(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case TimestampMicro:
			if chunkBodyEnd-chunkBodyStart >= 4 {
				hepMsg.TimestampMicro = binary.BigEndian.Uint32(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case ProtocolType:
			if chunkBodyEnd > chunkBodyStart {
				hepMsg.ProtocolType = udpPacket[chunkBodyStart]
			}
		case CaptureAgentID:
			if chunkBodyEnd-chunkBodyStart >= 2 {
				hepMsg.CaptureAgentID = binary.BigEndian.Uint16(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case KeepAliveTimer:
			if chunkBodyEnd-chunkBodyStart >= 2 {
				hepMsg.KeepAliveTimer = binary.BigEndian.Uint16(udpPacket[chunkBodyStart:chunkBodyEnd])
			}
		case AuthenticationKey:
			// 使用缓冲池中的缓冲区
			n := copy(payload[:cap(payload)], udpPacket[chunkBodyStart:chunkBodyEnd])
			hepMsg.AuthenticateKey = string(payload[:n])

		case PacketPayload:
			dataLen := chunkBodyEnd - chunkBodyStart
			if dataLen > 0 {
				// 确保缓冲区足够大
				if cap(payload) < int(dataLen) {
					payload = make([]byte, dataLen)
				}
				payload = payload[:dataLen]

				copy(payload, udpPacket[chunkBodyStart:chunkBodyEnd])
				hepMsg.Body = string(payload)

				if len(payload) > 24 {
					// 创建新的字符串，避免引用原始数据
					bodyStr := string(payload)
					hepMsg.SipMsg = sipparser.ParseMsg(bodyStr)
					if hepMsg.SipMsg.Error != nil {
						return hepMsg.SipMsg.Error
					}
				}
			}
		}
		currentByte += chunkLength
	}

	return nil
}
