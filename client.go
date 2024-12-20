/*
Copyright (C) 2024 Steve Miller KC1AWV

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"

	"go-m17gateway-monitor/codec2"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hajimehoshi/oto"
)

// Packet MAGIC constants
const (
	MagicM17 = "M17 "
)

// Client represents a M17 client
type Client struct {
	handle *pcap.Handle
	codec2 *codec2.Codec2
	player *oto.Player
	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient creates a new M17 client
func NewClient(interfaceName string) (*Client, error) {
	// Open device for packet capture
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	// Set BPF filter to capture only UDP packets on port 17010
	err = handle.SetBPFFilter("udp port 17010")
	if err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Initialize Codec 2 at 3200 bps
	codec2, err := codec2.New(codec2.MODE_3200)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize codec2: %w", err)
	}

	// Initialize Oto context and player
	ctx, err := oto.NewContext(8000, 1, 2, 8192)
	if err != nil {
		return nil, fmt.Errorf("failed to create oto context: %w", err)
	}

	player := ctx.NewPlayer()

	clientCtx, cancel := context.WithCancel(context.Background())

	return &Client{
		handle: handle,
		codec2: codec2,
		player: player,
		ctx:    clientCtx,
		cancel: cancel,
	}, nil
}

// Listen listens for incoming packets
func (c *Client) listen() {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-c.ctx.Done():
			return
		default:
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if debug {
					log.Printf("received packet from %v", packet.NetworkLayer().NetworkFlow().Src())
				}
				c.handlePacket(udp.Payload)
			}
		}
	}
}

// handlePacket handles incoming packets
func (c *Client) handlePacket(packet []byte) {
	if len(packet) < 4 {
		return
	}

	magic := string(packet[:4])
	switch magic {
	case MagicM17:
		c.handleM17(packet)
	}
}

// handleM17 handles a M17 packet
func (c *Client) handleM17(packet []byte) {
	if len(packet) < 54 {
		if debug {
			log.Printf("invalid M17 packet length: %d", len(packet))
		}
		return
	}

	// Parse M17 packet fields
	streamID := binary.BigEndian.Uint16(packet[4:6])
	lich := packet[6:34]
	frameNumber := binary.BigEndian.Uint16(packet[34:36])
	payload := packet[36:52]
	// reserved := packet[52:54] // Reserved field, not used

	// Parse LICH fields
	dst := decodeCallsign(lich[0:6])
	src := decodeCallsign(lich[6:12])
	typ := binary.BigEndian.Uint16(lich[12:14])
	meta := lich[14:28]

	// Parse Type field
	packetStreamIndicator := typ & 0x0001
	dataTypeIndicator := (typ >> 1) & 0x0003
	encryptionType := (typ >> 3) & 0x0003
	encryptionSubtype := (typ >> 5) & 0x0003
	channelAccessNumber := (typ >> 7) & 0x000F

	// Log packet fields
	if debug {
		log.Printf("Received M17 packet: StreamID=0x%X, FrameNumber=0x%X, DST=%s, SRC=%s, TYPE=0x%X, META=%x", streamID, frameNumber, dst, src, typ, meta)
		log.Printf("Type field breakdown: PacketStreamIndicator=%d, DataTypeIndicator=%d, EncryptionType=%d, EncryptionSubtype=%d, ChannelAccessNumber=%d",
			packetStreamIndicator, dataTypeIndicator, encryptionType, encryptionSubtype, channelAccessNumber)
	}

	// Filter out packets that are not stream mode or are encrypted
	if packetStreamIndicator == 0 || encryptionType != 0 {
		if debug {
			log.Printf("Ignoring packet mode or encrypted packet: TYPE=%d", typ)
		}
		return
	}

	// Filter out packets that are not voice or voice + data
	if dataTypeIndicator != 0b10 && dataTypeIndicator != 0b11 {
		if debug {
			log.Printf("Ignoring non-voice packet: TYPE=%d", typ)
		}
		return
	}

	// Ensure payload length is correct for Codec 2 at 3200 bps (16 bytes)
	if len(payload) != 16 {
		if debug {
			log.Printf("invalid payload length: %d", len(payload))
		}
		return
	}

	// Decode and play the voice stream using Codec 2
	audio1, err := c.codec2.Decode(payload[:8])
	if err != nil {
		if debug {
			log.Printf("failed to decode first voice frame: %v", err)
		}
		return
	}

	audio2, err := c.codec2.Decode(payload[8:])
	if err != nil {
		if debug {
			log.Printf("failed to decode second voice frame: %v", err)
		}
		return
	}

	// Combine the two audio frames
	audio := append(audio1, audio2...)

	// Play the audio
	c.playAudio(audio)
}

// playAudio plays audio using the Oto player
func (c *Client) playAudio(audio []int16) {
	// Convert int16 audio to byte slice
	buf := make([]byte, len(audio)*2)
	for i, sample := range audio {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(sample))
	}

	// Write audio to Oto player
	_, err := c.player.Write(buf)
	if err != nil {
		if debug {
			log.Printf("failed to play audio: %v", err)
		}
	}
}
