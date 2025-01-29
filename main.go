// Original Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Modification Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"bytes"
	"context"
	// crypto_rand "crypto/rand"
	// "encoding/binary"
	"fmt"
	// "hash/crc64"
	"io"
	"io/ioutil"
	"log"
	// math_rand "math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
)

var reqPort = 80

var s3Bucket = "locus-fastly-poc"

var cfg, _ = config.LoadDefaultConfig(context.TODO())

// if err != nil {
//     log.Fatal(err)
// }
var s3Client = s3.NewFromConfig(cfg)

type BucketBasics struct {
	S3Client *s3.Client
}

var bucketBasics = BucketBasics{S3Client: s3Client}

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

type RequestData struct {
	Path    string            `parquet:"name=path, type=UTF8"`
	Host    string            `parquet:"name=host, type=UTF8"`
	Headers map[string]string `parquet:"name=headers, type=MAP"`
	IP      string            `parquet:"name=ip, type=UTF8"`
	Body    string            `parquet:"name=body, type=UTF8"`
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			reqSourceIP := h.net.Src().String()
			reqDestionationPort := h.transport.Dst().String()
			body, bErr := ioutil.ReadAll(req.Body)
			if bErr != nil {
				return
			}
			req.Body.Close()
			go bucketBasics.forwardRequest(req, reqSourceIP, reqDestionationPort, body)
		}
	}
}

func convertToParquet(data RequestData) ([]byte, error) {
	var buf bytes.Buffer
	pw, err := writer.NewParquetWriterFromWriter(&buf, new(RequestData), 1)
	if err != nil {
		return nil, fmt.Errorf("failed to create Parquet writer: %w", err)
	}

	pw.RowGroupSize = 128 * 1024 * 1024 // 128MB
	pw.PageSize = 8 * 1024              // 8KB
	pw.CompressionType = parquet.CompressionCodec_SNAPPY

	if err := pw.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write Parquet data: %w", err)
	}

	if err := pw.WriteStop(); err != nil {
		return nil, fmt.Errorf("failed to finalize Parquet file: %w", err)
	}

	return buf.Bytes(), nil
}

func (basics BucketBasics) forwardRequest(req *http.Request, reqSourceIP string, reqDestionationPort string, body []byte) {
	if req.Method != http.MethodPost {
		return // Only process POST requests
	}

	hostname := req.Host
	if hostname == "" {
		hostname = "unknown"
	}

	now := time.Now()
	objectKey := fmt.Sprintf("%s/%d/%02d/%02d/%d.parquet",
		hostname, now.Year(), now.Month(), now.Day(), now.UnixMilli(),
	)

	headersMap := make(map[string]string)
	for key, values := range req.Header {
		headersMap[key] = values[0] // Take the first value for simplicity
	}

	requestData := RequestData{
		Path:    req.URL.Path,
		Host:    req.Host,
		Headers: headersMap,
		IP:      reqSourceIP,
		Body:    string(body),
	}

	parquetBuffer, err := convertToParquet(requestData)
	if err != nil {
		log.Println("Error converting to Parquet:", err)
		return
	}

	go func() {
		_, err := basics.S3Client.PutObject(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(s3Bucket),
			Key:    aws.String(objectKey),
			Body:   bytes.NewReader(parquetBuffer),
		})
		if err != nil {
			log.Println("Error uploading Parquet file to S3:", err)
		}
	}()
}

// Listen for incoming connections.
func openTCPClient() {
	ln, err := net.Listen("tcp", ":4789")
	if err != nil {
		// If TCP listener cannot be established, NLB health checks would fail
		// For this reason, we OS.exit
		log.Println("Error listening on TCP", ":", err)
		os.Exit(1)
	}
	log.Println("Listening on TCP 4789")
	for {
		// Listen for an incoming connection and close it immediately.
		conn, _ := ln.Accept()
		conn.Close()
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	log.Printf("Starting capture on interface vxlan0")
	handle, err = pcap.OpenLive("vxlan0", 8951, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Set up BPF filter
	BPFFilter := fmt.Sprintf("%s%d", "tcp and dst port ", reqPort)
	if err := handle.SetBPFFilter(BPFFilter); err != nil {
		log.Fatal(err)
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	//Open a TCP Client, for NLB Health Checks only
	go openTCPClient()

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				log.Println("no packet")
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 1 minute.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -1))
		}
	}
}
