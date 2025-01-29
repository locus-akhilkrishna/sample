package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
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

var (
	reqPort   = 80
	s3Bucket  = "locus-fastly-poc"
	cfg, _    = config.LoadDefaultConfig(context.TODO(), config.WithRegion("ap-south-1"))
	s3Client  = s3.NewFromConfig(cfg)
	bufferMap = make(map[string][]RequestData) // Group by host
	bufferMux sync.Mutex
	flushSize = 100              // Flush when 100 requests are collected per host
	flushTime = 60 * time.Second // Flush every 10 seconds per host
)

type BucketBasics struct {
	S3Client *s3.Client
}

var bucketBasics = BucketBasics{S3Client: s3Client}

type httpStreamFactory struct{}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

type RequestData struct {
	Path    string `parquet:"name=path, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Host    string `parquet:"name=host, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Headers string `parquet:"name=headers, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	IP      string `parquet:"name=ip, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Body    string `parquet:"name=body, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run()
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			continue
		}

		reqSourceIP := h.net.Src().String()
		body, bErr := io.ReadAll(req.Body)
		if bErr != nil {
			log.Println("Error reading request body:", bErr)
			continue
		}
		req.Body.Close()

		jsonData, err := json.Marshal(req.Header)
		if err != nil {
			log.Println("Error marshalling headers to JSON:", err)
			continue
		}

		hostname := req.Host
		if hostname == "" {
			hostname = "unknown"
		}

		data := RequestData{
			Path:    req.URL.Path,
			Host:    hostname,
			Headers: string(jsonData),
			IP:      reqSourceIP,
			Body:    string(body),
		}

		// Add data to buffer for specific host
		addToBuffer(hostname, data)
	}
}

// Add request data to buffer and flush if necessary
func addToBuffer(hostname string, data RequestData) {
	bufferMux.Lock()
	defer bufferMux.Unlock()

	bufferMap[hostname] = append(bufferMap[hostname], data)

	// If the buffer for this host reaches the threshold, flush it
	if len(bufferMap[hostname]) >= flushSize {
		go flushBuffer(hostname)
	}
}

// Periodically flush buffers per host
func startBufferFlushTimer() {
	ticker := time.NewTicker(flushTime)
	defer ticker.Stop()

	for range ticker.C {
		bufferMux.Lock()
		for hostname := range bufferMap {
			if len(bufferMap[hostname]) > 0 {
				go flushBuffer(hostname)
			}
		}
		bufferMux.Unlock()
	}
}

// Flush buffer to S3 in a Parquet file per hostname
func flushBuffer(hostname string) {
	bufferMux.Lock()
	if len(bufferMap[hostname]) == 0 {
		bufferMux.Unlock()
		return
	}

	dataToWrite := make([]RequestData, len(bufferMap[hostname]))
	copy(dataToWrite, bufferMap[hostname])
	bufferMap[hostname] = nil // Clear buffer for this host
	bufferMux.Unlock()

	now := time.Now()
	objectKey := fmt.Sprintf("%s/%d/%02d/%02d/%d.parquet",
		hostname, now.Year(), now.Month(), now.Day(), now.UnixMilli(),
	)

	parquetBuffer, err := convertToParquet(dataToWrite)
	if err != nil {
		log.Println("Error converting batch to Parquet:", err)
		return
	}

	_, err = bucketBasics.S3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(parquetBuffer),
	})
	if err != nil {
		log.Println("Error uploading batch to S3:", err)
	}
}

// Convert batch of RequestData to Parquet format
func convertToParquet(data []RequestData) ([]byte, error) {
	var buf bytes.Buffer
	pw, err := writer.NewParquetWriterFromWriter(&buf, new(RequestData), 4)
	if err != nil {
		return nil, fmt.Errorf("failed to create Parquet writer: %w", err)
	}

	pw.RowGroupSize = 128 * 1024 * 1024
	pw.PageSize = 8 * 1024
	pw.CompressionType = parquet.CompressionCodec_SNAPPY

	for _, record := range data {
		if err := pw.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write Parquet data: %w", err)
		}
	}

	if err := pw.WriteStop(); err != nil {
		return nil, fmt.Errorf("failed to finalize Parquet file: %w", err)
	}

	return buf.Bytes(), nil
}

// TCP Health Check Client
func openTCPClient() {
	ln, err := net.Listen("tcp", ":4789")
	if err != nil {
		log.Println("Error listening on TCP:", err)
		os.Exit(1)
	}
	log.Println("Listening on TCP 4789")
	for {
		conn, _ := ln.Accept()
		conn.Close()
	}
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	log.Println("Starting capture on interface vxlan0")
	handle, err = pcap.OpenLive("vxlan0", 8951, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	BPFFilter := fmt.Sprintf("tcp and dst port %d", reqPort)
	if err := handle.SetBPFFilter(BPFFilter); err != nil {
		log.Fatal(err)
	}

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	log.Println("Reading packets")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	go openTCPClient()
	go startBufferFlushTimer()

	for {
		select {
		case packet := <-packets:
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(-1 * time.Minute))
		}
	}
}
