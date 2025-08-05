package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DNSRecord struct {
	SrcIP      string
	DstIP      string
	Type       string // Request/Response
	RecordType string // A, TXT, etc.
	Size       int
	Domain     string
	Timestamp  time.Time
	ZValue     uint8
}

var verbose bool

func main() {
	// Parse command line flags
	pcapFile := flag.String("pcap", "", "Path to pcap(ng) file")
	ip1 := flag.String("ip1", "", "First IP address (can be source or destination)")
	ip2 := flag.String("ip2", "", "Second IP address (can be source or destination)")
	output := flag.String("output", "dns_zflag_analysis.csv", "Output CSV file name")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	// Validate inputs
	if *pcapFile == "" || *ip1 == "" || *ip2 == "" {
		fmt.Println("Usage: dns-zflag-analyzer -pcap <file> -ip1 <ip> -ip2 <ip> [-output <file>] [-verbose]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("Opening pcap file: %s\n", *pcapFile)
	fmt.Printf("Looking for DNS traffic between %s and %s\n", *ip1, *ip2)

	// Open pcap file
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("Error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Process packets
	records := processPackets(handle, *ip1, *ip2)

	// Write results to CSV
	if err := writeCSV(*output, records); err != nil {
		log.Fatalf("Error writing CSV: %v", err)
	}

	fmt.Printf("Analysis complete. Results written to %s\n", *output)
	fmt.Printf("Total DNS records analyzed: %d\n", len(records))

	// Print Z-flag statistics
	zFlagCount := 0
	for _, record := range records {
		if record.ZValue != 0 {
			zFlagCount++
		}
	}
	fmt.Printf("Records with non-zero Z-flag: %d\n", zFlagCount)
}

func processPackets(handle *pcap.Handle, ip1, ip2 string) []DNSRecord {
	var records []DNSRecord
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetCount := 0
	ipMatchCount := 0
	dnsPacketCount := 0

	for packet := range packetSource.Packets() {
		packetCount++

		// Get network layer
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			if verbose {
				fmt.Printf("Packet %d: No network layer\n", packetCount)
			}
			continue
		}

		var srcIP, dstIP string

		// Check if it's IPv4 packet
		if ipLayer, ok := networkLayer.(*layers.IPv4); ok {
			srcIP = ipLayer.SrcIP.String()
			dstIP = ipLayer.DstIP.String()
		} else if ipv6Layer, ok := networkLayer.(*layers.IPv6); ok {
			srcIP = ipv6Layer.SrcIP.String()
			dstIP = ipv6Layer.DstIP.String()
		} else {
			if verbose {
				fmt.Printf("Packet %d: Unknown network layer type\n", packetCount)
			}
			continue
		}

		// Check if packet is between our two IPs
		if !isPacketBetweenIPs(srcIP, dstIP, ip1, ip2) {
			continue
		}

		ipMatchCount++
		if verbose {
			fmt.Printf("Packet %d: IP match found - %s -> %s\n", packetCount, srcIP, dstIP)
		}

		// Check for DNS layer directly
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			if verbose {
				fmt.Printf("Packet %d: No DNS layer found\n", packetCount)
			}
			continue
		}

		dns, ok := dnsLayer.(*layers.DNS)
		if !ok {
			if verbose {
				fmt.Printf("Packet %d: Failed to cast DNS layer\n", packetCount)
			}
			continue
		}

		dnsPacketCount++
		if verbose {
			fmt.Printf("Packet %d: DNS packet found! ID: %d, QR: %v\n", packetCount, dns.ID, dns.QR)
		}

		// Extract DNS information
		record := extractDNSRecord(packet, dns, srcIP, dstIP)
		if record != nil {
			records = append(records, *record)
			if verbose {
				fmt.Printf("  -> Added record: %s -> %s, Type: %s, Domain: %s, Z: %d\n",
					record.SrcIP, record.DstIP, record.Type, record.Domain, record.ZValue)
			}
		}
	}

	fmt.Printf("\nPacket statistics:\n")
	fmt.Printf("Total packets processed: %d\n", packetCount)
	fmt.Printf("Packets between specified IPs: %d\n", ipMatchCount)
	fmt.Printf("DNS packets found: %d\n", dnsPacketCount)

	return records
}

func isPacketBetweenIPs(srcIP, dstIP, ip1, ip2 string) bool {
	return (srcIP == ip1 && dstIP == ip2) || (srcIP == ip2 && dstIP == ip1)
}

func extractDNSRecord(packet gopacket.Packet, dns *layers.DNS, srcIP, dstIP string) *DNSRecord {
	record := &DNSRecord{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		Size:      len(packet.Data()),
		Timestamp: packet.Metadata().Timestamp,
		ZValue:    extractZFlag(dns),
	}

	// Determine if it's a request or response
	if dns.QR {
		record.Type = "Response"
	} else {
		record.Type = "Request"
	}

	// Extract domain names and record types
	if len(dns.Questions) > 0 {
		record.Domain = string(dns.Questions[0].Name)
		record.RecordType = dns.Questions[0].Type.String()

		if verbose {
			fmt.Printf("  Question: %s (Type: %s)\n", record.Domain, record.RecordType)
		}
	}

	// For responses, also check answer records
	if dns.QR && len(dns.Answers) > 0 {
		// Use the first answer's type if available
		record.RecordType = dns.Answers[0].Type.String()
		if record.Domain == "" && dns.Answers[0].Name != nil {
			record.Domain = string(dns.Answers[0].Name)
		}

		if verbose {
			fmt.Printf("  Answer: Type %s\n", record.RecordType)
		}
	}

	// Handle cases where we might not have extracted a domain
	if record.Domain == "" {
		record.Domain = "<unknown>"
	}

	return record
}

func extractZFlag(dns *layers.DNS) uint8 {
	// The Z flag is stored directly in the DNS structure
	// In gopacket, it's already extracted for us
	return dns.Z
}

func writeCSV(filename string, records []DNSRecord) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Source IP",
		"Destination IP",
		"Type",
		"Record",
		"Size (bytes)",
		"Domain",
		"Time Stamp",
		"Z-value",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write records
	for _, record := range records {
		row := []string{
			record.SrcIP,
			record.DstIP,
			record.Type,
			record.RecordType,
			strconv.Itoa(record.Size),
			record.Domain,
			record.Timestamp.Format("2006-01-02 15:04:05.000000"),
			strconv.Itoa(int(record.ZValue)),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
