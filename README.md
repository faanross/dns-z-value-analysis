# DNS Z-Flag Analyzer

A Go tool for detecting covert DNS channel communication by analyzing Z-flag usage in DNS packets.

## Overview

This tool analyzes DNS traffic between two IP addresses to identify potential covert channels that abuse the DNS Z-flag (reserved bit) for command and control or data exfiltration.

## Installation

```bash
go get github.com/google/gopacket
go build -o dns-zflag-analyzer
```

## Usage

```bash
./dns-zflag-analyzer -pcap capture.pcapng -ip1 192.168.1.100 -ip2 8.8.8.8
```

### Flags

- `-pcap` - Path to pcap/pcapng file (required)
- `-ip1` - First IP address (required)
- `-ip2` - Second IP address (required)
- `-output` - Output CSV filename (default: dns_zflag_analysis.csv)
- `-verbose` - Enable detailed logging

## Output

Generates a CSV with the following columns:
- Source IP
- Destination IP
- Type (Request/Response)
- Record (A, TXT, etc.)
- Size (bytes)
- Domain
- Time Stamp
- Z-value (0 = normal, non-zero = suspicious)

## Example

```bash
# Basic analysis
./dns-zflag-analyzer -pcap dns_traffic.pcap -ip1 10.0.0.5 -ip2 8.8.8.8

# With verbose logging
./dns-zflag-analyzer -pcap dns_traffic.pcap -ip1 10.0.0.5 -ip2 8.8.8.8 -verbose
```

## Detection

Non-zero Z-flag values indicate potential covert channel activity, as this bit should always be 0 in legitimate DNS traffic.