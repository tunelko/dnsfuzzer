# DNS Fuzzer

Python tool to perform DNS server fuzzing and detect anomalies in their responses, including DNSSEC queries, timeout retransmissions, and detailed response analysis.

## Description

This script uses Scapy to generate random DNS queries against a target server, measures baseline behavior on a chosen domain, and applies the following tests:

* **DNSSEC record queries** (`DNSKEY`, `DS`, `RRSIG`, `NSEC`) and compares flags (`AA`, `RA`) with baseline.
* **Timeout handling and retransmissions**: retries on timeout and marks `timeout_retransmit` anomalies.
* **Response analysis**:

  * Verifies `RA` flag consistency.
  * Detects high (> 3600 s) and low (< 10 s) TTL values.
  * Checks TTL consistency across multiple records (`ttl_inconsistent`).
  * Detects duplicate records in a response (`duplicate_records`).
* **Optional CSV output** for further analysis.
* **Optional PCAP logging** to capture all DNS traffic.

## Requirements

* Python 3.6+
* [Scapy](https://scapy.net/)

## Installation

```bash
# Create and activate a virtual environment (optional)
python3 -m venv venv
source venv/bin/activate

# Install dependency
pip install scapy
```

## Usage

```bash
python3 dnsfuzzer.py TARGET_IP -d BASELINE_DOMAIN [-n ITERATIONS] [-t TIMEOUT] [-o OUTPUT_CSV] [--pcap PCAP_FILE]
```

### Arguments

* `TARGET_IP`: IP address of the DNS server to test.
* `-d, --domain`: Domain for baseline query (default: `yourdomain.com`). Baseline measures `rcode`, `an_count`, `AA` and `RA` flags.
* `-n, --iterations`: Number of queries to send (default: `100`).
* `-t, --timeout`: Timeout for each query, in seconds (default: `2.0`).
* `-o, --output`: Path to a CSV file to save results. Columns: `timestamp`, `iteration`, `qtype`, `duration`, `rcode`, `an_count`, `anom`.
* `--pcap`: Path to save a PCAP file capturing all DNS queries and responses.

### Example

```bash
# Fuzz 200 iterations against 8.8.8.8 with baseline example.com, save CSV and PCAP
python3 dnsfuzzer.py 8.8.8.8 -d example.com -n 200 -t 1.5 -o results.csv --pcap dns_traffic.pcap
```

* This will perform 200 random queries (including DNSSEC types), retry timeouts once, compare flags and TTLs, log anomalies to `results.csv`, and save the raw packets to `dns_traffic.pcap`.

## Interpreting Results

* **OK**: Response matches baseline and passes all checks.
* **NXDOMAIN**: Server returned `rcode=3` (nonexistent domain).
* **Anomalies**: See `anom` column for tags such as:

  * `timeout_retransmit`, `no_DNS_layer`, `rcode:<value>`, `aa:<value>`, `ra:<value>`
  * `slow:<duration>`, `ttl_high:<value>`, `ttl_low:<value>`, `ttl_inconsistent`, `duplicate_records`, `txt_payload`.

## License

MIT License
