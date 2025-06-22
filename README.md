# DNS Fuzzer

Python tool to perform DNS server fuzzing and detect anomalies in their responses.

## Description

DNS Fuzzer sends randomly generated DNS queries to a target server and analyzes the responses to identify unusual or potentially malicious behavior.

## Features

* **Configurable baseline**: uses a reference domain to establish expected values for `RCODE`, `AA`, and `ANCOUNT`.
* **Random generation** of domain names and query types (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`).
* Detection of anomalies in responses:

  * Unexpected response codes (`RCODE`).
  * Variation in the authority bit (`AA`).
  * Differences in the number of records (`ANCOUNT`).
  * Latencies beyond threshold (`µ + 3σ`).
  * RR types different from those requested.
  * Excessive TTL (> 3600 s).
  * Non-printable content in TXT records.
  * Responses missing DNS layer or with timeouts.
* **Optional CSV output** for further analysis.

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
python3 dnsfuzzer.py <SERVER_IP> \
    -d <BASELINE_DOMAIN> \
    -n <ITERATIONS> \
    -t <TIMEOUT> \
    -o <CSV_FILE>
```

### Parameters

* `SERVER_IP`: IP address of the DNS server to test.
* `-d, --domain`: domain for baseline query (default is `example.com`).
* `-n, --iterations`: number of queries to send (default is `100`).
* `-t, --timeout`: timeout in seconds (default is `2.0`).
* `-o, --output`: path to the CSV file to save results.

## Example

```bash
python3 dnsfuzzer.py 1.1.1.1 -d google.es -n 200 -t 1.5 -o results.csv
```

## Interpreting results

* `OK` lines indicate responses consistent with the baseline.
* `NXDOMAIN` is expected for nonexistent domains.
* `WARNING` highlights detailed anomalies (code, latency, TTL, etc.).
* The CSV includes columns: `timestamp, iteration, qtype, duration, rcode, an_count, anom`.

## Contributions

Feel free to open pull requests or issues for improvements or fixes.

## License

MIT License
