#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Fuzzer for anomaly detection.
Uses Scapy to generate random DNS queries against a server,
analyzes responses (response code, AA bit, RA bit, record count, RR type and TTL, TXT content),
applies statistical analysis of latencies, performs retransmissions on timeouts,
executes DNSSEC record queries, and logs all results to CSV and optionally to a PCAP file.
"""
import random
import string
import time
import logging
import statistics
import re
import csv
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, wrpcap

# Logging configuration
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger("dns_fuzzer")


class DNSFuzzer:
    TTL_THRESHOLD = 3600  # Maximum acceptable TTL in seconds
    LOW_TTL_THRESHOLD = 10  # Minimum TTL threshold for anomaly

    def __init__(
        self,
        target_ip,
        base_domain,
        port=53,
        timeout=2,
        iterations=100,
        outfile=None,
        pcap=None,
    ):
        self.target = target_ip
        self.base_domain = base_domain
        self.port = port
        self.timeout = timeout
        self.iterations = iterations
        self.outfile = outfile
        self.pcap = pcap
        self.baseline = self._query_baseline()
        self.times = []  # For latency statistics
        self.pcap_packets = []

        if self.outfile:
            with open(self.outfile, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "timestamp",
                        "iteration",
                        "qtype",
                        "duration",
                        "rcode",
                        "an_count",
                        "anomalies",
                    ]
                )

    def _random_domain(self, length=8):
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{name}.com"

    def _random_qtype(self):
        types = [
            "A",
            "AAAA",
            "MX",
            "NS",
            "TXT",
            "CNAME",
            "SOA",
            "DNSKEY",
            "DS",
            "RRSIG",
            "NSEC",
        ]
        return random.choice(types)

    def _build_packet(self, qtype=None, domain=None):
        transaction_id = random.randint(0, 0xFFFF)
        qname = domain or self._random_domain()
        qt = qtype or self._random_qtype()
        pkt = (
            IP(dst=self.target)
            / UDP(dport=self.port)
            / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=qname, qtype=qt))
        )
        return pkt, qt

    def _query_baseline(self):
        pkt, _ = self._build_packet(qtype="A", domain=self.base_domain)
        logger.info(f"Sending baseline query to {self.base_domain}")
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if not resp or DNS not in resp:
            logger.warning("No baseline response received")
            return None
        dns = resp[DNS]
        return {
            "rcode": dns.rcode,
            "an_count": dns.ancount,
            "aa": dns.aa,
            "ra": dns.ra,
        }

    def _log_csv(self, iteration, qtype, duration, dns, anomalies):
        if not self.outfile:
            return
        with open(self.outfile, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    iteration,
                    qtype,
                    f"{duration:.3f}",
                    getattr(dns, "rcode", ""),
                    getattr(dns, "ancount", ""),
                    ";".join(anomalies),
                ]
            )

    def fuzz(self):
        logger.info(
            f"Starting fuzzing: {self.iterations} iterations against {self.target} (baseline: {self.base_domain})"
        )
        for i in range(1, self.iterations + 1):
            pkt, qtype = self._build_packet()
            start = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            duration = time.time() - start
            self.times.append(duration)

            # Retransmission on timeout
            if not resp:
                logger.info(f"Iteration {i}: timeout, retrying")
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                anomalies = ["timeout_retransmit"]
            else:
                anomalies = []

            # PCAP logging
            if self.pcap:
                self.pcap_packets.append(pkt)
                if resp:
                    self.pcap_packets.append(resp)

            dns = resp[DNS] if resp and DNS in resp else None

            if not dns:
                anomalies.append("no_DNS_layer")
            else:
                # Check NXDOMAIN
                if dns.rcode == 3:
                    logger.info(f"Iteration {i}: NXDOMAIN")
                else:
                    # Baseline comparisons
                    if self.baseline:
                        if dns.rcode != self.baseline["rcode"]:
                            anomalies.append(f"rcode:{dns.rcode}")
                        if dns.aa != self.baseline["aa"]:
                            anomalies.append(f"aa:{dns.aa}")
                        if dns.ra != self.baseline["ra"]:
                            anomalies.append(f"ra:{dns.ra}")
                        if dns.ancount > self.baseline["an_count"] + 5:
                            anomalies.append(f"an_count:{dns.ancount}")
                    # Latency anomaly
                    if len(self.times) >= 10:
                        m, s = statistics.mean(self.times), statistics.stdev(self.times)
                        if duration > m + 3 * s:
                            anomalies.append(f"slow:{duration:.3f}")
                    # Record checks
                    if dns.ancount > 0:
                        # Multiple record consistency
                        ttls = []
                        rdatas = []
                        rr = dns.an
                        # handle single vs multiple
                        for j in range(dns.ancount):
                            r = resp.an[j] if isinstance(resp.an, list) else resp.an
                            if hasattr(r, "ttl"):
                                ttls.append(r.ttl)
                            if hasattr(r, "rdata"):
                                rdatas.append(r.rdata)
                            # Type mismatch
                            exp = pkt[DNSQR].qtype
                            if r.type != exp:
                                anomalies.append(f"type:{r.type}")
                            if r.ttl > self.TTL_THRESHOLD:
                                anomalies.append(f"ttl_high:{r.ttl}")
                            if r.ttl < self.LOW_TTL_THRESHOLD:
                                anomalies.append(f"ttl_low:{r.ttl}")
                            if qtype == "TXT" and hasattr(r, "rdata"):
                                payload = (
                                    r.rdata.decode(errors="ignore")
                                    if isinstance(r.rdata, (bytes, bytearray))
                                    else str(r.rdata)
                                )
                                if not re.match(r"^[\x20-\x7E]+$", payload):
                                    anomalies.append("txt_payload")
                        if len(set(ttls)) > 1:
                            anomalies.append("ttl_inconsistent")
                        if len(rdatas) != len(set(rdatas)):
                            anomalies.append("duplicate_records")

            if anomalies:
                logger.warning(f"Iteration {i}: Anomalies -> {', '.join(anomalies)}")
            else:
                status = "NXDOMAIN" if dns and dns.rcode == 3 else "OK"
                logger.info(f"Iteration {i}: {status} ({duration:.2f}s)")

            self._log_csv(i, qtype, duration, dns, anomalies)

        # Save PCAP if requested
        if self.pcap and self.pcap_packets:
            logger.info(
                f"Writing PCAP to {self.pcap} ({len(self.pcap_packets)} packets)"
            )
            wrpcap(self.pcap, self.pcap_packets)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DNS Fuzzer with advanced anomaly detection using Scapy"
    )
    parser.add_argument("target", help="Target DNS server IP address")
    parser.add_argument(
        "-d",
        "--domain",
        dest="domain",
        default="yourdomain.com",
        help="Domain for baseline query (default: yourdomain.com)",
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=100, help="Number of queries to send"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout for response (s)",
    )
    parser.add_argument("-o", "--output", help="CSV file to save results")
    parser.add_argument("--pcap", help="Path to save PCAP file of DNS traffic")
    args = parser.parse_args()

    fuzzer = DNSFuzzer(
        target_ip=args.target,
        base_domain=args.domain,
        iterations=args.iterations,
        timeout=args.timeout,
        outfile=args.output,
        pcap=args.pcap,
    )
    fuzzer.fuzz()
