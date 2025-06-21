#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Fuzzer para detección de anomalías.
Utiliza Scapy para generar consultas DNS aleatorias contra un servidor,
analiza las respuestas (código de respuesta, bit AA, número de registros, tipo y TTL de los RR, contenido de TXT), 
aplica un análisis estadístico de latencias para identificar respuestas inusuales y registra todos los resultados en un fichero CSV.
"""
import random
import string
import time
import logging
import statistics
import re
import csv
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1

# Configuración de logging
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
logger = logging.getLogger("dns_fuzzer")


class DNSFuzzer:
    TTL_THRESHOLD = 3600  # TTL máximo aceptable en segundos

    def __init__(
        self, target_ip, base_domain, port=53, timeout=2, iterations=100, outfile=None
    ):
        """
        :param target_ip: IP del servidor DNS a testear
        :param base_domain: Dominio para la consulta de baseline
        :param port: Puerto UDP (por defecto 53)
        :param timeout: Tiempo de espera para respuesta en segundos
        :param iterations: Número de paquetes de fuzzing a enviar
        :param outfile: Ruta de fichero CSV para guardar resultados
        """
        self.target = target_ip
        self.base_domain = base_domain
        self.port = port
        self.timeout = timeout
        self.iterations = iterations
        self.outfile = outfile
        self.baseline = self._query_baseline()
        self.times = []  # para análisis estadístico de tiempos
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
                        "anom",
                    ]
                )

    def _random_domain(self, length=8):
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{name}.com"

    def _random_qtype(self):
        types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        return random.choice(types)

    def _build_packet(self):
        """paquete DNS"""
        transaction_id = random.randint(0, 0xFFFF)
        qname = self._random_domain()
        qtype = self._random_qtype()
        pkt = (
            IP(dst=self.target)
            / UDP(dport=self.port)
            / DNS(id=transaction_id, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        )
        return pkt, qtype

    def _query_baseline(self):
        """guarda rcode, ancount y aa"""
        pkt = (
            IP(dst=self.target)
            / UDP(dport=self.port)
            / DNS(rd=1, qd=DNSQR(qname=self.base_domain, qtype="A"))
        )
        logger.info(f"Enviando consulta baseline a {self.base_domain}")
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if not resp or DNS not in resp:
            logger.warning("No se obtuvo respuesta baseline")
            return None
        dns = resp[DNS]
        return {"rcode": dns.rcode, "an_count": dns.ancount, "aa": dns.aa}

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
            f"Iniciando fuzzing: {self.iterations} iteraciones contra {self.target} (baseline: {self.base_domain})"
        )
        for i in range(1, self.iterations + 1):
            pkt, qtype = self._build_packet()
            start = time.time()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            duration = time.time() - start
            self.times.append(duration)
            anomalies = []
            dns = resp[DNS] if resp and DNS in resp else None

            if not resp:
                anomalies.append("timeout")
            elif not dns:
                anomalies.append("no_DNS_layer")
            else:
                if dns.rcode == 3:
                    logger.info(f"Iteración {i}: NXDOMAIN")
                else:
                    if self.baseline:
                        if dns.rcode != self.baseline["rcode"]:
                            anomalies.append(f"rcode:{dns.rcode}")
                        if dns.aa != self.baseline["aa"]:
                            anomalies.append(f"aa:{dns.aa}")
                        if dns.ancount > self.baseline["an_count"] + 5:
                            anomalies.append(f"ancount:{dns.ancount}")
                    if len(self.times) >= 10:
                        m, s = statistics.mean(self.times), statistics.stdev(self.times)
                        if duration > m + 3 * s:
                            anomalies.append(f"slow:{duration:.3f}")
                    if dns.ancount > 0:
                        rr = dns.an
                        exp = pkt[DNSQR].qtype
                        if hasattr(rr, "type") and rr.type != exp:
                            anomalies.append(f"type:{rr.type}")
                        if hasattr(rr, "ttl") and rr.ttl > self.TTL_THRESHOLD:
                            anomalies.append(f"ttl:{rr.ttl}")
                        if qtype == "TXT" and hasattr(rr, "rdata"):
                            payload = (
                                rr.rdata.decode(errors="ignore")
                                if isinstance(rr.rdata, (bytes, bytearray))
                                else str(rr.rdata)
                            )
                            if not re.match(r"^[\x20-\x7E]+$", payload):
                                anomalies.append("txt_payload")
            if anomalies:
                logger.warning(f"Iteración {i}: Anomalías -> {', '.join(anomalies)}")
            else:
                status = "NXDOMAIN" if dns and dns.rcode == 3 else "OK"
                logger.info(f"Iteración {i}: {status} ({duration:.2f}s)")
            self._log_csv(i, qtype, duration, dns, anomalies)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DNS Fuzzer con detección avanzada de anomalías usando Scapy"
    )
    parser.add_argument("target", help="IP del servidor DNS objetivo")
    parser.add_argument(
        "-d",
        "--domain",
        dest="domain",
        default="tudominio.com",
        help="Dominio para consulta baseline (por defecto: tudominio.com)",
    )
    parser.add_argument(
        "-n", "--iterations", type=int, default=100, help="Número de consultas a enviar"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Tiempo de espera por respuesta (s)",
    )
    parser.add_argument("-o", "--output", help="Fichero CSV para guardar resultados")
    args = parser.parse_args()

    fuzzer = DNSFuzzer(
        target_ip=args.target,
        base_domain=args.domain,
        iterations=args.iterations,
        timeout=args.timeout,
        outfile=args.output,
    )
    fuzzer.fuzz()
