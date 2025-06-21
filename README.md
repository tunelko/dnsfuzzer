# DNS Fuzzer

Herramienta en Python para realizar fuzzing de servidores DNS y detectar anomalías en sus respuestas.

## Descripción

DNS Fuzzer envía consultas DNS generadas aleatoriamente a un servidor objetivo y analiza las respuestas para identificar comportamientos inusuales o potencialmente maliciosos.

## Características

* **Baseline configurable**: usa un dominio de referencia para establecer valores de `RCODE`, `AA` y `ANCOUNT`.
* **Generación aleatoria** de nombres de dominio y tipos de consulta (`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`).
* Detección de anomalías en respuestas:

  * Códigos de respuesta inesperados (`RCODE`).
  * Variación en el bit de autoridad (`AA`).
  * Diferencias en el número de registros (`ANCOUNT`).
  * Latencias fuera de umbral (`µ + 3σ`).
  * Tipos de RR distintos a los solicitados.
  * TTL excesivo (> 3600 s).
  * Contenido no imprimible en registros TXT.
  * Respuestas sin capa DNS o timeouts.
* **Salida opcional en CSV** para análisis posterior.

## Requisitos

* Python 3.6+
* [Scapy](https://scapy.net/)

## Instalación

```bash
# Crear y activar un entorno virtual (opcional)
python3 -m venv venv
source venv/bin/activate

# Instalar dependencia
pip install scapy
```

## Uso

```bash
python3 dnsfuzzer.py <IP_SERVIDOR> \
    -d <DOMINIO_BASELINE> \
    -n <ITERACIONES> \
    -t <TIMEOUT> \
    -o <FICHERO_CSV>
```

### Parámetros

* `IP_SERVIDOR`: dirección IP del DNS a testear.
* `-d, --domain`: dominio para consulta baseline (por defecto `example.com`).
* `-n, --iterations`: número de consultas (por defecto `100`).
* `-t, --timeout`: tiempo de espera en segundos (por defecto `2.0`).
* `-o, --output`: ruta de fichero CSV para guardar resultados.

## Ejemplo

```bash
python3 dnsfuzzer.py 1.1.1.1 -d google.es -n 200 -t 1.5 -o resultados.csv
```

## Interpretación de resultados

* Las líneas `OK` indican respuestas coherentes con la baseline.
* `NXDOMAIN` es esperado para dominios inexistentes.
* `WARNING` destaca anomalías detalladas (código, latencia, TTL, etc.).
* El CSV incluye columnas: `timestamp, iteration, qtype, duration, rcode, an_count, anom`.

## Contribuciones

Si quieres, abre pull requests o issues para mejoras o correcciones.

## Licencia

MIT License

