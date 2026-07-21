---
# Network Traffic Analyzer

![Java](https://img.shields.io/badge/Java-17-orange?logo=openjdk&logoColor=white)

Herramienta de línea de comandos para capturar y analizar tráfico de red en tiempo real. Extrae metadatos de paquetes TCP/IP y los exporta en formato JSONL.

## Requisitos

- Java 17
- Maven
- libpcap (instalado en el sistema)
- Permisos de root

## Compilación

```
mvn clean package
```

## Uso

```
sudo java -jar target/network-analyzer-1.0.jar <interfaz>
```

Ejemplo:

```
sudo java -jar target/network-analyzer-1.0.jar eth0
```

Presiona `Ctrl+C` para detener la captura y ver el resumen final.

## Ejemplo de salida

```
{"timestamp":"2026-07-14T22:15:30.123Z","src_ip":"192.168.1.100","dst_ip":"8.8.8.8","ttl":64,"protocol":"TCP","src_port":54321,"dst_port":443,"window_size":65535,"tcp_flags":{"SYN":1,"ACK":0,"FIN":0,"RST":0,"PSH":0,"URG":0}}
{"timestamp":"2026-07-14T22:15:30.456Z","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","ttl":128,"protocol":"UDP","src_port":53,"dst_port":45678,"length":128}
```

## Nota

Este proyecto es solo para fines educativos y de diagnóstico en redes propias o con autorización explícita.


---

Este proyecto forma parte del [Ecosistema Nexus](https://github.com/Alonex-x/nexus-agent-api/blob/main/ECOSYSTEM.md).
