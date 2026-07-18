# Caso de estudio: network-traffic-analyzer

**Problema.** Diagnosticar problemas de red o entender qué está pasando en una interfaz suele requerir herramientas pesadas como Wireshark, que ofrecen mucha más información de la que un desarrollador o administrador necesita para una revisión rápida, y no siempre son prácticas para integrarse en un script o un pipeline de monitoreo.

**Solución.** `network-traffic-analyzer` es una herramienta de línea de comandos en Java que captura tráfico de forma pasiva sobre una interfaz de red y extrae, paquete por paquete, los metadatos más relevantes (IPs de origen y destino, puertos, protocolo, TTL, flags TCP) en formato JSON, listo para volcarse a un archivo, canalizarse a otra herramienta o analizarse con `jq`. Al cerrarse, imprime un resumen con el total de paquetes capturados y perdidos.

**Resultado.** El proyecto pasó de ser un script funcional a una base con tests automatizados (JUnit 5) que cubren tanto la extracción de metadatos como el comportamiento del punto de entrada, e integración continua con GitHub Actions que valida cada cambio antes de fusionarse a `main`. Esto lo deja en un estado más cercano a una herramienta mantenible que a un experimento de una sola sesión.
