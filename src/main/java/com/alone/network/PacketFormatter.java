        Instant timestamp = Instant.now();
Instant timestamp = Instant.now();package com.alone.network;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Clase utilitaria encargada de extraer metadatos de los paquetes capturados
 * y convertirlos a formato JSON. No mantiene estado interno.
 */
public final class PacketFormatter {

    // Formateador ISO 8601 con precision de milisegundos (ej. 2026-07-14T22:15:30.123Z)
    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ISO_INSTANT;

    private PacketFormatter() {
        // Clase utilitaria: no se debe instanciar.
    }

    /**
     * Extrae los metadatos relevantes de un paquete capturado.
     * Solo procesa paquetes con capa IP (v4 o v6) y transporte TCP o UDP.
     *
     * @param packet el paquete capturado por Pcap4J.
     * @return un mapa ordenado con los metadatos, o null si el paquete no es de interes.
     */
    public static Map<String, Object> extractMetadata(Packet packet) {
        // Usamos LinkedHashMap para preservar el orden de insercion en el JSON de salida.
        Map<String, Object> metadata = new LinkedHashMap<>();

        // 1. Timestamp del paquete, formateado como ISO 8601.
        Instant timestamp = Instant.now();
        metadata.put("timestamp", ISO_FORMATTER.format(timestamp));

        // 2. Determinar la capa IP (IPv4 o IPv6).
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);

        String srcIp;
        String dstIp;
        int ttl;

        if (ipV4Packet != null) {
            srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();
            ttl = ipV4Packet.getHeader().getTtl();
        } else if (ipV6Packet != null) {
            srcIp = ipV6Packet.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipV6Packet.getHeader().getDstAddr().getHostAddress();
            ttl = ipV6Packet.getHeader().getHopLimit();
        } else {
            // No hay capa IP: no nos interesa este paquete.
            return null;
        }

        metadata.put("src_ip", srcIp);
        metadata.put("dst_ip", dstIp);
        metadata.put("ttl", ttl);

        // 3. Determinar la capa de transporte (TCP o UDP).
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (tcpPacket != null) {
            metadata.put("protocol", "TCP");
            metadata.put("src_port", tcpPacket.getHeader().getSrcPort().valueAsInt());
            metadata.put("dst_port", tcpPacket.getHeader().getDstPort().valueAsInt());
            metadata.put("window_size", tcpPacket.getHeader().getWindow());

            // Sub-mapa con los flags TCP relevantes.
            Map<String, Integer> tcpFlags = new LinkedHashMap<>();
            tcpFlags.put("SYN", tcpPacket.getHeader().getSyn() ? 1 : 0);
            tcpFlags.put("ACK", tcpPacket.getHeader().getAck() ? 1 : 0);
            tcpFlags.put("FIN", tcpPacket.getHeader().getFin() ? 1 : 0);
            tcpFlags.put("RST", tcpPacket.getHeader().getRst() ? 1 : 0);
            tcpFlags.put("PSH", tcpPacket.getHeader().getPsh() ? 1 : 0);
            tcpFlags.put("URG", tcpPacket.getHeader().getUrg() ? 1 : 0);
            metadata.put("tcp_flags", tcpFlags);

        } else if (udpPacket != null) {
            metadata.put("protocol", "UDP");
            metadata.put("src_port", udpPacket.getHeader().getSrcPort().valueAsInt());
            metadata.put("dst_port", udpPacket.getHeader().getDstPort().valueAsInt());
            metadata.put("length", udpPacket.getHeader().getLength());

        } else {
            // No es TCP ni UDP: no nos interesa este paquete.
            return null;
        }

        return metadata;
    }

    /**
     * Convierte el mapa de metadatos a una linea JSON (sin indentacion).
     *
     * @param metadata mapa de metadatos generado por extractMetadata.
     * @return cadena JSON en una sola linea, o "{}" si ocurre un error de serializacion.
     */
    public static String toJson(Map<String, Object> metadata) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            // En caso de error de serializacion, devolvemos un objeto JSON vacio.
            return "{}";
        }
    }
}
