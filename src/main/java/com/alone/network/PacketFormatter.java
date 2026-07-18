package com.alone.network;

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

public final class PacketFormatter {

    private static final DateTimeFormatter ISO_FORMATTER =
            DateTimeFormatter.ISO_INSTANT;

    private PacketFormatter() {
    }

    public static Map<String, Object> extractMetadata(Packet packet) {
        Map<String, Object> metadata = new LinkedHashMap<>();

        Instant timestamp = Instant.now();
        metadata.put("timestamp", ISO_FORMATTER.format(timestamp));

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
            return null;
        }

        metadata.put("src_ip", srcIp);
        metadata.put("dst_ip", dstIp);
        metadata.put("ttl", ttl);

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        UdpPacket udpPacket = packet.get(UdpPacket.class);

        if (tcpPacket != null) {
            metadata.put("protocol", "TCP");
            metadata.put("src_port", tcpPacket.getHeader().getSrcPort().valueAsInt());
            metadata.put("dst_port", tcpPacket.getHeader().getDstPort().valueAsInt());
            metadata.put("window_size", tcpPacket.getHeader().getWindow());

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
            return null;
        }

        return metadata;
    }

    public static String toJson(Map<String, Object> metadata) {
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }
}
