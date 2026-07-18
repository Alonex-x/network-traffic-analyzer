package com.alone.network;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitarios para PacketFormatter.
 *
 * En lugar de mockear las clases de Pcap4J (varias son finales o dependen de
 * builders internos dificiles de simular fielmente), estos tests construyen
 * paquetes IPv4/TCP e IPv4/UDP reales usando los builders que ofrece la propia
 * libreria. Esto prueba extractMetadata() contra el comportamiento real de
 * Pcap4J en vez de contra un doble que podria no reflejarlo.
 */
class PacketFormatterTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private Inet4Address direccion(String ip) throws UnknownHostException {
        return (Inet4Address) InetAddress.getByName(ip);
    }

    private Packet construirPaqueteTcp() throws Exception {
        byte[] payload = "hola-tcp".getBytes();

        UnknownPacket.Builder payloadBuilder = new UnknownPacket.Builder();
        payloadBuilder.rawData(payload);

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
        tcpBuilder
                .srcPort(TcpPort.getInstance((short) 51234))
                .dstPort(TcpPort.getInstance((short) 443))
                .sequenceNumber(1000)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .syn(true)
                .ack(false)
                .fin(false)
                .rst(false)
                .psh(false)
                .urg(false)
                .window((short) 64240)
                .urgentPointer((short) 0)
                .srcAddr(direccion("192.168.1.10"))
                .dstAddr(direccion("93.184.216.34"))
                .payloadBuilder(payloadBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(direccion("192.168.1.10"))
                .dstAddr(direccion("93.184.216.34"))
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }

    private Packet construirPaqueteUdp() throws Exception {
        byte[] payload = "hola-udp".getBytes();

        UnknownPacket.Builder payloadBuilder = new UnknownPacket.Builder();
        payloadBuilder.rawData(payload);

        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .srcPort(UdpPort.getInstance((short) 5353))
                .dstPort(UdpPort.getInstance((short) 53))
                .srcAddr(direccion("192.168.1.10"))
                .dstAddr(direccion("8.8.8.8"))
                .payloadBuilder(payloadBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .ttl((byte) 128)
                .protocol(IpNumber.UDP)
                .srcAddr(direccion("192.168.1.10"))
                .dstAddr(direccion("8.8.8.8"))
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }

    @Test
    @DisplayName("extractMetadata reconoce un paquete TCP sobre IPv4 y extrae sus campos")
    void extractMetadataPaqueteTcp() throws Exception {
        Packet paqueteTcp = construirPaqueteTcp();

        Map<String, Object> metadata = PacketFormatter.extractMetadata(paqueteTcp);

        assertNotNull(metadata);
        assertEquals("192.168.1.10", metadata.get("src_ip"));
        assertEquals("93.184.216.34", metadata.get("dst_ip"));
        assertEquals(64, metadata.get("ttl"));
        assertEquals("TCP", metadata.get("protocol"));
        assertEquals(51234, metadata.get("src_port"));
        assertEquals(443, metadata.get("dst_port"));
        assertEquals((short) 64240, metadata.get("window_size"));
        assertNotNull(metadata.get("timestamp"));

        @SuppressWarnings("unchecked")
        Map<String, Integer> flags = (Map<String, Integer>) metadata.get("tcp_flags");
        assertEquals(1, flags.get("SYN"));
        assertEquals(0, flags.get("ACK"));
        assertEquals(0, flags.get("FIN"));
    }

    @Test
    @DisplayName("extractMetadata reconoce un paquete UDP sobre IPv4 y extrae sus campos")
    void extractMetadataPaqueteUdp() throws Exception {
        Packet paqueteUdp = construirPaqueteUdp();

        Map<String, Object> metadata = PacketFormatter.extractMetadata(paqueteUdp);

        assertNotNull(metadata);
        assertEquals("192.168.1.10", metadata.get("src_ip"));
        assertEquals("8.8.8.8", metadata.get("dst_ip"));
        assertEquals(128, metadata.get("ttl"));
        assertEquals("UDP", metadata.get("protocol"));
        assertEquals(5353, metadata.get("src_port"));
        assertEquals(53, metadata.get("dst_port"));
        assertNotNull(metadata.get("length"));
        assertFalse(metadata.containsKey("tcp_flags"));
    }

    @Test
    @DisplayName("extractMetadata devuelve null cuando el paquete no tiene capa TCP ni UDP")
    void extractMetadataSinTransporteConocido() throws Exception {
        UnknownPacket.Builder payloadBuilder = new UnknownPacket.Builder();
        payloadBuilder.rawData("sin-transporte".getBytes());

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .ihl((byte) 5)
                .ttl((byte) 64)
                .protocol(IpNumber.getInstance((byte) 253)) // protocolo experimental, sin parser TCP/UDP
                .srcAddr(direccion("10.0.0.1"))
                .dstAddr(direccion("10.0.0.2"))
                .payloadBuilder(payloadBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(ipBuilder.build());

        assertNull(metadata);
    }

    @Test
    @DisplayName("toJson serializa los metadatos a un JSON valido con los mismos valores")
    void toJsonSerializaCorrectamente() throws Exception {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("src_ip", "192.168.1.10");
        metadata.put("dst_ip", "93.184.216.34");
        metadata.put("protocol", "TCP");
        metadata.put("src_port", 51234);
        metadata.put("dst_port", 443);

        String json = PacketFormatter.toJson(metadata);
        JsonNode nodo = OBJECT_MAPPER.readTree(json);

        assertEquals("192.168.1.10", nodo.get("src_ip").asText());
        assertEquals("93.184.216.34", nodo.get("dst_ip").asText());
        assertEquals("TCP", nodo.get("protocol").asText());
        assertEquals(51234, nodo.get("src_port").asInt());
        assertEquals(443, nodo.get("dst_port").asInt());
    }

    @Test
    @DisplayName("toJson y extractMetadata funcionan juntos de extremo a extremo para un paquete TCP real")
    void extractMetadataYToJsonEnConjunto() throws Exception {
        Map<String, Object> metadata = PacketFormatter.extractMetadata(construirPaqueteTcp());
        String json = PacketFormatter.toJson(metadata);

        JsonNode nodo = OBJECT_MAPPER.readTree(json);

        assertEquals("TCP", nodo.get("protocol").asText());
        assertTrue(nodo.has("tcp_flags"));
        assertTrue(nodo.get("tcp_flags").has("SYN"));
    }
}
