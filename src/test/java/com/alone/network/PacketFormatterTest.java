
package com.alone.network;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.packet.namednumber.UdpPort;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests de PacketFormatter usando Mockito en lugar de construir paquetes
 * reales con los builders de Pcap4J 1.8.2.
 *
 * Motivo: en Pcap4J 1.8.2 los builders de IpV4Packet/TcpPacket/UdpPacket
 * exigen un orden y una cantidad de campos obligatorios (identification,
 * flags, checksum, etc.) muy estrictos; si falta uno solo, el build()
 * lanza NullPointerException. Como PacketFormatter solo LEE valores de
 * paquetes ya parseados (no los construye), simulamos esos valores con
 * mocks: es más simple, más estable y prueba exactamente la lógica que
 * queremos verificar.
 */
class PacketFormatterTest {

    private Inet4Address srcAddr;
    private Inet4Address dstAddr;

    @BeforeEach
    void setUp() throws Exception {
        srcAddr = (Inet4Address) InetAddress.getByName("192.168.1.10");
        dstAddr = (Inet4Address) InetAddress.getByName("93.184.216.34");
    }

    /**
     * Crea un mock de Packet con la capa IPv4 ya simulada
     * (src, dst, ttl) y sin capa IPv6.
     */
    private Packet mockPacketConCapaIpV4() {
        IpV4Packet ipV4Packet = mock(IpV4Packet.class);
        IpV4Packet.IpV4Header ipV4Header = mock(IpV4Packet.IpV4Header.class);

        when(ipV4Packet.getHeader()).thenReturn(ipV4Header);
        when(ipV4Header.getSrcAddr()).thenReturn(srcAddr);
        when(ipV4Header.getDstAddr()).thenReturn(dstAddr);
        when(ipV4Header.getTtl()).thenReturn((byte) 64);

        Packet packet = mock(Packet.class);
        when(packet.get(IpV4Packet.class)).thenReturn(ipV4Packet);
        when(packet.get(IpV6Packet.class)).thenReturn(null);
        return packet;
    }

    @Test
    @DisplayName("extractMetadata debe procesar correctamente un paquete TCP")
    void extractMetadata_conPaqueteTcp_devuelveMetadatosCorrectos() {
        Packet packet = mockPacketConCapaIpV4();

        // --- Simulamos la capa TCP ---
        TcpPacket tcpPacket = mock(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = mock(TcpPacket.TcpHeader.class);
        TcpPort srcPort = mock(TcpPort.class);
        TcpPort dstPort = mock(TcpPort.class);

        when(tcpPacket.getHeader()).thenReturn(tcpHeader);
        when(srcPort.valueAsInt()).thenReturn(51234);
        when(dstPort.valueAsInt()).thenReturn(443);
        when(tcpHeader.getSrcPort()).thenReturn(srcPort);
        when(tcpHeader.getDstPort()).thenReturn(dstPort);
        when(tcpHeader.getWindow()).thenReturn((short) 64240);
        when(tcpHeader.getSyn()).thenReturn(true);
        when(tcpHeader.getAck()).thenReturn(false);
        when(tcpHeader.getFin()).thenReturn(false);
        when(tcpHeader.getRst()).thenReturn(false);
        when(tcpHeader.getPsh()).thenReturn(false);
        when(tcpHeader.getUrg()).thenReturn(false);

        when(packet.get(TcpPacket.class)).thenReturn(tcpPacket);
        when(packet.get(UdpPacket.class)).thenReturn(null);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);

        assertNotNull(metadata);
        assertEquals("192.168.1.10", metadata.get("src_ip"));
        assertEquals("93.184.216.34", metadata.get("dst_ip"));
        assertEquals(64, metadata.get("ttl"));
        assertEquals("TCP", metadata.get("protocol"));
        assertEquals(51234, metadata.get("src_port"));
        assertEquals(443, metadata.get("dst_port"));
        // Comparamos como Number para no depender de si getWindow()
        // devuelve short o int en esta versión de Pcap4J.
        assertEquals(64240, ((Number) metadata.get("window_size")).intValue());

        @SuppressWarnings("unchecked")
        Map<String, Integer> flags = (Map<String, Integer>) metadata.get("tcp_flags");
        assertEquals(1, flags.get("SYN"));
        assertEquals(0, flags.get("ACK"));
        assertEquals(0, flags.get("FIN"));
        assertEquals(0, flags.get("RST"));
        assertEquals(0, flags.get("PSH"));
        assertEquals(0, flags.get("URG"));
    }

    @Test
    @DisplayName("extractMetadata debe procesar correctamente un paquete UDP")
    void extractMetadata_conPaqueteUdp_devuelveMetadatosCorrectos() {
        Packet packet = mockPacketConCapaIpV4();

        // --- Simulamos la capa UDP ---
        UdpPacket udpPacket = mock(UdpPacket.class);
        UdpPacket.UdpHeader udpHeader = mock(UdpPacket.UdpHeader.class);
        UdpPort srcPort = mock(UdpPort.class);
        UdpPort dstPort = mock(UdpPort.class);

        when(udpPacket.getHeader()).thenReturn(udpHeader);
        when(srcPort.valueAsInt()).thenReturn(53000);
        when(dstPort.valueAsInt()).thenReturn(53);
        when(udpHeader.getSrcPort()).thenReturn(srcPort);
        when(udpHeader.getDstPort()).thenReturn(dstPort);
        when(udpHeader.getLength()).thenReturn((short) 64);

        when(packet.get(TcpPacket.class)).thenReturn(null);
        when(packet.get(UdpPacket.class)).thenReturn(udpPacket);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);

        assertNotNull(metadata);
        assertEquals("UDP", metadata.get("protocol"));
        assertEquals(53000, metadata.get("src_port"));
        assertEquals(53, metadata.get("dst_port"));
        assertEquals(64, ((Number) metadata.get("length")).intValue());
    }

    @Test
    @DisplayName("extractMetadata debe devolver null si el paquete no tiene capa TCP ni UDP")
    void extractMetadata_sinCapaTcpNiUdp_devuelveNull() {
        Packet packet = mockPacketConCapaIpV4();

        when(packet.get(TcpPacket.class)).thenReturn(null);
        when(packet.get(UdpPacket.class)).thenReturn(null);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);

        assertNull(metadata);
    }

    @Test
    @DisplayName("extractMetadata debe devolver null si el paquete no tiene capa IP")
    void extractMetadata_sinCapaIp_devuelveNull() {
        Packet packet = mock(Packet.class);
        when(packet.get(IpV4Packet.class)).thenReturn(null);
        when(packet.get(IpV6Packet.class)).thenReturn(null);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);

        assertNull(metadata);
    }

    @Test
    @DisplayName("toJson debe serializar correctamente un mapa de metadatos")
    void toJson_conMetadataValido_devuelveJsonCorrecto() {
        Map<String, Object> metadata = new java.util.LinkedHashMap<>();
        metadata.put("src_ip", "192.168.1.10");
        metadata.put("dst_ip", "93.184.216.34");
        metadata.put("protocol", "TCP");
        metadata.put("src_port", 51234);
        metadata.put("dst_port", 443);

        String json = PacketFormatter.toJson(metadata);

        assertNotNull(json);
        assertTrue(json.contains("\"src_ip\":\"192.168.1.10\""));
        assertTrue(json.contains("\"dst_ip\":\"93.184.216.34\""));
        assertTrue(json.contains("\"protocol\":\"TCP\""));
        assertTrue(json.contains("\"src_port\":51234"));
        assertTrue(json.contains("\"dst_port\":443"));
    }

    @Test
    @DisplayName("extractMetadata + toJson deben funcionar juntos de punta a punta")
    void extractMetadataYToJson_conPaqueteTcp_generanJsonValido() {
        Packet packet = mockPacketConCapaIpV4();

        TcpPacket tcpPacket = mock(TcpPacket.class);
        TcpPacket.TcpHeader tcpHeader = mock(TcpPacket.TcpHeader.class);
        TcpPort srcPort = mock(TcpPort.class);
        TcpPort dstPort = mock(TcpPort.class);

        when(tcpPacket.getHeader()).thenReturn(tcpHeader);
        when(srcPort.valueAsInt()).thenReturn(51234);
        when(dstPort.valueAsInt()).thenReturn(443);
        when(tcpHeader.getSrcPort()).thenReturn(srcPort);
        when(tcpHeader.getDstPort()).thenReturn(dstPort);
        when(tcpHeader.getWindow()).thenReturn((short) 64240);
        when(tcpHeader.getSyn()).thenReturn(true);
        when(tcpHeader.getAck()).thenReturn(false);
        when(tcpHeader.getFin()).thenReturn(false);
        when(tcpHeader.getRst()).thenReturn(false);
        when(tcpHeader.getPsh()).thenReturn(false);
        when(tcpHeader.getUrg()).thenReturn(false);

        when(packet.get(TcpPacket.class)).thenReturn(tcpPacket);
        when(packet.get(UdpPacket.class)).thenReturn(null);

        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);
        String json = PacketFormatter.toJson(metadata);

        assertNotNull(json);
        assertTrue(json.contains("\"protocol\":\"TCP\""));
        assertTrue(json.contains("\"src_ip\":\"192.168.1.10\""));
        assertTrue(json.contains("\"tcp_flags\""));
    }
}
