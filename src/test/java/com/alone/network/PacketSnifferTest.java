package com.alone.network;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitarios para PacketSniffer (versión mejorada con flags).
 */
class PacketSnifferTest {

    private final PrintStream originalErr = System.err;
    private final PrintStream originalOut = System.out;
    private ByteArrayOutputStream errContent;
    private ByteArrayOutputStream outContent;

    @BeforeEach
    void setUp() {
        errContent = new ByteArrayOutputStream();
        outContent = new ByteArrayOutputStream();
        System.setErr(new PrintStream(errContent));
        System.setOut(new PrintStream(outContent));
    }

    @AfterEach
    void tearDown() {
        System.setErr(originalErr);
        System.setOut(originalOut);
    }

    // --- Helpers de reflexión ---

    private Object getPrivateField(Object target, String fieldName) throws Exception {
        Field field = PacketSniffer.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(target);
    }

    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field field = PacketSniffer.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private Object invokePrivateMethod(Object target, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method method = PacketSniffer.class.getDeclaredMethod(methodName, paramTypes);
        method.setAccessible(true);
        return method.invoke(target, args);
    }

    // --- Constructor y estado inicial ---

    @Test
    @DisplayName("El constructor guarda el nombre de interfaz y arranca los contadores en cero")
    void constructorInicializaEstado() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");

        assertEquals("eth0", getPrivateField(sniffer, "interfaceName"));
        AtomicInteger packetCount = (AtomicInteger) getPrivateField(sniffer, "packetCount");
        AtomicInteger lostCount = (AtomicInteger) getPrivateField(sniffer, "lostCount");
        assertEquals(0, packetCount.get());
        assertEquals(0, lostCount.get());
        boolean prettyPrint = (boolean) getPrivateField(sniffer, "prettyPrint");
        assertFalse(prettyPrint);
    }

    // --- Validación de argumentos en main() ---

    @Test
    @DisplayName("main() sin argumentos termina con código 1 y muestra mensaje de error")
    void mainSinArgumentosMuestraUso() {
        int exitCode = runMainAndCaptureExitCode(new String[]{});

        assertEquals(1, exitCode);
        String err = errContent.toString();
        assertTrue(err.contains("Error: no interface specified") || err.contains("Usage: java PacketSniffer"),
                "Debe mostrar un mensaje de error o la ayuda");
    }

    @Test
    @DisplayName("main() con solo flags y sin interfaz termina con código 1")
    void mainConFlagsSinInterfazMuestraError() {
        int exitCode = runMainAndCaptureExitCode(new String[]{"--pretty"});

        assertEquals(1, exitCode);
        String err = errContent.toString();
        assertTrue(err.contains("Error: no interface specified") || err.contains("Usage: java PacketSniffer"));
    }

    @Test
    @DisplayName("main() con --help muestra la ayuda y termina con código 0")
    void mainConFlagHelpMuestraAyudaYSaleCero() {
        int exitCode = runMainAndCaptureExitCode(new String[]{"--help"});

        assertEquals(0, exitCode);
        String out = outContent.toString();
        assertTrue(out.contains("Network Traffic Analyzer (Lite)"), "Debe mostrar la ayuda");
    }

    @Test
    @DisplayName("main() con --version muestra la versión y termina con código 0")
    void mainConFlagVersionMuestraVersionYSaleCero() {
        int exitCode = runMainAndCaptureExitCode(new String[]{"--version"});

        assertEquals(0, exitCode);
        String out = outContent.toString();
        assertTrue(out.contains("Network Traffic Analyzer v"), "Debe mostrar la versión");
    }

    // --- gotPacket(): conteo y filtrado por capa IP ---

    @Test
    @DisplayName("gotPacket incrementa el contador incluso si el paquete no tiene capa IP")
    void gotPacketIncrementaContadorSiempre() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");

        Packet paqueteSinIp = mock(Packet.class);
        when(paqueteSinIp.contains(IpV4Packet.class)).thenReturn(false);
        when(paqueteSinIp.contains(IpV6Packet.class)).thenReturn(false);

        invokePrivateMethod(sniffer, "gotPacket", new Class<?>[]{Packet.class}, paqueteSinIp);

        AtomicInteger packetCount = (AtomicInteger) getPrivateField(sniffer, "packetCount");
        assertEquals(1, packetCount.get());
        // Sin capa IP, PacketFormatter no debería invocarse y no debería imprimirse nada por stdout.
        assertEquals("", outContent.toString());
    }

    @Test
    @DisplayName("gotPacket detecta paquetes con capa IPv4 y no falla al intentar formatearlos")
    void gotPacketDetectaCapaIpv4() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");

        Packet paqueteConIp = mock(Packet.class);
        when(paqueteConIp.contains(IpV4Packet.class)).thenReturn(true);
        when(paqueteConIp.contains(IpV6Packet.class)).thenReturn(false);
        when(paqueteConIp.get(IpV4Packet.class)).thenReturn(null);
        when(paqueteConIp.get(IpV6Packet.class)).thenReturn(null);

        assertDoesNotThrow(() ->
                invokePrivateMethod(sniffer, "gotPacket", new Class<?>[]{Packet.class}, paqueteConIp));

        AtomicInteger packetCount = (AtomicInteger) getPrivateField(sniffer, "packetCount");
        assertEquals(1, packetCount.get());
    }

    // --- printSummary(): el shutdown hook ---

    @Test
    @DisplayName("printSummary imprime el resumen con los contadores actuales")
    void printSummaryImprimeResumen() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");
        AtomicInteger packetCount = (AtomicInteger) getPrivateField(sniffer, "packetCount");
        AtomicInteger lostCount = (AtomicInteger) getPrivateField(sniffer, "lostCount");
        packetCount.set(42);
        lostCount.set(3);

        invokePrivateMethod(sniffer, "printSummary", new Class<?>[]{});

        String salida = errContent.toString();
        assertTrue(salida.contains("Capture finished"));
        assertTrue(salida.contains("Packets: 42"));
        assertTrue(salida.contains("Lost: 3"));
    }

    // --- Método auxiliar para capturar System.exit ---

    @SuppressWarnings({"removal", "deprecation"})
    private int runMainAndCaptureExitCode(String[] args) {
        class ExitCaptured extends SecurityException {
            final int code;
            ExitCaptured(int code) { this.code = code; }
        }

        SecurityManager original = System.getSecurityManager();
        SecurityManager noExit = new SecurityManager() {
            @Override
            public void checkPermission(java.security.Permission perm) {
                // Se permite todo excepto la salida del proceso.
            }

            @Override
            public void checkExit(int status) {
                throw new ExitCaptured(status);
            }
        };

        System.setSecurityManager(noExit);
        try {
            PacketSniffer.main(args);
            return 0;
        } catch (ExitCaptured e) {
            return e.code;
        } finally {
            System.setSecurityManager(original);
        }
    }
}
