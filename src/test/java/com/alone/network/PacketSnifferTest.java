package com.alone.network;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitarios para PacketSniffer.
 *
 * Nota sobre el diseño de estos tests: como PacketSniffer usa campos privados,
 * metodos privados (gotPacket, printSummary) y llamadas estaticas de Pcap4J
 * (Pcaps.getDevByName, PcapHandle.Builder), la captura real de red NO se prueba
 * aqui (requeriria una interfaz de red real o mocks estaticos con
 * mockito-inline). En su lugar, se usa reflexion para acceder a estado y
 * metodos privados, y se prueban los comportamientos que SI son observables
 * sin abrir una interfaz real: validacion de argumentos, conteo de paquetes,
 * y el resumen final que imprime el shutdown hook.
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

    // --- Helpers de reflexion ---

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

    // --- Constructor / estado inicial ---

    @Test
    @DisplayName("El constructor guarda el nombre de interfaz y arranca los contadores en cero")
    void constructorInicializaEstado() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");

        assertEquals("eth0", getPrivateField(sniffer, "interfaceName"));
        assertEquals(0, getPrivateField(sniffer, "packetCount"));
        assertEquals(0, getPrivateField(sniffer, "lostCount"));
        assertEquals(false, getPrivateField(sniffer, "running"));
    }

    // --- Validacion de argumentos en main() ---

    @Test
    @DisplayName("main() sin argumentos termina con codigo 1 y muestra el mensaje de uso")
    void mainSinArgumentosMuestraUso() {
        int exitCode = runMainAndCaptureExitCode(new String[]{});

        assertEquals(1, exitCode);
        assertTrue(errContent.toString().contains("Uso: sudo java -jar network-analyzer.jar <interfaz>"));
    }

    @Test
    @DisplayName("main() con mas de un argumento termina con codigo 1 y muestra el mensaje de uso")
    void mainConDemasiadosArgumentosMuestraUso() {
        int exitCode = runMainAndCaptureExitCode(new String[]{"eth0", "extra"});

        assertEquals(1, exitCode);
        assertTrue(errContent.toString().contains("Uso: sudo java -jar network-analyzer.jar <interfaz>"));
    }

    /**
     * Ejecuta PacketSniffer.main capturando el codigo con el que se
     * "saldria" del proceso, sin matar realmente la JVM que corre los tests.
     * Se instala un SecurityManager temporal que intercepta checkExit.
     *
     * Nota: SecurityManager esta deprecado desde Java 17 pero sigue
     * disponible; si el proyecto migra a una version de Java donde ya no
     * exista, este helper debe reemplazarse (por ejemplo extrayendo la
     * validacion de argumentos a un metodo propio que no llame a
     * System.exit directamente).
     */
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
            // Si main no llamo a System.exit (por ejemplo con argumentos validos
            // pero sin interfaz real disponible), no hay codigo de salida que capturar.
            return 0;
        } catch (ExitCaptured e) {
            return e.code;
        } finally {
            System.setSecurityManager(original);
        }
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

        assertEquals(1, getPrivateField(sniffer, "packetCount"));
        // Sin capa IP, PacketFormatter no deberia invocarse y no deberia imprimirse nada por stdout.
        assertEquals("", outContent.toString());
    }

    @Test
    @DisplayName("gotPacket detecta paquetes con capa IPv4 y no falla al intentar formatearlos")
    void gotPacketDetectaCapaIpv4() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");

        Packet paqueteConIp = mock(Packet.class);
        when(paqueteConIp.contains(IpV4Packet.class)).thenReturn(true);
        when(paqueteConIp.contains(IpV6Packet.class)).thenReturn(false);
        // get(IpV4Packet.class) devuelve null porque el mock no simula la jerarquia completa;
        // esto ejercita la rama en la que extractMetadata no puede construir metadatos.
        when(paqueteConIp.get(IpV4Packet.class)).thenReturn(null);
        when(paqueteConIp.get(IpV6Packet.class)).thenReturn(null);

        assertDoesNotThrow(() ->
                invokePrivateMethod(sniffer, "gotPacket", new Class<?>[]{Packet.class}, paqueteConIp));

        assertEquals(1, getPrivateField(sniffer, "packetCount"));
    }

    // --- printSummary(): el shutdown hook ---

    @Test
    @DisplayName("printSummary con handle nulo imprime el resumen sin lanzar excepciones")
    void printSummaryConHandleNulo() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");
        setPrivateField(sniffer, "startTime", System.currentTimeMillis() - 500);
        setPrivateField(sniffer, "packetCount", 42);

        assertDoesNotThrow(() -> invokePrivateMethod(sniffer, "printSummary", new Class<?>[]{}));

        String salida = errContent.toString();
        assertTrue(salida.contains("Captura finalizada."));
        assertTrue(salida.contains("Paquetes: 42"));
    }

    @Test
    @DisplayName("printSummary cierra el handle si sigue abierto y usa sus estadisticas")
    void printSummaryCierraHandleAbierto() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");
        setPrivateField(sniffer, "startTime", System.currentTimeMillis() - 200);
        setPrivateField(sniffer, "packetCount", 10);

        PcapHandle handleMock = mock(PcapHandle.class);
        PcapStat statsMock = mock(PcapStat.class);
        when(statsMock.getNumPacketsDropped()).thenReturn(3L);
        when(handleMock.getStats()).thenReturn(statsMock);
        when(handleMock.isOpen()).thenReturn(true);

        setPrivateField(sniffer, "handle", handleMock);

        invokePrivateMethod(sniffer, "printSummary", new Class<?>[]{});

        verify(handleMock, times(1)).close();
        assertEquals(3, getPrivateField(sniffer, "lostCount"));
        assertTrue(errContent.toString().contains("Perdidos: 3"));
    }

    @Test
    @DisplayName("printSummary no intenta cerrar un handle que ya esta cerrado")
    void printSummaryNoCierraHandleYaCerrado() throws Exception {
        PacketSniffer sniffer = new PacketSniffer("eth0");
        setPrivateField(sniffer, "startTime", System.currentTimeMillis());

        PcapHandle handleMock = mock(PcapHandle.class);
        PcapStat statsMock = mock(PcapStat.class);
        when(statsMock.getNumPacketsDropped()).thenReturn(0L);
        when(handleMock.getStats()).thenReturn(statsMock);
        when(handleMock.isOpen()).thenReturn(false);

        setPrivateField(sniffer, "handle", handleMock);

        invokePrivateMethod(sniffer, "printSummary", new Class<?>[]{});

        verify(handleMock, never()).close();
    }
}
