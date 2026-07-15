package com.alone.network;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;

import java.util.Map;

/**
 * Clase principal de la herramienta. Se encarga de abrir la interfaz de red,
 * capturar paquetes de forma pasiva y delegar la extraccion/formateo de
 * metadatos a PacketFormatter.
 *
 * Solo realiza captura pasiva: no modifica, inyecta ni reenvia paquetes,
 * y no intenta descifrar trafico cifrado.
 */
public class PacketSniffer {

    private final String interfaceName;
    private int packetCount;
    private int lostCount;
    private long startTime;
    private boolean running;

    private PcapHandle handle;

    public PacketSniffer(String interfaceName) {
        this.interfaceName = interfaceName;
        this.packetCount = 0;
        this.lostCount = 0;
        this.running = false;
    }

    public static void main(String[] args) {
        // 1. Validar argumentos: se requiere exactamente el nombre de la interfaz.
        if (args.length != 1) {
            System.err.println("Uso: sudo java -jar network-analyzer.jar <interfaz>");
            System.exit(1);
        }

        String interfaceName = args[0];

        // 2. Instanciar el sniffer y arrancar la captura.
        PacketSniffer sniffer = new PacketSniffer(interfaceName);
        sniffer.startCapture();
    }

    /**
     * Abre la interfaz indicada e inicia el bucle de captura pasiva.
     */
    public void startCapture() {
        this.startTime = System.currentTimeMillis();
        this.running = true;

        // 1. Registrar el hook de cierre (Ctrl+C) para imprimir el resumen final.
        Runtime.getRuntime().addShutdownHook(new Thread(this::printSummary));

        try {
            // 2. Obtener la interfaz de red por nombre.
            PcapNetworkInterface networkInterface = Pcaps.getDevByName(interfaceName);
            if (networkInterface == null) {
                System.err.println("Error: Interfaz no encontrada: " + interfaceName);
                System.exit(1);
                return;
            }

            // Abrir la interfaz en modo promiscuo, solo lectura de trafico (captura pasiva).
            handle = new PcapHandle.Builder(interfaceName)
                    .snaplen(65536)
                    .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                    .timeout(10)
                    .build();

            // 3. Configurar el listener de paquetes.
            org.pcap4j.core.PacketListener listener = this::gotPacket;

            // 4. Iniciar el bucle de captura. Bloquea hasta Ctrl+C o cierre del handle.
            handle.loop(-1, listener);

        } catch (PcapNativeException e) {
            System.err.println("Error: No se pudo abrir la interfaz. ¿Ejecutaste con sudo?");
            System.exit(1);
        } catch (NotOpenException | InterruptedException e) {
            System.err.println("Error durante la captura: " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Callback invocado por Pcap4J por cada paquete capturado.
     * Solo realiza lectura pasiva: extrae metadatos y los imprime como JSON.
     */
    private void gotPacket(Packet packet) {
        packetCount++;

        // Verificar si el paquete contiene una capa IP (v4 o v6).
        boolean tieneCapaIp = packet.contains(IpV4Packet.class) || packet.contains(IpV6Packet.class);

        if (tieneCapaIp) {
            Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);
            if (metadata != null) {
                String jsonLine = PacketFormatter.toJson(metadata);
                System.out.println(jsonLine);
            }
        }

        // Cada 1000 paquetes, imprimir estadisticas de progreso en stderr.
        if (packetCount % 1000 == 0) {
            try {
                PcapStat stats = handle.getStats();
                lostCount = (int) stats.getNumPacketsDropped();
                System.err.println("Paquetes capturados: " + packetCount + " | Perdidos: " + lostCount);
            } catch (Exception e) {
                // Si no se pueden obtener estadisticas, se ignora silenciosamente.
            }
        }
    }

    /**
     * Imprime el resumen final de la captura al finalizar (Ctrl+C).
     */
    private void printSummary() {
        running = false;

        // Intentar obtener las estadisticas finales del handle antes de cerrarlo.
        if (handle != null) {
            try {
                PcapStat stats = handle.getStats();
                lostCount = (int) stats.getNumPacketsDropped();
            } catch (Exception e) {
                // Si el handle ya esta cerrado o no soporta estadisticas, se conserva el ultimo valor conocido.
            }
            if (handle.isOpen()) {
                handle.close();
            }
        }

        double elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000.0;
        System.err.printf("Captura finalizada. Paquetes: %d | Perdidos: %d | Tiempo: %.1fs%n",
                packetCount, lostCount, elapsedSeconds);
    }
}
