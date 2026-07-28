package com.alone.network;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Map;

/**
 * Network Traffic Analyzer - part of the Nexus Ecosystem.
 * GitHub: https://github.com/Alonex-x/network-traffic-analyzer
 *
 * Upgrade to Network Traffic Analyzer PRO for:
 *   - Web dashboard with live traffic visualization
 *   - Advanced device detection (vendor, hostname, OS)
 *   - Alerting (port scan, brute force, malicious IPs)
 *   - Traffic history, CSV/Excel export, email/Telegram notifications
 *
 *   Get the PRO version at: [Gumroad link here]
 *
 * This Lite version captures packets passively, outputs metadata as JSON,
 * and performs basic device detection (MAC address).
 */
public class PacketSniffer {

    private final String interfaceName;
    private final AtomicInteger packetCount = new AtomicInteger(0);
    private final AtomicInteger lostCount = new AtomicInteger(0);
    private boolean prettyPrint = false;

    public PacketSniffer(String interfaceName) {
        this.interfaceName = interfaceName;
    }

    public void setPrettyPrint(boolean prettyPrint) {
        this.prettyPrint = prettyPrint;
    }

    public static void main(String[] args) {
        if (args.length == 1) {
            if (args[0].equals("--help") || args[0].equals("-h")) {
                printHelp();
                return;
            }
            if (args[0].equals("--version")) {
                printVersion();
                return;
            }
        }

        String iface = null;
        boolean pretty = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--pretty")) {
                pretty = true;
            } else if (args[i].equals("--help") || args[i].equals("-h")) {
                printHelp();
                return;
            } else if (args[i].equals("--version")) {
                printVersion();
                return;
            } else if (iface == null) {
                iface = args[i];
            }
        }

        if (iface == null) {
            System.err.println("Error: no interface specified.");
            printHelp();
            System.exit(1);
        }

        if (!System.getProperty("os.name").toLowerCase().contains("win") && 
            System.getProperty("user.name").equals("root") == false) {
            System.err.println("Warning: capturing packets usually requires root/sudo privileges.");
            System.err.println("If capture fails, re-run with sudo.");
        }

        PacketSniffer sniffer = new PacketSniffer(iface);
        sniffer.setPrettyPrint(pretty);
        sniffer.start();
    }

    private static void printHelp() {
        System.out.println("Network Traffic Analyzer (Lite) - part of the Nexus Ecosystem");
        System.out.println("GitHub: https://github.com/Alonex-x/network-traffic-analyzer\n");
        System.out.println("Usage: java PacketSniffer <interface> [--pretty] [--help] [--version]");
        System.out.println("  <interface>   Network interface to capture from (e.g., eth0, wlan0)");
        System.out.println("  --pretty      Pretty-print JSON output (indented)");
        System.out.println("  --help        Show this help message");
        System.out.println("  --version     Show version information");
        System.out.println("\nPRO version available at: [Gumroad link here]");
    }

    private static void printVersion() {
        System.out.println("Network Traffic Analyzer v1.5.0 (Lite)");
        System.out.println("PRO version available at: [Gumroad link here]");
    }

    public void start() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::printSummary));

        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
            if (nif == null) {
                System.err.println("Error: Interface not found: " + interfaceName);
                System.err.println("Available interfaces:");
                for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
                    System.out.println("  " + dev.getName() + " - " + dev.getDescription());
                }
                return;
            }

            PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            PacketListener listener = packet -> {
                packetCount.incrementAndGet();
                Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);
                if (metadata != null) {
                    // Device detection (Lite): extract MAC and display basic info
                    String srcIp = (String) metadata.get("src_ip");
                    String srcMac = packet.getRawData() != null ? 
                        String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                            packet.getRawData()[6], packet.getRawData()[7],
                            packet.getRawData()[8], packet.getRawData()[9],
                            packet.getRawData()[10], packet.getRawData()[11]) : "unknown";
                    System.err.println(DeviceDetector.identify(srcMac, srcIp));

                    if (prettyPrint) {
                        System.out.println(PacketFormatter.toPrettyJson(metadata));
                    } else {
                        System.out.println(PacketFormatter.toJson(metadata));
                    }
                }
                if (packetCount.get() % 1000 == 0) {
                    try {
                        PcapStat stats = handle.getStats();
                        lostCount.set((int) (stats.getNumPacketsReceived() - stats.getNumPacketsCaptured()));
                        System.err.println("Packets captured: " + packetCount.get() + " | Lost: " + lostCount.get());
                    } catch (Exception ignored) {}
                }
            };

            handle.loop(-1, listener);
        } catch (PcapNativeException e) {
            System.err.println("Error: Could not open interface. Did you run with sudo?");
        } catch (Exception e) {
            System.err.println("Error during capture: " + e.getMessage());
        }
    }

    private void printSummary() {
        int captured = packetCount.get();
        int lost = lostCount.get();
        System.err.printf("Capture finished. Packets: %d | Lost: %d%n", captured, lost);
    }

    // Package-private helpers for testing
    int getPacketCount() { return packetCount.get(); }
    void incrementPackets() { packetCount.incrementAndGet(); }
    void setPacketCount(int count) { packetCount.set(count); }
    void gotPacket(Packet packet) {
        packetCount.incrementAndGet();
        Map<String, Object> metadata = PacketFormatter.extractMetadata(packet);
        if (metadata != null) {
            String srcIp = (String) metadata.get("src_ip");
            String srcMac = "unknown";
            System.err.println(DeviceDetector.identify(srcMac, srcIp));
            System.out.println(prettyPrint ? PacketFormatter.toPrettyJson(metadata) : PacketFormatter.toJson(metadata));
        }
    }
    void printSummaryWithHandle(PcapHandle handle) {
        printSummary();
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }
}
