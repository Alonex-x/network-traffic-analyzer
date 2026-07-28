package com.alone.network;

/**
 * Provides device identification capabilities.
 * The Lite version extracts MAC addresses and indicates that vendor lookup
 * is available in the PRO version.
 */
public class DeviceDetector {

    /**
     * Returns a formatted string with device information.
     * In PRO version, this would include vendor, hostname, and OS detection.
     *
     * @param mac MAC address of the device
     * @param ip  IP address of the device
     * @return Formatted device information string
     */
    public static String identify(String mac, String ip) {
        return String.format("Device detected - MAC: %s, IP: %s [Vendor lookup: PRO version]", mac, ip);
    }
}
