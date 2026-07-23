package com.alone.network;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class NexusHeartbeat {
    private static final String API_BASE = System.getenv().getOrDefault("NEXUS_API_BASE", "http://localhost:8080");
    private static final String API_KEY = System.getenv().getOrDefault("NETWORK_AGENT_KEY", "CLAVE_POR_DEFECTO");

    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        System.out.println("Agente Network-Analyzer iniciado. Enviando heartbeats...");
        while (true) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_BASE + "/api/v1/agents/heartbeat"))
                    .header("X-Agent-Key", API_KEY)
                    .timeout(Duration.ofSeconds(5))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                System.out.println("Heartbeat enviado: " + response.statusCode());
            } catch (Exception e) {
                System.out.println("Error enviando heartbeat: " + e.getMessage());
            }
            Thread.sleep(60000);
        }
    }
}
