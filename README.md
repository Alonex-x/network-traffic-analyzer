# Network Traffic Analyzer

![Java](https://img.shields.io/badge/Java-17-orange)
![Maven](https://img.shields.io/badge/Maven-3.9-blue)

A lightweight command-line tool for passive network traffic analysis. Captures packets on a specified network interface and extracts relevant metadata (source/destination IP, ports, protocol, TTL, TCP flags) in JSON format, ready to be piped into other tools or analyzed with jq.

This project is for educational and diagnostic purposes only, on networks you own or have explicit permission to monitor.

## Features

- Captures IP headers, TCP/UDP ports, TTL, and TCP flags
- Outputs each packet as a JSON object
- Configurable packet count limit
- Summary report on shutdown with total packets captured and lost
- CI/CD with GitHub Actions and automated tests (JUnit 5)

## Requirements

- Java 17
- Maven 3.9+

## Installation

git clone <repo-url>
cd network-traffic-analyzer
mvn package

## Usage

java -jar target/network-traffic-analyzer-1.0.jar --interface eth0 --count 100

## Tests

mvn test

## Notes

Educational and portfolio project.
