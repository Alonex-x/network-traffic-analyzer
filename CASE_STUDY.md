# Case Study: network-traffic-analyzer

**Problem.** Diagnosing network issues or understanding traffic patterns often requires heavy tools like Wireshark, which provide far more detail than needed for a quick assessment. Integrating such tools into lightweight monitoring scripts is not always practical.

**Solution.** network-traffic-analyzer is a lightweight command-line tool that passively captures traffic on a network interface. It extracts only the most relevant metadata (source/destination IP, ports, protocol, TTL, TCP flags) and outputs each packet as a JSON object, making it easy to pipe into other tools or analyze with jq.

**Result.** The project evolved from a functional script into a maintainable tool with automated tests (JUnit 5) and CI/CD via GitHub Actions. It fills the gap between a full packet analyzer and a simple ping test, providing just enough detail for routine diagnostics.
