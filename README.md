# SafeGate
**Check before you click.** A Java URL-pattern triage CLI.

## Run
```bash
mvn clean test
mvn exec:java -Dexec.mainClass=io.safegate.Main
```
Enter a URL; type `quit` to exit.

## Included
- URL normalization and syntax checks
- Warnings for HTTP, URL credentials syntax, known shorteners, IDN hostnames, raw IPs, and deep subdomains
- Explainable heuristic score and unit tests

## Limitations
This MVP does not check threat-intelligence feeds, follow redirects, validate certificates, inspect page content, or classify explicit content. It does not open or crawl URLs. A low score does not mean a site is safe; the score is not a probability.

## Roadmap
Threat-intelligence integration with privacy controls, JavaFX UI, hardened redirect analysis, and expanded tests.
