# web-osint 🇩🇪

Ein in Go entwickeltes OSINT-Werkzeug zur Analyse **öffentlich beobachtbarer Informationen** über Domains und Websites.

> Das Projekt greift nicht auf private Systeme zu, umgeht keine Authentifizierung und behauptet keine autoritativen Besucherzahlen aus öffentlichen HTTP-Antworten. Traffic-Werte sind als Schätzungen zu behandeln, sofern sie von einem dokumentierten Drittanbieter stammen.

## Funktionen

- HTTP/HTTPS-Status und Redirects
- Antwortzeit
- Server- und Content-Type-Informationen
- DNS: A, AAAA, MX, NS und TXT
- TLS-Version und Zertifikatsinformationen inklusive Zertifikatsvalidierung
- grundlegende Technologie-Erkennung aus öffentlich ausgelieferten Inhalten
- Security-Header-Prüfung
- `robots.txt` und `sitemap.xml`
- RDAP-Domaininformationen im erweiterten Scan
- IP-/ASN-/Provider-Anreicherung
- Certificate-Transparency-basierte Subdomain-Erkennung
- Erkennung ausgewählter Web-Tracker und Analytics-Technologien
- lesbarer Terminal-Report
- JSON-Ausgabe für Automatisierung
- separates Modul für öffentliche Traffic-/Popularity-Daten
- Validierung öffentlicher Scanziele und sichere Redirect-Prüfung
- Go-Implementierung ohne externe Abhängigkeiten für den Basisscanner

## Sicherheit der Zieleingabe

Der Basisscanner ist auf öffentlich erreichbare Ziele ausgelegt. Vor HTTP-Requests werden Ziel und Redirects validiert.

Abgewiesen werden unter anderem:

- Loopback-Adressen wie `127.0.0.1`
- private IPv4-/IPv6-Netze
- Link-Local- und Multicast-Adressen
- nicht auflösbare Hostnamen
- ungültige Hostnamen
- `file://`, `ftp://` und andere nicht unterstützte Schemes
- URLs mit eingebetteten Zugangsdaten

Damit wird verhindert, dass eine manipulierte Eingabe den Scanner als einfachen SSRF-Proxy für interne Systeme verwendet.

## Installation

Voraussetzung ist Go 1.24 oder neuer.

Repository klonen:

```bash
git clone https://github.com/linuxaaron/web-osint.git
cd web-osint
```

Basisscanner direkt ausführen:

```bash
go run ./cmd/web-osint example.com
```

## Vollständige Analyse

Mit `--full` werden zusätzliche öffentliche Quellen abgefragt:

```bash
go run ./cmd/web-osint --full example.com
```

JSON-Report erzeugen:

```bash
go run ./cmd/web-osint --full --json example.com > report.json
```

## Eigenständiges Binary bauen

Linux/macOS:

```bash
go build -o web-osint ./cmd/web-osint
./web-osint --full example.com
```

Windows:

```powershell
go build -o web-osint.exe ./cmd/web-osint
.\web-osint.exe --full example.com
```

## Tests

Die CI führt Formatierung, Build und Unit-Tests aus:

```bash
gofmt -w .
go build ./...
go test ./...
```

Die Regressionstests decken insbesondere die Zielvalidierung, den Schutz vor privaten Adressen und die Security-Header-Auswertung ab.

## Traffic- und Popularitätsdaten

Die tatsächliche Besucherzahl einer fremden Website kann normalerweise nicht allein über DNS oder HTTP ermittelt werden. Deshalb erzeugt `web-osint` **keine erfundenen Besucherzahlen**.

Für öffentlich verfügbare Drittanbieter-Messwerte gibt es ein separates Traffic-Modul:

```bash
go run ./cmd/web-osint-traffic example.com
```

JSON-Ausgabe:

```bash
go run ./cmd/web-osint-traffic --json example.com
```

Die Ergebnisse müssen als das gekennzeichnet werden, was sie sind:

- **Traffic-Schätzung:** kein autoritativer Serverwert
- **Popularity Rank:** Popularitätsindikator, keine direkte Besucherzählung
- **Quelle:** wird im Report angegeben
- **Messzeitpunkt:** wird im Report angegeben, soweit verfügbar

API-Zugangsdaten werden ausschließlich über Umgebungsvariablen konfiguriert und nicht im Quellcode gespeichert.

Beispiel:

```bash
export SIMILARWEB_API_KEY="DEIN_API_KEY"
export CLOUDFLARE_API_TOKEN="DEIN_TOKEN"
```

## Datenschutz und verantwortungsvolle Nutzung

Das Tool ist für passive bzw. öffentlich zugängliche Web- und Domain-Recherche vorgesehen.

Nutze es insbesondere für:

- eigene Domains und Systeme
- Systeme, für deren Analyse du ausdrücklich autorisiert bist
- Sicherheitsforschung im erlaubten Rahmen
- akademische und journalistische Recherche
- allgemeine OSINT-Recherche auf Basis öffentlich verfügbarer Informationen

Das Projekt ist **kein Exploit-Scanner** und enthält bewusst keine Funktionen zum Umgehen von Authentifizierung oder Zugriffskontrollen.

## Roadmap

- [x] RDAP-Metadaten
- [x] ASN-/IP-Anreicherung
- [x] Certificate-Transparency-Subdomains
- [x] verbesserte Technologie-/Tracker-Erkennung
- [x] öffentliche Traffic-/Popularity-Datenquellen
- [x] Ziel- und Redirect-Validierung
- [x] TLS-Zertifikatsvalidierung
- [x] Regressionstests für Sicherheitsfunktionen
- [ ] versioniertes strukturiertes Report-Schema
- [ ] konfigurierbare Rate-Limits
- [ ] umfangreichere Integrationstests
- [ ] Release-Binaries für Linux/macOS/Windows
- [ ] erweiterbares Provider-Interface für weitere OSINT-Datenquellen

## Lizenz

MIT

## Rechtliche Hinweise

Nutze dieses Tool ausschließlich für Domains, Systeme und Informationen, deren Untersuchung du ausdrücklich autorisiert durchführen darfst, oder für rechtmäßige Recherche auf Basis öffentlich verfügbarer Informationen. Verwende es nicht zum Umgehen von Authentifizierung oder Zugriffskontrollen, zum Umgehen von Rate-Limits, für unbefugtes Scanning, zur Störung von Diensten oder zur Beschaffung nicht öffentlicher Informationen.

Du bist selbst für die Nutzung der Software sowie für die Einhaltung geltender Gesetze, Datenschutzanforderungen, vertraglicher Einschränkungen und Nutzungsbedingungen Dritter verantwortlich. Die MIT-Lizenz gewährt Rechte am Quellcode, aber keine Berechtigung zum Zugriff auf fremde Systeme oder Daten.
