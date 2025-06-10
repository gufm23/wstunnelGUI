# Grafische Benutzeroberfläche für wstunnel

Dieses Repository enthält den Quellcode für eine grafische Benutzeroberfläche (GUI), die im Rahmen eines Hochschulprojekts für das Kommandozeilen-Tool [wstunnel](https://github.com/erebe/wstunnel) entwickelt wurde. Die Anwendung wurde mit Python und dem Qt-Framework (über PyQt) realisiert.

## Inhaltsverzeichnis

- [Projektbeschreibung](#projektbeschreibung)
- [Funktionen der GUI](#funktionen-der-gui)
- [Installationsanleitung](#installationsanleitung)
  - [Voraussetzungen](#voraussetzungen)
  - [Installation](#installation)
- [Nutzung](#nutzung)
- [Projektbeteiligte](#projektbeteiligte)
- [Entwicklung](#entwicklung)

## Projektbeschreibung

Das Ziel dieses Projekts war die Entwicklung einer intuitiven und benutzerfreundlichen grafischen Oberfläche für das bestehende Kommandozeilen-Tool `wstunnel`. `wstunnel` ermöglicht es, TCP-Verkehr über einen WebSocket zu tunneln, was nützlich ist, um Firewalls oder restriktive Netzwerkumgebungen zu umgehen. Unsere GUI vereinfacht die Konfiguration und Steuerung von `wstunnel`-Servern und -Clients, indem sie eine visuelle Alternative zu den langen und komplexen Kommandozeilenbefehlen bietet. Anstatt Befehle manuell im Terminal einzugeben, können Benutzer alle Parameter bequem über Formularfelder und Schalter in der Anwendung einstellen.

## Funktionen der GUI

Die Benutzeroberfläche ist in zwei Hauptbereiche unterteilt, um die Konfiguration des `wstunnel`-Tools zu erleichtern: **Server-Modus** und **Client-Modus**.

### Server-Parameter

Im Server-Modus können folgende Einstellungen vorgenommen werden:

-   **Listen Address:** Geben Sie die IP-Adresse und den Port an, auf dem der WebSocket-Server lauschen soll (z.B. `0.0.0.0:8080`).
-   **Tunnel Address:** Definieren Sie das Ziel, zu dem der Verkehr weitergeleitet werden soll (z.B. `localhost:22` für eine SSH-Verbindung).
-   **Protokoll-Upgrade:** Aktivieren Sie diese Option, um ein Upgrade auf das `ws/wss`-Protokoll zu erzwingen.
-   **TLS-Verschlüsselung:** Sichern Sie die Verbindung durch die Verwendung von TLS.
-   **Weitere Optionen:** Zusätzliche Parameter wie `http-proxy` oder `chisel` können bei Bedarf konfiguriert werden.

### Client-Parameter

Im Client-Modus stehen folgende Konfigurationsmöglichkeiten zur Verfügung:

-   **WebSocket URL:** Die vollständige URL des `wstunnel`-Servers, mit dem sich der Client verbinden soll (z.B. `ws://ihre-server-ip:8080`).
-   **Lokale Bindungsadresse:** Geben Sie die lokale IP-Adresse und den Port an, auf dem der Client lauschen soll, um Verbindungen entgegenzunehmen (z.B. `127.0.0.1:1080`).
-   **Remote-Ziel:** (Optional) Überschreiben Sie das auf dem Server definierte Tunnel-Ziel.
-   **TLS-Optionen:** Konfigurieren Sie die TLS-Verbindung, z.B. durch das Ignorieren von Zertifikatsfehlern (nützlich für selbstsignierte Zertifikate).
-   **Proxy-Einstellungen:** Leiten Sie den Verkehr über einen lokalen HTTP- oder SOCKS5-Proxy.

## Installationsanleitung

Um die GUI zu verwenden, müssen sowohl das `wstunnel`-Tool als auch die für unsere Anwendung erforderlichen Python-Bibliotheken installiert sein.

### Voraussetzungen

-   Python 3.6 oder höher
-   PIP (Python Package Installer)
-   Das `wstunnel`-Binary muss im Systempfad (`PATH`) verfügbar sein oder sich im selben Verzeichnis wie die Anwendung befinden. Anweisungen zur Installation finden Sie auf der [offiziellen wstunnel GitHub-Seite](https://github.com/erebe/wstunnel).

### Installation

1.  **Repository klonen:**
    ```bash
    git clone [https://github.com/gufm23/wstunnelGUI.git](https://github.com/gufm23/wstunnelGUI.git)
    cd wstunnelGUI
    ```

2.  **Abhängigkeiten installieren:**
    Unsere Anwendung benötigt `PyQt6`. Installieren Sie es mit pip:
    ```bash
    pip install -r requirements.txt
    ```
    *(Hinweis: Erstellen Sie eine `requirements.txt`-Datei im Hauptverzeichnis Ihres Projekts mit dem Inhalt `PyQt6`)*

## Nutzung

Nach der erfolgreichen Installation können Sie die Anwendung starten:

```bash
python main.py
