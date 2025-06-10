# Importieren der benötigten Module
import sys
import json
import subprocess

# PyQt6-Module für GUI-Elemente und Validierung
from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import QAction, QIntValidator, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QGroupBox, QLineEdit, QFormLayout,
    QFileDialog, QMessageBox, QTabWidget, QCheckBox,
    QListWidget, QComboBox
)

# Hauptklasse für die Wstunnel GUI-Anwendung
class WstunnelGUIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wstunnel GUI")  # Fenster-Titel setzen
        self.setFixedSize(800, 600)  # Feste Fenstergröße

        self.current_file = None
        self.connection_active = False  # Verbindungsstatus
        self.process = None  # Subprozess für wstunnel

        self.create_menu_bar()  # Menüleiste erstellen

        # Haupt-Widget und Layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        self.tab_widget = QTabWidget()  # Tabs für Server/Client
        main_layout.addWidget(self.tab_widget)

        self.create_server_tab()  # Server-Konfigurations-Tab
        self.create_client_tab()  # Client-Konfigurations-Tab

        # Verbindungsstatus-Anzeige
        status_panel = QGroupBox("Connection Status")
        status_layout = QHBoxLayout(status_panel)
        self.status_label = QLabel("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        self.activate_button = QPushButton("Activate")
        self.activate_button.setStyleSheet("font-size: 14px;")
        self.activate_button.clicked.connect(self.toggle_connection)
        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.activate_button)
        main_layout.addWidget(status_panel)

        # Dictionary für Konfigurationsdaten
        self.config_dic = {"server": {}, "client": {}}
        self.wstunnel_executable = None  # Pfad zur wstunnel-Executable

    # Erstellt das Server-Konfigurationsformular
    def create_server_tab(self):
        server_tab = QWidget()
        server_layout = QFormLayout(server_tab)

        # WebSocket-Adresseingabe mit Validierung
        self.server_address = QLineEdit()
        self.server_address.setPlaceholderText("e.g., wss://0.0.0.0:8080")
        rx_server = QRegularExpression(r"^(ws|wss)://[\w\.\:]+(:[0-9]{1,5})?$")
        self.server_address.setValidator(QRegularExpressionValidator(rx_server))
        server_layout.addRow("WebSocket URL:", self.server_address)
        self.server_address.editingFinished.connect(lambda: self.config_changed(self.server_address))

        # Bind-Adresse
        self.bind_address = QLineEdit("0.0.0.0")
        server_layout.addRow("Bind Address:", self.bind_address)
        self.bind_address.editingFinished.connect(lambda: self.config_changed(self.bind_address))

        # Socket SO Mark (numerischer Wert)
        self.socket_so_mark = QLineEdit()
        self.socket_so_mark.setValidator(QIntValidator(0, 2147483647))
        self.socket_so_mark.setPlaceholderText("e.g., 1234")
        server_layout.addRow("Socket SO Mark:", self.socket_so_mark)
        self.socket_so_mark.editingFinished.connect(lambda: self.config_changed(self.socket_so_mark))

        # Portnummer
        self.server_port_number = QLineEdit()
        self.server_port_number.setValidator(QIntValidator(1, 65535))
        server_layout.addRow("Listen Port:", self.server_port_number)
        self.server_port_number.editingFinished.connect(lambda: self.config_changed(self.server_port_number))

        # TLS aktivieren
        self.tls_checkbox = QCheckBox("Enable TLS")
        self.tls_checkbox.stateChanged.connect(lambda: self.config_changed(self.tls_checkbox))
        server_layout.addRow(self.tls_checkbox)

        # Tab zum Widget hinzufügen
        self.tab_widget.addTab(server_tab, "Server")

    # Erstellt das Client-Konfigurationsformular
    def create_client_tab(self):
        client_tab = QWidget()
        client_layout = QFormLayout(client_tab)

        # WebSocket-Adresse für den Client
        self.ws_url_input = QLineEdit()
        self.ws_url_input.setPlaceholderText("e.g., wss://server:8080")
        client_layout.addRow("WebSocket URL:", self.ws_url_input)
        self.ws_url_input.editingFinished.connect(lambda: self.config_changed(self.ws_url_input))

        # Lokale Bind-Adresse
        self.local_bind_input = QLineEdit("127.0.0.1:1080")
        client_layout.addRow("Local bind (IP:Port):", self.local_bind_input)
        self.local_bind_input.editingFinished.connect(lambda: self.config_changed(self.local_bind_input))

        # Optionales Ziel auf der Serverseite
        self.remote_target_input = QLineEdit()
        client_layout.addRow("Remote Target (optional):", self.remote_target_input)
        self.remote_target_input.editingFinished.connect(lambda: self.config_changed(self.remote_target_input))

        # TLS-Zertifikatsfehler ignorieren
        self.ignore_cert_checkbox = QCheckBox("Ignore TLS Certificate Errors")
        self.ignore_cert_checkbox.stateChanged.connect(lambda: self.config_changed(self.ignore_cert_checkbox))
        client_layout.addRow(self.ignore_cert_checkbox)

        # Proxy-Einstellungen
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("e.g., socks5://127.0.0.1:9050")
        client_layout.addRow("Proxy:", self.proxy_input)
        self.proxy_input.editingFinished.connect(lambda: self.config_changed(self.proxy_input))

        # Tab zum Widget hinzufügen
        self.tab_widget.addTab(client_tab, "Client")

    # Aktualisiert die Konfigurationsdaten bei Änderungen im Formular
    def config_changed(self, widget):
        # Je nach Eingabefeld die zugehörige Einstellung speichern
        if widget == self.server_address:
            self.config_dic["server"]["ws_url"] = widget.text()
        elif widget == self.bind_address:
            self.config_dic["server"]["bind_address"] = widget.text()
        elif widget == self.socket_so_mark:
            self.config_dic["server"]["so_mark"] = widget.text()
        elif widget == self.server_port_number:
            self.config_dic["server"]["port"] = widget.text()
        elif widget == self.tls_checkbox:
            self.config_dic["server"]["tls"] = widget.isChecked()
        elif widget == self.ws_url_input:
            self.config_dic["client"]["ws_url"] = widget.text()
        elif widget == self.local_bind_input:
            self.config_dic["client"]["local_bind"] = widget.text()
        elif widget == self.remote_target_input:
            self.config_dic["client"]["remote_target"] = widget.text()
        elif widget == self.ignore_cert_checkbox:
            self.config_dic["client"]["ignore_cert"] = widget.isChecked()
        elif widget == self.proxy_input:
            self.config_dic["client"]["proxy"] = widget.text()

    # Verbindungsstatus umschalten (aktivieren/deaktivieren)
    def toggle_connection(self):
        if self.connection_active:
            self.deactivate_connection()
        else:
            self.activate_connection()

    # Verbindung aktivieren und wstunnel starten
    def activate_connection(self):
        self.tab_widget.setEnabled(False)
        self.connection_active = True
        self.activate_button.setText("Deactivate")
        self.status_label.setText("Connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: green;")

        # Kommandozeile je nach Tab (Server oder Client) erstellen
        if self.tab_widget.currentIndex() == 0:
            cmd = [
                self.wstunnel_executable or "wstunnel", "server",
                "--local-port", self.server_port_number.text(),
                "--bind-address", self.bind_address.text()
            ]
            if self.tls_checkbox.isChecked():
                cmd.append("--tls")
        else:
            ws_url = self.ws_url_input.text()
            local_bind = self.local_bind_input.text()
            if not ws_url or not local_bind:
                QMessageBox.warning(self, "Missing Input", "WebSocket URL bzw. Local bind fehlen.")
                self.deactivate_connection()
                return
            local_ip, local_port = local_bind.split(":")
            cmd = [
                self.wstunnel_executable or "wstunnel", "client",
                "--remote-addr", ws_url,
                "--local-addr", f"{local_ip}:{local_port}"
            ]
            if self.remote_target_input.text():
                cmd += ["--tunnel-addr", self.remote_target_input.text()]
            if self.ignore_cert_checkbox.isChecked():
                cmd.append("--insecure")
            if self.proxy_input.text():
                cmd += ["--proxy", self.proxy_input.text()]

        # Prozess starten
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            QMessageBox.information(self, "Started", "wstunnel gestartet.")
        except Exception as e:
            self.deactivate_connection()
            QMessageBox.critical(self, "Error", str(e))

    # Verbindung deaktivieren und Prozess beenden
    def deactivate_connection(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
        self.tab_widget.setEnabled(True)
        self.connection_active = False
        self.activate_button.setText("Activate")
        self.status_label.setText("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        QMessageBox.information(self, "Stopped", "wstunnel wurde gestoppt.")

    # Menüleiste mit "Datei"-Menü und Executable-Auswahl
    def create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("File")
        select_exec = QAction("Select wstunnel Executable", self)
        select_exec.triggered.connect(self.select_wstunnel_executable)
        file_menu.addAction(select_exec)

    # Dialog zur Auswahl der ausführbaren Datei öffnen
    def select_wstunnel_executable(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Executable", "", "")
        if path:
            self.wstunnel_executable = path

    # Beim Schließen der Anwendung sicherstellen, dass Prozesse beendet werden
    def closeEvent(self, event):
        if self.connection_active:
            self.deactivate_connection()
        event.accept()


# Hauptprogrammstart
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WstunnelGUIApp()
    window.show()
    sys.exit(app.exec())
