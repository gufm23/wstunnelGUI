import sys
import json
import subprocess

from PyQt6.QtCore import QRegularExpression
from PyQt6.QtGui import QAction, QIntValidator, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QGroupBox, QLineEdit, QFormLayout,
    QMenuBar, QFileDialog, QMessageBox, QTabWidget, QCheckBox,
    QListWidget, QComboBox
)

class WstunnelGUIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wstunnel GUI")
        self.setFixedSize(800, 600)

        self.current_file = None
        self.connection_active = False

        self.create_menu_bar()

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # Create tab widget for configuration
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Create server and client tabs
        self.create_server_tab()
        self.create_client_tab()

        # Status and activation panel at the bottom
        status_panel = QGroupBox("Connection Status")
        status_layout = QHBoxLayout(status_panel)

        # Connection status
        self.status_label = QLabel("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")

        # Activate button
        self.activate_button = QPushButton("Activate")
        self.activate_button.setStyleSheet("font-size: 14px;")
        self.activate_button.clicked.connect(self.toggle_connection)

        status_layout.addWidget(self.status_label, 1)
        status_layout.addWidget(self.activate_button)

        main_layout.addWidget(status_panel)

        self.config_dic = {"server": {}, "client": {}}
        self.wstunnel_executable = None

    def create_server_tab(self):
        """Create the server configuration tab"""
        server_tab = QWidget()
        server_layout = QFormLayout(server_tab)

        # Add server parameters
        # 1. Server Address (ws[s]://0.0.0.0[:port])
        self.server_address = QLineEdit()
        self.server_address.setInputMask(">Aaa://099.099.099.099:00000;_")
        rx_server = QRegularExpression(
            r"^(ws|wss)://([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[\w:]+)(:[0-9]{1,5})?$")
        self.server_address.setValidator(QRegularExpressionValidator(rx_server))
        self.server_address.setPlaceholderText("e.g., wss://0.0.0.0:8080")
        self.server_address.editingFinished.connect(lambda: self.config_changed(self.server_address))
        server_layout.addRow("Server Address:", self.server_address)

        # 2. --socket-so-mark <INT>
        self.socket_so_mark = QLineEdit()
        self.socket_so_mark.setInputMask("0000000000")
        self.socket_so_mark.setValidator(QIntValidator(0, 2147483647))
        self.socket_so_mark.setPlaceholderText("e.g., 1234")
        self.socket_so_mark.editingFinished.connect(lambda: self.config_changed(self.socket_so_mark))
        server_layout.addRow("Socket SO Mark:", self.socket_so_mark)
        self.server_port_number = QLineEdit()
        server_layout.addRow(QLabel("Listen on port number:"), self.server_port_number)

        # 3. --websocket-ping-frequency-sec <seconds>
        self.ping_frequency = QLineEdit()
        self.ping_frequency.setInputMask("00000")
        self.ping_frequency.setValidator(QIntValidator(0, 99999))
        self.ping_frequency.setPlaceholderText("e.g., 30")
        self.ping_frequency.editingFinished.connect(lambda: self.config_changed(self.ping_frequency))
        server_layout.addRow("Ping Frequency (sec):", self.ping_frequency)

        # 4. --no-color
        self.no_color = QCheckBox("Disable color output in logs")
        self.no_color.stateChanged.connect(lambda: self.config_changed(self.no_color))
        server_layout.addRow("No Color:", self.no_color)

        # 5. --websocket-mask-frame
        self.websocket_mask = QCheckBox("Enable WebSocket frame masking")
        self.websocket_mask.stateChanged.connect(lambda: self.config_changed(self.websocket_mask))
        server_layout.addRow("WebSocket Mask Frame:", self.websocket_mask)

        # 6. --nb-worker-threads <INT>
        self.worker_threads = QLineEdit()
        self.worker_threads.setInputMask("000")
        self.worker_threads.setValidator(QIntValidator(1, 999))
        self.worker_threads.setPlaceholderText("e.g., 4")
        self.worker_threads.editingFinished.connect(lambda: self.config_changed(self.worker_threads))
        server_layout.addRow("Worker Threads:", self.worker_threads)

        # 7. --restrict-to <DEST:PORT>
        self.restrict_to_list = QListWidget()
        self.restrict_to_input = QLineEdit()
        self.restrict_to_input.setInputMask(">A{255}:00000")
        rx_restrict = QRegularExpression(r"^[\w\-\.]+:[0-9]{1,5}$")
        self.restrict_to_input.setValidator(QRegularExpressionValidator(rx_restrict))
        self.restrict_to_input.setPlaceholderText("e.g., google.com:443")
        add_restrict_btn = QPushButton("Add")
        add_restrict_btn.clicked.connect(self.add_restrict_to)
        remove_restrict_btn = QPushButton("Remove")
        remove_restrict_btn.clicked.connect(lambda: self.restrict_to_list.takeItem(self.restrict_to_list.currentRow()))
        restrict_layout = QHBoxLayout()
        restrict_layout.addWidget(self.restrict_to_input)
        restrict_layout.addWidget(add_restrict_btn)
        restrict_layout.addWidget(remove_restrict_btn)
        server_layout.addRow("Restrict To:", self.restrict_to_list)
        server_layout.addRow("Add Restrict To:", restrict_layout)

        # 8. --dns-resolver <DNS_RESOLVER>
        self.dns_resolver_list = QListWidget()
        self.dns_resolver_input = QLineEdit()
        self.dns_resolver_input.setInputMask(">A{255}")
        rx_dns = QRegularExpression(r"^(dns://|dns\+https://|dns\+tls://|system://)[\w\.:?\=-]+$")
        self.dns_resolver_input.setValidator(QRegularExpressionValidator(rx_dns))
        self.dns_resolver_input.setPlaceholderText("e.g., dns://1.1.1.1")
        add_dns_btn = QPushButton("Add")
        add_dns_btn.clicked.connect(self.add_dns_resolver)
        remove_dns_btn = QPushButton("Remove")
        remove_dns_btn.clicked.connect(lambda: self.dns_resolver_list.takeItem(self.dns_resolver_list.currentRow()))
        dns_layout = QHBoxLayout()
        dns_layout.addWidget(self.dns_resolver_input)
        dns_layout.addWidget(add_dns_btn)
        dns_layout.addWidget(remove_dns_btn)
        server_layout.addRow("DNS Resolver:", self.dns_resolver_list)
        server_layout.addRow("Add DNS Resolver:", dns_layout)

        # 9. --log-lvl <LOG_LEVEL>
        self.log_level = QComboBox()
        self.log_level.addItems(["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "OFF"])
        self.log_level.setCurrentText("INFO")
        self.log_level.currentTextChanged.connect(lambda: self.config_changed(self.log_level))
        server_layout.addRow("Log Level:", self.log_level)

        # 10. --restrict-http-upgrade-path-prefix
        self.http_upgrade_path = QLineEdit()
        self.http_upgrade_path.setInputMask(">/{255}")
        rx_path = QRegularExpression(r"^/[\w\-\/]+$")
        self.http_upgrade_path.setValidator(QRegularExpressionValidator(rx_path))
        self.http_upgrade_path.setPlaceholderText("e.g., /mysecret")
        self.http_upgrade_path.editingFinished.connect(lambda: self.config_changed(self.http_upgrade_path))
        server_layout.addRow("HTTP Upgrade Path Prefix:", self.http_upgrade_path)

        # 11. --restrict-config <FILE_PATH>
        self.restrict_config = QLineEdit()
        self.restrict_config.setPlaceholderText("e.g., /path/to/restrict.yaml")
        browse_restrict_btn = QPushButton("Browse")
        browse_restrict_btn.clicked.connect(self.browse_restrict_config)
        restrict_config_layout = QHBoxLayout()
        restrict_config_layout.addWidget(self.restrict_config)
        restrict_config_layout.addWidget(browse_restrict_btn)
        self.restrict_config.editingFinished.connect(lambda: self.config_changed(self.restrict_config))
        server_layout.addRow("Restrict Config File:", restrict_config_layout)

        # 12. --tls-certificate <FILE_PATH>
        self.tls_cert = QLineEdit()
        self.tls_cert.setPlaceholderText("e.g., /path/to/cert.pem")
        browse_cert_btn = QPushButton("Browse")
        browse_cert_btn.clicked.connect(self.browse_tls_cert)
        cert_layout = QHBoxLayout()
        cert_layout.addWidget(self.tls_cert)
        cert_layout.addWidget(browse_cert_btn)
        self.tls_cert.editingFinished.connect(lambda: self.config_changed(self.tls_cert))
        server_layout.addRow("TLS Certificate:", cert_layout)

        # 13. --tls-private-key <FILE_PATH>
        self.tls_key = QLineEdit()
        self.tls_key.setPlaceholderText("e.g., /path/to/key.pem")
        browse_key_btn = QPushButton("Browse")
        browse_key_btn.clicked.connect(self.browse_tls_key)
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.tls_key)
        key_layout.addWidget(browse_key_btn)
        self.tls_key.editingFinished.connect(lambda: self.config_changed(self.tls_key))
        server_layout.addRow("TLS Private Key:", key_layout)

        # 14. --tls-client-ca-certs <FILE_PATH>
        self.tls_ca_certs = QLineEdit()
        self.tls_ca_certs.setPlaceholderText("e.g., /path/to/ca.pem")
        browse_ca_btn = QPushButton("Browse")
        browse_ca_btn.clicked.connect(self.browse_tls_ca_certs)
        ca_layout = QHBoxLayout()
        ca_layout.addWidget(self.tls_ca_certs)
        ca_layout.addWidget(browse_ca_btn)
        self.tls_ca_certs.editingFinished.connect(lambda: self.config_changed(self.tls_ca_certs))
        server_layout.addRow("TLS Client CA Certs:", ca_layout)

        # 15. --http-proxy <USER:PASS@HOST:PORT>
        self.http_proxy = QLineEdit()
        self.http_proxy.setInputMask(">A{255}@099.099.099.099:00000")
        rx_proxy = QRegularExpression(r"^([\w\-]+:[\w\-]+@)?[\w\-\.]+:[0-9]{1,5}$")
        self.http_proxy.setValidator(QRegularExpressionValidator(rx_proxy))
        self.http_proxy.setPlaceholderText("e.g., user:pass@1.1.1.1:8080")
        self.http_proxy.editingFinished.connect(lambda: self.config_changed(self.http_proxy))
        server_layout.addRow("HTTP Proxy:", self.http_proxy)

        # 16. --http-proxy-login <LOGIN>
        self.proxy_login = QLineEdit()
        rx_login = QRegularExpression(r"^[\w\-]+$")
        self.proxy_login.setValidator(QRegularExpressionValidator(rx_login))
        self.proxy_login.setPlaceholderText("e.g., myuser")
        self.proxy_login.editingFinished.connect(lambda: self.config_changed(self.proxy_login))
        server_layout.addRow("HTTP Proxy Login:", self.proxy_login)

        # 17. --http-proxy-password <PASSWORD>
        self.proxy_password = QLineEdit()
        self.proxy_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.proxy_password.setPlaceholderText("e.g., mypassword")
        self.proxy_password.editingFinished.connect(lambda: self.config_changed(self.proxy_password))
        server_layout.addRow("HTTP Proxy Password:", self.proxy_password)

        self.tab_widget.addTab(server_tab, "Server")

    def create_client_tab(self):
        """Create the client configuration tab"""
        client_tab = QWidget()
        client_layout = QFormLayout(client_tab)

        # WebSocket URL
        self.ws_url_input = QLineEdit()
        client_layout.addRow(QLabel("WebSocket URL:"), self.ws_url_input)
        self.ws_url_input.editingFinished.connect(lambda: self.config_changed(self.ws_url_input))

        # Local Binding Address
        self.local_bind_input = QLineEdit("127.0.0.1:1080")
        client_layout.addRow(QLabel("Local Binding Address:"), self.local_bind_input)
        self.local_bind_input.editingFinished.connect(lambda: self.config_changed(self.local_bind_input))

        # Remote Target (optional)
        self.remote_target_input = QLineEdit()
        client_layout.addRow(QLabel("Remote Target (optional):"), self.remote_target_input)
        self.remote_target_input.editingFinished.connect(lambda: self.config_changed(self.remote_target_input))

        # TLS Ignore Cert Errors
        self.ignore_cert_checkbox = QCheckBox("Ignore TLS Certificate Errors")
        self.ignore_cert_checkbox.stateChanged.connect(lambda: self.config_changed(self.ignore_cert_checkbox))
        client_layout.addRow(self.ignore_cert_checkbox)

        # Proxy Settings
        self.proxy_input = QLineEdit()
        client_layout.addRow(QLabel("Proxy (e.g. socks5://127.0.0.1:9050):"), self.proxy_input)
        self.proxy_input.editingFinished.connect(lambda: self.config_changed(self.proxy_input))

        self.tab_widget.addTab(client_tab, "Client")

    def config_changed(self, widget):
        if widget == self.ws_url_input:
            self.config_dic["client"]["ws_url"] = widget.text()
        elif widget == self.local_bind_input:
            self.config_dic["client"]["local_bind"] = widget.text()
        elif widget == self.remote_target_input:
            self.config_dic["client"]["remote_target"] = widget.text()
        elif widget == self.ignore_cert_checkbox:
            self.config_dic["client"]["ignore_cert"] = widget.isChecked()
        elif widget == self.proxy_input:
            self.config_dic["client"]["proxy"] = widget.text()
        elif widget == self.client_port_number:
            self.config_dic["client"]["port"] = widget.text()
        elif widget == self.server_port_number:
            self.config_dic["server"]["port"] = widget.text()

    def create_menu_bar(self):
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("File")

        open_action = QAction("Open Config", self)
        open_action.triggered.connect(self.open_config)
        file_menu.addAction(open_action)

        save_action = QAction("Save Config", self)
        save_action.triggered.connect(self.save_config)
        file_menu.addAction(save_action)

        save_as_action = QAction("Save Config As", self)
        save_as_action.triggered.connect(self.save_config_as)
        file_menu.addAction(save_as_action)

        edit_menu = menu_bar.addMenu("Edit")

        select_executable_action = QAction("Select Wstunnel Executable", self)
        select_executable_action.triggered.connect(self.select_wstunnel_executable)
        edit_menu.addAction(select_executable_action)

    def select_wstunnel_executable(self):
        """Open file dialog to select wstunnel executable"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Wstunnel Executable", "", )

        if file_path:
            self.wstunnel_executable = file_path

    def open_config(self):
        if self.connection_active:
            QMessageBox.warning(self, "Connection Active", "Cannot load config while connection is active")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Config File", "", "WireGuard Config Files (*.conf);;All Files (*)"
        )

        if file_path:
            try:
                self.current_file = file_path
                QMessageBox.information(
                    self, "Config Loaded",
                    f"Config file loaded from:\n{file_path}\n\n(Actual loading not implemented in this example)"
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load config:\n{str(e)}")

    def save_config(self):
        if not self.current_file:
            self.save_config_as()
            return

        try:
            with open(self.current_file, "w", encoding="utf-8") as f:
                json.dump(self.config_dic, f, indent=4)
            QMessageBox.information(
                self, "Config Saved",
                f"Config saved to:\n{self.current_file}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save config:\n{str(e)}")

    def save_config_as(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Config File", "", "Wstunnel JSON Config Files (*.json);;All Files (*)"
        )

        if file_path:
            if not file_path.endswith('.conf'):
                file_path += '.conf'
            self.current_file = file_path
            self.save_config()

    def toggle_connection(self):
        if self.connection_active:
            self.deactivate_connection()
        else:
            self.activate_connection()

    def activate_connection(self):
        # Freeze the configuration tabs
        self.tab_widget.setEnabled(False)
        self.connection_active = True

        # Update status
        self.status_label.setText("Connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: green;")
        self.activate_button.setText("Deactivate")

        # Determine which tab is active
        current_tab = self.tab_widget.currentIndex()
        if current_tab == 0:  # Server tab
            config_type = "Server"
            port = self.server_port_number.text()
            bind_addr = self.bind_address.text() or "0.0.0.0"
            cmd = f"wstunnel server --local-port {port} --bind-address {bind_addr}"
            if self.tls_checkbox.isChecked():
                cmd += " --tls"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception(result.stderr)
                QMessageBox.information(self, "Connection Started", "Server configuration activated")
            except Exception as e:
                self.deactivate_connection()
                QMessageBox.critical(self, "Error", f"Failed to start server: {str(e)}")
            else:  # Client tab
                config_type = "Client"
                ws_url = self.ws_url_input.text()
                local_bind = self.local_bind_input.text()
                remote_target = self.remote_target_input.text()
                ignore_cert = self.ignore_cert_checkbox.isChecked()
                proxy = self.proxy_input.text()

                if not ws_url or not local_bind:
                    QMessageBox.warning(self, "Missing Input", "WebSocket URL and Local Binding Address are required.")
                    self.deactivate_connection()
                    return

                # Split local bind
                try:
                    local_ip, local_port = local_bind.split(":")
                except ValueError:
                    QMessageBox.critical(self, "Input Error", "Local Binding Address must be in IP:PORT format.")
                    self.deactivate_connection()
                    return

                cmd = f"{self.wstunnel_executable or 'wstunnel'} client --remote-addr {ws_url} --local-addr {local_ip}:{local_port}"

                if remote_target:
                    cmd += f" --tunnel-addr {remote_target}"

                if ignore_cert:
                    cmd += " --insecure"

                if proxy:
                    cmd += f" --proxy {proxy}"

                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode != 0:
                        raise Exception(result.stderr)
                    QMessageBox.information(self, "Connection Started", "Client configuration activated")
                except Exception as e:
                    self.deactivate_connection()
                    QMessageBox.critical(self, "Error", f"Failed to start client: {str(e)}")


def deactivate_connection(self):
        # Unfreeze the configuration tabs
        self.tab_widget.setEnabled(True)
        self.connection_active = False

        # Update status
        self.status_label.setText("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        self.activate_button.setText("Activate")

        QMessageBox.information(self, "Connection Stopped", "Connection deactivated")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WstunnelGUIApp()
    window.show()
    sys.exit(app.exec())
