# Import required modules
import sys
import json
import subprocess
import shutil
from pathlib import Path
import os

# PyQt6 modules for GUI elements and validation
from PyQt6.QtCore import QRegularExpression, QMetaObject, Qt, Q_ARG
from PyQt6.QtGui import QAction, QIntValidator, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QGroupBox, QLineEdit, QFormLayout,
    QMenuBar, QFileDialog, QMessageBox, QTabWidget, QCheckBox,
    QListWidget, QComboBox, QScrollArea, QSizePolicy, QTextEdit
)

# Main class for the Wstunnel GUI application
class WstunnelGUIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wstunnel GUI")
        # Removed fixed size to allow resizing
        self.setMinimumSize(800, 600)  # Set minimum size instead

        self.current_file = None
        self.connection_active = False  # Connection status
        self.process = None  # Subprocess for wstunnel

        self.create_menu_bar()  # Create menu bar

        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # Create a scroll area for the tab widget
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        # Create tab widget for configuration
        self.tab_widget = QTabWidget()
        self.tab_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # Set the tab widget as the scroll area's widget
        scroll_area.setWidget(self.tab_widget)
        main_layout.addWidget(scroll_area, 1)  # Add stretch factor to make it resizable

        # Create server and client tabs
        self.create_server_tab()
        self.create_client_tab()

        # Connection status display
        status_panel = QGroupBox("Connection Status")
        status_layout = QVBoxLayout(status_panel)  # Changed to VBox for better layout

        # Top row with status and button
        top_row = QWidget()
        top_row_layout = QHBoxLayout(top_row)
        
        # Connection status
        self.status_label = QLabel("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        
        # Activate button
        self.activate_button = QPushButton("Activate")
        self.activate_button.setStyleSheet("font-size: 14px;")
        self.activate_button.clicked.connect(self.toggle_connection)

        top_row_layout.addWidget(self.status_label, 1)
        top_row_layout.addWidget(self.activate_button)
        status_layout.addWidget(top_row)

        # Output console for command line stdout
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setStyleSheet("""
            QTextEdit {
                border: 1px solid #ccc;
                font-family: monospace;
                min-height: 100px;
            }
        """)
        self.output_console.setSizePolicy(
            QSizePolicy.Policy.Expanding, 
            QSizePolicy.Policy.Expanding
        )
        status_layout.addWidget(self.output_console, 1)  # Add stretch factor

        main_layout.addWidget(status_panel)

        self.config_dic = {"server": {}, "client": {}}
        self.wstunnel_executable = None  # Path to wstunnel executable

        self.find_wstunnel_executable()  # Try to find it automatically

    def find_wstunnel_executable(self):
        """
        Search for wstunnel executable in:
        1. System PATH
        2. Same directory as the Python script
        """
        # Check system PATH first
        wstunnel_path = shutil.which('wstunnel')
        if wstunnel_path:
            self.wstunnel_executable = wstunnel_path
            return
        
        # Check same directory as the Python script
        script_dir = Path(sys.argv[0]).parent.resolve()
        local_path = script_dir / 'wstunnel'
        if local_path.exists() and os.access(local_path, os.X_OK):
            self.wstunnel_executable = str(local_path)
            return
        
        # If not found, leave it as is (None or previously set value)
        self.append_output("Note: wstunnel executable not found in standard locations\n")


    def create_server_tab(self):

        server_tab = QWidget()
        server_scroll = QScrollArea()
        server_scroll.setWidgetResizable(True)
        
        server_content = QWidget()
        server_layout = QFormLayout(server_content)
        
        
        # Add server parameters
        # 1. Server Address (ws[s]://0.0.0.0[:port])
        self.server_address = QLineEdit()
        self.server_address.setPlaceholderText("e.g., wss://0.0.0.0:8080")
        rx_server = QRegularExpression(r"^(ws|wss)://[\w\.\:]+(:[0-9]{1,5})?$")
        self.server_address.setValidator(QRegularExpressionValidator(rx_server))
        server_layout.addRow("WebSocket URL:", self.server_address)
        self.server_address.editingFinished.connect(lambda: self.config_changed(self.server_address))

        # Socket SO Mark (numeric value)
        self.socket_so_mark = QLineEdit()
        self.socket_so_mark.setValidator(QIntValidator(0, 2147483647))
        self.socket_so_mark.setPlaceholderText("e.g., 1234")
        server_layout.addRow("Socket SO Mark:", self.socket_so_mark)
        self.socket_so_mark.editingFinished.connect(lambda: self.config_changed(self.socket_so_mark))

        # Port number
        self.server_port_number = QLineEdit()
        self.server_port_number.setValidator(QIntValidator(1, 65535))
        self.server_port_number.setPlaceholderText("e.g., 1234")
        server_layout.addRow("Listen Port:", self.server_port_number)
        self.server_port_number.editingFinished.connect(lambda: self.config_changed(self.server_port_number))

        # 3. --websocket-ping-frequency-sec <seconds>
        self.ping_frequency = QLineEdit()
        self.ping_frequency.setInputMask("00000")
        self.ping_frequency.setValidator(QIntValidator(0, 99999))
        self.ping_frequency.setPlaceholderText("e.g., 30")
        self.ping_frequency.editingFinished.connect(lambda: self.config_changed(self.ping_frequency))
        server_layout.addRow("Ping Frequency (sec):", self.ping_frequency)

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

        # Set the content widget
        server_scroll.setWidget(server_content)
        
        # Create a layout for the tab and add the scroll area
        tab_layout = QVBoxLayout(server_tab)
        tab_layout.addWidget(server_scroll)

        self.tab_widget.addTab(server_tab, "Server")

    def add_restrict_to(self):
        """Add restrict-to entry to the list"""
        restrict_text = self.restrict_to_input.text()
        if restrict_text:
            self.restrict_to_list.addItem(restrict_text)
            self.restrict_to_input.clear()
            self.config_dic["server"]["restrict_to"] = [
                self.restrict_to_list.item(i).text() for i in range(self.restrict_to_list.count())
            ]

    def add_dns_resolver(self):
        """Add DNS resolver entry to the list"""
        dns_text = self.dns_resolver_input.text()
        if dns_text:
            self.dns_resolver_list.addItem(dns_text)
            self.dns_resolver_input.clear()
            self.config_dic["server"]["dns_resolvers"] = [
                self.dns_resolver_list.item(i).text() for i in range(self.dns_resolver_list.count())
            ]

    def browse_restrict_config(self):
        """Browse for restrict config file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Restrict Config File", "", "YAML Files (*.yaml);;All Files (*)")
        if file_path:
            self.restrict_config.setText(file_path)
            self.config_changed(self.restrict_config)

    def browse_tls_cert(self):
        """Browse for TLS certificate file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select TLS Certificate File", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.tls_cert.setText(file_path)
            self.config_changed(self.tls_cert)

    def browse_tls_key(self):
        """Browse for TLS private key file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select TLS Private Key File", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.tls_key.setText(file_path)
            self.config_changed(self.tls_key)

    def browse_tls_ca_certs(self):
        """Browse for TLS CA certificates file"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select TLS CA Certificates File", "", "PEM Files (*.pem);;All Files (*)")
        if file_path:
            self.tls_ca_certs.setText(file_path)
            self.config_changed(self.tls_ca_certs)

    def create_client_tab(self):
        """Create the client configuration tab with scrollable content"""
        client_tab = QWidget()
        client_scroll = QScrollArea()
        client_scroll.setWidgetResizable(True)
        
        client_content = QWidget()
        client_layout = QFormLayout(client_content)

        # WebSocket URL
        self.ws_url_input = QLineEdit()
        self.ws_url_input.setPlaceholderText("e.g., wss://server:8080")
        client_layout.addRow("WebSocket URL:", self.ws_url_input)
        self.ws_url_input.editingFinished.connect(lambda: self.config_changed(self.ws_url_input))

        # Local bind address
        self.local_bind_input = QLineEdit("127.0.0.1:1080")
        client_layout.addRow("Local bind (IP:Port):", self.local_bind_input)
        self.local_bind_input.editingFinished.connect(lambda: self.config_changed(self.local_bind_input))

        # Optional remote target on the server side
        self.remote_target_input = QLineEdit()
        client_layout.addRow("Remote Target (optional):", self.remote_target_input)
        self.remote_target_input.editingFinished.connect(lambda: self.config_changed(self.remote_target_input))

        # Ignore TLS certificate errors
        self.ignore_cert_checkbox = QCheckBox("Ignore TLS Certificate Errors")
        self.ignore_cert_checkbox.stateChanged.connect(lambda: self.config_changed(self.ignore_cert_checkbox))
        client_layout.addRow(self.ignore_cert_checkbox)

        # Proxy settings
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("e.g., socks5://127.0.0.1:9050")
        client_layout.addRow("Proxy:", self.proxy_input)
        self.proxy_input.editingFinished.connect(lambda: self.config_changed(self.proxy_input))

        client_scroll.setWidget(client_content)
        
        # Create a layout for the tab and add the scroll area
        tab_layout = QVBoxLayout(client_tab)
        tab_layout.addWidget(client_scroll)
        
        self.tab_widget.addTab(client_tab, "Client")

    def config_changed(self, widget):
        """Update config dictionary when any server configuration changes"""
        server_config = self.config_dic.setdefault("server", {})
        
        if widget == self.server_address:
            server_config["ws_url"] = widget.text()
        elif widget == self.socket_so_mark:
            server_config["so_mark"] = widget.text()
        elif widget == self.server_port_number:
            server_config["port"] = widget.text()
        elif widget == self.ping_frequency:
            server_config["ping_frequency"] = widget.text()
        elif widget == self.websocket_mask:
            server_config["websocket_mask"] = widget.isChecked()
        elif widget == self.worker_threads:
            server_config["worker_threads"] = widget.text()
        elif widget == self.log_level:
            server_config["log_level"] = widget.currentText()
        elif widget == self.http_upgrade_path:
            server_config["http_upgrade_path"] = widget.text()
        elif widget == self.restrict_config:
            server_config["restrict_config"] = widget.text()
        elif widget == self.tls_cert:
            server_config["tls_cert"] = widget.text()
        elif widget == self.tls_key:
            server_config["tls_key"] = widget.text()
        elif widget == self.tls_ca_certs:
            server_config["tls_ca_certs"] = widget.text()
        elif widget == self.http_proxy:
            server_config["http_proxy"] = widget.text()
        elif widget == self.proxy_login:
            server_config["proxy_login"] = widget.text()
        elif widget == self.proxy_password:
            server_config["proxy_password"] = widget.text()
        
        # Handle list widgets separately
        if hasattr(self, 'restrict_to_list'):
            server_config["restrict_to"] = [
                self.restrict_to_list.item(i).text() 
                for i in range(self.restrict_to_list.count())
            ]
        
        if hasattr(self, 'dns_resolver_list'):
            server_config["dns_resolvers"] = [
                self.dns_resolver_list.item(i).text() 
                for i in range(self.dns_resolver_list.count())
            ]

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
            self, "Open Config File", "", "JSON Config Files (*.json);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.config_dic = json.load(f)
                
                # Update server tab widgets
                if "server" in self.config_dic:
                    server = self.config_dic["server"]
                    self.server_address.setText(server.get("ws_url", ""))
                    self.socket_so_mark.setText(server.get("so_mark", ""))
                    self.server_port_number.setText(server.get("port", ""))
                    self.ping_frequency.setText(server.get("ping_frequency", ""))
                    self.websocket_mask.setChecked(server.get("websocket_mask", False))
                    self.worker_threads.setText(server.get("worker_threads", ""))
                    self.log_level.setCurrentText(server.get("log_level", "INFO"))
                    self.http_upgrade_path.setText(server.get("http_upgrade_path", ""))
                    self.restrict_config.setText(server.get("restrict_config", ""))
                    self.tls_cert.setText(server.get("tls_cert", ""))
                    self.tls_key.setText(server.get("tls_key", ""))
                    self.tls_ca_certs.setText(server.get("tls_ca_certs", ""))
                    self.http_proxy.setText(server.get("http_proxy", ""))
                    self.proxy_login.setText(server.get("proxy_login", ""))
                    self.proxy_password.setText(server.get("proxy_password", ""))
                    
                    # Populate list widgets
                    if "restrict_to" in server:
                        self.restrict_to_list.clear()
                        for item in server["restrict_to"]:
                            self.restrict_to_list.addItem(item)
                    
                    if "dns_resolvers" in server:
                        self.dns_resolver_list.clear()
                        for item in server["dns_resolvers"]:
                            self.dns_resolver_list.addItem(item)
                
                # Update client tab widgets if needed
                if "client" in self.config_dic:
                    client = self.config_dic["client"]
                    # Add similar population for client widgets here
                
                self.current_file = file_path
                QMessageBox.information(
                    self, "Config Loaded", 
                    f"Configuration loaded successfully from:\n{file_path}"
                )
                
            except json.JSONDecodeError:
                QMessageBox.critical(self, "Error", "Invalid JSON format in config file")
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
            if not file_path.endswith('.json'):
                file_path += '.json'
            self.current_file = file_path
            self.save_config()

    def toggle_connection(self):
        if self.connection_active:
            self.deactivate_connection()
        else:
            self.activate_connection()

    def closeEvent(self, event):
        if self.connection_active:
            self.deactivate_connection()
        event.accept()

    def activate_connection(self):
        # Check if executable is available
        if not self.wstunnel_executable:
            self.append_output("Error: Wstunnel executable not selected\n")
            QMessageBox.warning(self, "Error", "Wstunnel executable not selected")
            return

        # Freeze the configuration tabs
        self.tab_widget.setEnabled(False)
        self.connection_active = True
        
        # Update status
        self.status_label.setText("Connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: green;")
        self.activate_button.setText("Deactivate")

        try:
            # Determine which tab is active
            current_tab = self.tab_widget.currentIndex()
            
            if current_tab == 0:  # Server tab
                if not self.start_wstunnel_server():
                    self.deactivate_connection()
            else:  # Client tab
                if not self.start_wstunnel_client():
                    self.deactivate_connection()
                    
        except Exception as e:
            self.append_output(f"Unexpected error: {str(e)}\n")
            self.deactivate_connection()

    def start_wstunnel_server(self):
        """Start wstunnel in server mode with configured parameters"""
        server_config = self.config_dic.get("server", {})
        
        # Build command arguments
        cmd = [self.wstunnel_executable, "server"]
        
        # Required parameters
        ws_url = server_config.get("ws_url")
        if not ws_url:
            self.append_output("Error: WebSocket URL is required (e.g., wss://0.0.0.0:8080)\n")
            return False
        
        cmd.append(ws_url)
        
        # Optional parameters
        
        if server_config.get("so_mark"):
            cmd.extend(["--socket-so-mark", server_config["so_mark"]])
        
        if server_config.get("ping_frequency"):
            cmd.extend(["--websocket-ping-frequency-sec", server_config["ping_frequency"]])
        
        if server_config.get("websocket_mask", False):
            cmd.append("--websocket-mask-frame")
        
        if server_config.get("worker_threads"):
            cmd.extend(["--nb-worker-threads", server_config["worker_threads"]])
        
        if "restrict_to" in server_config:
            for dest in server_config["restrict_to"]:
                cmd.extend(["--restrict-to", dest])
        
        if "dns_resolvers" in server_config:
            for resolver in server_config["dns_resolvers"]:
                cmd.extend(["--dns-resolver", resolver])
        
        if server_config.get("log_level"):
            cmd.extend(["--log-lvl", server_config["log_level"]])
        
        if server_config.get("http_upgrade_path"):
            cmd.extend(["--restrict-http-upgrade-path-prefix", server_config["http_upgrade_path"]])
        
        if server_config.get("restrict_config"):
            cmd.extend(["--restrict-config", server_config["restrict_config"]])
        
        if server_config.get("tls_cert"):
            cmd.extend(["--tls-certificate", server_config["tls_cert"]])
        
        if server_config.get("tls_key"):
            cmd.extend(["--tls-private-key", server_config["tls_key"]])
        
        if server_config.get("tls_ca_certs"):
            cmd.extend(["--tls-client-ca-certs", server_config["tls_ca_certs"]])
        
        if server_config.get("http_proxy"):
            cmd.extend(["--http-proxy", server_config["http_proxy"]])
        
        if server_config.get("proxy_login"):
            cmd.extend(["--http-proxy-login", server_config["proxy_login"]])
        
        if server_config.get("proxy_password"):
            cmd.extend(["--http-proxy-password", server_config["proxy_password"]])
        
        # Log the command
        self.append_output(f"Starting server with command:\n{' '.join(cmd)}\n\n")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.start_output_reader()
            return True
        except Exception as e:
            self.append_output(f"Failed to start server: {str(e)}\n")
            return False

    def start_wstunnel_client(self):
        """Start wstunnel in client mode with configured parameters"""
        client_config = self.config_dic.get("client", {})
        
        # Build command arguments
        cmd = [self.wstunnel_executable, "client"]
        
        # Required parameters
        ws_url = client_config.get("ws_url")
        if not ws_url:
            self.append_output("Error: WebSocket URL is required (e.g., wss://example.com:8080)\n")
            return False
        
        local_bind = client_config.get("local_bind")
        if not local_bind:
            self.append_output("Error: Local bind address is required (e.g., 127.0.0.1:1234)\n")
            return False
        
        remote_target = client_config.get("remote_target")
        if not remote_target:
            self.append_output("Error: Remote target is required (e.g., google.com:443)\n")
            return False
        
        cmd.extend([ws_url, f"L:{local_bind}", f"R:{remote_target}"])
        
        # Optional parameters
        if client_config.get("ignore_cert", False):
            cmd.append("--tls-skip-verify")
        
        if client_config.get("proxy"):
            cmd.extend(["--http-proxy", client_config["proxy"]])
        
        # Log the command
        self.append_output(f"Starting client with command:\n{' '.join(cmd)}\n\n")
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            self.start_output_reader()
            return True
        except Exception as e:
            self.append_output(f"Failed to start client: {str(e)}\n")
            return False

    def deactivate_connection(self):
        """Stop the connection and clean up resources"""
        # Stop any running process
        if hasattr(self, 'process'):
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
            except Exception as e:
                self.append_output(f"Error stopping process: {str(e)}\n")
            finally:
                del self.process
        
        # Unfreeze the configuration tabs
        self.tab_widget.setEnabled(True)
        self.connection_active = False
        
        # Update status
        self.status_label.setText("Not connected!")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        self.activate_button.setText("Activate")
    
        self.append_output("Connection stopped\n")

    def start_output_reader(self):
        """Start threads to read stdout and stderr from the process"""
        from threading import Thread
        
        def read_stream(stream, callback):
            while True:
                line = stream.readline()
                if not line:
                    break
                callback(line)
        
        # Create and start threads for stdout and stderr
        self.stdout_thread = Thread(
            target=read_stream,
            args=(self.process.stdout, self.append_output))
        self.stderr_thread = Thread(
            target=read_stream,
            args=(self.process.stderr, self.append_output))
        
        self.stdout_thread.daemon = True
        self.stderr_thread.daemon = True
        
        self.stdout_thread.start()
        self.stderr_thread.start()

    def append_output(self, text):
        """Thread-safe output appending"""
        QMetaObject.invokeMethod(
            self.output_console,
            'append',
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(str, text)
        )

# Main program start
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WstunnelGUIApp()
    window.show()
    sys.exit(app.exec())
