import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import strongdm
import os
import csv
import json
import logging
from datetime import datetime
import threading
import base64
from pathlib import Path
import io
import sys
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_and_upgrade_sdk():
    """Check for and upgrade StrongDM SDK and CLI to latest versions"""
    # Upgrade Python SDK via pip
    try:
        logger.info("Checking for StrongDM Python SDK updates...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", "strongdm"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            if "Successfully installed" in result.stdout:
                logger.info(f"StrongDM SDK upgraded: {result.stdout.strip()}")
            else:
                logger.info("StrongDM SDK is already up to date")
        else:
            logger.warning(f"SDK upgrade check completed with warnings: {result.stderr}")

    except subprocess.TimeoutExpired:
        logger.warning("SDK upgrade check timed out after 30 seconds")
    except Exception as e:
        logger.warning(f"Could not check for SDK updates: {e}")
        logger.info("Continuing with current SDK version...")

    # Check for and update StrongDM CLI
    try:
        logger.info("Checking for StrongDM CLI...")
        # Try both 'sdm' and 'sdm.exe' for Windows compatibility
        sdm_commands = ["sdm", "sdm.exe"] if sys.platform == "win32" else ["sdm"]

        cli_found = False
        for sdm_cmd in sdm_commands:
            try:
                check_result = subprocess.run(
                    [sdm_cmd, "version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if check_result.returncode == 0:
                    logger.info(f"StrongDM CLI found: {check_result.stdout.strip()}")
                    cli_found = True

                    # Update the CLI
                    logger.info("Updating StrongDM CLI...")
                    update_result = subprocess.run(
                        [sdm_cmd, "update"],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )

                    if update_result.returncode == 0:
                        logger.info("StrongDM CLI updated successfully")
                    else:
                        logger.info("StrongDM CLI is already up to date")
                    break
            except FileNotFoundError:
                continue

        if not cli_found:
            logger.info("StrongDM CLI not found. Install from: https://www.strongdm.com/docs/admin-ui/install-sdm-cli")

    except subprocess.TimeoutExpired:
        logger.warning("CLI update check timed out")
    except Exception as e:
        logger.warning(f"Could not check for CLI updates: {e}")

class StrongDMManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 StrongDM Resource Manager")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f8f9fa')  # Modern light background
        
        # Set app icon and styling
        self.setup_styling()
        
        self.client = None
        self.authenticated = False
        
        self.tags = []
        self.secret_stores = []
        self.proxy_clusters = []
        self.identity_sets = []
        self.certificate_authorities = []
        self.ssh_key_types = ["RSA-2048", "RSA-4096", "ECDSA-256", "ECDSA-384", "ECDSA-521", "ED25519"]  # fallback
        self.current_row = 6  # Initialize current_row for form management
        
        # Credential storage
        self.config_dir = Path.home() / ".strongdm_manager"
        self.config_file = self.config_dir / "config.json"
        
        # API logging
        self.api_log_buffer = io.StringIO()
        self.api_logging_enabled = tk.BooleanVar(value=True)  # Initialize here
        self.api_logger = self.setup_api_logging()
        
        self.setup_ui()
        self.load_saved_credentials()
        
    def setup_styling(self):
        """Setup modern styling for the application"""
        style = ttk.Style()
        
        # Configure modern theme
        style.theme_use('clam')
        
        # Modern professional color palette - store as instance variables
        self.primary_color = '#2563eb'      # Modern blue
        self.secondary_color = '#64748b'    # Slate gray
        self.success_color = '#059669'      # Emerald green
        self.warning_color = '#d97706'      # Amber
        self.danger_color = '#dc2626'       # Red
        self.bg_color = '#ffffff'           # Pure white background
        self.card_bg = '#f8fafc'            # Very light gray for cards
        self.text_color = '#0f172a'         # Almost black for text
        self.text_muted = '#64748b'         # Muted text
        self.border_color = '#e2e8f0'       # Light border
        
        # Keep local variables for style configuration
        primary_color = self.primary_color
        secondary_color = self.secondary_color
        success_color = self.success_color
        warning_color = self.warning_color
        danger_color = self.danger_color
        bg_color = self.bg_color
        card_bg = self.card_bg
        text_color = self.text_color
        text_muted = self.text_muted
        border_color = self.border_color
        
        # Configure notebook (tabs) - simple blue, no animations
        style.configure('TNotebook', background=bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', 
                       background='#e5e7eb',  # Light gray for inactive
                       foreground=text_color,
                       padding=[20, 10],
                       font=('Segoe UI', 10, 'normal'),
                       borderwidth=0,
                       relief='flat',
                       focuscolor='none')
        # ONLY color changes, NO other effects
        style.map('TNotebook.Tab',
                 background=[('selected', primary_color)],
                 foreground=[('selected', 'white')],
                 padding=[('selected', [20, 10])],  # Keep same padding
                 borderwidth=[('selected', 0)],     # Keep same border
                 relief=[('selected', 'flat')])     # Keep flat relief
        
        # Configure frames - clean, minimal borders
        style.configure('TLabelframe', 
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'normal'),
                       borderwidth=1,
                       relief='flat')
        style.configure('TLabelframe.Label', 
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'normal'))
        
        # Configure buttons
        # Modern buttons with rounded corners and shadow effect
        style.configure('Primary.TButton',
                       background=primary_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Primary.TButton',
                 background=[('active', '#1d4ed8'), ('pressed', '#1e40af')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        style.configure('Success.TButton',
                       background=success_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Success.TButton',
                 background=[('active', '#10b981'), ('pressed', '#047857')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        style.configure('Danger.TButton',
                       background=danger_color,
                       foreground='white',
                       font=('Segoe UI', 10, 'bold'),
                       padding=[25, 12],
                       borderwidth=2,
                       relief='raised',
                       focuscolor='none')
        style.map('Danger.TButton',
                 background=[('active', '#ef4444'), ('pressed', '#b91c1c')],
                 relief=[('pressed', 'sunken'), ('active', 'raised')])
        
        # Configure entry fields - no highlighting or contrasts
        style.configure('TEntry',
                       fieldbackground='white',
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 9, 'bold'))
        # Remove all focus and selection highlighting
        style.map('TEntry',
                 fieldbackground=[('focus', 'white'), ('!focus', 'white')],
                 selectbackground=[('focus', 'white')],
                 selectforeground=[('focus', 'black')])
        
        # Configure comboboxes
        style.configure('TCombobox',
                       fieldbackground='white',
                       borderwidth=1,
                       relief='flat',
                       font=('Segoe UI', 9, 'bold'))
        # Remove combobox highlighting
        style.map('TCombobox',
                 fieldbackground=[('focus', 'white'), ('!focus', 'white')],
                 selectbackground=[('focus', 'white')],
                 selectforeground=[('focus', 'black')])
        
        # Configure labels - bold text, bigger icons
        style.configure('Heading.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 18, 'bold'))  # Bigger heading
        
        style.configure('Info.TLabel',
                       background=bg_color,
                       foreground=text_muted,
                       font=('Segoe UI', 10, 'bold'))  # Bold info text
        
        # Required field label style - bold 
        style.configure('Required.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 10, 'bold'))  # Bold labels
        
        # Instruction style - bold
        style.configure('Instruction.TLabel',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 12, 'bold'))  # Bold instructions, bigger
        
        # Configure checkboxes
        style.configure('TCheckbutton',
                       background=bg_color,
                       foreground=text_color,
                       font=('Segoe UI', 9, 'normal'))
    def create_required_label(self, parent, text, row, column=0):
        """Create a label with red asterisk for required fields"""
        # Remove asterisk from text if present
        base_text = text.replace('*:', ':').replace('*', '')
        
        # Create frame for label and asterisk
        label_frame = ttk.Frame(parent)
        label_frame.grid(row=row, column=column, sticky="w", padx=5, pady=2)
        
        # Main label text
        ttk.Label(label_frame, text=base_text, style='Required.TLabel').pack(side="left")
        
        # Red asterisk
        ttk.Label(label_frame, text="*", foreground=self.danger_color, 
                 background=self.bg_color, font=('Segoe UI', 10, 'bold')).pack(side="left")
        
        return label_frame
                       
    def setup_api_logging(self):
        """Setup API request/response logging"""
        # Create a separate logger for API calls
        api_logger = logging.getLogger('strongdm_api')
        api_logger.setLevel(logging.DEBUG)
        
        # Create handler that writes to our buffer
        handler = logging.StreamHandler(self.api_log_buffer)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        api_logger.addHandler(handler)
        
        return api_logger
        
    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        
        self.setup_login_tab()
        
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
    def setup_login_tab(self):
        self.login_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.login_frame, text="🔑 Login")
        
        # Main login container with padding
        login_container = ttk.Frame(self.login_frame)
        login_container.pack(expand=True, fill="both", padx=40, pady=30)
        
        # Header with icon and title
        header_frame = ttk.Frame(login_container)
        header_frame.pack(fill="x", pady=(0, 30))
        
        ttk.Label(header_frame, text="🔐 StrongDM API Credentials", 
                 style="Heading.TLabel").pack()
        ttk.Label(header_frame, text="Enter your API credentials to connect", 
                 style="Info.TLabel").pack(pady=(5, 0))
        
        # Credentials frame
        cred_frame = ttk.LabelFrame(login_container, text="API Credentials", padding=20)
        cred_frame.pack(fill="x", pady=(0, 20))
        
        # Access Key
        ttk.Label(cred_frame, text="🔑 API Access Key:", font=('Segoe UI', 9, 'bold')).pack(anchor="w", pady=(0, 5))
        self.access_key_var = tk.StringVar()
        access_entry = ttk.Entry(cred_frame, textvariable=self.access_key_var, 
                               width=60, show="*", font=('Consolas', 9))
        access_entry.pack(fill="x", pady=(0, 15))
        
        # Secret Key
        ttk.Label(cred_frame, text="🔐 API Secret Key:", font=('Segoe UI', 9, 'bold')).pack(anchor="w", pady=(0, 5))
        self.secret_key_var = tk.StringVar()
        secret_entry = ttk.Entry(cred_frame, textvariable=self.secret_key_var, 
                               width=60, show="*", font=('Consolas', 9))
        secret_entry.pack(fill="x", pady=(0, 15))
        
        # Save credentials option
        self.save_credentials_var = tk.BooleanVar()
        ttk.Checkbutton(cred_frame, text="💾 Save credentials (stored locally)", 
                       variable=self.save_credentials_var).pack(anchor="w")
        
        # Button frame
        button_frame = ttk.Frame(login_container)
        button_frame.pack(fill="x", pady=20)

        # Store connect button reference so we can update it after login
        self.connect_button = ttk.Button(button_frame, text="🚀 Connect", style="Success.TButton",
                  command=self.authenticate)
        self.connect_button.pack(side="left", padx=(0, 10))

        # Store logout button reference so we can show/hide it
        self.logout_button = ttk.Button(button_frame, text="🔓 Logout / Reset Connection", style="Danger.TButton",
                  command=self.logout_and_reset)
        self.logout_button.pack(side="left", padx=(10, 0))
        self.logout_button.pack_forget()  # Hide initially
        
        # Status with better styling
        status_frame = ttk.Frame(login_container)
        status_frame.pack(fill="x", pady=(20, 0))
        
        self.status_label = ttk.Label(status_frame, text="", 
                                     font=('Segoe UI', 9, 'bold'))
        self.status_label.pack()
        
        # Resource list frame (hidden initially)
        self.resource_list_frame = ttk.LabelFrame(login_container, text="📋 Resources", padding=10)
        
        # Create scrollable resource list
        resource_scroll_frame = ttk.Frame(self.resource_list_frame)
        resource_scroll_frame.pack(fill="both", expand=True)

        # Resource list with scrollbar - wrap=none for no horizontal wrapping
        self.resource_text = tk.Text(resource_scroll_frame, height=12, wrap=tk.NONE,
                                   font=('Consolas', 9), bg='#f8f9fa', fg='#212529')
        resource_scrollbar = ttk.Scrollbar(resource_scroll_frame, orient="vertical",
                                         command=self.resource_text.yview)
        self.resource_text.configure(yscrollcommand=resource_scrollbar.set)

        self.resource_text.pack(side="left", fill="both", expand=True)
        resource_scrollbar.pack(side="right", fill="y")
        
    def authenticate(self):
        try:
            access_key = self.access_key_var.get().strip()
            secret_key = self.secret_key_var.get().strip()
            
            if not access_key or not secret_key:
                self.status_label.config(text="Please enter both access key and secret key")
                return
                
            self.client = strongdm.Client(access_key, secret_key)
            
            # Test connection by listing resources
            resources = list(self.client.resources.list(""))
            
            self.authenticated = True
            self.status_label.config(text=f"Connected successfully! Found {len(resources)} resources.",
                                   foreground="green")

            # Update Connect button to show Connected state
            self.connect_button.config(text="✓ Connected", state="disabled")

            # Show logout button
            self.logout_button.pack(side="left", padx=(10, 0))

            # Show and populate resource list
            self.resource_list_frame.pack(fill="both", expand=True, pady=(10, 0))
            self.display_resources(resources)
            
            # Save credentials if requested
            if self.save_credentials_var.get():
                self.save_credentials()
            
            # Load tenant data and setup tabs
            self.load_tenant_data()
            
            # Reset tabs to ensure clean recreation
            self.reset_tabs()
            self.setup_main_tabs()
            
        except Exception as e:
            self.status_label.config(text=f"Authentication failed: {str(e)}", 
                                   foreground="red")
            logger.error(f"Authentication error: {e}")
            
    def display_resources(self, resources):
        """Display resources in a simplified table with health status"""
        self.resource_text.config(state=tk.NORMAL)
        self.resource_text.delete(1.0, tk.END)

        # Configure text tags for colored status indicators
        self.resource_text.tag_config("healthy", foreground="green")
        self.resource_text.tag_config("unhealthy", foreground="red")
        self.resource_text.tag_config("unknown", foreground="gray")

        if not resources:
            self.resource_text.insert(tk.END, "No resources found in this tenant.\n")
            self.resource_text.config(state=tk.DISABLED)
            return

        # Fetch health check data
        try:
            health_checks = list(self.client.health_checks.list(''))
            # Build health map by resource_id
            health_map = {}
            for hc in health_checks:
                resource_id = getattr(hc, 'resource_id', None)
                healthy = getattr(hc, 'healthy', False)
                if resource_id:
                    # If any node reports healthy, mark resource as healthy
                    if resource_id not in health_map or healthy:
                        health_map[resource_id] = healthy
        except Exception as e:
            logger.warning(f"Could not fetch health checks: {e}")
            health_map = {}

        # Header
        header = f"   {'Name':<40} {'Type':<15} {'Hostname':<35} {'Port':<6}\n"
        header += "   " + "=" * 96 + "\n"
        self.resource_text.insert(tk.END, header)

        for i, resource in enumerate(resources, 1):
            try:
                # Get resource ID
                resource_id = getattr(resource, 'id', None)

                # Determine health status
                if resource_id in health_map:
                    is_healthy = health_map[resource_id]
                    status_symbol = "✓" if is_healthy else "✗"
                    status_tag = "healthy" if is_healthy else "unhealthy"
                else:
                    status_symbol = "?"
                    status_tag = "unknown"

                # Get basic info
                name = getattr(resource, 'name', 'Unknown')[:39]
                resource_type = type(resource).__name__[:14]
                hostname = getattr(resource, 'hostname', 'N/A')[:34]
                port = str(getattr(resource, 'port', 'N/A'))[:5]

                # Insert status indicator with color
                self.resource_text.insert(tk.END, " ")
                self.resource_text.insert(tk.END, status_symbol, status_tag)
                self.resource_text.insert(tk.END, " ")

                # Insert resource data
                line = f"{name:<40} {resource_type:<15} {hostname:<35} {port:<6}\n"
                self.resource_text.insert(tk.END, line)

            except Exception as e:
                # Fallback for any resource that fails to parse
                self.resource_text.insert(tk.END, f" ? Resource {i}: Error parsing - {str(e)[:70]}...\n")

        # Summary at the bottom
        self.resource_text.insert(tk.END, f"\n   {'-' * 96}\n")

        # Count resource types and health status
        type_counts = {}
        healthy_count = 0
        unhealthy_count = 0
        unknown_count = 0

        for resource in resources:
            resource_type = type(resource).__name__
            type_counts[resource_type] = type_counts.get(resource_type, 0) + 1

            resource_id = getattr(resource, 'id', None)
            if resource_id in health_map:
                if health_map[resource_id]:
                    healthy_count += 1
                else:
                    unhealthy_count += 1
            else:
                unknown_count += 1

        # Resource type summary
        self.resource_text.insert(tk.END, "   Resource Types: ")
        summary_parts = [f"{count} {rtype}" for rtype, count in sorted(type_counts.items())]
        self.resource_text.insert(tk.END, ", ".join(summary_parts) + "\n")

        # Health summary
        self.resource_text.insert(tk.END, "   Health Status: ")
        self.resource_text.insert(tk.END, f"{healthy_count} healthy", "healthy")
        self.resource_text.insert(tk.END, ", ")
        self.resource_text.insert(tk.END, f"{unhealthy_count} unhealthy", "unhealthy")
        self.resource_text.insert(tk.END, ", ")
        self.resource_text.insert(tk.END, f"{unknown_count} unknown\n", "unknown")

        # Make the text read-only
        self.resource_text.config(state=tk.DISABLED)
            
    def load_tenant_data(self):
        """Load tags, secret stores, and proxy clusters from tenant"""
        try:
            # Load tags from existing resources
            self.tags = set()  # Use set to avoid duplicates
            try:
                # Get tags from existing resources
                resources = list(self.client.resources.list(""))
                self.log_api_call("LIST", "/resources", None, f"Found {len(resources)} resources")
                logger.info(f"Found {len(resources)} resources to scan for tags")
                
                for resource in resources:
                    # Log each resource details for debugging
                    self.log_api_call("RESOURCE_DETAIL", f"/resources/{getattr(resource, 'id', 'unknown')}", 
                                    None, resource)
                    
                    if hasattr(resource, 'tags') and resource.tags:
                        logger.info(f"Resource {getattr(resource, 'name', 'unknown')} has tags: {resource.tags}")
                        # Create key:value pairs for meaningful tags
                        for tag_key, tag_value in resource.tags.items():
                            if tag_value:
                                # Create key=value format to match GUI format
                                tag_pair = f"{tag_key}={tag_value}"
                                self.tags.add(tag_pair)
                            else:
                                # If no value, just add the key
                                self.tags.add(tag_key)
                
                # Convert to sorted list - DON'T add defaults, only show real tenant tags
                self.tags = sorted(list(self.tags))
                logger.info(f"Extracted tags: {self.tags}")
                
                if not self.tags:
                    logger.info("No tags found in resources - will show empty dropdown")
                    self.tags = []  # Empty list, no dummy values
                    
            except Exception as e:
                logger.error(f"Error loading tags from resources: {e}")
                self.tags = []  # Empty on error, no dummy values
                
            # Load secret stores (including Strong Vault)
            self.secret_stores = ["Strong Vault", "None"]
            try:
                secret_stores_response = self.client.secret_stores.list("")
                for store in secret_stores_response:
                    # Avoid duplicates and put Strong Vault first
                    if store.name not in self.secret_stores:
                        self.secret_stores.append(store.name)
            except:
                self.secret_stores = ["Strong Vault", "None", "AWS Secrets Manager", "HashiCorp Vault"]
                
            # Load proxy clusters
            self.proxy_clusters = ["None (Use Gateway)"]
            try:
                clusters_response = self.client.proxy_clusters.list("")
                clusters_found = False
                for cluster in clusters_response:
                    self.proxy_clusters.append(cluster.name)
                    clusters_found = True
                if not clusters_found:
                    logger.info("No proxy clusters found, defaulting to Gateway only")
            except Exception as e:
                logger.info(f"Could not load proxy clusters: {e}, defaulting to Gateway only")
                # Keep default: ["None (Use Gateway)"]
                
            # Load identity sets for RDP Certificate authentication
            self.identity_sets = []
            try:
                identity_sets_response = self.client.identity_sets.list("")
                for identity_set in identity_sets_response:
                    self.identity_sets.append({
                        'id': identity_set.id,
                        'name': getattr(identity_set, 'name', identity_set.id)
                    })
                logger.info(f"Loaded {len(self.identity_sets)} identity sets")
            except Exception as e:
                logger.error(f"Error loading identity sets: {e}")
                self.identity_sets = []
                
            # Load certificate authorities for RDP Certificate authentication
            self.certificate_authorities = []
            try:
                # Try different possible API endpoints for certificate authorities
                possible_endpoints = ['certificate_authorities', 'certificate_authority', 'ca']
                for endpoint_name in possible_endpoints:
                    if hasattr(self.client, endpoint_name):
                        endpoint = getattr(self.client, endpoint_name)
                        ca_response = endpoint.list("")
                        for ca in ca_response:
                            self.certificate_authorities.append({
                                'id': ca.id,
                                'name': getattr(ca, 'name', ca.id)
                            })
                        logger.info(f"Loaded {len(self.certificate_authorities)} certificate authorities via {endpoint_name}")
                        break
                else:
                    logger.warning("No certificate authorities endpoint found in API")
            except Exception as e:
                logger.error(f"Error loading certificate authorities: {e}")
                self.certificate_authorities = []
            
            # Load SSH key types from API
            try:
                self.load_ssh_key_types()
            except Exception as e:
                logger.error(f"Error loading SSH key types: {e}")
                # Keep fallback values
                
        except Exception as e:
            logger.error(f"Error loading tenant data: {e}")
            # Set fallback values - only real data
            self.tags = []  # Empty, no dummy values
            self.secret_stores = ["Strong Vault", "None"]
            self.proxy_clusters = ["None (Use Gateway)"]
            
    def load_ssh_key_types(self):
        """Load SSH key types from StrongDM API"""
        try:
            # Try to get key types from a test SSH certificate resource creation
            # This will help us understand what key types are supported
            test_cert = strongdm.SSHCert()
            
            # Check if there's a key_type attribute and what values it accepts
            if hasattr(test_cert, 'key_type'):
                # Try different key types to see which ones are valid
                valid_key_types = []
                test_key_types = [
                    "rsa-2048", "rsa-4096", 
                    "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
                    "ed25519",
                    "RSA-2048", "RSA-4096",
                    "ECDSA-256", "ECDSA-384", "ECDSA-521",
                    "ED25519"
                ]
                
                for key_type in test_key_types:
                    try:
                        test_cert.key_type = key_type
                        # If no error, it's a valid key type
                        valid_key_types.append(key_type)
                    except:
                        continue
                
                if valid_key_types:
                    # Filter to only lowercase/hyphenated format which actually works with the API
                    # Based on error "invalid Key Type RSA-2048", we need lowercase format
                    lowercase_types = [kt for kt in valid_key_types if not kt.isupper() or kt == "ED25519"]
                    if lowercase_types:
                        # Remove duplicates and prefer the working format
                        unique_types = []
                        seen = set()
                        for kt in lowercase_types:
                            # Normalize to avoid duplicates (e.g., "ed25519" and "ED25519")
                            normalized = kt.lower()
                            if normalized not in seen:
                                seen.add(normalized)
                                unique_types.append(kt)
                        self.ssh_key_types = unique_types
                    else:
                        self.ssh_key_types = ["rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519"]
                    logger.info(f"Loaded SSH key types: {self.ssh_key_types}")
                else:
                    logger.info("Using fallback SSH key types")
            else:
                logger.info("SSHCert has no key_type attribute, using fallback key types")
                
        except Exception as e:
            logger.error(f"Error testing SSH key types: {e}")
            # Keep fallback values
            
    def setup_main_tabs(self):
        """Setup main application tabs after authentication"""
        
        # Check if tabs already exist to prevent duplicates
        if hasattr(self, 'main_tabs_created'):
            logger.info("Main tabs already created, skipping recreation")
            return
            
        logger.info("Creating main application tabs...")
            
        # Monitoring Dashboard Tab - moved after login
        try:
            self.monitoring_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.monitoring_frame, text="📊 Monitoring")
            self.setup_monitoring_tab()
            logger.info("Monitoring tab created successfully")
        except Exception as e:
            logger.error(f"Failed to create monitoring tab: {e}")
            # Create a simple monitoring tab as fallback
            self.monitoring_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.monitoring_frame, text="📊 Monitoring")
            ttk.Label(self.monitoring_frame, text=f"Monitoring tab error: {str(e)}").pack(pady=20)

        # Single Resource Tab
        self.single_resource_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.single_resource_frame, text="➕ Add Resource")
        self.setup_single_resource_tab()

        # CSV Bulk Import Tab
        self.csv_import_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.csv_import_frame, text="📥 Bulk Import")
        self.setup_csv_import_tab()

        # CSV Bulk Export Tab
        self.csv_export_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.csv_export_frame, text="📤 Bulk Export")
        self.setup_csv_export_tab()

        # Secrets Tab - moved after Bulk Import/Export
        try:
            self.secrets_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.secrets_frame, text="🔐 Secrets")
            self.setup_secrets_tab()
            logger.info("Secrets tab created successfully")
        except Exception as e:
            logger.error(f"Failed to create secrets tab: {e}")
            # Create a simple secrets tab as fallback
            self.secrets_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.secrets_frame, text="🔐 Secrets")
            ttk.Label(self.secrets_frame, text=f"Secrets tab error: {str(e)}").pack(pady=20)

        # Versions Tab - new
        try:
            self.versions_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.versions_frame, text="📦 Versions")
            self.setup_versions_tab()
            logger.info("Versions tab created successfully")
        except Exception as e:
            logger.error(f"Failed to create versions tab: {e}")
            # Create a simple versions tab as fallback
            self.versions_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.versions_frame, text="📦 Versions")
            ttk.Label(self.versions_frame, text=f"Versions tab error: {str(e)}").pack(pady=20)

        # Debug Tab
        try:
            self.debug_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.debug_frame, text="🔧 Debug")
            self.setup_debug_tab()
            logger.info("Debug tab created successfully")
        except Exception as e:
            logger.error(f"Failed to create debug tab: {e}")
            # Create a simple debug tab as fallback
            self.debug_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.debug_frame, text="🔧 Debug")
            ttk.Label(self.debug_frame, text=f"Debug tab error: {str(e)}").pack(pady=20)

        # API Logs Tab
        self.api_logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.api_logs_frame, text="📡 API Logs")
        self.setup_api_logs_tab()
        
        # Mark tabs as created
        self.main_tabs_created = True
        logger.info("All main tabs created successfully")
        
    def reset_tabs(self):
        """Reset tabs to allow recreation"""
        if hasattr(self, 'main_tabs_created'):
            delattr(self, 'main_tabs_created')
        
        # Remove existing tabs (except login)
        for i in range(self.notebook.index("end") - 1, 0, -1):  # Reverse order to avoid index issues
            try:
                self.notebook.forget(i)
            except:
                pass
        
        logger.info("Tabs reset for recreation")
        
    def setup_single_resource_tab(self):
        """Setup single resource creation tab with scrollable content"""
        
        # Create scrollable canvas for the tab content - full width scaling
        main_canvas = tk.Canvas(self.single_resource_frame)
        main_scrollbar = ttk.Scrollbar(self.single_resource_frame, orient="vertical", command=main_canvas.yview)
        self.scrollable_frame = ttk.Frame(main_canvas)
        
        # Bind both configure events for proper scaling in both dimensions
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        main_canvas.bind(
            "<Configure>",
            lambda e: main_canvas.itemconfig(canvas_window, width=e.width)
        )
        
        canvas_window = main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True)
        main_scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas for scrolling
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)  # Windows
        main_canvas.bind_all("<Button-4>", lambda e: main_canvas.yview_scroll(-1, "units"))  # Linux
        main_canvas.bind_all("<Button-5>", lambda e: main_canvas.yview_scroll(1, "units"))  # Linux
        
        # Resource type selection (now on scrollable frame)
        type_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Type")
        type_frame.pack(fill="x", padx=10, pady=5)
        
        self.resource_type_var = tk.StringVar(value="SSH")
        ttk.Radiobutton(type_frame, text="SSH", variable=self.resource_type_var, 
                       value="SSH", command=self.update_resource_form).pack(side="left")
        ttk.Radiobutton(type_frame, text="RDP", variable=self.resource_type_var, 
                       value="RDP", command=self.update_resource_form).pack(side="left")
        ttk.Radiobutton(type_frame, text="Database", variable=self.resource_type_var, 
                       value="Database", command=self.update_resource_form).pack(side="left")
        
        # Resource subtype selection
        self.subtype_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Subtype")
        self.subtype_frame.pack(fill="x", padx=5, pady=5)
        
        # Resource form frame - scale with window
        self.resource_form_frame = ttk.LabelFrame(self.scrollable_frame, text="Resource Details", padding=10)
        self.resource_form_frame.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Configure grid weights for the resource form frame - allow full expansion
        self.resource_form_frame.grid_columnconfigure(0, weight=0)  # Labels column
        self.resource_form_frame.grid_columnconfigure(1, weight=1)  # Input fields expand
        self.resource_form_frame.grid_columnconfigure(2, weight=0)  # Buttons column
        
        self.update_resource_form()
        
    def update_resource_form(self):
        """Update the resource form based on selected type"""
        # Clear existing forms AND any existing button frames
        for widget in self.subtype_frame.winfo_children():
            widget.destroy()
        for widget in self.resource_form_frame.winfo_children():
            widget.destroy()
        
        # Clear any existing button frames from scrollable_frame
        if hasattr(self, 'button_frame') and self.button_frame.winfo_exists():
            self.button_frame.destroy()
            
        resource_type = self.resource_type_var.get()
        
        # Setup subtypes based on main type
        self.setup_subtypes(resource_type)
        
        # Common fields
        self.create_common_fields()
        
        # Type-specific fields based on subtype
        self.create_type_specific_fields()
            
        # Action buttons - pinned to bottom like debug tab
        self.button_frame = ttk.Frame(self.scrollable_frame)
        self.button_frame.pack(fill="x", padx=10, pady=10, side="bottom")
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Button(self.button_frame, text="🔄 Clear Form", 
                  command=self.update_resource_form).grid(row=0, column=0, padx=5, sticky="ew")
        ttk.Button(self.button_frame, text="✅ Create Resource", style="Success.TButton",
                  command=self.create_single_resource).grid(row=0, column=1, padx=5, sticky="ew")
    
    def on_credential_type_change(self, event=None):
        """Handle credential type change for SSH Certificate"""
        if not hasattr(self, 'ssh_cert_fields'):
            return
            
        credential_type = self.credential_type_var.get()
        
        if credential_type == "Username":
            # Show username fields, hide identity set fields
            self.ssh_cert_fields['username_label'].grid()
            self.ssh_cert_fields['username_entry'].grid()
            self.ssh_cert_fields['identity_label'].grid_remove()
            self.ssh_cert_fields['identity_combo'].grid_remove()
        else:  # Identity Alias
            # Hide username fields, show identity set fields
            self.ssh_cert_fields['username_label'].grid_remove()
            self.ssh_cert_fields['username_entry'].grid_remove()
            self.ssh_cert_fields['identity_label'].grid(row=self.current_row-1, column=0, sticky="w", padx=5, pady=2)
            self.ssh_cert_fields['identity_combo'].grid(row=self.current_row-1, column=1, padx=5, pady=2, sticky="ew")
    
    def on_rdp_credential_type_change(self, event=None):
        """Handle RDP credential type change for Certificate authentication"""
        if not hasattr(self, 'rdp_cert_fields'):
            return
            
        credential_type = self.rdp_credential_type_var.get()
        
        if credential_type == "Leased Credential":
            # Show username fields, hide identity set fields  
            self.rdp_cert_fields['username_label'].grid()
            self.rdp_cert_fields['username_entry'].grid()
            
            # Hide identity alias fields
            self.rdp_cert_fields['identity_label'].grid_remove()
            self.rdp_cert_fields['identity_combo'].grid_remove()
            self.rdp_cert_fields['healthcheck_info'].grid_remove()
            self.rdp_cert_fields['service_account_label'].grid_remove()
            self.rdp_cert_fields['service_account_entry'].grid_remove()
                
        else:  # Identity Alias
            # Hide username fields
            self.rdp_cert_fields['username_label'].grid_remove()
            self.rdp_cert_fields['username_entry'].grid_remove()
            
            # Show identity set field and AD Service Account fields
            # Use a base row that accounts for all RDP Certificate fields properly
            base_row = 9  # Fixed position after CA field (row 8) + 1
            
            # Identity Set
            self.rdp_cert_fields['identity_label'].grid(row=base_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_cert_fields['identity_combo'].grid(row=base_row, column=1, padx=5, pady=2, sticky="ew")
            self.rdp_cert_fields['healthcheck_info'].grid(row=base_row, column=2, sticky="w", padx=(5, 0), pady=2)
            
            # AD Service Account
            self.rdp_cert_fields['service_account_label'].grid(row=base_row+1, column=0, sticky="w", padx=5, pady=2)
            self.rdp_cert_fields['service_account_entry'].grid(row=base_row+1, column=1, padx=5, pady=2, sticky="ew")
                  
    def setup_subtypes(self, resource_type):
        """Setup subtype selection based on main resource type"""
        if resource_type == "SSH":
            self.subtype_var = tk.StringVar(value="Password")
            ttk.Radiobutton(self.subtype_frame, text="🔐 Password", variable=self.subtype_var, 
                           value="Password", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="🔑 Public Key", variable=self.subtype_var, 
                           value="PublicKey", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="📜 Certificate", variable=self.subtype_var, 
                           value="Certificate", command=self.create_type_specific_fields).pack(side="left", padx=5)
        elif resource_type == "RDP":
            self.subtype_var = tk.StringVar(value="Basic")
            ttk.Radiobutton(self.subtype_frame, text="🔐 Basic Auth", variable=self.subtype_var, 
                           value="Basic", command=self.create_type_specific_fields).pack(side="left", padx=5)
            ttk.Radiobutton(self.subtype_frame, text="📜 Certificate", variable=self.subtype_var, 
                           value="Certificate", command=self.create_type_specific_fields).pack(side="left", padx=5)
        elif resource_type == "Database":
            self.subtype_var = tk.StringVar(value="Standard")
            ttk.Label(self.subtype_frame, text="All database types use standard authentication").pack(side="left", padx=10)
        else:
            self.subtype_var = tk.StringVar(value="Standard")
            
    def create_type_specific_fields(self):
        """Create type and subtype specific fields"""
        # Clear existing type-specific fields (keep common fields)
        if hasattr(self, 'current_row') and self.current_row > 6:  # After common fields
            # Remove widgets after row 6 (common fields end at row 5)
            for widget in self.resource_form_frame.grid_slaves():
                info = widget.grid_info()
                if info and int(info['row']) > 5:
                    widget.destroy()
            self.current_row = 6
        
        resource_type = self.resource_type_var.get()
        subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
        
        if resource_type == "SSH":
            self.create_ssh_fields(subtype)
        elif resource_type == "RDP":
            self.create_rdp_fields(subtype)
        elif resource_type == "Database":
            self.create_database_fields()
            
        # Update buttons remain pinned at bottom - no need to re-add
                  
    def create_common_fields(self):
        """Create common fields for all resource types"""
        
        # Resource Name
        self.create_required_label(self.resource_form_frame, "Resource Name:", 0)
        self.name_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.name_var).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        
        # Hostname
        self.create_required_label(self.resource_form_frame, "Hostname:", 1)
        self.hostname_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.hostname_var).grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        
        # Port
        self.create_required_label(self.resource_form_frame, "Port:", 2)
        self.port_var = tk.StringVar()
        
        # Set default port based on resource type
        resource_type = self.resource_type_var.get()
        if resource_type == "SSH":
            self.port_var.set("22")
        elif resource_type == "RDP":
            self.port_var.set("3389")
        elif resource_type == "Database":
            self.port_var.set("3306")  # MySQL default
        
        ttk.Entry(self.resource_form_frame, textvariable=self.port_var).grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        
        # Set initial current_row for type-specific fields
        self.current_row = 3
        
        # For database resources, tags will be added after database-specific fields
        # For other resource types, add tags immediately
        resource_type = self.resource_type_var.get()
        if resource_type != "Database":
            self.add_tags_interface()
        
    def add_tags_interface(self):
        """Add tags interface at current row position"""
        # Tags - Improved Multi-select interface
        ttk.Label(self.resource_form_frame, text="Tags:").grid(row=self.current_row, column=0, sticky="nw", padx=5, pady=2)
        
        # Create main tags container with better styling
        tags_container = ttk.LabelFrame(self.resource_form_frame, text="Tag Selection", padding=10)
        tags_container.grid(row=self.current_row, column=1, columnspan=2, padx=5, pady=2, sticky="ew")
        
        # Existing tags section
        if self.tags:
            existing_frame = ttk.LabelFrame(tags_container, text=f"Available Tags ({len(self.tags)})", padding=5)
            existing_frame.pack(fill="both", expand=True, pady=(0, 10))
            
            # Scrollable tags with better sizing
            tags_canvas = tk.Canvas(existing_frame, height=120, width=450, bg='white', relief='sunken', bd=1)
            tags_scrollbar = ttk.Scrollbar(existing_frame, orient="vertical", command=tags_canvas.yview)
            self.tags_checkbox_frame = ttk.Frame(tags_canvas, padding=5)
            
            self.tags_checkbox_frame.bind(
                "<Configure>",
                lambda e: tags_canvas.configure(scrollregion=tags_canvas.bbox("all"))
            )
            
            tags_canvas.create_window((0, 0), window=self.tags_checkbox_frame, anchor="nw")
            tags_canvas.configure(yscrollcommand=tags_scrollbar.set)
            
            tags_canvas.pack(side="left", fill="both", expand=True)
            tags_scrollbar.pack(side="right", fill="y")
                
            # Create checkboxes with better layout
            self.selected_tags = {}
            cols = 3  # Use 3 columns for better space utilization
            for i, tag in enumerate(self.tags):
                var = tk.BooleanVar()
                self.selected_tags[tag] = var
                # Truncate long tags for display
                display_tag = tag[:35] + "..." if len(tag) > 35 else tag
                ttk.Checkbutton(self.tags_checkbox_frame, text=display_tag, variable=var).grid(
                    row=i//cols, column=i%cols, sticky="w", padx=5, pady=2
                )
        else:
            self.selected_tags = {}
            self.tags_checkbox_frame = ttk.Frame(tags_container)
            ttk.Label(tags_container, text="No existing tags found", style="Info.TLabel").pack(pady=10)
        
        # New tag section with better styling
        new_tag_frame = ttk.LabelFrame(tags_container, text="Add New Tag", padding=5)
        new_tag_frame.pack(fill="x", pady=(5, 0))
        
        entry_frame = ttk.Frame(new_tag_frame)
        entry_frame.pack(fill="x")
        
        ttk.Label(entry_frame, text="Tag (key=value format):").pack(side="left")
        self.new_tag_var = tk.StringVar()
        new_tag_entry = ttk.Entry(entry_frame, textvariable=self.new_tag_var)
        new_tag_entry.pack(side="left", padx=(10, 0), fill="x", expand=True)
        
        # Help text
        help_frame = ttk.Frame(new_tag_frame)
        help_frame.pack(fill="x", pady=(5, 0))
        ttk.Label(help_frame, text="💡 Examples: env=prod, team=devops, region=us-east", 
                 style="Info.TLabel").pack(side="left")
        
        # Update current_row to next position after tags interface
        self.current_row += 1
    
    def get_selected_tags(self):
        """Get all selected tags as a dictionary for resource creation"""
        tags_dict = {}
        
        # Get checked existing tags
        if hasattr(self, 'selected_tags'):
            for tag, var in self.selected_tags.items():
                if var.get():  # If checkbox is checked
                    # Parse tag (assuming format: key=value or key:value or just key)
                    if '=' in tag:
                        key, value = tag.split('=', 1)
                        tags_dict[key.strip()] = value.strip()
                    elif ':' in tag:
                        key, value = tag.split(':', 1)
                        tags_dict[key.strip()] = value.strip()
                    else:
                        tags_dict[tag.strip()] = ""
        
        # Get new tag from entry field
        if hasattr(self, 'new_tag_var') and self.new_tag_var.get().strip():
            new_tag = self.new_tag_var.get().strip()
            if '=' in new_tag:
                key, value = new_tag.split('=', 1)
                tags_dict[key.strip()] = value.strip()
            elif ':' in new_tag:
                key, value = new_tag.split(':', 1)
                tags_dict[key.strip()] = value.strip()
            else:
                tags_dict[new_tag.strip()] = ""
                
        return tags_dict
    
    def refresh_certificate_authorities(self, event=None):
        """Refresh certificate authorities from StrongDM API"""
        if not self.client or not hasattr(self, 'rdp_ca_combo'):
            return
            
        try:
            # Reload certificate authorities from API
            ca_list = []
            try:
                # Try the correct StrongDM SDK endpoint
                possible_endpoints = [
                    'certificate_authorities',  # Primary endpoint
                    'ca_certificates',          # Alternative
                    'certificates'              # Alternative
                ]
                
                for endpoint_name in possible_endpoints:
                    if hasattr(self.client, endpoint_name):
                        try:
                            endpoint = getattr(self.client, endpoint_name)
                            # Try list with filter
                            ca_response = endpoint.list("")
                            for ca in ca_response:
                                ca_list.append({
                                    'id': ca.id,
                                    'name': getattr(ca, 'name', getattr(ca, 'display_name', ca.id))
                                })
                            logger.info(f"Refreshed {len(ca_list)} certificate authorities via {endpoint_name}")
                            break
                        except Exception as endpoint_error:
                            logger.debug(f"Failed to access {endpoint_name}: {endpoint_error}")
                            continue
                
                # If no endpoints work, try direct client inspection
                if not ca_list:
                    # Log available client attributes for debugging
                    client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_') and 'cert' in attr.lower()]
                    logger.debug(f"Available certificate-related client attributes: {client_attrs}")
                    
                    # Also check for CA-related attributes
                    ca_attrs = [attr for attr in dir(self.client) if not attr.startswith('_') and 'ca' in attr.lower()]
                    logger.debug(f"Available CA-related client attributes: {ca_attrs}")
                    
                    logger.warning("No certificate authorities endpoint found during refresh")
                    
            except Exception as e:
                logger.error(f"Error refreshing certificate authorities: {e}")
            
            # Update dropdown values
            ca_values = []
            ca_id_map = {}
            
            if ca_list:
                for ca in ca_list:
                    display_name = ca['name']
                    ca_values.append(display_name)
                    ca_id_map[display_name] = ca['id']
            else:
                # Default to Strong CA if no CAs found via API
                ca_values = ["Strong CA"]
                ca_id_map["Strong CA"] = "strong-ca"
                logger.info("Using default certificate authority (Strong CA)")
            
            # Update combobox
            self.rdp_ca_combo['values'] = ca_values
            
            # Store the updated ID mapping
            self.rdp_ca_id_map = ca_id_map
            
            # Set default if nothing selected
            if not self.rdp_certificate_authority_var.get() and ca_values:
                self.rdp_ca_combo.set(ca_values[0])
            
        except Exception as e:
            logger.error(f"Error in refresh_certificate_authorities: {e}")
        
        # Secret Store
        ttk.Label(self.resource_form_frame, text="Secret Store:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.secret_store_var = tk.StringVar(value="Strong Vault")
        secret_store_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.secret_store_var, 
                                         values=self.secret_stores, width=37)
        secret_store_combo.grid(row=4, column=1, padx=5, pady=2, sticky="ew")
        
        # Proxy Cluster
        ttk.Label(self.resource_form_frame, text="Proxy Cluster:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.proxy_cluster_var = tk.StringVar(value="None (Use Gateway)")
        proxy_cluster_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.proxy_cluster_var, 
                                          values=self.proxy_clusters, width=37)
        proxy_cluster_combo.grid(row=5, column=1, padx=5, pady=2, sticky="ew")
        
        self.current_row = 6
        
    def create_ssh_fields(self, subtype="Password"):
        """Create SSH-specific fields based on subtype"""
        
        # Username (not needed for Certificate - it has its own credential handling)
        if subtype != "Certificate":
            ttk.Label(self.resource_form_frame, text="Username*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.username_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
        
        if subtype == "Password":
            # Password authentication
            ttk.Label(self.resource_form_frame, text="Password*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.password_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                     show="*").grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
        elif subtype == "PublicKey":
            # Public key authentication - key pair is auto-generated
            ttk.Label(self.resource_form_frame, text="🔑 SSH Key Pair:", 
                     style="Info.TLabel").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            ttk.Label(self.resource_form_frame, text="Will be auto-generated by StrongDM", 
                     style="Info.TLabel").grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
            self.current_row += 1
            
        elif subtype == "Certificate":
            # Certificate-based authentication
            
            # Key Type dropdown
            ttk.Label(self.resource_form_frame, text="Key Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.key_type_var = tk.StringVar(value=self.ssh_key_types[0] if self.ssh_key_types else "RSA-2048")
            key_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.key_type_var, 
                                         values=self.ssh_key_types, width=37, state="readonly")
            key_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Credential type selection
            ttk.Label(self.resource_form_frame, text="Credential Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.credential_type_var = tk.StringVar(value="Username")
            credential_types = ["Username", "Identity Alias"]
            credential_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.credential_type_var, 
                                               values=credential_types, width=37, state="readonly")
            credential_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            credential_type_combo.bind("<<ComboboxSelected>>", self.on_credential_type_change)
            self.current_row += 1
            
            # Username field (shown by default)
            self.username_label = ttk.Label(self.resource_form_frame, text="Username*:")
            self.username_label.grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.ssh_cert_username_var = tk.StringVar()
            self.username_entry = ttk.Entry(self.resource_form_frame, textvariable=self.ssh_cert_username_var)
            self.username_entry.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Identity Set dropdown (initially hidden)
            self.identity_label = ttk.Label(self.resource_form_frame, text="Identity Set*:")
            self.identity_set_var = tk.StringVar()
            
            # Create dropdown values from loaded identity sets
            identity_set_values = []
            for identity_set in self.identity_sets:
                display_name = f"{identity_set['name']} ({identity_set['id']})"
                identity_set_values.append(display_name)
            
            if not identity_set_values:
                identity_set_values = ["No identity sets found - check API permissions"]
            
            self.identity_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.identity_set_var, 
                                            values=identity_set_values, state="readonly")
            
            # Store references for toggling visibility
            self.ssh_cert_fields = {
                'username_label': self.username_label,
                'username_entry': self.username_entry,
                'identity_label': self.identity_label,
                'identity_combo': self.identity_combo
            }
        
    def create_rdp_fields(self, subtype="Basic"):
        """Create RDP-specific fields based on subtype"""
        
        if subtype == "Basic":
            # Basic username/password authentication
            # Username
            ttk.Label(self.resource_form_frame, text="Username*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.username_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # Password
            ttk.Label(self.resource_form_frame, text="Password*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.password_var = tk.StringVar()
            ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                     show="*").grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
        elif subtype == "Certificate":
            # Certificate-based authentication
            
            # Credential type selection
            ttk.Label(self.resource_form_frame, text="Credential Type*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_credential_type_var = tk.StringVar(value="Leased Credential")
            credential_types = ["Leased Credential", "Identity Alias"]
            credential_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.rdp_credential_type_var, 
                                               values=credential_types, width=37, state="readonly")
            credential_type_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            credential_type_combo.bind("<<ComboboxSelected>>", self.on_rdp_credential_type_change)
            self.current_row += 1
            
            # Certificate Authority selection
            ttk.Label(self.resource_form_frame, text="Certificate Authority*:").grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_certificate_authority_var = tk.StringVar()
            
            # Create dropdown with refresh capability
            self.rdp_ca_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.rdp_certificate_authority_var, 
                                           width=37, state="readonly")
            self.rdp_ca_combo.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            
            # Bind focus event to refresh CA list
            self.rdp_ca_combo.bind("<Button-1>", self.refresh_certificate_authorities)
            self.rdp_ca_combo.bind("<FocusIn>", self.refresh_certificate_authorities)
            
            # Initial load
            self.refresh_certificate_authorities()
            self.current_row += 1
            
            # Leased Credential fields (shown by default) - Username + SID
            self.rdp_username_label = ttk.Label(self.resource_form_frame, text="Username*:")
            self.rdp_username_label.grid(row=self.current_row, column=0, sticky="w", padx=5, pady=2)
            self.rdp_username_var = tk.StringVar()
            self.rdp_username_entry = ttk.Entry(self.resource_form_frame, textvariable=self.rdp_username_var)
            self.rdp_username_entry.grid(row=self.current_row, column=1, padx=5, pady=2, sticky="ew")
            self.current_row += 1
            
            # SID field removed - not supported by StrongDM Python SDK
            # self.rdp_sid_label = ttk.Label(self.resource_form_frame, text="SID (Optional):")
            # self.rdp_sid_var = tk.StringVar()
            # self.rdp_sid_entry = ttk.Entry(self.resource_form_frame, textvariable=self.rdp_sid_var, )
            
            # Identity Alias fields (initially hidden) - Identity Set dropdown
            self.rdp_identity_label = ttk.Label(self.resource_form_frame, text="Identity Set*:")
            self.identity_set_id_var = tk.StringVar()
            
            # Create dropdown values from loaded identity sets
            identity_set_values = []
            for identity_set in self.identity_sets:
                display_name = f"{identity_set['name']} ({identity_set['id']})"
                identity_set_values.append(display_name)
            
            if not identity_set_values:
                identity_set_values = ["No identity sets found - check API permissions"]
            
            self.rdp_identity_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.identity_set_id_var, 
                                                 values=identity_set_values, state="readonly")
            
            self.rdp_healthcheck_info = ttk.Label(self.resource_form_frame, text="💡 e.g. administrator@domain.local", style="Info.TLabel")
            
            # AD Service Account fields (for Identity Alias)
            self.rdp_service_account_label = ttk.Label(self.resource_form_frame, text="AD Service Account:")
            self.service_account_var = tk.StringVar()
            self.rdp_service_account_entry = ttk.Entry(self.resource_form_frame, textvariable=self.service_account_var)
            
            # AD Service Account SID and Domain Controller fields removed - not supported by StrongDM Python SDK
            # self.rdp_service_account_sid_label = ttk.Label(self.resource_form_frame, text="AD Service Account SID (Optional):")
            # self.service_account_sid_var = tk.StringVar()
            # self.rdp_service_account_sid_entry = ttk.Entry(self.resource_form_frame, textvariable=self.service_account_sid_var, )
            # 
            # self.rdp_domain_controller_label = ttk.Label(self.resource_form_frame, text="Domain Controller Hostnames (Optional):")
            # self.domain_controller_var = tk.StringVar()
            # self.rdp_domain_controller_entry = ttk.Entry(self.resource_form_frame, textvariable=self.domain_controller_var, )
            # 
            # self.rdp_domain_controller_info = ttk.Label(self.resource_form_frame, text="💡 Comma-separated hostnames", style="Info.TLabel")
            
            # Store references for toggling visibility (removed unsupported fields)
            self.rdp_cert_fields = {
                'username_label': self.rdp_username_label,
                'username_entry': self.rdp_username_entry,
                'identity_label': self.rdp_identity_label,
                'identity_combo': self.rdp_identity_combo,
                'service_account_label': self.rdp_service_account_label,
                'service_account_entry': self.rdp_service_account_entry,
                'healthcheck_info': self.rdp_healthcheck_info
            }
        
        # Update current_row to be after the RDP Certificate fields if they exist
        if subtype == "Certificate":
            # Certificate fields end at base_row+1 (service account), so set current_row accordingly
            self.current_row = 11  # base_row (9) + 2 fields (identity, service account)
        
        # Downgrade NLA (only for basic auth) - place before lock required
        if subtype == "Basic":
            self.downgrade_nla_var = tk.BooleanVar()
            ttk.Checkbutton(self.resource_form_frame, text="Downgrade NLA Connections", 
                           variable=self.downgrade_nla_var).grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
            self.current_row += 1
        
        # Common RDP options - Lock Required (always at bottom before buttons)
        self.lock_required_var = tk.BooleanVar()
        ttk.Checkbutton(self.resource_form_frame, text="Resource Lock Required", 
                       variable=self.lock_required_var).grid(row=self.current_row, column=1, sticky="w", padx=5, pady=2)
        self.current_row += 1
        
    def create_database_fields(self):
        """Create database-specific fields"""
        
        # Move Database Type to the top (after hostname/port, at row 3)
        db_type_row = 3
        self.create_required_label(self.resource_form_frame, "Database Type:", db_type_row)
        self.db_type_var = tk.StringVar(value="mysql")
        db_type_combo = ttk.Combobox(self.resource_form_frame, textvariable=self.db_type_var, 
                                    values=["mysql", "postgresql", "mssql", "redis"], width=37, state="readonly")
        db_type_combo.grid(row=db_type_row, column=1, padx=5, pady=2, sticky="ew")
        db_type_combo.bind("<<ComboboxSelected>>", self.update_db_port)
        
        # Username (required for databases)
        username_row = 4
        self.create_required_label(self.resource_form_frame, "Username:", username_row)
        self.username_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.username_var).grid(row=username_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Password (required for databases)
        password_row = 5
        self.create_required_label(self.resource_form_frame, "Password:", password_row)
        self.password_var = tk.StringVar()
        ttk.Entry(self.resource_form_frame, textvariable=self.password_var, 
                 show="*").grid(row=password_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Database Name (optional for some DB types)
        db_name_row = 6
        self.db_name_label = ttk.Label(self.resource_form_frame, text="Database Name:")
        self.db_name_label.grid(row=db_name_row, column=0, sticky="w", padx=5, pady=2)
        self.database_var = tk.StringVar()
        self.db_name_entry = ttk.Entry(self.resource_form_frame, textvariable=self.database_var)
        self.db_name_entry.grid(row=db_name_row, column=1, padx=5, pady=2, sticky="ew")
        
        # Set current_row to continue after database-specific fields
        self.current_row = 7  # Next row after database name
        
        # Add tags interface after database fields
        self.add_tags_interface()
        
        # Initial database type update to set correct port and field requirements
        self.update_db_fields()
        
    def update_db_port(self, event=None):
        """Update port based on database type selection"""
        self.update_db_fields()
        
    def update_db_fields(self):
        """Update port and field requirements based on database type"""
        db_type = self.db_type_var.get()
        
        # Update port based on database type
        port_map = {
            "mysql": "3306",
            "postgresql": "5432", 
            "mssql": "1433",
            "redis": "6379"
        }
        if db_type in port_map:
            self.port_var.set(port_map[db_type])
        
        # Update database name field requirements based on database type
        if hasattr(self, 'db_name_label') and hasattr(self, 'db_name_entry'):
            if db_type == "redis":
                # Redis doesn't typically use database names (uses database numbers)
                self.db_name_label.config(text="Database Number (optional):")
                self.database_var.set("0")  # Default Redis database
            elif db_type == "mssql":
                # MSSQL often requires database name
                self.db_name_label.config(text="Database Name*:")
            else:
                # MySQL and PostgreSQL can be optional
                self.db_name_label.config(text="Database Name:")
        
    def create_single_resource(self):
        """Create a single resource"""
        try:
            resource_type = self.resource_type_var.get()
            subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
            
            # Validate required fields based on type and subtype
            if not self.validate_required_fields(resource_type, subtype):
                return
                
            # Create resource based on type and subtype
            if resource_type == "SSH":
                resource = self.create_ssh_resource(subtype)
            elif resource_type == "RDP":
                resource = self.create_rdp_resource(subtype)
            elif resource_type == "Database":
                resource = self.create_database_resource()
                
            # Debug log the resource object before creation
            if hasattr(self, 'debug_text'):
                from datetime import datetime
                self.debug_text.insert(tk.END, f"[{datetime.now()}] ATTEMPTING RESOURCE CREATION:\n")
                self.debug_text.insert(tk.END, f"  Resource Type: {type(resource).__name__}\n")
                for attr in dir(resource):
                    if not attr.startswith('_') and not callable(getattr(resource, attr)):
                        try:
                            value = getattr(resource, attr)
                            if value:  # Only show non-empty values
                                self.debug_text.insert(tk.END, f"  {attr}: {value}\n")
                        except:
                            pass
                self.debug_text.insert(tk.END, "\n")
                self.debug_text.see(tk.END)
                
            # Add the resource
            self.log_api_call("CREATE", "/resources", resource, None)
            response = self.client.resources.create(resource)
            self.log_api_call("CREATE_RESPONSE", "/resources", None, response)
            success_msg = f"Resource '{self.name_var.get()}' created successfully!"
            messagebox.showinfo("Success", success_msg)
            
            # Don't clear form to allow quick creation of similar resources
            # Only clear the name field to force user to enter a unique name
            self.name_var.set("")
            
        except Exception as e:
            error_msg = f"Failed to create resource: {str(e)}"
            messagebox.showerror("Error", error_msg)
            logger.error(f"Resource creation error: {e}")
            
            # Also log to debug panel if available
            if hasattr(self, 'debug_text'):
                from datetime import datetime
                self.debug_text.insert(tk.END, f"[{datetime.now()}] RESOURCE CREATION ERROR: {str(e)}\n")
                
                # Log the resource details that were attempted
                try:
                    resource_type = self.resource_type_var.get()
                    subtype = getattr(self, 'subtype_var', tk.StringVar()).get()
                    self.debug_text.insert(tk.END, f"  Resource Type: {resource_type}\n")
                    self.debug_text.insert(tk.END, f"  Subtype: {subtype}\n")
                    
                    if resource_type == "RDP" and subtype == "Certificate":
                        credential_type = self.rdp_credential_type_var.get()
                        self.debug_text.insert(tk.END, f"  RDP Credential Type: {credential_type}\n")
                        if credential_type == "Leased Credential":
                            self.debug_text.insert(tk.END, f"  Username: '{self.rdp_username_var.get()}'\n")
                            self.debug_text.insert(tk.END, f"  SID: '{self.rdp_sid_var.get()}'\n")
                        else:
                            self.debug_text.insert(tk.END, f"  Identity Set: '{self.identity_set_id_var.get()}'\n")
                            
                except Exception as debug_e:
                    self.debug_text.insert(tk.END, f"  (Error getting debug details: {debug_e})\n")
                    
                self.debug_text.insert(tk.END, "\n")
                self.debug_text.see(tk.END)
            
    def validate_required_fields(self, resource_type, subtype):
        """Validate required fields based on resource type and subtype"""
        # Common required fields
        if not all([self.name_var.get(), self.hostname_var.get(), self.port_var.get()]):
            messagebox.showerror("Error", "Please fill in Name, Hostname, and Port")
            return False
            
        if resource_type in ["SSH", "RDP"]:
            if resource_type == "SSH":
                if subtype == "Password" and not self.password_var.get():
                    messagebox.showerror("Error", "Password is required for SSH Password authentication")
                    return False
                # PublicKey subtype has no required fields - key pair is auto-generated
                elif subtype == "Certificate":
                    credential_type = self.credential_type_var.get()
                    if credential_type == "Username" and not self.ssh_cert_username_var.get():
                        messagebox.showerror("Error", "Username is required for SSH Certificate authentication")
                        return False
                    elif credential_type == "Identity Alias" and not self.identity_set_var.get():
                        messagebox.showerror("Error", "Identity Set is required for SSH Certificate authentication with Identity Alias")
                        return False
            elif resource_type == "RDP":
                if subtype == "Basic":
                    if not all([self.username_var.get(), self.password_var.get()]):
                        messagebox.showerror("Error", "Username and Password are required for RDP Basic authentication")
                        return False
                elif subtype == "Certificate":
                    credential_type = self.rdp_credential_type_var.get()
                    if credential_type == "Leased Credential" and not self.rdp_username_var.get():
                        messagebox.showerror("Error", "Username is required for RDP Certificate with Leased Credential")
                        return False
                    elif credential_type == "Identity Alias":
                        if not self.identity_set_id_var.get():
                            messagebox.showerror("Error", "Identity Set is required for RDP Certificate with Identity Alias")
                            return False
                        # Check if AD Service Account is provided (recommended for better healthchecks)
                        if not hasattr(self, 'service_account_var') or not self.service_account_var.get().strip():
                            # Show info message but don't block - we have a default
                            logger.info("No AD Service Account specified, using default for healthcheck")
                    # Validate Certificate Authority selection
                    if not self.rdp_certificate_authority_var.get():
                        messagebox.showerror("Error", "Certificate Authority is required for RDP Certificate authentication")
                        return False
        elif resource_type == "Database":
            if not all([self.username_var.get(), self.password_var.get()]):
                messagebox.showerror("Error", "Username and Password are required for Database resources")
                return False
                
        return True
            
    def create_ssh_resource(self, subtype="Password"):
        """Create SSH resource object based on subtype"""
        try:
            # Use specific SSH classes for different authentication types
            if subtype == "Password":
                # SSH with password authentication (SSHPassword class)
                resource = strongdm.SSHPassword(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get(),
                    password=self.password_var.get()
                )
                    
            elif subtype == "PublicKey":
                # SSH with public key authentication - key pair auto-generated by StrongDM
                resource = strongdm.SSH(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get()
                    # public_key will be auto-generated by StrongDM
                )
                    
            elif subtype == "Certificate":
                # SSH with certificate authentication (SSHCert class)
                credential_type = self.credential_type_var.get()
                
                if credential_type == "Username":
                    # Use username for certificate authentication
                    resource = strongdm.SSHCert(
                        name=self.name_var.get(),
                        hostname=self.hostname_var.get(),
                        port=int(self.port_var.get()),
                        username=self.ssh_cert_username_var.get()
                    )
                else:  # Identity Alias
                    # Use identity set for certificate authentication
                    resource = strongdm.SSHCert(
                        name=self.name_var.get(),
                        hostname=self.hostname_var.get(),
                        port=int(self.port_var.get())
                    )
                    # Extract ID from the dropdown selection "Name (id-xxx)"
                    identity_selection = self.identity_set_var.get()
                    if '(' in identity_selection and ')' in identity_selection:
                        # Extract ID from "Name (id-xxx)" format
                        identity_id = identity_selection.split('(')[1].split(')')[0]
                        if hasattr(resource, 'identity_set_id'):
                            resource.identity_set_id = identity_id
                    
                # Set key type
                if hasattr(resource, 'key_type'):
                    resource.key_type = self.key_type_var.get()
                    
            elif subtype == "CustomerManagedKey":
                # SSH with customer managed key (might be SSH class with specific attributes)
                private_key_content = self.private_key_text.get("1.0", tk.END).strip()
                resource = strongdm.SSH(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.username_var.get(),
                    public_key=private_key_content
                )
                # Set key_type if available
                if hasattr(resource, 'key_type') and hasattr(self, 'key_type_var'):
                    resource.key_type = self.key_type_var.get()
                    
            else:
                raise ValueError(f"Unsupported SSH subtype: {subtype}")
            
            # Add tags if provided
            selected_tags = self.get_selected_tags()
            if selected_tags:
                resource.tags = selected_tags
                
            return resource
            
        except Exception as e:
            logger.error(f"Error creating SSH resource: {e}")
            raise e
        
    def create_rdp_resource(self, subtype="Basic"):
        """Create RDP resource object based on subtype"""
        if subtype == "Basic":
            # Basic RDP with username/password
            resource = strongdm.RDP(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
            
            # Downgrade NLA option for basic auth
            if hasattr(self, 'downgrade_nla_var'):
                resource.downgrade_nla_connections = self.downgrade_nla_var.get()
                
        elif subtype == "Certificate":
            # RDP with certificate authentication using RDPCert class
            credential_type = self.rdp_credential_type_var.get()
            
            # Get selected certificate authority
            ca_selection = self.rdp_certificate_authority_var.get()
            ca_id = None
            if ca_selection and ca_selection in self.rdp_ca_id_map:
                ca_id = self.rdp_ca_id_map[ca_selection]
            
            if credential_type == "Leased Credential":
                # Leased credential: username + SID (optional)
                resource = strongdm.RDPCert(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get()),
                    username=self.rdp_username_var.get()  # Set the username field that API requires
                )
                # Also set the healthcheck username for leased credentials
                resource.identity_alias_healthcheck_username = self.rdp_username_var.get()
                
                # Note: Optional fields removed from UI since they're not supported by StrongDM Python SDK
                    
            else:  # Identity Alias
                # Identity alias: identity set
                resource = strongdm.RDPCert(
                    name=self.name_var.get(),
                    hostname=self.hostname_var.get(),
                    port=int(self.port_var.get())
                )
                # Use identity set for identity alias
                identity_selection = self.identity_set_id_var.get()
                if '(' in identity_selection and ')' in identity_selection:
                    # Extract ID from "Name (id-xxx)" format
                    identity_id = identity_selection.split('(')[1].split(')')[0]
                    resource.identity_set_id = identity_id
                else:
                    # Fallback - use the whole string
                    resource.identity_set_id = identity_selection
                
                # Set the required identity_alias_healthcheck_username
                # Use AD Service Account if provided, otherwise use a default
                healthcheck_username = self.service_account_var.get().strip()
                if not healthcheck_username:
                    # Default to administrator@domain if no service account specified
                    healthcheck_username = "administrator@domain.local"
                resource.identity_alias_healthcheck_username = healthcheck_username
                
                # Note: Optional fields removed from UI since they're not supported by StrongDM Python SDK
                    
            # Debug: Log ALL available attributes for RDPCert
            all_attrs = [attr for attr in dir(resource) if not attr.startswith('_') and not callable(getattr(resource, attr))]
            logger.info(f"ALL RDPCert attributes: {sorted(all_attrs)}")
            
            # Log current values of all attributes
            logger.info("=== RDPCert Current Values ===")
            for attr in sorted(all_attrs):
                try:
                    value = getattr(resource, attr)
                    logger.info(f"  {attr}: {value}")
                except:
                    logger.info(f"  {attr}: <error getting value>")
            logger.info("=== End RDPCert Values ===")
            
            # Note: Certificate Authority is not supported by StrongDM Python SDK RDPCert object
            # Certificate authority is likely managed through StrongDM internally
            if ca_id:
                logger.info(f"NOTE: Certificate Authority '{ca_selection}' not set - not supported by RDPCert object")
                
        else:
            raise ValueError(f"Unsupported RDP subtype: {subtype}")
        
        # Common RDP options
        if hasattr(self, 'lock_required_var'):
            resource.lock_required = self.lock_required_var.get()
            
        # Add tags if provided
        selected_tags = self.get_selected_tags()
        if selected_tags:
            resource.tags = selected_tags
            
        return resource
        
    def create_database_resource(self):
        """Create database resource object"""
        db_type = self.db_type_var.get()
        
        # Create appropriate database resource type  
        if db_type == "mysql":
            resource = strongdm.Mysql(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "postgresql":
            resource = strongdm.Postgres(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "mssql":
            resource = strongdm.SQLServer(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get(),
                password=self.password_var.get()
            )
        elif db_type == "redis":
            resource = strongdm.Redis(
                name=self.name_var.get(),
                hostname=self.hostname_var.get(),
                port=int(self.port_var.get()),
                username=self.username_var.get() if self.username_var.get() else "",
                password=self.password_var.get()
            )
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        if hasattr(resource, 'database') and self.database_var.get():
            resource.database = self.database_var.get()
            
        # Add tags if provided
        selected_tags = self.get_selected_tags()
        if selected_tags:
            resource.tags = selected_tags
            
        return resource
        
    def setup_csv_import_tab(self):
        """Setup CSV bulk import tab"""
        
        # Instructions with better styling
        instructions_frame = ttk.LabelFrame(self.csv_import_frame, text="CSV Format Requirements")
        instructions_frame.pack(fill="x", padx=10, pady=5)
        
        # Main instructions text with left alignment and bold style
        instructions_text = """Required columns: type, name, hostname, port, username, password
Optional columns: tags, secret_store, proxy_cluster, database_name, key_type
Supported types: SSH, RDP, RDP Certificate, MySQL, PostgreSQL, MSSQL, Redis
Boolean fields (lock_required, downgrade_nla): use true/false"""
        
        ttk.Label(instructions_frame, text=instructions_text, justify="left", 
                 style="Instruction.TLabel").pack(anchor="w", padx=15, pady=10)
        
        # File selection
        file_frame = ttk.LabelFrame(self.csv_import_frame, text="Select CSV File")
        file_frame.pack(fill="x", padx=10, pady=5)
        
        self.csv_file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.csv_file_var).pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(file_frame, text="📁 Browse", style="Primary.TButton",
                  command=self.browse_csv_file).pack(side="left", padx=5)
        
        # Import options
        options_frame = ttk.LabelFrame(self.csv_import_frame, text="Import Options")
        options_frame.pack(fill="x", padx=10, pady=5)
        
        self.skip_errors_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Skip rows with errors and continue", 
                       variable=self.skip_errors_var).pack(anchor="w", padx=10)
        
        self.dry_run_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Dry run (validate only, don't create)", 
                       variable=self.dry_run_var).pack(anchor="w", padx=10)
        
        # Import button
        ttk.Button(self.csv_import_frame, text="🚀 Import Resources", style="Primary.TButton",
                  command=self.import_csv_resources).pack(pady=20)
        
        # Progress
        self.progress_var = tk.StringVar(value="Ready to import")
        ttk.Label(self.csv_import_frame, textvariable=self.progress_var).pack()
        
        self.progress_bar = ttk.Progressbar(self.csv_import_frame, mode='indeterminate')
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        
        # Results
        results_frame = ttk.LabelFrame(self.csv_import_frame, text="Import Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_text = tk.Text(results_frame, height=15, 
                                   bg='white', fg='black', 
                                   font=('Segoe UI', 9), 
                                   relief='flat', borderwidth=1,
                                   selectbackground='#dbeafe')
        results_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_text.pack(side="left", fill="both", expand=True)
        results_scrollbar.pack(side="right", fill="y")
        
    def browse_csv_file(self):
        """Browse for CSV file"""
        filename = filedialog.askopenfilename(
            title="Select CSV file",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.csv_file_var.set(filename)
            
    def import_csv_resources(self):
        """Import resources from CSV file"""
        csv_file = self.csv_file_var.get()
        if not csv_file:
            messagebox.showerror("Error", "Please select a CSV file")
            return
            
        if not os.path.exists(csv_file):
            messagebox.showerror("Error", "CSV file does not exist")
            return
            
        # Start import in separate thread
        thread = threading.Thread(target=self._import_csv_worker, args=(csv_file,))
        thread.daemon = True
        thread.start()
        
    def _import_csv_worker(self, csv_file):
        """Worker thread for CSV import"""
        try:
            self.progress_bar.start()
            self.progress_var.set("Reading CSV file...")
            self.results_text.delete(1.0, tk.END)
            
            with open(csv_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
            total_rows = len(rows)
            success_count = 0
            error_count = 0
            
            self.results_text.insert(tk.END, f"Processing {total_rows} resources...\n\n")
            
            for i, row in enumerate(rows, 1):
                try:
                    self.progress_var.set(f"Processing row {i} of {total_rows}")
                    
                    resource = self.create_resource_from_csv_row(row)
                    
                    if not self.dry_run_var.get():
                        response = self.client.resources.create(resource)
                        
                    self.results_text.insert(tk.END, f"✓ Row {i}: {row.get('name', 'Unknown')} - Success\n")
                    success_count += 1
                    
                except Exception as e:
                    error_msg = f"✗ Row {i}: {row.get('name', 'Unknown')} - Error: {str(e)}\n"
                    self.results_text.insert(tk.END, error_msg)
                    error_count += 1
                    
                    if not self.skip_errors_var.get():
                        break
                        
                self.results_text.see(tk.END)
                self.root.update()
                
            # Summary
            summary = f"\n--- Import Complete ---\n"
            summary += f"Total processed: {i}\n"
            summary += f"Successful: {success_count}\n"
            summary += f"Errors: {error_count}\n"
            
            if self.dry_run_var.get():
                summary += "\nDry run completed - no resources were actually created.\n"
                
            self.results_text.insert(tk.END, summary)
            self.results_text.see(tk.END)
            
        except Exception as e:
            error_msg = f"Import failed: {str(e)}\n"
            self.results_text.insert(tk.END, error_msg)
            logger.error(f"CSV import error: {e}")
            
        finally:
            self.progress_bar.stop()
            self.progress_var.set("Import completed")
            
    def create_resource_from_csv_row(self, row):
        """Create resource object from CSV row"""
        resource_type = row.get('type', '').upper()
        
        if resource_type == 'SSH':
            resource = strongdm.SSH(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port']),
                username=row['username']
            )
            
            # SSH objects use public_key field, not password
            if row.get('password'):
                if row.get('key_type') == 'private_key' or '-----BEGIN' in row['password']:
                    # This is a private key
                    resource.public_key = row['password']  
                else:
                    # This is a password - but SSH objects don't support password auth
                    # SSH resources typically use key-based authentication in StrongDM
                    logger.warning(f"SSH resource '{row['name']}' password ignored - SSH resources use key-based authentication")
                    resource.public_key = ""  # Set empty key if no key provided
                
        elif resource_type == 'RDP':
            resource = strongdm.RDP(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port']),
                username=row['username'],
                password=row['password']
            )
            
            if row.get('lock_required', '').lower() == 'true':
                resource.lock_required = True
            if row.get('downgrade_nla', '').lower() == 'true':
                resource.downgrade_nla_connections = True
                
        elif resource_type == 'RDP CERTIFICATE':
            # Handle RDP Certificate resources
            resource = strongdm.RDPCert(
                name=row['name'],
                hostname=row['hostname'],
                port=int(row['port'])
            )
            
            # Set identity set if provided (skip if it's a friendly name, needs actual ID)
            if row.get('identity_set') and row['identity_set'].startswith('ig-'):
                resource.identity_set_id = row['identity_set']
            elif row.get('identity_set'):
                logger.warning(f"Skipping identity set '{row['identity_set']}' - CSV import requires actual identity set ID (ig-xxxxx format)")
            
            # Set username if provided (for leased credential)
            if row.get('username'):
                resource.username = row['username']
                resource.identity_alias_healthcheck_username = row['username']
            
            # Set service account as healthcheck username if no username provided
            if row.get('service_account') and not row.get('username'):
                resource.identity_alias_healthcheck_username = row['service_account']
            
            if row.get('lock_required', '').lower() == 'true':
                resource.lock_required = True
            
            # Note: RDPCert objects don't support downgrade_nla_connections
            if row.get('downgrade_nla', '').lower() == 'true':
                logger.warning(f"Skipping downgrade_nla for RDP Certificate '{row['name']}' - not supported by RDPCert objects")
                
        elif resource_type in ['MYSQL', 'POSTGRESQL', 'MSSQL', 'REDIS']:
            if resource_type == 'MYSQL':
                resource = strongdm.Mysql(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'POSTGRESQL':
                resource = strongdm.Postgres(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'MSSQL':
                resource = strongdm.SQLServer(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row['username'],
                    password=row['password']
                )
            elif resource_type == 'REDIS':
                resource = strongdm.Redis(
                    name=row['name'],
                    hostname=row['hostname'],
                    port=int(row['port']),
                    username=row.get('username', ''),
                    password=row['password']
                )
            
            if row.get('database_name'):
                resource.database = row['database_name']
                
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")
            
        # Add tags if provided
        if row.get('tags'):
            tag_input = row['tags'].strip()
            # Handle multiple delimiters: =, :, -, | (= first to match GUI format)
            delimiters = ["=", ":", "-", "|"]
            tag_key = tag_input
            tag_value = ""
            
            for delimiter in delimiters:
                if delimiter in tag_input:
                    parts = tag_input.split(delimiter, 1)
                    tag_key = parts[0].strip()
                    tag_value = parts[1].strip()
                    break
            
            resource.tags = {tag_key: tag_value}
            
        return resource

    def setup_csv_export_tab(self):
        """Setup CSV bulk export tab"""

        # Instructions with better styling
        instructions_frame = ttk.LabelFrame(self.csv_export_frame, text="Export Resources to CSV")
        instructions_frame.pack(fill="x", padx=10, pady=5)

        # Main instructions text
        instructions_text = """Export StrongDM resources to CSV format for backup or migration.
Select a resource type and choose where to save the exported file.
Export format matches the sample CSV templates for easy re-import."""

        ttk.Label(instructions_frame, text=instructions_text, justify="left",
                 style="Instruction.TLabel").pack(anchor="w", padx=15, pady=10)

        # Resource type selection
        type_frame = ttk.LabelFrame(self.csv_export_frame, text="Select Resource Type to Export")
        type_frame.pack(fill="x", padx=10, pady=5)

        self.export_type_var = tk.StringVar(value="SSH")
        resource_types = ["SSH", "RDP", "RDP Certificate", "MySQL", "PostgreSQL", "MSSQL", "Redis", "All Resources"]

        for rtype in resource_types:
            ttk.Radiobutton(type_frame, text=rtype, variable=self.export_type_var,
                          value=rtype).pack(anchor="w", padx=10, pady=2)

        # Export options
        export_options_frame = ttk.LabelFrame(self.csv_export_frame, text="Export Options")
        export_options_frame.pack(fill="x", padx=10, pady=5)

        self.include_tags_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_options_frame, text="Include tags",
                       variable=self.include_tags_var).pack(anchor="w", padx=10)

        self.mask_secrets_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(export_options_frame, text="Mask passwords (replace with ********)",
                       variable=self.mask_secrets_var).pack(anchor="w", padx=10)

        # Export button
        ttk.Button(self.csv_export_frame, text="📤 Export to CSV", style="Primary.TButton",
                  command=self.export_resources_to_csv).pack(pady=20)

        # Progress
        self.export_progress_var = tk.StringVar(value="Ready to export")
        ttk.Label(self.csv_export_frame, textvariable=self.export_progress_var).pack()

        self.export_progress_bar = ttk.Progressbar(self.csv_export_frame, mode='indeterminate')
        self.export_progress_bar.pack(fill="x", padx=10, pady=5)

        # Results
        export_results_frame = ttk.LabelFrame(self.csv_export_frame, text="Export Results")
        export_results_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.export_results_text = tk.Text(export_results_frame, height=15,
                                   bg='white', fg='black',
                                   font=('Segoe UI', 9),
                                   relief='flat', borderwidth=1,
                                   selectbackground='#dbeafe')
        export_results_scrollbar = ttk.Scrollbar(export_results_frame, orient="vertical", command=self.export_results_text.yview)
        self.export_results_text.configure(yscrollcommand=export_results_scrollbar.set)

        self.export_results_text.pack(side="left", fill="both", expand=True)
        export_results_scrollbar.pack(side="right", fill="y")

    def export_resources_to_csv(self):
        """Export resources to CSV file with save dialog"""
        export_type = self.export_type_var.get()

        # Open file save dialog
        default_filename = f"strongdm_{export_type.lower().replace(' ', '_')}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filename = filedialog.asksaveasfilename(
            title="Save CSV Export",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_filename
        )

        if not filename:
            return  # User cancelled

        # Start export in separate thread
        thread = threading.Thread(target=self._export_csv_worker, args=(filename, export_type))
        thread.daemon = True
        thread.start()

    def _export_csv_worker(self, filename, export_type):
        """Worker thread for CSV export"""
        try:
            self.export_progress_bar.start()
            self.export_progress_var.set("Fetching resources from StrongDM...")
            self.export_results_text.delete(1.0, tk.END)

            # Fetch all resources
            all_resources = list(self.client.resources.list(""))

            # Log all unique resource class names for debugging
            unique_classes = set(type(r).__name__ for r in all_resources)
            logger.info(f"Found resource classes: {sorted(unique_classes)}")
            self.export_results_text.insert(tk.END, f"Available resource types: {', '.join(sorted(unique_classes))}\n\n")

            # Log EVERY resource with its name and class
            logger.info("=== ALL RESOURCES WITH CLASSES ===")
            for r in all_resources:
                r_name = getattr(r, 'name', 'Unknown')
                r_class = type(r).__name__
                logger.info(f"  {r_name} -> {r_class}")
            logger.info("=== END RESOURCE LIST ===")

            # Filter by type if not "All Resources"
            if export_type != "All Resources":
                filtered_resources = []
                for resource in all_resources:
                    resource_class = type(resource).__name__
                    resource_name = getattr(resource, 'name', 'Unknown')

                    # SSH resources - include all SSH variants
                    if export_type == "SSH" and resource_class in ["SSH", "SSHPassword", "SSHCert", "SSHCustomerKey"]:
                        filtered_resources.append(resource)
                        logger.info(f"✓ Matched SSH resource: {resource_name} (class: {resource_class})")
                    elif export_type == "SSH":
                        logger.info(f"✗ Skipped non-SSH resource: {resource_name} (class: {resource_class})")
                    # RDP resources - include basic RDP only
                    elif export_type == "RDP" and resource_class == "RDP":
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting RDP resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
                    # RDP Certificate resources
                    elif export_type == "RDP Certificate" and resource_class == "RDPCert":
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting RDPCert resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
                    # MySQL resources
                    elif export_type == "MySQL" and resource_class == "Mysql":
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting MySQL resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
                    # PostgreSQL resources
                    elif export_type == "PostgreSQL" and resource_class in ["Postgres", "PostgreSQL"]:
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting Postgres resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
                    # MSSQL resources
                    elif export_type == "MSSQL" and resource_class in ["SQLServer", "MSSQL"]:
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting MSSQL resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
                    # Redis resources
                    elif export_type == "Redis" and resource_class == "Redis":
                        filtered_resources.append(resource)
                        logger.debug(f"Exporting Redis resource: {getattr(resource, 'name', 'Unknown')} (class: {resource_class})")
            else:
                filtered_resources = all_resources
                logger.info(f"Exporting all {len(all_resources)} resources")

            if not filtered_resources:
                self.export_results_text.insert(tk.END, f"No resources found for type: {export_type}\n")
                self.export_progress_var.set("Export complete - no resources found")
                return

            self.export_progress_var.set(f"Exporting {len(filtered_resources)} resources...")

            # Show breakdown by class for filtered resources
            if export_type != "All Resources":
                filtered_classes = {}
                for r in filtered_resources:
                    class_name = type(r).__name__
                    filtered_classes[class_name] = filtered_classes.get(class_name, 0) + 1

                self.export_results_text.insert(tk.END, f"Exporting {len(filtered_resources)} resources:\n")
                for class_name, count in sorted(filtered_classes.items()):
                    self.export_results_text.insert(tk.END, f"  - {count} {class_name}\n")
                self.export_results_text.insert(tk.END, "\n")
            else:
                self.export_results_text.insert(tk.END, f"Found {len(filtered_resources)} resources to export\n\n")

            # Write to CSV
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                # Determine columns based on resource type
                columns = self._get_csv_columns_for_type(export_type)
                writer = csv.DictWriter(f, fieldnames=columns)
                writer.writeheader()

                for i, resource in enumerate(filtered_resources, 1):
                    try:
                        row_data = self._resource_to_csv_row(resource, columns)
                        writer.writerow(row_data)
                        self.export_results_text.insert(tk.END, f"✓ Exported: {resource.name}\n")
                        self.export_results_text.see(tk.END)
                        self.root.update()
                    except Exception as e:
                        self.export_results_text.insert(tk.END, f"✗ Error exporting {resource.name}: {str(e)}\n")
                        logger.error(f"Error exporting resource {resource.name}: {e}")

            # Summary
            summary = f"\n--- Export Complete ---\n"
            summary += f"Total exported: {len(filtered_resources)}\n"
            summary += f"File saved to: {filename}\n"

            self.export_results_text.insert(tk.END, summary)
            self.export_results_text.see(tk.END)
            self.export_progress_var.set("Export complete")

            # Show success message
            messagebox.showinfo("Export Complete", f"Successfully exported {len(filtered_resources)} resources to:\n{filename}")

        except Exception as e:
            error_msg = f"Export failed: {str(e)}\n"
            self.export_results_text.insert(tk.END, error_msg)
            logger.error(f"CSV export error: {e}")
            messagebox.showerror("Export Failed", str(e))

        finally:
            self.export_progress_bar.stop()

    def _get_csv_columns_for_type(self, export_type):
        """Get CSV column headers for resource type"""
        # Base columns for all types
        base_columns = ['type', 'name', 'hostname', 'port', 'username', 'password']

        if export_type in ["SSH"]:
            return base_columns + ['tags', 'secret_store', 'proxy_cluster', 'key_type']
        elif export_type in ["RDP"]:
            return base_columns + ['tags', 'secret_store', 'proxy_cluster', 'lock_required', 'downgrade_nla']
        elif export_type in ["RDP Certificate"]:
            return ['type', 'name', 'hostname', 'port', 'username', 'identity_set', 'service_account', 'tags', 'secret_store', 'proxy_cluster', 'lock_required']
        elif export_type in ["MySQL", "PostgreSQL", "MSSQL"]:
            return base_columns + ['database_name', 'tags', 'secret_store', 'proxy_cluster', 'lock_required']
        elif export_type in ["Redis"]:
            return base_columns + ['tags', 'secret_store', 'proxy_cluster']
        else:  # All Resources
            # Return comprehensive column set
            return ['type', 'name', 'hostname', 'port', 'username', 'password', 'database_name',
                   'tags', 'secret_store', 'proxy_cluster', 'lock_required', 'downgrade_nla',
                   'key_type', 'identity_set', 'service_account']

    def _resource_to_csv_row(self, resource, columns):
        """Convert resource object to CSV row dictionary"""
        resource_class = type(resource).__name__

        # Map resource class to CSV type
        type_map = {
            'SSH': 'SSH',
            'SSHPassword': 'SSH',
            'SSHCert': 'SSH',
            'SSHCustomerKey': 'SSH',
            'RDP': 'RDP',
            'RDPCert': 'RDP Certificate',
            'Mysql': 'MySQL',
            'Postgres': 'PostgreSQL',
            'PostgreSQL': 'PostgreSQL',
            'SQLServer': 'MSSQL',
            'MSSQL': 'MSSQL',
            'Redis': 'Redis'
        }

        row = {}

        # Fill in columns
        for col in columns:
            if col == 'type':
                row[col] = type_map.get(resource_class, resource_class)
            elif col == 'name':
                row[col] = getattr(resource, 'name', '')
            elif col == 'hostname':
                row[col] = getattr(resource, 'hostname', '')
            elif col == 'port':
                row[col] = getattr(resource, 'port', '')
            elif col == 'username':
                row[col] = getattr(resource, 'username', '')
            elif col == 'password':
                # Mask password if option is enabled
                if self.mask_secrets_var.get():
                    row[col] = '********'
                else:
                    row[col] = getattr(resource, 'password', '')
            elif col == 'database_name':
                row[col] = getattr(resource, 'database', '')
            elif col == 'tags':
                # Format tags back to key=value format
                if self.include_tags_var.get():
                    tags = getattr(resource, 'tags', {})
                    if tags:
                        # Convert dict to key=value|key=value format
                        tag_strings = [f"{k}={v}" for k, v in tags.items()]
                        row[col] = '|'.join(tag_strings)
                    else:
                        row[col] = ''
                else:
                    row[col] = ''
            elif col == 'secret_store':
                row[col] = getattr(resource, 'secret_store_id', '')
            elif col == 'proxy_cluster':
                row[col] = getattr(resource, 'egress_filter', '')
            elif col == 'lock_required':
                row[col] = str(getattr(resource, 'lock_required', False)).lower()
            elif col == 'downgrade_nla':
                row[col] = str(getattr(resource, 'downgrade_nla_connections', False)).lower()
            elif col == 'key_type':
                # For SSH - check if using public_key
                public_key = getattr(resource, 'public_key', '')
                if public_key:
                    row[col] = 'private_key' if '-----BEGIN' in str(public_key) else ''
                else:
                    row[col] = ''
            elif col == 'identity_set':
                row[col] = getattr(resource, 'identity_set_id', '')
            elif col == 'service_account':
                row[col] = getattr(resource, 'identity_alias_healthcheck_username', '')
            else:
                row[col] = ''

        return row

    def setup_monitoring_tab(self):
        """Setup monitoring dashboard tab - fills 100% of screen"""

        # Configure grid layout for full screen usage
        self.monitoring_frame.grid_rowconfigure(1, weight=1)  # Gateway section
        self.monitoring_frame.grid_rowconfigure(2, weight=1)  # Sessions section
        self.monitoring_frame.grid_rowconfigure(3, weight=1)  # Activity section
        self.monitoring_frame.grid_columnconfigure(0, weight=1)

        # Header with refresh button
        header_frame = ttk.Frame(self.monitoring_frame)
        header_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        ttk.Label(header_frame, text="StrongDM Monitoring Dashboard",
                 font=('Segoe UI', 14, 'bold')).pack(side="left")

        ttk.Button(header_frame, text="🔄 Refresh All",
                  command=self.refresh_monitoring_data,
                  style="Primary.TButton").pack(side="right", padx=5)

        # Summary Stats Section (in header row)
        stats_subframe = ttk.Frame(header_frame)
        stats_subframe.pack(side="left", padx=20)

        # Org and User stats
        self.stat_org = ttk.Label(stats_subframe, text="Org: -", font=('Segoe UI', 9, 'bold'))
        self.stat_org.pack(side="left", padx=10)

        self.stat_users = ttk.Label(stats_subframe, text="Users: -", font=('Segoe UI', 9, 'bold'))
        self.stat_users.pack(side="left", padx=10)

        # Separator
        ttk.Separator(stats_subframe, orient='vertical').pack(side="left", fill='y', padx=5)

        # Other stat labels in a single row
        self.stat_gateways = ttk.Label(stats_subframe, text="Gateways: -", font=('Segoe UI', 9))
        self.stat_gateways.pack(side="left", padx=10)

        self.stat_sessions = ttk.Label(stats_subframe, text="Sessions: -", font=('Segoe UI', 9))
        self.stat_sessions.pack(side="left", padx=10)

        self.stat_activities = ttk.Label(stats_subframe, text="Activities: -", font=('Segoe UI', 9))
        self.stat_activities.pack(side="left", padx=10)

        self.stat_health = ttk.Label(stats_subframe, text="Health: -", font=('Segoe UI', 9))
        self.stat_health.pack(side="left", padx=10)

        # Gateway Status Section
        gateway_frame = ttk.LabelFrame(self.monitoring_frame, text="🌐 Gateway Health Status")
        gateway_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        # Gateway tree
        gateway_tree_frame = ttk.Frame(gateway_frame)
        gateway_tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        gateway_columns = ("node_id", "healthy_resources", "unhealthy_resources", "health_pct", "last_check")
        self.gateway_tree = ttk.Treeview(gateway_tree_frame, columns=gateway_columns, show="tree headings",
                                        selectmode="browse")

        self.gateway_tree.heading("#0", text="Gateway Name")
        self.gateway_tree.heading("node_id", text="Node ID")
        self.gateway_tree.heading("healthy_resources", text="Healthy")
        self.gateway_tree.heading("unhealthy_resources", text="Unhealthy")
        self.gateway_tree.heading("health_pct", text="Health %")
        self.gateway_tree.heading("last_check", text="Last Check")

        self.gateway_tree.column("#0", width=200, minwidth=150)
        self.gateway_tree.column("node_id", width=120, minwidth=100)
        self.gateway_tree.column("healthy_resources", width=80, minwidth=60)
        self.gateway_tree.column("unhealthy_resources", width=90, minwidth=70)
        self.gateway_tree.column("health_pct", width=80, minwidth=60)
        self.gateway_tree.column("last_check", width=150, minwidth=120)

        gateway_scrollbar = ttk.Scrollbar(gateway_tree_frame, orient="vertical", command=self.gateway_tree.yview)
        self.gateway_tree.configure(yscrollcommand=gateway_scrollbar.set)

        self.gateway_tree.pack(side="left", fill="both", expand=True)
        gateway_scrollbar.pack(side="right", fill="y")

        # Recent Sessions Section
        sessions_frame = ttk.LabelFrame(self.monitoring_frame, text="👥 Recent/Active Sessions")
        sessions_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        # Sessions tree
        sessions_tree_frame = ttk.Frame(sessions_frame)
        sessions_tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        sessions_columns = ("user", "resource", "resource_type", "gateway_node", "start_time", "duration_ms")
        self.sessions_tree = ttk.Treeview(sessions_tree_frame, columns=sessions_columns, show="headings",
                                         selectmode="browse")

        self.sessions_tree.heading("user", text="User")
        self.sessions_tree.heading("resource", text="Resource")
        self.sessions_tree.heading("resource_type", text="Type")
        self.sessions_tree.heading("gateway_node", text="Gateway Node")
        self.sessions_tree.heading("start_time", text="Start Time")
        self.sessions_tree.heading("duration_ms", text="Duration (ms)")

        self.sessions_tree.column("user", width=180, minwidth=120)
        self.sessions_tree.column("resource", width=180, minwidth=120)
        self.sessions_tree.column("resource_type", width=100, minwidth=80)
        self.sessions_tree.column("gateway_node", width=120, minwidth=100)
        self.sessions_tree.column("start_time", width=150, minwidth=120)
        self.sessions_tree.column("duration_ms", width=100, minwidth=80)

        sessions_scrollbar = ttk.Scrollbar(sessions_tree_frame, orient="vertical", command=self.sessions_tree.yview)
        self.sessions_tree.configure(yscrollcommand=sessions_scrollbar.set)

        self.sessions_tree.pack(side="left", fill="both", expand=True)
        sessions_scrollbar.pack(side="right", fill="y")

        # Activity Intelligence Section
        activity_frame = ttk.LabelFrame(self.monitoring_frame, text="📋 Activity Intelligence (Parsed)")
        activity_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=5)

        # Activity tree with intelligent categorization
        activity_tree_frame = ttk.Frame(activity_frame)
        activity_tree_frame.pack(fill="both", expand=True, padx=5, pady=5)

        activity_columns = ("category", "actor", "details", "timestamp")
        self.activity_tree = ttk.Treeview(activity_tree_frame, columns=activity_columns, show="tree headings",
                                         selectmode="browse")

        self.activity_tree.heading("#0", text="Activity Type")
        self.activity_tree.heading("category", text="Category")
        self.activity_tree.heading("actor", text="Actor")
        self.activity_tree.heading("details", text="Details")
        self.activity_tree.heading("timestamp", text="Timestamp")

        self.activity_tree.column("#0", width=200, minwidth=150)
        self.activity_tree.column("category", width=120, minwidth=100)
        self.activity_tree.column("actor", width=180, minwidth=120)
        self.activity_tree.column("details", width=300, minwidth=200)
        self.activity_tree.column("timestamp", width=150, minwidth=120)

        activity_scrollbar = ttk.Scrollbar(activity_tree_frame, orient="vertical", command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scrollbar.set)

        self.activity_tree.pack(side="left", fill="both", expand=True)
        activity_scrollbar.pack(side="right", fill="y")

        # Load data automatically
        self.root.after(100, self.refresh_monitoring_data)

    def refresh_monitoring_data(self):
        """Refresh all monitoring data"""
        threading.Thread(target=self._refresh_monitoring_worker, daemon=True).start()

    def _refresh_monitoring_worker(self):
        """Worker thread to refresh monitoring data"""
        try:
            # Load gateway health
            self.load_gateway_health()

            # Load recent sessions
            self.load_recent_sessions()

            # Load and parse activities
            self.load_activity_intelligence()

            # Update summary stats
            self.update_summary_stats()

        except Exception as e:
            logger.error(f"Error refreshing monitoring data: {e}")

    def load_gateway_health(self):
        """Load gateway health status"""
        try:
            # Clear existing items
            for item in self.gateway_tree.get_children():
                self.gateway_tree.delete(item)

            # Get health checks
            health_checks = list(self.client.health_checks.list(''))

            # Aggregate by gateway - check for both attribute name styles
            gateway_health = {}
            for hc in health_checks:
                # Try different attribute names (snake_case vs PascalCase)
                node_name = getattr(hc, 'node_name', getattr(hc, 'NodeName', 'Unknown'))
                node_id = getattr(hc, 'node_id', getattr(hc, 'NodeID', 'N/A'))
                healthy = getattr(hc, 'healthy', getattr(hc, 'Healthy', False))
                check_time = getattr(hc, 'checked_at', getattr(hc, 'Time', datetime.now()))

                if node_name not in gateway_health:
                    gateway_health[node_name] = {
                        'node_id': node_id,
                        'healthy': 0,
                        'unhealthy': 0,
                        'last_check': check_time
                    }

                if healthy:
                    gateway_health[node_name]['healthy'] += 1
                else:
                    gateway_health[node_name]['unhealthy'] += 1

            # Populate tree
            for gateway_name, data in gateway_health.items():
                total = data['healthy'] + data['unhealthy']
                health_pct = (data['healthy'] / total * 100) if total > 0 else 0

                last_check_str = data['last_check'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(data['last_check'], 'strftime') else str(data['last_check'])

                self.gateway_tree.insert("", "end", text=gateway_name,
                                        values=(data['node_id'], data['healthy'], data['unhealthy'],
                                               f"{health_pct:.1f}%", last_check_str))

        except Exception as e:
            logger.error(f"Error loading gateway health: {e}", exc_info=True)

    def load_recent_sessions(self):
        """Load recent sessions from queries"""
        try:
            # Clear existing items
            for item in self.sessions_tree.get_children():
                self.sessions_tree.delete(item)

            # Get recent queries - sort by timestamp (newest first)
            all_queries = list(self.client.queries.list(''))

            # Sort by timestamp, newest first
            all_queries.sort(key=lambda q: getattr(q, 'timestamp', datetime.min), reverse=True)
            queries = all_queries[:50]  # Take top 50 newest

            # Populate tree
            for query in queries:
                # Extract data using correct attribute names from SDK
                user = getattr(query, 'account_email', 'N/A')
                resource = getattr(query, 'resource_name', '')
                resource_type = getattr(query, 'resource_type', '')
                gateway_node = getattr(query, 'egress_node_id', '')

                # Get resource_id to filter out non-resource queries
                resource_id = getattr(query, 'resource_id', '')

                # Skip queries with no real resource (admin UI operations have resource_id = rs-0000000000000000)
                if not resource and not resource_type and (not resource_id or resource_id == 'rs-0000000000000000'):
                    continue

                # Handle timestamp
                timestamp = getattr(query, 'timestamp', None)
                if timestamp and hasattr(timestamp, 'strftime'):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = str(timestamp) if timestamp else 'N/A'

                # Handle duration (timedelta object)
                duration = getattr(query, 'duration', None)
                if duration:
                    # Convert timedelta to milliseconds
                    duration_ms = int(duration.total_seconds() * 1000)
                else:
                    duration_ms = 0

                # Show resource or query category if no resource
                if not resource or resource == '':
                    query_category = getattr(query, 'query_category', 'N/A')
                    resource = f"[{query_category}]" if query_category else 'N/A'

                self.sessions_tree.insert("", "end",
                                         values=(user, resource, resource_type, gateway_node,
                                                timestamp_str, duration_ms))

        except Exception as e:
            logger.error(f"Error loading recent sessions: {e}", exc_info=True)

    def load_activity_intelligence(self):
        """Load and intelligently parse activity logs"""
        try:
            # Clear existing items
            for item in self.activity_tree.get_children():
                self.activity_tree.delete(item)

            # Get recent activities - sort by timestamp (newest first)
            all_activities = list(self.client.activities.list(''))

            # Sort by completed_at timestamp, newest first
            all_activities.sort(key=lambda a: getattr(a, 'completed_at', datetime.min), reverse=True)
            activities = all_activities[:100]  # Take top 100 newest

            # Parse and categorize activities
            for activity in activities:
                # Extract data using correct attribute names from SDK
                activity_text = getattr(activity, 'description', 'Unknown')

                # Actor is an object with email attribute
                actor = getattr(activity, 'actor', None)
                if actor and hasattr(actor, 'email'):
                    actor_email = actor.email
                else:
                    actor_email = 'System'

                # Handle timestamp
                timestamp = getattr(activity, 'completed_at', None)
                if timestamp and hasattr(timestamp, 'strftime'):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    timestamp_str = str(timestamp) if timestamp else 'N/A'

                # Intelligent categorization
                category, details = self.parse_activity(activity_text)

                self.activity_tree.insert("", "end", text=activity_text[:50],
                                         values=(category, actor_email, details, timestamp_str))

        except Exception as e:
            logger.error(f"Error loading activity intelligence: {e}", exc_info=True)

    def parse_activity(self, activity_text):
        """Parse activity text and extract intelligence"""
        activity_lower = activity_text.lower()

        # Authentication events
        if 'logged in' in activity_lower or 'login' in activity_lower:
            return ('🔐 Auth', 'User logged in')
        elif 'logout' in activity_lower or 'logged out' in activity_lower:
            return ('🔐 Auth', 'User logged out')
        elif 'authentication failed' in activity_lower or 'failed login' in activity_lower:
            return ('⚠️ Security', 'Authentication failed')

        # User management
        elif 'user created' in activity_lower:
            return ('👤 User', 'New user created')
        elif 'user deleted' in activity_lower or 'user suspended' in activity_lower:
            return ('👤 User', 'User removed/suspended')
        elif 'user updated' in activity_lower:
            return ('👤 User', 'User modified')

        # Resource management
        elif 'resource created' in activity_lower:
            return ('🔧 Resource', 'New resource created')
        elif 'resource deleted' in activity_lower:
            return ('🔧 Resource', 'Resource deleted')
        elif 'resource updated' in activity_lower:
            return ('🔧 Resource', 'Resource modified')

        # Gateway/Node events
        elif 'node' in activity_lower or 'gateway' in activity_lower:
            if 'created' in activity_lower:
                return ('🌐 Gateway', 'Gateway/node added')
            elif 'deleted' in activity_lower:
                return ('🌐 Gateway', 'Gateway/node removed')
            else:
                return ('🌐 Gateway', 'Gateway/node modified')

        # Permission changes
        elif 'role' in activity_lower or 'permission' in activity_lower or 'grant' in activity_lower:
            return ('🔑 Permission', 'Permission/role change')

        # Secret operations
        elif 'secret' in activity_lower:
            if 'rotated' in activity_lower:
                return ('🔐 Secret', 'Secret rotated')
            elif 'validated' in activity_lower:
                return ('🔐 Secret', 'Secret validated')
            else:
                return ('🔐 Secret', 'Secret operation')

        # API operations
        elif 'api' in activity_lower or 'token' in activity_lower:
            return ('🔧 API', 'API token operation')

        # SSO/Configuration
        elif 'sso' in activity_lower or 'saml' in activity_lower:
            return ('⚙️ Config', 'SSO configuration change')

        # Default
        else:
            return ('📋 Other', activity_text[:100])

    def update_summary_stats(self):
        """Update summary statistics"""
        try:
            # Get org name and user count
            try:
                # Get organization name
                orgs = list(self.client.organizations.list(''))
                org_name = orgs[0].name if orgs else "Unknown"
                self.stat_org.config(text=f"Org: {org_name}")

                # Get user count
                users = list(self.client.accounts.list(''))
                user_count = len(users)
                self.stat_users.config(text=f"Users: {user_count}")
            except Exception as e:
                logger.warning(f"Error getting org/user stats: {e}")
                self.stat_org.config(text="Org: -")
                self.stat_users.config(text="Users: -")

            # Count gateways
            gateway_count = len(self.gateway_tree.get_children())
            self.stat_gateways.config(text=f"Gateways: {gateway_count}")

            # Count sessions
            session_count = len(self.sessions_tree.get_children())
            self.stat_sessions.config(text=f"Recent Sessions: {session_count}")

            # Count activities
            activity_count = len(self.activity_tree.get_children())
            self.stat_activities.config(text=f"Recent Activities: {activity_count}")

            # Calculate average health
            total_health = 0
            gateway_count_for_avg = 0
            for item in self.gateway_tree.get_children():
                values = self.gateway_tree.item(item)['values']
                health_pct_str = values[3]  # health_pct column
                health_pct = float(health_pct_str.replace('%', ''))
                total_health += health_pct
                gateway_count_for_avg += 1

            avg_health = (total_health / gateway_count_for_avg) if gateway_count_for_avg > 0 else 0
            self.stat_health.config(text=f"Avg Health: {avg_health:.1f}%")

        except Exception as e:
            logger.error(f"Error updating summary stats: {e}")

    def setup_versions_tab(self):
        """Setup versions inspector tab"""
        # Header
        header_frame = ttk.Frame(self.versions_frame)
        header_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(header_frame, text="Version Inspector",
                 font=('Segoe UI', 14, 'bold')).pack(side="left")

        ttk.Button(header_frame, text="🔄 Refresh",
                  command=self.load_versions,
                  style="Primary.TButton").pack(side="right", padx=5)

        # Versions tree
        tree_frame = ttk.Frame(self.versions_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)

        columns = ("actor", "version", "warnings", "registered", "ip", "heartbeat")
        self.versions_tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", selectmode="browse")

        # Configure headings
        self.versions_tree.heading("#0", text="Name")
        self.versions_tree.heading("actor", text="Actor")
        self.versions_tree.heading("version", text="Version")
        self.versions_tree.heading("warnings", text="Warnings")
        self.versions_tree.heading("registered", text="Registered Time")
        self.versions_tree.heading("ip", text="IP Address")
        self.versions_tree.heading("heartbeat", text="Last Heartbeat")

        # Configure columns
        self.versions_tree.column("#0", width=200, minwidth=150)
        self.versions_tree.column("actor", width=150, minwidth=100)
        self.versions_tree.column("version", width=120, minwidth=80)
        self.versions_tree.column("warnings", width=150, minwidth=100)
        self.versions_tree.column("registered", width=180, minwidth=120)
        self.versions_tree.column("ip", width=130, minwidth=100)
        self.versions_tree.column("heartbeat", width=180, minwidth=120)

        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.versions_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.versions_tree.xview)
        self.versions_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.versions_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Load versions on tab creation
        self.load_versions()

    def load_versions(self):
        """Load version data from nodes"""
        try:
            # Clear existing items
            for item in self.versions_tree.get_children():
                self.versions_tree.delete(item)

            # Get all nodes (gateways and relays)
            nodes = list(self.client.nodes.list(''))

            for node in nodes:
                name = getattr(node, 'name', 'Unknown')
                actor = getattr(node, 'type', 'N/A')  # gateway, relay, etc.
                version = getattr(node, 'version', 'N/A')

                # Check for warnings/errors
                warnings = []
                healthy = getattr(node, 'healthy', True)
                error = getattr(node, 'error', '')
                if not healthy:
                    warnings.append("Unhealthy")
                if error:
                    warnings.append(f"Error: {error[:50]}")
                warnings_str = ', '.join(warnings) if warnings else "None"

                # Timestamps
                registered = getattr(node, 'created_at', None)
                registered_str = registered.strftime('%Y-%m-%d %H:%M:%S') if registered and hasattr(registered, 'strftime') else 'N/A'

                heartbeat = getattr(node, 'last_seen_at', None)
                heartbeat_str = heartbeat.strftime('%Y-%m-%d %H:%M:%S') if heartbeat and hasattr(heartbeat, 'strftime') else 'Never'

                # IP/hostname
                listen_address = getattr(node, 'listen_address', '')
                bind_address = getattr(node, 'bind_address', '')
                ip = listen_address or bind_address or 'N/A'

                self.versions_tree.insert("", "end", text=name,
                                        values=(actor, version, warnings_str, registered_str, ip, heartbeat_str))

        except Exception as e:
            logger.error(f"Error loading versions: {e}", exc_info=True)

    def setup_debug_tab(self):
        """Setup debug tab"""
        
        # Create scrollable frame for debug buttons - full width scaling
        debug_canvas = tk.Canvas(self.debug_frame)
        debug_scrollbar = ttk.Scrollbar(self.debug_frame, orient="vertical", command=debug_canvas.yview)
        debug_scrollable_frame = ttk.Frame(debug_canvas)
        
        # Bind both configure events for proper scaling in both dimensions
        debug_scrollable_frame.bind(
            "<Configure>",
            lambda e: debug_canvas.configure(scrollregion=debug_canvas.bbox("all"))
        )
        debug_canvas.bind(
            "<Configure>",
            lambda e: debug_canvas.itemconfig(debug_window, width=e.width)
        )
        
        debug_window = debug_canvas.create_window((0, 0), window=debug_scrollable_frame, anchor="nw")
        debug_canvas.configure(yscrollcommand=debug_scrollbar.set)
        
        # API Test Section with grid layout for better button wrapping
        api_test_frame = ttk.LabelFrame(debug_scrollable_frame, text="API Testing")
        api_test_frame.pack(fill="x", padx=10, pady=5)
        api_test_frame.grid_columnconfigure(0, weight=1)
        api_test_frame.grid_columnconfigure(1, weight=1)
        api_test_frame.grid_columnconfigure(2, weight=1)
        
        # Debug buttons in a 3-column grid for better wrapping
        buttons = [
            ("Test Connection", self.test_connection),
            ("List Resources", self.list_resources),
            ("List Tags", self.list_tags),
            ("List Secret Stores", self.list_secret_stores),
            ("List Proxy Clusters", self.debug_proxy_clusters),
            ("Debug Resource Tags", self.debug_resource_tags),
            ("Tag Management", self.debug_tag_management),
        ]
        
        for i, (text, command) in enumerate(buttons):
            row = i // 3
            col = i % 3
            ttk.Button(api_test_frame, text=text, command=command).grid(
                row=row, column=col, padx=5, pady=2, sticky="ew"
            )
        
        # Custom Query Section
        query_frame = ttk.LabelFrame(debug_scrollable_frame, text="Custom Query")
        query_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(query_frame, text="Filter:").pack(side="left")
        self.query_var = tk.StringVar()
        ttk.Entry(query_frame, textvariable=self.query_var).pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(query_frame, text="Execute", 
                  command=self.execute_query).pack(side="left", padx=5)
        
        # Debug Output
        output_frame = ttk.LabelFrame(debug_scrollable_frame, text="Debug Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.debug_text = tk.Text(output_frame, height=20,
                                 bg='white', fg='black', 
                                 font=('Segoe UI', 9), 
                                 relief='flat', borderwidth=1,
                                 selectbackground='#dbeafe')
        debug_output_scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.debug_text.yview)
        self.debug_text.configure(yscrollcommand=debug_output_scrollbar.set)
        
        self.debug_text.pack(side="left", fill="both", expand=True)
        debug_output_scrollbar.pack(side="right", fill="y")
        
        # Add clear debug button at bottom
        clear_frame = ttk.Frame(debug_scrollable_frame)
        clear_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(clear_frame, text="Clear Debug Window", 
                  command=self.clear_debug_window, 
                  style="Danger.TButton").pack(pady=5)
        
        # Pack the scrollable canvas with minimal padding
        debug_canvas.pack(side="left", fill="both", expand=True, padx=(2, 0))
        debug_scrollbar.pack(side="right", fill="y", padx=(0, 2))
        
    def test_connection(self):
        """Test API connection"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Testing connection...\n")
            
            accounts = list(self.client.accounts.list(""))
            if accounts:
                accounts = accounts[:1]  # Take only first account
            self.debug_text.insert(tk.END, f"✓ Connection successful! Found {len(accounts)} account(s)\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Connection failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
    
    def clear_debug_window(self):
        """Clear the debug output window"""
        self.debug_text.delete(1.0, tk.END)
        self.debug_text.insert(tk.END, f"[{datetime.now()}] Debug window cleared.\n")
        
    def list_resources(self):
        """List all resources"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing resources...\n")
            
            resources = list(self.client.resources.list(""))
            self.log_api_call("DEBUG_LIST", "/resources", None, f"Found {len(resources)} resources")
            self.debug_text.insert(tk.END, f"Found {len(resources)} resources:\n")
            
            for resource in resources:
                self.debug_text.insert(tk.END, f"  - {resource.name} ({type(resource).__name__})\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Failed to list resources: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def list_tags(self):
        """List all tags from existing resources"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing tags from resources...\n")
            
            # Get tags from existing resources (same method as load_tenant_data)
            tags = set()
            resources = list(self.client.resources.list(""))
            
            self.debug_text.insert(tk.END, f"Scanning {len(resources)} resources for tags...\n")
            
            for resource in resources:
                if hasattr(resource, 'tags') and resource.tags:
                    for tag_key, tag_value in resource.tags.items():
                        if tag_value:
                            # Create key=value format to match GUI format
                            tag_pair = f"{tag_key}={tag_value}"
                            tags.add(tag_pair)
                        else:
                            # If no value, just add the key
                            tags.add(tag_key)
            
            tags = sorted(list(tags))
            self.debug_text.insert(tk.END, f"Found {len(tags)} unique tags:\n")
            
            if tags:
                for tag in tags:
                    self.debug_text.insert(tk.END, f"  - {tag}\n")
            else:
                self.debug_text.insert(tk.END, "  No tags found on existing resources\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Failed to list tags: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def list_secret_stores(self):
        """List all secret stores"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Listing secret stores...\n")

            # Try to list secret stores
            stores_iter = self.client.secret_stores.list("")
            stores = []
            store_count = 0

            # Iterate through stores, catching individual parsing errors
            for store in stores_iter:
                try:
                    stores.append(store)
                    store_count += 1
                    self.debug_text.insert(tk.END, f"  - {store.name} ({type(store).__name__})\n")
                except Exception as parse_error:
                    # Some store types may not be recognized by this SDK version
                    self.debug_text.insert(tk.END, f"  - [Unrecognized store type - SDK update may be needed]\n")
                    store_count += 1

            self.debug_text.insert(tk.END, f"\nFound {store_count} secret store(s)\n")

            if store_count == 0:
                self.debug_text.insert(tk.END, "No secret stores configured in this tenant.\n")

        except Exception as e:
            error_msg = str(e)
            self.debug_text.insert(tk.END, f"✗ Failed to list secret stores: {error_msg}\n")

            # Provide helpful guidance
            if "unknown polymorphic type" in error_msg.lower() or "upgrade your sdk" in error_msg.lower():
                self.debug_text.insert(tk.END, "\n⚠ SDK COMPATIBILITY ISSUE:\n")
                self.debug_text.insert(tk.END, "   • Your tenant has secret stores using newer types\n")
                self.debug_text.insert(tk.END, "   • Update the SDK: pip install --upgrade strongdm\n")
                self.debug_text.insert(tk.END, f"   • Current SDK version: {strongdm.__version__ if hasattr(strongdm, '__version__') else 'unknown'}\n")
                self.debug_text.insert(tk.END, "   • Alternatively, use the StrongDM Admin UI to view secret stores\n")

        self.debug_text.see(tk.END)
        
    def execute_query(self):
        """Execute custom query"""
        try:
            query = self.query_var.get()
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Executing query: '{query}'\n")
            
            resources = list(self.client.resources.list(query))
            self.debug_text.insert(tk.END, f"Query returned {len(resources)} resources:\n")
            
            for resource in resources:
                self.debug_text.insert(tk.END, f"  - {resource.name} ({type(resource).__name__})\n")
                
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Query failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def debug_resource_tags(self):
        """Debug detailed resource tag information"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Debugging resource tags in detail...\n")
            
            resources = list(self.client.resources.list(""))
            self.debug_text.insert(tk.END, f"Found {len(resources)} resources:\n\n")
            
            for i, resource in enumerate(resources, 1):
                resource_name = getattr(resource, 'name', f'Resource_{i}')
                resource_type = type(resource).__name__
                
                self.debug_text.insert(tk.END, f"Resource {i}: {resource_name} ({resource_type})\n")
                
                # Check all possible tag attributes
                tag_attrs_found = []
                for attr in ['tags', 'tag', 'labels', 'metadata']:
                    if hasattr(resource, attr):
                        value = getattr(resource, attr)
                        if value:
                            tag_attrs_found.append(f"  - {attr}: {value} (type: {type(value).__name__})")
                
                if tag_attrs_found:
                    self.debug_text.insert(tk.END, "  Tag attributes found:\n")
                    for attr_info in tag_attrs_found:
                        self.debug_text.insert(tk.END, f"{attr_info}\n")
                else:
                    self.debug_text.insert(tk.END, "  - No tag attributes found\n")
                
                # Show all attributes to see what's available
                self.debug_text.insert(tk.END, "  All attributes:\n")
                attrs = [attr for attr in dir(resource) if not attr.startswith('_') and not callable(getattr(resource, attr, None))]
                for attr in attrs[:10]:  # Show first 10 non-callable attributes
                    try:
                        value = getattr(resource, attr)
                        self.debug_text.insert(tk.END, f"    - {attr}: {value}\n")
                    except:
                        self.debug_text.insert(tk.END, f"    - {attr}: (error reading)\n")
                
                if len(attrs) > 10:
                    self.debug_text.insert(tk.END, f"    ... and {len(attrs) - 10} more attributes\n")
                    
                self.debug_text.insert(tk.END, "\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug resource tags failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
        
    def debug_proxy_clusters(self):
        """Debug proxy clusters API call"""
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Testing proxy clusters API call...\n")
            
            # First, let's check what attributes are available on the client
            self.debug_text.insert(tk.END, "Available client attributes:\n")
            client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_')]
            for attr in client_attrs:
                self.debug_text.insert(tk.END, f"  - {attr}\n")
            
            self.debug_text.insert(tk.END, "\nTrying different proxy cluster API approaches...\n")
            
            # Try different possible API endpoints
            possible_endpoints = [
                ('nodes', 'self.client.nodes.list("")'),
                ('proxy_cluster_keys', 'self.client.proxy_cluster_keys.list("")'),
                ('clusters', 'getattr(self.client, "clusters", None)'),
                ('proxies', 'getattr(self.client, "proxies", None)')
            ]
            
            found_clusters = False
            for endpoint_name, endpoint_code in possible_endpoints:
                try:
                    self.debug_text.insert(tk.END, f"\nTrying {endpoint_name}...\n")
                    
                    if endpoint_name == 'nodes':
                        clusters_response = self.client.nodes.list("")
                        clusters_list = list(clusters_response)
                        
                        self.debug_text.insert(tk.END, f"Found {len(clusters_list)} nodes:\n")
                        for node in clusters_list:
                            self.debug_text.insert(tk.END, f"  - {node.name} (Type: {type(node).__name__})\n")
                            # Check if this is a proxy cluster node
                            for attr in ['type', 'kind', 'role']:
                                if hasattr(node, attr):
                                    value = getattr(node, attr)
                                    self.debug_text.insert(tk.END, f"    {attr}: {value}\n")
                        found_clusters = True
                        
                    elif endpoint_name == 'proxy_cluster_keys':
                        clusters_response = self.client.proxy_cluster_keys.list("")
                        clusters_list = list(clusters_response)
                        
                        self.debug_text.insert(tk.END, f"Found {len(clusters_list)} proxy cluster keys:\n")
                        for key in clusters_list:
                            self.debug_text.insert(tk.END, f"  - {getattr(key, 'name', 'unnamed')} (ID: {getattr(key, 'id', 'no-id')})\n")
                        found_clusters = True
                        
                except Exception as e:
                    self.debug_text.insert(tk.END, f"  ✗ {endpoint_name} failed: {str(e)}\n")
            
            if not found_clusters:
                self.debug_text.insert(tk.END, "\n⚠️ No proxy cluster API endpoints found. This might mean:\n")
                self.debug_text.insert(tk.END, "  1. No proxy clusters are configured in this tenant\n")
                self.debug_text.insert(tk.END, "  2. The API endpoint name is different\n")
                self.debug_text.insert(tk.END, "  3. Insufficient permissions to list clusters\n")
                
            # Also show what's currently loaded in the dropdown
            self.debug_text.insert(tk.END, f"\nCurrent dropdown values: {self.proxy_clusters}\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug proxy clusters failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)
    
    def debug_tag_management(self):
        """Debug tag management and unused tags"""
        from datetime import datetime
        try:
            self.debug_text.insert(tk.END, f"[{datetime.now()}] Exploring tag management capabilities...\n")
            
            # First, let's check for tag-related endpoints
            self.debug_text.insert(tk.END, "\n=== Searching for Tag-Related API Endpoints ===\n")
            client_attrs = [attr for attr in dir(self.client) if not attr.startswith('_')]
            tag_related = []
            
            for attr in client_attrs:
                if 'tag' in attr.lower():
                    tag_related.append(attr)
                    endpoint = getattr(self.client, attr)
                    self.debug_text.insert(tk.END, f"🏷️  Found: {attr}")
                    if hasattr(endpoint, 'list'):
                        self.debug_text.insert(tk.END, " (has list method)")
                    if hasattr(endpoint, 'create'):
                        self.debug_text.insert(tk.END, " (has create method)")
                    if hasattr(endpoint, 'delete'):
                        self.debug_text.insert(tk.END, " (has delete method)")
                    self.debug_text.insert(tk.END, "\n")
            
            if not tag_related:
                self.debug_text.insert(tk.END, "❌ No direct tag management endpoints found\n")
            
            # Get all resources and analyze tag usage
            self.debug_text.insert(tk.END, "\n=== Analyzing Tag Usage Across Resources ===\n")
            resources = list(self.client.resources.list(""))
            
            all_tags = {}  # tag_key:tag_value -> count
            resource_count = 0
            
            for resource in resources:
                resource_count += 1
                if hasattr(resource, 'tags') and resource.tags:
                    for tag_key, tag_value in resource.tags.items():
                        tag_combo = f"{tag_key}={tag_value}" if tag_value else tag_key
                        all_tags[tag_combo] = all_tags.get(tag_combo, 0) + 1
            
            self.debug_text.insert(tk.END, f"📊 Analyzed {resource_count} resources\n")
            self.debug_text.insert(tk.END, f"📋 Found {len(all_tags)} unique tag combinations:\n\n")
            
            # Sort tags by usage (most used first)
            sorted_tags = sorted(all_tags.items(), key=lambda x: x[1], reverse=True)
            
            for tag, count in sorted_tags:
                self.debug_text.insert(tk.END, f"  • {tag} (used {count} times)\n")
            
            # Look for potential cleanup candidates
            self.debug_text.insert(tk.END, "\n=== Tag Cleanup Analysis ===\n")
            single_use_tags = [tag for tag, count in sorted_tags if count == 1]
            
            if single_use_tags:
                self.debug_text.insert(tk.END, f"⚠️  Found {len(single_use_tags)} tags used only once:\n")
                for tag in single_use_tags:
                    self.debug_text.insert(tk.END, f"  • {tag}\n")
            else:
                self.debug_text.insert(tk.END, "✅ No single-use tags found\n")
            
            # Note about tag management
            self.debug_text.insert(tk.END, "\n=== Tag Management Notes ===\n")
            self.debug_text.insert(tk.END, "📝 Tags are managed at the resource level in StrongDM\n")
            self.debug_text.insert(tk.END, "📝 To delete unused tags, update/remove them from resources\n")
            self.debug_text.insert(tk.END, "📝 No separate tag entity management endpoint appears to exist\n")
            
            self.debug_text.insert(tk.END, "\n✅ Tag analysis completed\n\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"✗ Debug tag management failed: {str(e)}\n")
            
        self.debug_text.see(tk.END)

    def setup_secrets_tab(self):
        """Setup secrets management tab"""

        # Create main container with canvas for scrolling
        secrets_canvas = tk.Canvas(self.secrets_frame, bg=self.bg_color)
        secrets_scrollbar = ttk.Scrollbar(self.secrets_frame, orient="vertical", command=secrets_canvas.yview)
        secrets_scrollable_frame = ttk.Frame(secrets_canvas)

        secrets_scrollable_frame.bind(
            "<Configure>",
            lambda e: secrets_canvas.configure(scrollregion=secrets_canvas.bbox("all"))
        )

        secrets_window = secrets_canvas.create_window((0, 0), window=secrets_scrollable_frame, anchor="nw")
        secrets_canvas.configure(yscrollcommand=secrets_scrollbar.set)

        # Make canvas scale with window width
        secrets_canvas.bind(
            "<Configure>",
            lambda e: secrets_canvas.itemconfig(secrets_window, width=e.width)
        )

        # Header section
        header_frame = ttk.Frame(secrets_scrollable_frame)
        header_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(header_frame, text="Managed Secrets",
                 font=('Segoe UI', 14, 'bold'),
                 foreground=self.primary_color).pack(side="left")

        ttk.Button(header_frame, text="🔄 Refresh",
                  command=self.load_secrets).pack(side="right", padx=5)

        # Info section - Common issues and requirements
        info_frame = ttk.LabelFrame(secrets_scrollable_frame, text="ℹ️ Requirements & Common Issues")
        info_frame.pack(fill="x", padx=10, pady=5)

        info_text = tk.Text(info_frame, height=4, wrap=tk.WORD,
                           bg='#fffef0', fg='#1f2937',
                           font=('Segoe UI', 9),
                           relief='flat', borderwidth=0)
        info_text.pack(fill="x", padx=5, pady=5)

        info_content = """Common Issues:
• "No nodes match engine tags": Secret engine requires specific gateway tags. Ensure gateways have matching tags.
• "Permission denied": Your API key lacks necessary permissions. Contact admin for access.
• Rotation timeout: Operations can take 30+ seconds. Verify gateway connectivity to target systems."""

        info_text.insert("1.0", info_content)
        info_text.config(state=tk.DISABLED)

        # Actions frame - moved up, now right after info section
        actions_frame = ttk.LabelFrame(secrets_scrollable_frame, text="Actions")
        actions_frame.pack(fill="x", padx=10, pady=5)

        # Action buttons
        button_frame = ttk.Frame(actions_frame)
        button_frame.pack(pady=10)

        # Add Secret button removed - function disabled per user request
        # ttk.Button(button_frame, text="➕ Add Secret",
        #           command=self.add_secret,
        #           width=15).pack(side="left", padx=5)

        ttk.Button(button_frame, text="✓ Validate",
                  command=self.validate_secret,
                  width=15).pack(side="left", padx=5)

        ttk.Button(button_frame, text="🔄 Rotate",
                  command=self.rotate_secret,
                  width=15).pack(side="left", padx=5)

        ttk.Button(button_frame, text="👁 Retrieve",
                  command=self.retrieve_secret,
                  width=15).pack(side="left", padx=5)

        # Secrets list frame
        list_frame = ttk.LabelFrame(secrets_scrollable_frame, text="Secrets")
        list_frame.pack(fill="x", padx=10, pady=5)

        # Create Treeview for secrets list - reduced height from 15 to 8
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill="x", padx=5, pady=5)

        # Define columns - VIEW COLUMN ADDED, plus TAGS and PATH
        columns = ("view", "name", "engine_id", "tags", "path", "last_rotated", "status")

        # Create style for larger font in treeview
        style = ttk.Style()
        style.configure("Secrets.Treeview", font=('Segoe UI', 11), rowheight=25)

        self.secrets_tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings",
                                         selectmode="browse", height=8, style="Secrets.Treeview")

        # Configure column headings and widths (VIEW COLUMN + TAGS + PATH)
        self.secrets_tree.heading("#0", text="ID")
        self.secrets_tree.heading("view", text="View")
        self.secrets_tree.heading("name", text="Secret Name")
        self.secrets_tree.heading("engine_id", text="Secret Engine")
        self.secrets_tree.heading("tags", text="Tags")
        self.secrets_tree.heading("path", text="Store Path")
        self.secrets_tree.heading("last_rotated", text="Last Rotated")
        self.secrets_tree.heading("status", text="Status")

        self.secrets_tree.column("#0", width=150, minwidth=100)
        self.secrets_tree.column("view", width=60, minwidth=50, anchor="center")
        self.secrets_tree.column("name", width=180, minwidth=120)
        self.secrets_tree.column("engine_id", width=150, minwidth=100)
        self.secrets_tree.column("tags", width=150, minwidth=100)
        self.secrets_tree.column("path", width=150, minwidth=100)
        self.secrets_tree.column("last_rotated", width=150, minwidth=100)
        self.secrets_tree.column("status", width=80, minwidth=60, anchor="center")  # Centered

        # Configure tags for status colors - using brighter colors
        self.secrets_tree.tag_configure("healthy", foreground="#00cc00")  # Bright green
        self.secrets_tree.tag_configure("unhealthy", foreground="#ff0000")  # Bright red

        # Bind click handler for view button
        self.secrets_tree.bind("<Button-1>", self.on_secret_tree_click)

        # Add scrollbar to treeview
        tree_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.secrets_tree.yview)
        self.secrets_tree.configure(yscrollcommand=tree_scrollbar.set)

        self.secrets_tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar.pack(side="right", fill="y")

        # Output section - fixed height, no expand
        output_frame = ttk.LabelFrame(secrets_scrollable_frame, text="Output")
        output_frame.pack(fill="x", padx=10, pady=5)

        self.secrets_output = tk.Text(output_frame, height=12, width=80,
                                      bg='white', fg='black',
                                      font=('Consolas', 9),
                                      relief='flat', borderwidth=1,
                                      selectbackground='#dbeafe',
                                      wrap=tk.WORD)
        secrets_output_scrollbar = ttk.Scrollbar(output_frame, orient="vertical",
                                                 command=self.secrets_output.yview)
        self.secrets_output.configure(yscrollcommand=secrets_output_scrollbar.set)

        self.secrets_output.pack(side="left", fill="x", padx=5, pady=5)
        secrets_output_scrollbar.pack(side="right", fill="y", pady=5)

        # Pack canvas and scrollbar
        secrets_canvas.pack(side="left", fill="both", expand=True)
        secrets_scrollbar.pack(side="right", fill="y")

        # Load secrets automatically
        self.root.after(100, self.load_secrets)

    def load_secrets(self):
        """Load and display managed secrets"""
        try:
            # Build output message chronologically
            output = f"[{datetime.now().strftime('%H:%M:%S')}] Loading secrets...\n"

            # Clear existing items
            for item in self.secrets_tree.get_children():
                self.secrets_tree.delete(item)

            # List all managed secrets
            secrets = list(self.client.managed_secrets.list(""))

            output += f"Found {len(secrets)} managed secret(s)\n"

            if not secrets:
                output += "No secrets found.\n"
                self.log_secret_output(output)
                return

            # Populate tree
            for secret in secrets:
                secret_id = secret.id
                name = getattr(secret, 'name', 'N/A')
                engine_id = getattr(secret, 'secret_engine_id', 'N/A')

                # Get tags and format as comma-separated key=value pairs
                tags = getattr(secret, 'tags', {})
                if tags:
                    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()])
                else:
                    tags_str = ''

                # Get secret store path
                path = getattr(secret, 'secret_store_path', '')

                # Format last rotated date
                last_rotated = getattr(secret, 'last_rotated_at', None)
                if last_rotated:
                    last_rotated_str = last_rotated.strftime('%Y-%m-%d %H:%M:%S') if hasattr(last_rotated, 'strftime') else str(last_rotated)
                else:
                    last_rotated_str = 'Never'

                # Determine health status (green check if rotated, red X if never rotated)
                # Use colored emoji instead of plain text to avoid coloring entire row
                if last_rotated:
                    status = "✅"  # Green check emoji
                else:
                    status = "❌"  # Red X emoji

                # Insert into tree with view icon, tags, and path (no color tags)
                item_id = self.secrets_tree.insert("", "end", text=secret_id,
                                        values=("👁", name, engine_id, tags_str, path, last_rotated_str, status),
                                        tags=(secret_id,))

            output += f"✓ Secrets loaded successfully\n"
            self.log_secret_output(output)

        except Exception as e:
            output = f"[{datetime.now().strftime('%H:%M:%S')}] Loading secrets...\n"
            output += f"✗ Error loading secrets: {str(e)}\n"
            self.log_secret_output(output)
            logger.error(f"Error loading secrets: {e}")

    def get_selected_secret(self):
        """Get the currently selected secret from the tree"""
        selection = self.secrets_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a secret first")
            return None

        item = selection[0]
        secret_id = self.secrets_tree.item(item)['text']
        return secret_id

    def log_secret_output(self, text):
        """Insert text at the top of secrets output (newest first) and auto-scroll"""
        self.secrets_output.insert("1.0", text)
        self.secrets_output.see("1.0")  # Scroll to show the newest message

    def validate_secret(self):
        """Validate a selected secret"""
        secret_id = self.get_selected_secret()
        if not secret_id:
            return

        try:
            output = f"\n[{datetime.now().strftime('%H:%M:%S')}] Validating secret {secret_id}...\n"

            # Call validate API
            result = self.client.managed_secrets.validate(secret_id)

            if result.valid:
                output += f"✓ Secret is VALID\n"
                # Update status in tree
                self.update_secret_status(secret_id, "Valid")
            else:
                invalid_info = getattr(result, 'invalid_info', 'No details provided')
                output += f"✗ Secret is INVALID: {invalid_info}\n"
                # Update status in tree
                self.update_secret_status(secret_id, "Invalid")

            self.log_secret_output(output)

        except Exception as e:
            error_msg = str(e)
            output = f"\n[{datetime.now().strftime('%H:%M:%S')}] Validating secret {secret_id}...\n"
            output += f"✗ Validation failed: {error_msg}\n"

            # Provide helpful guidance based on error type
            if "no nodes match engine tags" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • The secret engine requires specific gateway/node tags\n"
                output += "   • Ensure your gateways have matching tags configured\n"
                output += "   • Check the secret engine configuration in the Admin UI\n"
                self.update_secret_status(secret_id, "No Gateway")
            elif "permission denied" in error_msg.lower() or "access denied" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • Your API key lacks 'validate secret' permissions\n"
                output += "   • Contact your admin to grant necessary permissions\n"
                self.update_secret_status(secret_id, "No Permission")
            else:
                self.update_secret_status(secret_id, "Error")

            self.log_secret_output(output)
            logger.error(f"Error validating secret: {e}")

    def rotate_secret(self):
        """Rotate a selected secret"""
        secret_id = self.get_selected_secret()
        if not secret_id:
            return

        # Confirm rotation
        if not messagebox.askyesno("Confirm Rotation",
                                   f"Are you sure you want to rotate secret {secret_id}?\n\n"
                                   "This will generate new credentials immediately."):
            return

        try:
            output = f"\n[{datetime.now().strftime('%H:%M:%S')}] Rotating secret {secret_id}...\n"
            output += "⏳ This may take a few seconds...\n"
            self.log_secret_output(output)

            # Call rotate API (this can take time)
            result = self.client.managed_secrets.rotate(secret_id)

            self.log_secret_output(f"✓ Secret rotated successfully\n")

            # Reload secrets to show updated last_rotated time
            self.root.after(500, self.load_secrets)

        except Exception as e:
            error_msg = str(e)
            output = f"✗ Rotation failed: {error_msg}\n"

            # Provide helpful guidance based on error type
            if "no nodes match engine tags" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • The secret engine requires specific gateway/node tags\n"
                output += "   • Ensure your gateways have matching tags configured\n"
                output += "   • Check the secret engine configuration in the Admin UI\n"
                output += "   • Verify at least one gateway is online and healthy\n"
            elif "permission denied" in error_msg.lower() or "access denied" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • Your API key lacks 'rotate secret' permissions\n"
                output += "   • Contact your admin to grant necessary permissions\n"
            elif "timeout" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • Rotation timed out (this can take 30+ seconds)\n"
                output += "   • Check gateway connectivity to the target system\n"
                output += "   • Verify secret engine configuration is correct\n"

            self.log_secret_output(output)
            logger.error(f"Error rotating secret: {e}")

    def retrieve_secret_by_id(self, secret_id):
        """Retrieve a specific secret value by ID with RSA decryption"""
        # Select the secret in the tree first
        for item in self.secrets_tree.get_children():
            if self.secrets_tree.item(item)['text'] == secret_id:
                self.secrets_tree.selection_set(item)
                break

        # Call the main retrieve function
        self._do_retrieve_secret(secret_id)

    def retrieve_secret(self):
        """Retrieve a selected secret value with RSA decryption"""
        secret_id = self.get_selected_secret()
        if not secret_id:
            return

        self._do_retrieve_secret(secret_id)

    def _do_retrieve_secret(self, secret_id):
        """Internal method to retrieve and decrypt a secret"""

        output = f"\n[{datetime.now().strftime('%H:%M:%S')}] Retrieving secret {secret_id}...\n"
        output += "🔐 Generating RSA key pair for secure retrieval...\n"
        self.log_secret_output(output)

        try:
            # Step 1: Generate RSA key pair (4096 for larger secret support)
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )

            # Step 2: Export public key in PEM format (keep as bytes - SDK expects bytes)
            public_key_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.log_secret_output("📡 Requesting encrypted secret from StrongDM...\n")

            # Step 3: Call retrieve API with public key (pass as bytes)
            retrieve_response = self.client.managed_secrets.retrieve(secret_id, public_key_pem)

            # Step 4: Extract the encrypted value from response
            secret_data = retrieve_response.managed_secret
            encrypted_value = getattr(secret_data, 'value', None)

            if not encrypted_value:
                self.log_secret_output("✗ No encrypted value returned from API\n")
                return

            self.log_secret_output(f"🔓 Decrypting secret... (value type: {type(encrypted_value).__name__}, len: {len(encrypted_value) if encrypted_value else 0})\n")

            # Step 5: Decrypt the secret value using private key
            # The API returns encrypted_value as RAW BYTES (not base64 encoded)
            try:
                if isinstance(encrypted_value, bytes):
                    # Already raw encrypted bytes - use directly (512 bytes for 4096-bit RSA)
                    encrypted_bytes = encrypted_value
                elif isinstance(encrypted_value, str):
                    # If it's a string, it might be base64 encoded
                    encrypted_bytes = base64.b64decode(encrypted_value)
                else:
                    self.log_secret_output(f"✗ Unexpected encrypted value type: {type(encrypted_value)}\n")
                    return

                # Decrypt using OAEP padding
                decrypted_value = private_key.decrypt(
                    encrypted_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')

                self.log_secret_output("✓ Secret retrieved and decrypted successfully!\n")

                # Step 6: Show secret in popup dialog
                self.show_secret_popup(secret_id, secret_data, decrypted_value)

            except Exception as decrypt_error:
                self.log_secret_output(f"✗ Decryption error: {str(decrypt_error)}\n")
                self.log_secret_output(f"   Debug: encrypted_value type={type(encrypted_value)}, len={len(encrypted_value) if encrypted_value else 0}\n")
                raise  # Re-raise to be caught by outer exception handler

        except Exception as e:
            error_msg = str(e)
            output = f"✗ Retrieval failed: {error_msg}\n"

            # Provide helpful guidance based on error type
            if "message too long" in error_msg.lower() and "rsa" in error_msg.lower():
                output += "\n⚠ SECRET TOO LARGE:\n"
                output += "   • The secret value exceeds RSA-4096 encryption capacity (~446 bytes)\n"
                output += "   • RSA encryption has size limits for secure retrieval\n"
                output += "   • Consider using shorter secret values or alternative storage\n"
            elif "permission denied" in error_msg.lower() or "access denied" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • Your API key lacks 'retrieve secret' permissions\n"
                output += "   • Secret value access requires specific permissions\n"
                output += "   • Contact your admin to grant necessary permissions\n"
            elif "not found" in error_msg.lower():
                output += "\n⚠ Secret may have been deleted or ID is incorrect\n"
            elif "no nodes match engine tags" in error_msg.lower():
                output += "\n⚠ TROUBLESHOOTING:\n"
                output += "   • The secret engine requires specific gateway/node tags\n"
                output += "   • Ensure your gateways have matching tags configured\n"
            elif "expected bytes" in error_msg.lower():
                output += "\n⚠ DECRYPTION ERROR:\n"
                output += "   • The encrypted value format is unexpected\n"
                output += "   • This may indicate an SDK version mismatch\n"
                output += "   • Try restarting the application to trigger SDK upgrade\n"

            self.log_secret_output(output)
            logger.error(f"Error retrieving secret: {e}", exc_info=True)

    def show_secret_popup(self, secret_id, secret_data, decrypted_value):
        """Display the decrypted secret in a popup dialog"""
        # Create popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"Secret Value - {getattr(secret_data, 'name', secret_id)}")
        popup.geometry("650x500")
        popup.configure(bg='#f8f9fa')
        popup.resizable(True, True)

        # Center the popup
        popup.update_idletasks()
        x = (popup.winfo_screenwidth() // 2) - (650 // 2)
        y = (popup.winfo_screenheight() // 2) - (500 // 2)
        popup.geometry(f'650x500+{x}+{y}')

        # Warning header
        warning_frame = ttk.Frame(popup)
        warning_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(warning_frame, text="⚠️ SENSITIVE INFORMATION",
                 font=('Segoe UI', 12, 'bold'),
                 foreground='#dc2626').pack()

        ttk.Label(warning_frame, text="Do not share this secret value with unauthorized users",
                 font=('Segoe UI', 9),
                 foreground='#64748b').pack()

        # Secret metadata
        metadata_frame = ttk.LabelFrame(popup, text="Secret Information")
        metadata_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(metadata_frame, text=f"ID: {secret_id}",
                 font=('Segoe UI', 9)).pack(anchor="w", padx=10, pady=2)
        ttk.Label(metadata_frame, text=f"Name: {getattr(secret_data, 'name', 'N/A')}",
                 font=('Segoe UI', 9)).pack(anchor="w", padx=10, pady=2)
        ttk.Label(metadata_frame, text=f"Engine: {getattr(secret_data, 'secret_engine_id', 'N/A')}",
                 font=('Segoe UI', 9)).pack(anchor="w", padx=10, pady=2)

        # Try to parse as JSON
        try:
            import json
            secret_json = json.loads(decrypted_value)
            is_json = isinstance(secret_json, dict)
        except:
            is_json = False
            secret_json = None

        if is_json and secret_json:
            # Filter fields - only show user_dn and password, skip password_policy
            filtered_fields = {}
            for key, value in secret_json.items():
                if key not in ['password_policy']:  # Skip password_policy
                    filtered_fields[key] = value

            # Calculate popup height based on number of fields
            num_fields = len(filtered_fields)
            field_height = 95  # Height per field (label + textbox + padding)
            base_height = 250  # Header + metadata + buttons
            popup_height = min(base_height + (num_fields * field_height), 700)  # Cap at 700px

            # Update popup size
            popup.geometry(f"650x{popup_height}")
            popup.update_idletasks()
            x = (popup.winfo_screenwidth() // 2) - (650 // 2)
            y = (popup.winfo_screenheight() // 2) - (popup_height // 2)
            popup.geometry(f'650x{popup_height}+{x}+{y}')

            # Create frame for JSON fields (no scrollbar needed)
            value_frame = ttk.LabelFrame(popup, text="Secret Fields")
            value_frame.pack(fill="both", expand=True, padx=10, pady=5)

            # Display each JSON field with its own copy button
            for field_name, field_value in filtered_fields.items():
                field_frame = ttk.Frame(value_frame)
                field_frame.pack(fill="x", padx=10, pady=8)

                # Field name label
                ttk.Label(field_frame, text=f"{field_name}:",
                         font=('Segoe UI', 9, 'bold'),
                         foreground='#475569').pack(anchor="w")

                # Field value and copy button container
                value_container = ttk.Frame(field_frame)
                value_container.pack(fill="x", pady=2)

                # Field value text box
                field_text = tk.Text(value_container, height=2, wrap=tk.WORD,
                                    bg='#1e1e1e', fg='#00ff00',
                                    font=('Consolas', 10, 'bold'),
                                    relief='flat', borderwidth=3,
                                    selectbackground='#3b82f6',
                                    selectforeground='white')
                field_text.pack(side="left", fill="x", expand=True, padx=(0, 5))

                # Convert non-string values to string for display
                if isinstance(field_value, dict) or isinstance(field_value, list):
                    display_value = json.dumps(field_value, indent=2)
                else:
                    display_value = str(field_value)

                field_text.insert("1.0", display_value)
                field_text.config(state=tk.NORMAL)

                # Copy button for this field
                def make_copy_func(text_widget, value, btn):
                    def copy_func():
                        popup.clipboard_clear()
                        # Convert to string if it's a dict/list
                        if isinstance(value, dict) or isinstance(value, list):
                            popup.clipboard_append(json.dumps(value))
                        else:
                            popup.clipboard_append(str(value))
                        btn.config(text="✓")
                        popup.after(2000, lambda: btn.config(text="📋"))
                    return copy_func

                copy_field_btn = ttk.Button(value_container, text="📋", width=4,
                                           command=make_copy_func(field_text, field_value, None))
                copy_field_btn.pack(side="right")
                # Update the command now that we have the button reference
                copy_field_btn.config(command=make_copy_func(field_text, field_value, copy_field_btn))

            # Bottom button frame
            button_frame = ttk.Frame(popup)
            button_frame.pack(fill="x", padx=10, pady=10)

            def copy_all_json():
                popup.clipboard_clear()
                popup.clipboard_append(decrypted_value)
                copy_all_btn.config(text="✓ Copied All!")
                popup.after(2000, lambda: copy_all_btn.config(text="📋 Copy All (JSON)"))

            copy_all_btn = ttk.Button(button_frame, text="📋 Copy All (JSON)",
                                     command=copy_all_json)
            copy_all_btn.pack(side="left", padx=5)

            ttk.Button(button_frame, text="Close",
                      command=popup.destroy).pack(side="right", padx=5)

        else:
            # Non-JSON: Display as single value (original behavior)
            value_frame = ttk.LabelFrame(popup, text="Secret Value")
            value_frame.pack(fill="both", expand=True, padx=10, pady=5)

            secret_text = tk.Text(value_frame, height=8, wrap=tk.WORD,
                                 bg='#1e1e1e', fg='#00ff00',
                                 font=('Consolas', 11, 'bold'),
                                 relief='flat', borderwidth=5,
                                 selectbackground='#3b82f6',
                                 selectforeground='white')
            secret_text.pack(fill="both", expand=True, padx=5, pady=5)

            secret_text.insert("1.0", decrypted_value)
            secret_text.config(state=tk.NORMAL)

            # Buttons
            button_frame = ttk.Frame(popup)
            button_frame.pack(fill="x", padx=10, pady=10)

            def copy_to_clipboard():
                popup.clipboard_clear()
                popup.clipboard_append(decrypted_value)
                copy_btn.config(text="✓ Copied!")
                popup.after(2000, lambda: copy_btn.config(text="📋 Copy to Clipboard"))

            copy_btn = ttk.Button(button_frame, text="📋 Copy to Clipboard",
                                 command=copy_to_clipboard)
            copy_btn.pack(side="left", padx=5)

            ttk.Button(button_frame, text="Close",
                      command=popup.destroy).pack(side="right", padx=5)

            # Focus and select all text
            secret_text.focus_set()
            secret_text.tag_add("sel", "1.0", "end")

        # Make popup modal
        popup.transient(self.root)
        popup.grab_set()
        self.root.wait_window(popup)

    def on_secret_tree_click(self, event):
        """Handle single-click on secrets tree to open view dialog"""
        # Get the region that was clicked
        region = self.secrets_tree.identify_region(event.x, event.y)
        if region != "cell":
            return

        # Get the column and item
        column = self.secrets_tree.identify_column(event.x)
        item = self.secrets_tree.identify_row(event.y)

        if not item:
            return

        # Select the item first
        self.secrets_tree.selection_set(item)

        secret_id = self.secrets_tree.item(item)['text']

        # Column #1 is the "view" column with eye icon "👁"
        if column == "#1":  # View column
            # Open view dialog showing all secret data
            self.view_secret(secret_id)

    def view_secret(self, secret_id):
        """View all secret data in a popup"""
        try:
            # Fetch secret details
            secrets = list(self.client.managed_secrets.list(f'id:{secret_id}'))
            if not secrets:
                messagebox.showerror("Error", "Secret not found")
                return

            secret = secrets[0]

            # Create view dialog
            dialog = tk.Toplevel(self.root)
            dialog.title(f"View Secret - {getattr(secret, 'name', secret_id)}")
            dialog.geometry("700x600")
            dialog.configure(bg='#f8f9fa')
            dialog.resizable(True, True)

            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (700 // 2)
            y = (dialog.winfo_screenheight() // 2) - (600 // 2)
            dialog.geometry(f'700x600+{x}+{y}')

            # Header
            header_frame = ttk.Frame(dialog)
            header_frame.pack(fill="x", padx=20, pady=10)
            ttk.Label(header_frame, text="Secret Details (All Available Data)",
                     font=('Segoe UI', 14, 'bold'),
                     foreground=self.primary_color).pack()

            # Create scrollable canvas for content
            canvas = tk.Canvas(dialog, bg='#f8f9fa')
            scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            # Make canvas scale with window width
            canvas.bind(
                "<Configure>",
                lambda e: canvas.itemconfig(canvas_window, width=e.width)
            )

            # Display all secret attributes
            data_frame = ttk.LabelFrame(scrollable_frame, text="Secret Data")
            data_frame.pack(fill="both", expand=True, padx=20, pady=10)

            # Get all attributes
            text_widget = tk.Text(data_frame, height=25, width=80,
                                 bg='white', fg='black',
                                 font=('Consolas', 10),
                                 relief='flat', borderwidth=1,
                                 wrap=tk.WORD)
            text_widget.pack(padx=10, pady=10, fill="both", expand=True)

            # Add all available data
            text_widget.insert("end", "=" * 80 + "\n")
            text_widget.insert("end", "MANAGED SECRET - ALL AVAILABLE DATA\n")
            text_widget.insert("end", "=" * 80 + "\n\n")

            # Core fields
            text_widget.insert("end", f"ID: {getattr(secret, 'id', 'N/A')}\n")
            text_widget.insert("end", f"Name: {getattr(secret, 'name', 'N/A')}\n")
            text_widget.insert("end", f"Secret Engine ID: {getattr(secret, 'secret_engine_id', 'N/A')}\n")
            text_widget.insert("end", f"Secret Store Path: {getattr(secret, 'secret_store_path', 'N/A')}\n\n")

            # Timestamps
            text_widget.insert("end", "TIMESTAMPS:\n")
            text_widget.insert("end", "-" * 40 + "\n")
            last_rotated = getattr(secret, 'last_rotated_at', None)
            if last_rotated:
                last_rotated_str = last_rotated.strftime('%Y-%m-%d %H:%M:%S') if hasattr(last_rotated, 'strftime') else str(last_rotated)
            else:
                last_rotated_str = 'Never'
            text_widget.insert("end", f"Last Rotated: {last_rotated_str}\n")

            expires_at = getattr(secret, 'expires_at', None)
            if expires_at:
                expires_str = expires_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(expires_at, 'strftime') else str(expires_at)
            else:
                expires_str = 'Never'
            text_widget.insert("end", f"Expires At: {expires_str}\n\n")

            # Tags
            text_widget.insert("end", "TAGS:\n")
            text_widget.insert("end", "-" * 40 + "\n")
            tags = getattr(secret, 'tags', {})
            if tags:
                for key, value in tags.items():
                    text_widget.insert("end", f"  {key}: {value}\n")
            else:
                text_widget.insert("end", "  No tags\n")
            text_widget.insert("end", "\n")

            # Policy
            text_widget.insert("end", "POLICY:\n")
            text_widget.insert("end", "-" * 40 + "\n")
            policy = getattr(secret, 'policy', None)
            if policy:
                text_widget.insert("end", f"{policy}\n")
            else:
                text_widget.insert("end", "  No policy configured\n")
            text_widget.insert("end", "\n")

            # Config
            text_widget.insert("end", "CONFIG:\n")
            text_widget.insert("end", "-" * 40 + "\n")
            config = getattr(secret, 'config', None)
            if config:
                text_widget.insert("end", f"{config}\n")
            else:
                text_widget.insert("end", "  No config\n")
            text_widget.insert("end", "\n")

            # Raw object dump
            text_widget.insert("end", "RAW OBJECT ATTRIBUTES:\n")
            text_widget.insert("end", "-" * 40 + "\n")
            for attr in dir(secret):
                if not attr.startswith('_') and attr not in ['from_dict', 'to_dict']:
                    try:
                        value = getattr(secret, attr, 'N/A')
                        if not callable(value):
                            text_widget.insert("end", f"{attr}: {value}\n")
                    except:
                        pass

            text_widget.config(state=tk.DISABLED)

            # Pack canvas and scrollbar
            canvas.pack(side="left", fill="both", expand=True, padx=20)
            scrollbar.pack(side="right", fill="y")

            # Close button
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill="x", padx=20, pady=10)
            ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side="right", padx=5)

            # Make modal
            dialog.transient(self.root)
            dialog.grab_set()

        except Exception as e:
            logger.error(f"Failed to view secret: {e}", exc_info=True)
            messagebox.showerror("Error", f"Failed to view secret:\n{str(e)}")

    def add_secret(self):
        """Open dialog to add a new managed secret"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Managed Secret")
        dialog.geometry("600x450")
        dialog.configure(bg='#f8f9fa')
        dialog.resizable(False, False)

        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (dialog.winfo_screenheight() // 2) - (450 // 2)
        dialog.geometry(f'600x450+{x}+{y}')

        # Header
        header_frame = ttk.Frame(dialog)
        header_frame.pack(fill="x", padx=20, pady=10)
        ttk.Label(header_frame, text="Create Managed Secret",
                 font=('Segoe UI', 14, 'bold'),
                 foreground=self.primary_color).pack()

        # Form frame
        form_frame = ttk.LabelFrame(dialog, text="Secret Details")
        form_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Name field
        ttk.Label(form_frame, text="Secret Name *", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        name_var = tk.StringVar()
        name_entry = ttk.Entry(form_frame, textvariable=name_var, width=50)
        name_entry.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        # Secret Engine field (engines are configured in secret stores)
        ttk.Label(form_frame, text="Secret Engine *", font=('Segoe UI', 9, 'bold'), foreground='red').grid(row=1, column=0, sticky="w", padx=10, pady=5)

        # Load available secret engines
        try:
            engines = list(self.client.secret_engines.list(""))
            engine_options = [f"{e.name} ({e.id})" for e in engines]
            engine_ids = {f"{e.name} ({e.id})": e.id for e in engines}
        except:
            engine_options = []
            engine_ids = {}

        engine_var = tk.StringVar()
        engine_combo = ttk.Combobox(form_frame, textvariable=engine_var, values=engine_options, state="readonly", width=47)
        engine_combo.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

        if engine_options:
            engine_combo.current(0)

        # Tags field (optional)
        ttk.Label(form_frame, text="Tags (key=value)", font=('Segoe UI', 9)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        tags_var = tk.StringVar()
        tags_entry = ttk.Entry(form_frame, textvariable=tags_var, width=50)
        tags_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

        ttk.Label(form_frame, text="Separate multiple tags with commas: env=prod,type=db",
                 font=('Segoe UI', 8), foreground='#64748b').grid(row=3, column=1, sticky="w", padx=10)

        form_frame.grid_columnconfigure(1, weight=1)

        # Info message
        info_frame = ttk.LabelFrame(dialog, text="ℹ️ Important Information")
        info_frame.pack(fill="x", padx=20, pady=5)

        info_text = tk.Text(info_frame, height=4, wrap=tk.WORD,
                           bg='#fffef0', fg='#1f2937',
                           font=('Segoe UI', 9),
                           relief='flat', borderwidth=0)
        info_text.pack(fill="x", padx=10, pady=5)

        info_content = """This creates a managed secret entry. The actual credential values (username, password, user_dn, etc.) are automatically generated by the selected secret engine.

After creation, use the "👁 Retrieve" button to view the generated credential values."""

        info_text.insert("1.0", info_content)
        info_text.config(state=tk.DISABLED)

        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill="x", padx=20, pady=10)

        def create_secret():
            name = name_var.get().strip()
            engine_selection = engine_var.get()
            tags_input = tags_var.get().strip()

            if not name:
                messagebox.showwarning("Validation Error", "Secret name is required")
                return

            if not engine_selection:
                messagebox.showwarning("Validation Error", "Secret engine is required")
                return

            engine_id = engine_ids.get(engine_selection)

            # Parse tags
            tags_dict = {}
            if tags_input:
                for tag in tags_input.split(','):
                    tag = tag.strip()
                    if '=' in tag:
                        key, value = tag.split('=', 1)
                        tags_dict[key.strip()] = value.strip()
                    else:
                        tags_dict[tag] = ""

            try:
                # Create managed secret - ONLY name, engine_id, tags
                new_secret = strongdm.ManagedSecret(
                    name=name,
                    secret_engine_id=engine_id,
                    tags=tags_dict
                )

                # Log what we're sending to API
                output = f"[{datetime.now().strftime('%H:%M:%S')}] Creating secret...\n"
                output += f"📤 Sending to StrongDM API:\n"
                output += f"   name: {new_secret.name}\n"
                output += f"   secret_engine_id: {new_secret.secret_engine_id}\n"
                output += f"   tags: {new_secret.tags}\n"
                self.log_secret_output(output)

                response = self.client.managed_secrets.create(new_secret)

                output = f"[{datetime.now().strftime('%H:%M:%S')}] Secret created successfully!\n"
                output += f"✓ Secret ID: {response.managed_secret.id}\n"
                output += f"✓ Name: {name}\n"
                output += f"✓ Engine: {engine_id}\n"
                self.log_secret_output(output)

                # Reload secrets
                self.load_secrets()
                dialog.destroy()
                messagebox.showinfo("Success", f"Secret '{name}' created successfully!")

            except Exception as e:
                error_msg = str(e)
                output = f"[{datetime.now().strftime('%H:%M:%S')}] Failed to create secret\n"
                output += f"✗ Error: {error_msg}\n"

                # Add troubleshooting tips for common errors
                if "could not decrypt a secret value" in error_msg.lower():
                    output += "\n⚠ BACKEND ERROR - 'could not decrypt a secret value'\n\n"
                    output += "   This error occurs when the StrongDM backend cannot process the secret.\n"
                    output += "   The API call from the client is correct (as shown above).\n\n"
                    output += "   POSSIBLE CAUSES:\n\n"
                    output += "   1. SECRET ENGINE CONFIGURATION:\n"
                    output += "      • Secret engine may not be fully configured\n"
                    output += "      • Engine credentials may be incorrect or expired\n"
                    output += "      • Test the engine in StrongDM Admin UI first\n\n"
                    output += "   2. GATEWAY/CONNECTIVITY:\n"
                    output += "      • Gateway cannot reach the target system\n"
                    output += "      • Network/firewall blocking connection\n"
                    output += "      • Gateway tags don't match engine requirements\n\n"
                    output += "   3. BACKEND/POLICY ISSUE:\n"
                    output += "      • Cedar policies may be misconfigured\n"
                    output += "      • Internal backend error\n"
                    output += "      • Contact StrongDM support: support@strongdm.com\n"

                self.log_secret_output(output)
                messagebox.showerror("Error", f"Failed to create secret:\n{error_msg}")

        ttk.Button(button_frame, text="✓ Create Secret", command=create_secret).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)

        # Make modal
        dialog.transient(self.root)
        dialog.grab_set()
        name_entry.focus_set()

    def view_secret(self, secret_id):
        """View secret configuration (read-only)"""
        try:
            # Fetch secret details
            secrets = list(self.client.managed_secrets.list(f'id:{secret_id}'))
            if not secrets:
                messagebox.showerror("Error", "Secret not found")
                return

            secret = secrets[0]

            # DEBUG: Log all attributes of secret object - COMPREHENSIVE
            logger.info(f"\n{'='*80}")
            logger.info(f"SECRET OBJECT COMPREHENSIVE DEBUG FOR: {getattr(secret, 'name', 'N/A')}")
            logger.info(f"{'='*80}")
            logger.info(f"Type: {type(secret).__name__}")
            secret_attrs = [a for a in dir(secret) if not a.startswith('_')]
            logger.info(f"All attributes: {', '.join(secret_attrs)}")

            # Log actual values of all non-callable attributes
            for attr in secret_attrs:
                try:
                    val = getattr(secret, attr, None)
                    if not callable(val):
                        # Special handling for nested objects
                        if hasattr(val, '__dict__') or (hasattr(val, '__class__') and hasattr(val.__class__, '__name__')):
                            logger.info(f"  {attr} = <{type(val).__name__} object>")
                            # If it's a nested object, show its attributes too
                            if hasattr(val, '__dict__'):
                                for sub_attr in dir(val):
                                    if not sub_attr.startswith('_'):
                                        try:
                                            sub_val = getattr(val, sub_attr, None)
                                            if not callable(sub_val):
                                                logger.info(f"    {attr}.{sub_attr} = {sub_val}")
                                        except:
                                            pass
                        else:
                            logger.info(f"  {attr} = {val}")
                except Exception as e:
                    logger.info(f"  {attr} = ERROR: {e}")
            logger.info(f"{'='*80}\n")

            # Fetch the secret engine to get rotation/policy settings
            secret_engine = None
            engine_id = getattr(secret, 'secret_engine_id', None)
            if engine_id:
                try:
                    engines = list(self.client.secret_engines.list(f'id:{engine_id}'))
                    if engines:
                        secret_engine = engines[0]

                        # DEBUG: Log all attributes of secret_engine
                        logger.info(f"SECRET ENGINE OBJECT DEBUG:")
                        logger.info(f"Type: {type(secret_engine).__name__}")
                        all_attrs = [a for a in dir(secret_engine) if not a.startswith('_')]
                        logger.info(f"All attributes: {', '.join(all_attrs)}")

                        # Log actual values of all non-callable attributes
                        for attr in all_attrs:
                            try:
                                val = getattr(secret_engine, attr, None)
                                if not callable(val):
                                    logger.info(f"  {attr} = {val}")
                            except:
                                pass

                except Exception as e:
                    logger.warning(f"Could not fetch secret engine {engine_id}: {e}")

            # Create view dialog with scrollable content
            dialog = tk.Toplevel(self.root)
            dialog.title(f"View Secret - {getattr(secret, 'name', secret_id)}")
            dialog.geometry("650x700")
            dialog.configure(bg='#f8f9fa')
            dialog.resizable(True, True)

            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (650 // 2)
            y = (dialog.winfo_screenheight() // 2) - (700 // 2)
            dialog.geometry(f'650x700+{x}+{y}')

            # Header
            header_frame = ttk.Frame(dialog)
            header_frame.pack(fill="x", padx=20, pady=10)
            ttk.Label(header_frame, text="Secret Configuration",
                     font=('Segoe UI', 14, 'bold'),
                     foreground=self.primary_color).pack()

            # Create scrollable canvas for content
            canvas = tk.Canvas(dialog, bg='#f8f9fa')
            scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            # Make canvas scale with window width
            canvas.bind(
                "<Configure>",
                lambda e: canvas.itemconfig(canvas_window, width=e.width)
            )

            # Details frame
            details_frame = ttk.LabelFrame(scrollable_frame, text="Basic Information")
            details_frame.pack(fill="x", padx=20, pady=10)

            # Display fields (read-only)
            row = 0

            # ID
            ttk.Label(details_frame, text="Secret ID:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            id_text = tk.Text(details_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            id_text.insert("1.0", secret_id)
            id_text.config(state=tk.DISABLED)
            id_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Name
            ttk.Label(details_frame, text="Name:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            name_text = tk.Text(details_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            name_text.insert("1.0", getattr(secret, 'name', 'N/A'))
            name_text.config(state=tk.DISABLED)
            name_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Engine ID
            ttk.Label(details_frame, text="Secret Engine:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            engine_text = tk.Text(details_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            engine_text.insert("1.0", getattr(secret, 'secret_engine_id', 'N/A'))
            engine_text.config(state=tk.DISABLED)
            engine_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Last Rotated
            ttk.Label(details_frame, text="Last Rotated:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            last_rotated = getattr(secret, 'last_rotated_at', None)
            if last_rotated:
                last_rotated_str = last_rotated.strftime('%Y-%m-%d %H:%M:%S') if hasattr(last_rotated, 'strftime') else str(last_rotated)
            else:
                last_rotated_str = 'Never'
            rotated_text = tk.Text(details_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            rotated_text.insert("1.0", last_rotated_str)
            rotated_text.config(state=tk.DISABLED)
            rotated_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Tags
            ttk.Label(details_frame, text="Tags:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="nw", padx=10, pady=5)
            tags = getattr(secret, 'tags', {})
            tags_str = ", ".join([f"{k}={v}" if v else k for k, v in tags.items()]) if tags else "None"
            tags_text = tk.Text(details_frame, height=3, width=50, bg='#e2e8f0', relief='flat', wrap=tk.WORD)
            tags_text.insert("1.0", tags_str)
            tags_text.config(state=tk.DISABLED)
            tags_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)

            details_frame.grid_columnconfigure(1, weight=1)

            # Rotation Settings Frame
            rotation_frame = ttk.LabelFrame(scrollable_frame, text="Rotation & Timeout Settings")
            rotation_frame.pack(fill="x", padx=20, pady=10)

            row = 0

            # Credential Rotation Interval (check secret first, then engine)
            ttk.Label(rotation_frame, text="Rotation Interval:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)

            # Get engine default
            engine_rotation_days = getattr(secret_engine, 'key_rotation_interval_days', 0) if secret_engine else 0

            # Check if secret has override (only if > 0 and different from engine)
            secret_rotation_days = getattr(secret, 'key_rotation_interval_days', 0)
            rotation_source = ""

            if secret_rotation_days > 0 and secret_rotation_days != engine_rotation_days:
                rotation_days = secret_rotation_days
                rotation_source = " (secret override)"
            else:
                rotation_days = engine_rotation_days
                rotation_source = " (from engine)" if engine_rotation_days > 0 else ""

            if rotation_days and rotation_days > 0:
                rotation_interval_str = f"{rotation_days} day{'s' if rotation_days != 1 else ''}{rotation_source}"
            else:
                rotation_interval_str = "Not configured (manual rotation only)"

            rotation_text = tk.Text(rotation_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            rotation_text.insert("1.0", rotation_interval_str)
            rotation_text.config(state=tk.DISABLED)
            rotation_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Connection Timeout (check secret first, then engine)
            ttk.Label(rotation_frame, text="Connection Timeout:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)

            # Get engine default
            engine_timeout = getattr(secret_engine, 'connection_timeout', 0) if secret_engine else 0

            # Check if secret has override (only if > 0 and different from engine)
            secret_timeout = getattr(secret, 'connection_timeout', 0)
            timeout_source = ""

            if secret_timeout > 0 and secret_timeout != engine_timeout:
                timeout = secret_timeout
                timeout_source = " (secret override)"
            else:
                timeout = engine_timeout
                timeout_source = " (from engine)" if engine_timeout > 0 else ""

            if timeout and timeout > 0:
                read_timeout_str = f"{timeout} seconds{timeout_source}"
            else:
                read_timeout_str = "Not configured (default)"

            timeout_text = tk.Text(rotation_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            timeout_text.insert("1.0", read_timeout_str)
            timeout_text.config(state=tk.DISABLED)
            timeout_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)

            rotation_frame.grid_columnconfigure(1, weight=1)

            # Password Policy Frame
            policy_frame = ttk.LabelFrame(scrollable_frame, text="Password Policy")
            policy_frame.pack(fill="x", padx=20, pady=10)

            row = 0

            # Get password policy - check secret first for overrides, then fall back to engine
            password_policy = {}
            policy_source = "Not configured"

            # First, get engine policy as baseline
            if secret_engine:
                # Get policy object from secret_engine
                policy_obj = getattr(secret_engine, 'policy', None)

                if policy_obj:
                    # Get password_policy from policy object
                    pwd_policy = getattr(policy_obj, 'password_policy', None)

                    if pwd_policy:
                        # Convert to dict by reading attributes (engine defaults)
                        password_policy = {
                            'length': getattr(pwd_policy, 'length', 'Not set'),
                            'num_digits': getattr(pwd_policy, 'num_digits', 'Not set'),
                            'num_symbols': getattr(pwd_policy, 'num_symbols', 'Not set'),
                            'exclude_characters': getattr(pwd_policy, 'exclude_characters', 'Not set'),
                            'exclude_upper_case': getattr(pwd_policy, 'exclude_upper_case', False),
                            'allow_repeat': getattr(pwd_policy, 'allow_repeat', False),
                        }
                        policy_source = f"Engine: {getattr(secret_engine, 'name', 'N/A')}"
                        logger.info(f"Engine password policy loaded: {password_policy}")

            # Second, check if secret has override policy
            secret_policy_obj = getattr(secret, 'policy', None)
            has_overrides = False

            if secret_policy_obj:
                secret_pwd_policy = getattr(secret_policy_obj, 'password_policy', None)

                if secret_pwd_policy:
                    # Get secret-specific policy values
                    secret_overrides = {
                        'length': getattr(secret_pwd_policy, 'length', 0),
                        'num_digits': getattr(secret_pwd_policy, 'num_digits', 0),
                        'num_symbols': getattr(secret_pwd_policy, 'num_symbols', 0),
                        'exclude_characters': getattr(secret_pwd_policy, 'exclude_characters', ''),
                        'exclude_upper_case': getattr(secret_pwd_policy, 'exclude_upper_case', None),
                        'allow_repeat': getattr(secret_pwd_policy, 'allow_repeat', None),
                    }

                    # Only apply overrides if they're meaningful (non-zero, non-empty, or different from engine)
                    for key, val in secret_overrides.items():
                        # For numbers: only override if > 0
                        if key in ['length', 'num_digits', 'num_symbols'] and val > 0:
                            if password_policy.get(key) != val:
                                password_policy[key] = val
                                has_overrides = True
                        # For strings: only override if not empty
                        elif key == 'exclude_characters' and val != '':
                            if password_policy.get(key) != val:
                                password_policy[key] = val
                                has_overrides = True
                        # For bools: only override if different from engine default
                        elif key in ['exclude_upper_case', 'allow_repeat'] and val is not None:
                            if password_policy.get(key) != val:
                                password_policy[key] = val
                                has_overrides = True

                    if has_overrides:
                        policy_source = f"Secret Override (from {getattr(secret, 'name', 'N/A')})"
                        logger.info(f"Secret has password policy overrides: {secret_overrides}")
                        logger.info(f"Final merged password policy: {password_policy}")
                    else:
                        logger.info(f"Secret has no meaningful password policy overrides, using engine defaults")

            # Length
            ttk.Label(policy_frame, text="Length:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            length = password_policy.get('length', 'Not set')
            length_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            length_text.insert("1.0", str(length) if length != 'Not set' else "Not configured")
            length_text.config(state=tk.DISABLED)
            length_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Number of Digits
            ttk.Label(policy_frame, text="Number of Digits:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            digits = password_policy.get('num_digits', 'Not set')
            digits_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            digits_text.insert("1.0", str(digits) if digits != 'Not set' else "Not configured")
            digits_text.config(state=tk.DISABLED)
            digits_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Number of Symbols
            ttk.Label(policy_frame, text="Number of Symbols:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            symbols = password_policy.get('num_symbols', 'Not set')
            symbols_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            symbols_text.insert("1.0", str(symbols) if symbols != 'Not set' else "Not configured")
            symbols_text.config(state=tk.DISABLED)
            symbols_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Exclude Characters
            ttk.Label(policy_frame, text="Exclude Characters:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            exclude_chars = password_policy.get('exclude_characters', 'Not set')
            exclude_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            # Show empty string if it's empty, otherwise show the value
            display_chars = exclude_chars if exclude_chars and exclude_chars != 'Not set' else ("(none)" if exclude_chars == '' else "Not configured")
            exclude_text.insert("1.0", display_chars)
            exclude_text.config(state=tk.DISABLED)
            exclude_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Exclude Uppercase
            ttk.Label(policy_frame, text="Exclude Uppercase:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            exclude_uppercase = password_policy.get('exclude_upper_case', False)
            uppercase_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            uppercase_text.insert("1.0", "Yes" if exclude_uppercase else "No")
            uppercase_text.config(state=tk.DISABLED)
            uppercase_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Allow Repeat
            ttk.Label(policy_frame, text="Allow Repeat:", font=('Segoe UI', 9, 'bold')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            allow_repeat = password_policy.get('allow_repeat', False)
            repeat_text = tk.Text(policy_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            repeat_text.insert("1.0", "Yes" if allow_repeat else "No")
            repeat_text.config(state=tk.DISABLED)
            repeat_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
            row += 1

            # Policy Source
            ttk.Label(policy_frame, text="Settings Source:", font=('Segoe UI', 9, 'bold', 'italic')).grid(row=row, column=0, sticky="w", padx=10, pady=5)
            source_text = tk.Text(policy_frame, height=1, width=50, bg='#fffef0', relief='flat', font=('Segoe UI', 9, 'italic'))
            source_text.insert("1.0", policy_source)
            source_text.config(state=tk.DISABLED)
            source_text.grid(row=row, column=1, sticky="ew", padx=10, pady=5)

            policy_frame.grid_columnconfigure(1, weight=1)

            # Info note about rotation/policy settings
            if not secret_engine:
                note_frame = ttk.LabelFrame(scrollable_frame, text="ℹ️ Note")
                note_frame.pack(fill="x", padx=20, pady=10)
                note_text = tk.Text(note_frame, height=2, wrap=tk.WORD, bg='#fffef0', fg='#1f2937',
                                   font=('Segoe UI', 9), relief='flat', borderwidth=0)
                note_text.insert("1.0", "Could not load Secret Engine details. Rotation and password policy settings are configured at the Secret Engine level. Check the StrongDM Admin UI for these settings.")
                note_text.config(state=tk.DISABLED)
                note_text.pack(fill="x", padx=5, pady=5)

            # Pack canvas and scrollbar
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill="x", padx=20, pady=10)

            ttk.Button(button_frame, text="📝 Edit", command=lambda: [dialog.destroy(), self.edit_secret(secret_id)]).pack(side="left", padx=5)
            ttk.Button(button_frame, text="👁 Retrieve Values", command=lambda: [dialog.destroy(), self.retrieve_secret_by_id(secret_id)]).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side="right", padx=5)

            # Make modal
            dialog.transient(self.root)
            dialog.grab_set()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load secret:\n{str(e)}")

    def edit_secret(self, secret_id):
        """Edit secret configuration"""
        try:
            # Fetch secret details
            secrets = list(self.client.managed_secrets.list(f'id:{secret_id}'))
            if not secrets:
                messagebox.showerror("Error", "Secret not found")
                return

            secret = secrets[0]

            # Create edit dialog with scrollable content
            dialog = tk.Toplevel(self.root)
            dialog.title(f"Edit Secret - {getattr(secret, 'name', secret_id)}")
            dialog.geometry("700x750")
            dialog.configure(bg='#f8f9fa')
            dialog.resizable(True, True)

            # Center dialog
            dialog.update_idletasks()
            x = (dialog.winfo_screenwidth() // 2) - (700 // 2)
            y = (dialog.winfo_screenheight() // 2) - (750 // 2)
            dialog.geometry(f'700x750+{x}+{y}')

            # Header
            header_frame = ttk.Frame(dialog)
            header_frame.pack(fill="x", padx=20, pady=10)
            ttk.Label(header_frame, text="Edit Secret Configuration",
                     font=('Segoe UI', 14, 'bold'),
                     foreground=self.primary_color).pack()

            # Create scrollable canvas for content
            canvas = tk.Canvas(dialog, bg='#f8f9fa')
            scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            # Make canvas scale with window width
            canvas.bind(
                "<Configure>",
                lambda e: canvas.itemconfig(canvas_window, width=e.width)
            )

            # Basic Info Frame
            form_frame = ttk.LabelFrame(scrollable_frame, text="Basic Information")
            form_frame.pack(fill="x", padx=20, pady=10)

            # ID (read-only)
            ttk.Label(form_frame, text="Secret ID", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky="w", padx=10, pady=5)
            id_text = tk.Text(form_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            id_text.insert("1.0", secret_id)
            id_text.config(state=tk.DISABLED)
            id_text.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

            # Name (editable)
            ttk.Label(form_frame, text="Name *", font=('Segoe UI', 9, 'bold')).grid(row=1, column=0, sticky="w", padx=10, pady=5)
            name_var = tk.StringVar(value=getattr(secret, 'name', ''))
            name_entry = ttk.Entry(form_frame, textvariable=name_var, width=50)
            name_entry.grid(row=1, column=1, sticky="ew", padx=10, pady=5)

            # Tags (editable)
            ttk.Label(form_frame, text="Tags", font=('Segoe UI', 9, 'bold')).grid(row=2, column=0, sticky="w", padx=10, pady=5)
            tags = getattr(secret, 'tags', {})
            tags_str = ", ".join([f"{k}={v}" if v else k for k, v in tags.items()])
            tags_var = tk.StringVar(value=tags_str)
            tags_entry = ttk.Entry(form_frame, textvariable=tags_var, width=50)
            tags_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=5)

            ttk.Label(form_frame, text="Separate multiple tags with commas: env=prod,type=db",
                     font=('Segoe UI', 8), foreground='#64748b').grid(row=3, column=1, sticky="w", padx=10)

            # Engine (read-only - can't change engine)
            ttk.Label(form_frame, text="Secret Engine", font=('Segoe UI', 9, 'bold')).grid(row=4, column=0, sticky="w", padx=10, pady=5)
            engine_text = tk.Text(form_frame, height=1, width=50, bg='#e2e8f0', relief='flat')
            engine_text.insert("1.0", getattr(secret, 'secret_engine_id', 'N/A'))
            engine_text.config(state=tk.DISABLED)
            engine_text.grid(row=4, column=1, sticky="ew", padx=10, pady=5)

            ttk.Label(form_frame, text="Note: Secret engine cannot be changed after creation",
                     font=('Segoe UI', 8), foreground='#64748b').grid(row=5, column=1, sticky="w", padx=10)

            form_frame.grid_columnconfigure(1, weight=1)

            # Note about rotation/policy settings
            note_frame = ttk.LabelFrame(scrollable_frame, text="ℹ️ Additional Settings")
            note_frame.pack(fill="x", padx=20, pady=10)
            ttk.Label(note_frame, text="Rotation intervals and password policies are configured at the Secret Engine level,\nnot per-secret. Edit those settings in the StrongDM Admin UI for the secret engine.",
                     font=('Segoe UI', 9), foreground='#64748b', justify="left").pack(padx=10, pady=10)

            # Pack canvas and scrollbar
            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Buttons
            button_frame = ttk.Frame(dialog)
            button_frame.pack(fill="x", padx=20, pady=10)

            def save_changes():
                name = name_var.get().strip()
                tags_input = tags_var.get().strip()

                if not name:
                    messagebox.showwarning("Validation Error", "Secret name is required")
                    return

                # Parse tags
                tags_dict = {}
                if tags_input:
                    for tag in tags_input.split(','):
                        tag = tag.strip()
                        if '=' in tag:
                            key, value = tag.split('=', 1)
                            tags_dict[key.strip()] = value.strip()
                        else:
                            tags_dict[tag] = ""

                try:
                    # SIMPLIFIED UPDATE: Only update name and tags
                    current_name = getattr(secret, 'name', '')
                    current_tags = getattr(secret, 'tags', {})

                    # Check if anything actually changed
                    name_changed = name != current_name
                    tags_changed = tags_dict != current_tags

                    if not (name_changed or tags_changed):
                        output = f"[{datetime.now().strftime('%H:%M:%S')}] No changes detected\n"
                        output += f"ℹ️ Name and tags are already set to these values\n"
                        output += f"   Current name: {current_name}\n"
                        output += f"   Current tags: {current_tags}\n"
                        self.log_secret_output(output)
                        dialog.destroy()
                        messagebox.showinfo("No Changes", "No changes were made to the secret.")
                        return

                    # Create minimal update object - BARE MINIMUM
                    clean_secret = strongdm.ManagedSecret(
                        id=secret.id,
                        name=name,
                        secret_engine_id=secret.secret_engine_id,
                        tags=tags_dict
                    )

                    # Log what we're sending
                    output = f"[{datetime.now().strftime('%H:%M:%S')}] Updating secret...\n"
                    output += f"📤 Sending to StrongDM API:\n"
                    output += f"   id: {clean_secret.id}\n"
                    output += f"   name: {clean_secret.name}\n"
                    output += f"   secret_engine_id: {clean_secret.secret_engine_id}\n"
                    output += f"   tags: {clean_secret.tags}\n"
                    self.log_secret_output(output)

                    response = self.client.managed_secrets.update(clean_secret)

                    output = f"[{datetime.now().strftime('%H:%M:%S')}] Secret updated successfully!\n"
                    output += f"✓ Secret ID: {secret_id}\n"
                    output += f"✓ Name: {name}\n"
                    self.log_secret_output(output)

                    # Reload secrets
                    self.load_secrets()
                    dialog.destroy()
                    messagebox.showinfo("Success", f"Secret '{name}' updated successfully!")

                except Exception as e:
                    error_msg = str(e)
                    output = f"[{datetime.now().strftime('%H:%M:%S')}] Failed to update secret\n"
                    output += f"✗ Error: {error_msg}\n"

                    # Add troubleshooting tips for common errors
                    if "could not decrypt a secret value" in error_msg.lower():
                        output += "\n⚠ BACKEND ERROR - 'could not decrypt a secret value'\n\n"
                        output += "   This error occurs when the StrongDM backend cannot process the update.\n"
                        output += "   The API call from the client is correct (as shown above).\n"
                        output += "   Updates should only modify metadata (name, tags).\n\n"
                        output += "   POSSIBLE CAUSES:\n\n"
                        output += "   1. BACKEND TRIGGERING VALIDATION:\n"
                        output += "      • Backend may be incorrectly validating the secret\n"
                        output += "      • This should NOT happen for metadata-only updates\n\n"
                        output += "   2. SECRET ENGINE ISSUE:\n"
                        output += "      • Engine configuration may have changed\n"
                        output += "      • Gateway connectivity issues\n\n"
                        output += "   3. BACKEND/POLICY ISSUE:\n"
                        output += "      • Cedar policies may be misconfigured\n"
                        output += "      • Internal backend error\n"
                        output += "      • Contact StrongDM support: support@strongdm.com\n"

                    self.log_secret_output(output)
                    messagebox.showerror("Error", f"Failed to update secret:\n{error_msg}")

            ttk.Button(button_frame, text="✓ Save Changes", command=save_changes).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)

            # Make modal
            dialog.transient(self.root)
            dialog.grab_set()
            name_entry.focus_set()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to load secret:\n{str(e)}")

    def update_secret_status(self, secret_id, status):
        """Update the status column for a secret in the tree"""
        for item in self.secrets_tree.get_children():
            if self.secrets_tree.item(item)['text'] == secret_id:
                current_values = self.secrets_tree.item(item)['values']
                new_values = list(current_values)
                new_values[4] = status  # Update status column (now index 4 instead of 3 due to actions column)
                self.secrets_tree.item(item, values=new_values)
                break

    def setup_api_logs_tab(self):
        """Setup API logs tab"""
        
        # Control buttons
        control_frame = ttk.LabelFrame(self.api_logs_frame, text="API Logging Controls")
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="🔄 Refresh Logs", 
                  command=self.refresh_api_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="🗑️ Clear Logs", 
                  command=self.clear_api_logs).pack(side="left", padx=5)
        ttk.Button(control_frame, text="📋 Copy All", 
                  command=self.copy_api_logs).pack(side="left", padx=5)
        
        # Enable/Disable logging (use existing variable)
        ttk.Checkbutton(control_frame, text="Enable API Logging", 
                       variable=self.api_logging_enabled).pack(side="left", padx=10)
        
        # API Logs Output
        logs_frame = ttk.LabelFrame(self.api_logs_frame, text="API Request/Response Logs")
        logs_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.api_logs_text = tk.Text(logs_frame, height=25, 
                                    bg='white', fg='black',
                                    font=('Consolas', 9), 
                                    relief='flat', borderwidth=1,
                                    selectbackground='#dbeafe')
        api_scrollbar = ttk.Scrollbar(logs_frame, orient="vertical", command=self.api_logs_text.yview)
        self.api_logs_text.configure(yscrollcommand=api_scrollbar.set)
        
        self.api_logs_text.pack(side="left", fill="both", expand=True)
        api_scrollbar.pack(side="right", fill="y")
        
    def refresh_api_logs(self):
        """Refresh API logs display"""
        logs_content = self.api_log_buffer.getvalue()
        self.api_logs_text.delete(1.0, tk.END)
        self.api_logs_text.insert(1.0, logs_content)
        self.api_logs_text.see(tk.END)
        
    def clear_api_logs(self):
        """Clear API logs"""
        self.api_log_buffer.seek(0)
        self.api_log_buffer.truncate(0)
        self.api_logs_text.delete(1.0, tk.END)
        
    def copy_api_logs(self):
        """Copy API logs to clipboard"""
        logs_content = self.api_log_buffer.getvalue()
        self.root.clipboard_clear()
        self.root.clipboard_append(logs_content)
        messagebox.showinfo("Copied", "API logs copied to clipboard!")
        
    def log_api_call(self, method, endpoint, data=None, response=None):
        """Log API call details"""
        if not self.api_logging_enabled.get():
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        log_entry = f"\n{'='*60}\n"
        log_entry += f"[{timestamp}] {method} {endpoint}\n"
        log_entry += f"{'='*60}\n"
        
        if data:
            log_entry += f"REQUEST DATA:\n{json.dumps(data, indent=2, default=str)}\n\n"
        
        if response:
            if hasattr(response, '__dict__'):
                # Convert object to dict
                response_dict = {}
                for attr in dir(response):
                    if not attr.startswith('_'):
                        try:
                            value = getattr(response, attr)
                            if not callable(value):
                                response_dict[attr] = value
                        except:
                            pass
                log_entry += f"RESPONSE:\n{json.dumps(response_dict, indent=2, default=str)}\n"
            else:
                log_entry += f"RESPONSE:\n{response}\n"
        
        self.api_log_buffer.write(log_entry)
        
        # Auto-refresh API logs display if it exists
        if hasattr(self, 'api_logs_text'):
            try:
                self.root.after_idle(self.refresh_api_logs)
            except:
                pass  # Widget might not exist yet
        
    def save_credentials(self):
        """Save API credentials to local config file"""
        try:
            # Create config directory if it doesn't exist
            self.config_dir.mkdir(exist_ok=True)
            
            # Simple encoding (not encryption, just obfuscation)
            access_key = base64.b64encode(self.access_key_var.get().encode()).decode()
            secret_key = base64.b64encode(self.secret_key_var.get().encode()).decode()
            
            config = {
                "access_key": access_key,
                "secret_key": secret_key,
                "saved_at": datetime.now().isoformat()
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            logger.info("Credentials saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")
            messagebox.showerror("Error", f"Failed to save credentials: {str(e)}")
            
    def load_saved_credentials(self):
        """Load saved API credentials if they exist"""
        try:
            if not self.config_file.exists():
                return
                
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                
            # Decode credentials
            access_key = base64.b64decode(config["access_key"]).decode()
            secret_key = base64.b64decode(config["secret_key"]).decode()
            
            # Set in UI
            self.access_key_var.set(access_key)
            self.secret_key_var.set(secret_key)
            self.save_credentials_var.set(True)
            
            # Show when credentials were saved
            saved_at = config.get("saved_at", "Unknown")
            self.status_label.config(text=f"Credentials loaded (saved: {saved_at[:10]}) - Attempting auto-login...", 
                                   foreground="blue")
            
            logger.info("Credentials loaded successfully - attempting auto-login")
            
            # Automatically attempt to connect
            try:
                self.authenticate()
            except Exception as auto_login_e:
                logger.error(f"Auto-login failed: {auto_login_e}")
                self.status_label.config(text=f"Auto-login failed: {str(auto_login_e)}", 
                                       foreground="red")
            
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            # Don't show error to user, just log it
            
    def clear_saved_credentials(self):
        """Clear saved credentials"""
        try:
            if self.config_file.exists():
                self.config_file.unlink()

            # Clear UI
            self.access_key_var.set("")
            self.secret_key_var.set("")
            self.save_credentials_var.set(False)
            self.status_label.config(text="Saved credentials cleared",
                                   foreground="orange")

            logger.info("Credentials cleared successfully")

        except Exception as e:
            logger.error(f"Failed to clear credentials: {e}")
            messagebox.showerror("Error", f"Failed to clear credentials: {str(e)}")

    def logout_and_reset(self):
        """Logout and reset connection to allow new API key"""
        try:
            # Clear the client connection
            self.client = None
            self.authenticated = False

            # Clear UI fields
            self.access_key_var.set("")
            self.secret_key_var.set("")
            self.save_credentials_var.set(False)

            # Reset connect button
            self.connect_button.config(text="🚀 Connect", state="normal")

            # Hide logout button
            self.logout_button.pack_forget()

            # Clear resource list
            if hasattr(self, 'resource_text'):
                self.resource_text.config(state=tk.NORMAL)
                self.resource_text.delete(1.0, tk.END)
                self.resource_text.config(state=tk.DISABLED)

            # Hide resource list frame
            if hasattr(self, 'resource_list_frame'):
                self.resource_list_frame.pack_forget()

            # Remove all tabs except login
            if hasattr(self, 'notebook'):
                for i in range(len(self.notebook.tabs()) - 1, 0, -1):
                    self.notebook.forget(i)

            # Update status
            self.status_label.config(text="Logged out. Enter new credentials to reconnect.",
                                   foreground="blue")

            logger.info("Successfully logged out and reset connection")

        except Exception as e:
            logger.error(f"Failed to logout: {e}")
            messagebox.showerror("Error", f"Failed to logout: {str(e)}")

    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    # Create splash screen for SDK update
    splash = tk.Tk()
    splash.title("StrongDM Manager")
    splash.geometry("400x150")
    splash.configure(bg='#2563eb')
    splash.resizable(False, False)

    # Center the splash screen
    splash.update_idletasks()
    x = (splash.winfo_screenwidth() // 2) - (400 // 2)
    y = (splash.winfo_screenheight() // 2) - (150 // 2)
    splash.geometry(f'400x150+{x}+{y}')

    # Splash content
    tk.Label(splash, text="🔐 StrongDM Resource Manager",
             font=('Segoe UI', 16, 'bold'),
             bg='#2563eb', fg='white').pack(pady=20)

    status_label = tk.Label(splash, text="Checking for SDK updates...",
                           font=('Segoe UI', 10),
                           bg='#2563eb', fg='white')
    status_label.pack(pady=10)

    progress_label = tk.Label(splash, text="⏳ Please wait...",
                             font=('Segoe UI', 9),
                             bg='#2563eb', fg='#dbeafe')
    progress_label.pack(pady=5)

    splash.update()

    # Run SDK upgrade check
    def upgrade_sdk_with_feedback():
        try:
            status_label.config(text="Upgrading StrongDM SDK...")
            splash.update()
            check_and_upgrade_sdk()
            status_label.config(text="✓ SDK check complete")
            progress_label.config(text="Starting application...")
            splash.update()
        except Exception as e:
            logger.error(f"Error during SDK upgrade: {e}")
            status_label.config(text="⚠ Continuing with current SDK")
            splash.update()

    upgrade_sdk_with_feedback()

    # Close splash after a brief delay
    splash.after(1000, splash.destroy)
    splash.mainloop()

    # Start main application
    app = StrongDMManager()
    app.run()