import os
import sys
import datetime
import logging
import argparse
# import subprocess # Not used in the provided snippet, keeping for potential future use
import json
import yaml
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import collections.abc
import getpass
import traceback # Import traceback for detailed error logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding # Renamed to avoid conflict
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID, SubjectInformationAccessOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm, AlreadyFinalized # Import specific cryptography exceptions


# --- Custom Exception ---
class PKIToolError(Exception):
    """Custom exception for PKI Tool errors."""
    pass

# --- Configure logging ---
# GUI Log Handler
class TextHandler(logging.Handler):
    """
    A logging handler that sends log records to a Tkinter Text widget.
    Uses threading.Event and widget.after to ensure thread-safe updates.
    """
    def __init__(self, text_widget):
        logging.Handler.__init__(self)
        self.text_widget = text_widget
        self.queue = [] # Queue for messages before GUI is fully ready or from other threads
        self.is_gui_ready = False
        # Check if widget is already created and mapped
        if self.text_widget.winfo_exists() and self.text_widget.winfo_ismapped():
            self.is_gui_ready = True
            self._process_queue()
        else:
             # Schedule a check if the widget becomes ready
             self.text_widget.after(100, self._check_gui_ready)


    def _check_gui_ready(self):
        """Periodically check if the GUI widget is ready."""
        if self.text_widget.winfo_exists() and self.text_widget.winfo_ismapped():
             self.is_gui_ready = True
             self._process_queue()
        else:
             self.text_widget.after(100, self._check_gui_ready) # Check again later


    def set_gui_ready(self):
        """Explicitly signal that the GUI is ready."""
        self.is_gui_ready = True
        self._process_queue()

    def _process_queue(self):
        """Process messages waiting in the queue."""
        while self.queue:
            record = self.queue.pop(0)
            self._emit_to_widget(record)

    def _emit_to_widget(self, record):
        """Format and append a single log record to the text widget."""
        msg = self.format(record)
        # This is to ensure GUI updates happen in the main thread
        def append():
            if self.text_widget.winfo_exists(): # Check if widget still exists
                self.text_widget.configure(state='normal')
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.configure(state='disabled')
                self.text_widget.yview(tk.END)
            # else: Widget destroyed, drop the message

        try:
            # Schedule the append function to run in the main Tkinter thread
            self.text_widget.after(0, append)
        except tk.TclError:
            # This can happen if the mainloop has stopped or widget is destroyed
            # Re-queueing might lead to memory issues if GUI never becomes ready.
            # For simplicity here, we'll drop the message, but a more robust
            # solution might log to stderr as a fallback.
            pass


    def emit(self, record):
        """Emit a log record."""
        if self.is_gui_ready and self.text_widget.winfo_exists():
            self._process_queue() # Process any backlog before adding new
            self._emit_to_widget(record)
        else:
            # Queue the message if GUI is not ready or widget doesn't exist yet
            self.queue.append(record)


logger = logging.getLogger("pki_tool")
logger.setLevel(logging.INFO)
# Prevent duplicate handlers if script is re-run in some environments (e.g., interactive sessions)
if not logger.handlers:
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # File Handler
    fh = logging.FileHandler("pki_tool.log")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console Handler (for CLI mode) - Only add if not in GUI mode initially
    # The GUI mode will replace or manage this handler
    if '--gui' not in sys.argv: # Simple check to avoid adding console handler in GUI mode start
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


# --- Password Dialog for GUI ---
class PasswordDialog(simpledialog.Dialog):
    """Custom dialog for getting password input."""
    def __init__(self, parent, title=None, prompt_main=None, prompt_confirm=None, show_confirm=True):
        self.prompt_main = prompt_main or "Enter Password:"
        self.prompt_confirm = prompt_confirm or "Confirm Password:"
        self.show_confirm = show_confirm
        self.password = None
        # simpledialog.Dialog requires a parent. If None is passed,
        # it uses a temporary root, which is generally fine.
        super().__init__(parent, title)

    def body(self, master):
        """Create dialog body widgets."""
        ttk.Label(master, text=self.prompt_main).grid(row=0, sticky=tk.W, padx=5, pady=5)
        self.entry_main = ttk.Entry(master, show="*")
        self.entry_main.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        if self.show_confirm:
            ttk.Label(master, text=self.prompt_confirm).grid(row=2, sticky=tk.W, padx=5, pady=5)
            self.entry_confirm = ttk.Entry(master, show="*")
            self.entry_confirm.grid(row=3, column=0, padx=5, pady=5, sticky="ew")

        master.grid_columnconfigure(0, weight=1)
        return self.entry_main # initial focus

    def buttonbox(self):
        """Create standard button box."""
        box = ttk.Frame(self)

        w = ttk.Button(box, text="OK", width=10, command=self.ok, default=tk.ACTIVE)
        w.pack(side=tk.LEFT, padx=5, pady=5)
        w = ttk.Button(box, text="Cancel", width=10, command=self.cancel)
        w.pack(side=tk.LEFT, padx=5, pady=5)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

        box.pack()

    def validate(self):
        """Validate input before closing dialog."""
        main_pass = self.entry_main.get()
        # Allow empty password if show_confirm is False (e.g. for decryption)
        if not main_pass and self.show_confirm:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return 0

        if self.show_confirm:
            confirm_pass = self.entry_confirm.get()
            if main_pass != confirm_pass:
                messagebox.showerror("Error", "Passwords do not match.", parent=self)
                return 0

        self.password = main_pass
        return 1

    def apply(self):
        """Process the validated input (password is already stored in validate)."""
        pass


# --- PKITool Class ---
class PKITool:
    """Core class for PKI operations."""
    def __init__(self, config_path=None, gui_mode=False, gui_root=None):
        self.gui_mode = gui_mode
        self.gui_root = gui_root # Store gui_root for PasswordDialog
        self.config = self._load_config(config_path)
        # In-memory cache for loaded CAs {ca_name: {cert_obj, key_obj, paths}}
        # Storing key_obj here means it's in memory after loading.
        # Consider if this is acceptable for security vs performance.
        self.ca_certs = {}

        # Ensure base directories exist
        try:
            os.makedirs(self.config["ca_path"], exist_ok=True)
            os.makedirs(self.config["cert_path"], exist_ok=True)
            os.makedirs(os.path.join(self.config["cert_path"], "csr"), exist_ok=True)
            os.makedirs(os.path.join(self.config["cert_path"], "cicd"), exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create necessary directories: {e}")
            # Depending on severity, might raise PKIToolError or continue with warning

    def _deep_update(self, source, overrides):
        """Update a nested dictionary or similar mapping."""
        for key, value in overrides.items():
            if isinstance(value, collections.abc.Mapping) and value:
                returned = self._deep_update(source.get(key, {}), value)
                source[key] = returned
            else:
                source[key] = overrides[key]
        return source

    def _load_config(self, config_path):
        """Loads configuration from a YAML file, merging with defaults."""
        default_config = {
            "ca_path": "ca",
            "cert_path": "certificates",
            "default_key_type": "rsa", # rsa or ec
            "default_rsa_key_size": 4096, # For CA
            "default_ec_curve": "SECP384R1", # For CA: SECP256R1, SECP384R1, SECP521R1
            "default_cert_rsa_key_size": 2048, # For issued certs
            "default_cert_ec_curve": "SECP256R1", # For issued certs
            "default_digest_algorithm": "SHA256", # SHA256, SHA384, SHA512
            "default_ca_validity_days": 3650, # 10 years
            "default_cert_validity_days": 365, # 1 year
            "default_country_name": "US",
            "default_state_province_name": "California", # Added state/province
            "default_locality_name": "San Francisco", # Added locality
            "default_organization_name_ca": "My PKI Tool CA",
            "default_organization_name_user": "My PKI Tool User",
            "default_email_address": "pki-tool@example.com", # Added email
            "cloud": {
                "aws": {"region": "us-east-1"},
                "azure": {"vault_url": "https://your-vault.vault.azure.net/"},
                "gcp": {"project_id": "your-project-id", "location": "global", "keyring": "pki-tool-keyring"}
            },
            "hsm": {
                "enabled": False,
                "type": "softhsm", # or pkcs11
                "module_path": "/usr/lib/softhsm/libsofthsm2.so", # Example
                "token_label": "my_token",
                "pin": None # To be prompted
            }
        }

        config = default_config # Start with defaults

        if config_path:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        user_config = yaml.safe_load(f)
                        if user_config:
                            config = self._deep_update(config, user_config)
                        else:
                            logger.warning(f"Config file {config_path} is empty. Using default configuration.")
                except Exception as e:
                    logger.error(f"Error loading config from {config_path}: {e}. Using default configuration.")
            else:
                 logger.warning(f"Config file {config_path} not found. Using default configuration.")

        return config

    def _get_password_for_encryption(self, prompt_message="Enter new encryption password for the private key:"):
        """Prompts user for a password to encrypt a private key."""
        if self.gui_mode:
            # Use Tkinter dialog in the main thread
            # Using a container list/dict and event for thread communication
            result_container = [None]
            event = threading.Event()

            def show_dialog():
                try:
                    # Explicitly hold a reference to the dialog
                    dialog = PasswordDialog(self.gui_root, title="Set Key Password", prompt_main=prompt_message)
                    result_container[0] = dialog.password # Store result
                finally:
                    event.set() # Signal completion even if an error occurred or dialog cancelled

            # Schedule the dialog to run in the main Tkinter thread
            self.gui_root.after(0, show_dialog)

            # Wait for the dialog to complete
            event.wait()

            password = result_container[0]
            return password.encode() if password is not None else None # Return None if dialog cancelled

        else: # CLI mode
            while True:
                password = getpass.getpass(prompt_message)
                if not password:
                    confirm_empty = input("Password is empty. Are you sure you want to save the key unencrypted? (yes/no): ").lower()
                    if confirm_empty == 'yes':
                        return None # Explicitly confirmed no password
                    else:
                        logger.info("Password not set. Please try again.")
                        continue
                password_confirm = getpass.getpass("Confirm password: ")
                if password == password_confirm:
                    return password.encode()
                else:
                    logger.error("Passwords do not match. Please try again.")

    def _get_password_for_decryption(self, key_path):
        """Prompts user for a password to decrypt a private key."""
        prompt = f"Enter password for private key {os.path.basename(key_path)}: "
        if self.gui_mode:
            # Using a container list/dict and event for thread communication
            result_container = [None]
            event = threading.Event()

            def show_dialog():
                try:
                    # Explicitly hold a reference to the dialog
                    dialog = PasswordDialog(self.gui_root, title="Unlock Key", prompt_main=prompt, show_confirm=False)
                    result_container[0] = dialog.password # Store result
                finally:
                    event.set() # Signal completion even if an error occurred or dialog cancelled

            # Schedule the dialog to run in the main Tkinter thread
            self.gui_root.after(0, show_dialog)

            # Wait for the dialog to complete
            event.wait()

            password = result_container[0]
            # For decryption, an empty password might be valid if the key was saved unencrypted
            # The dialog returns None if cancelled, empty string if user entered nothing and hit OK.
            # load_pem_private_key expects bytes or None.
            if password is None: # Dialog cancelled
                return None
            return password.encode() # Returns b'' if user entered empty string


        else: # CLI mode
            # getpass can return empty string if user just hits enter
            password_str = getpass.getpass(prompt)
            return password_str.encode() if password_str else b'' # Return b'' for empty password


    def _get_digest_algorithm(self, algo_name=None):
        """Returns the cryptography hash algorithm object based on name."""
        algo_name = (algo_name or self.config.get("default_digest_algorithm", "SHA256")).upper()
        if algo_name == "SHA256": return hashes.SHA256()
        if algo_name == "SHA384": return hashes.SHA384()
        if algo_name == "SHA512": return hashes.SHA512()
        raise PKIToolError(f"Unsupported digest algorithm: {algo_name}. Supported: SHA256, SHA384, SHA512")

    def _generate_private_key(self, key_type=None, rsa_key_size=None, ec_curve_name=None):
        """Generates a private key based on type and parameters."""
        key_type = (key_type or self.config.get("default_key_type", "rsa")).lower()
        rsa_key_size = rsa_key_size or self.config.get("default_cert_rsa_key_size", 2048) # Use cert size as default for generic key gen
        ec_curve_name = ec_curve_name or self.config.get("default_cert_ec_curve", "SECP256R1") # Use cert curve as default

        try:
            if key_type == "rsa":
                logger.info(f"Generating RSA key with size {rsa_key_size}")
                return rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=rsa_key_size,
                    backend=default_backend()
                )
            elif key_type == "ec":
                curve_map = {
                    "SECP256R1": ec.SECP256R1(),
                    "SECP384R1": ec.SECP384R1(),
                    "SECP521R1": ec.SECP521R1(),
                }
                curve = curve_map.get(ec_curve_name.upper())
                if not curve:
                    raise PKIToolError(f"Unsupported EC curve: {ec_curve_name}. Supported: {list(curve_map.keys())}")
                logger.info(f"Generating EC key with curve {ec_curve_name}")
                return ec.generate_private_key(curve, default_backend())
            else:
                raise PKIToolError(f"Unsupported key type: {key_type}. Supported: rsa, ec")
        except Exception as e:
             logger.error(f"Error generating private key: {e}")
             raise PKIToolError(f"Failed to generate private key: {e}")


    def create_ca(self, common_name,
                  key_type=None, rsa_key_size=None, ec_curve=None,
                  validity_days=None, org_name=None, country_name=None,
                  state_province_name=None, locality_name=None, email_address=None,
                  password=None): # Password can be pre-supplied (e.g. for automation)
        """Creates a new self-signed Certificate Authority (CA)."""
        logger.info(f"Attempting to create CA: {common_name}")

        # Use provided parameters or fall back to config defaults
        key_type = key_type or self.config.get("default_key_type", "rsa")
        rsa_key_size = rsa_key_size or self.config.get("default_rsa_key_size", 4096)
        ec_curve = ec_curve or self.config.get("default_ec_curve", "SECP384R1")
        validity_days = validity_days or self.config.get("default_ca_validity_days", 3650)
        org_name = org_name or self.config.get("default_organization_name_ca", "My PKI Tool CA")
        country_name = country_name or self.config.get("default_country_name", "US")
        state_province_name = state_province_name or self.config.get("default_state_province_name", "California")
        locality_name = locality_name or self.config.get("default_locality_name", "San Francisco")
        email_address = email_address or self.config.get("default_email_address", "pki-tool-ca@example.com") # Specific default for CA email
        digest_algo = self._get_digest_algorithm()

        # Sanitize common name for directory creation
        ca_dir_name = common_name.replace(" ", "_").replace("/", "_").lower()
        ca_dir = os.path.join(self.config["ca_path"], ca_dir_name)
        os.makedirs(ca_dir, exist_ok=True) # Ensure directory exists

        key_path = os.path.join(ca_dir, "ca_key.pem")
        cert_path = os.path.join(ca_dir, "ca_cert.pem")

        if os.path.exists(key_path) or os.path.exists(cert_path):
            raise PKIToolError(f"CA '{common_name}' already exists at {ca_dir}. Aborting.")

        logger.info(f"Generating private key for CA '{common_name}'...")
        private_key = self._generate_private_key(key_type, rsa_key_size, ec_curve)

        # Build the subject name
        subject_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        ]
        if state_province_name:
             # Corrected OID name
             subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_province_name))
        if locality_name:
             subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name))
        if email_address:
             subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

        subject = issuer = x509.Name(subject_attributes)

        logger.info(f"Building certificate for CA '{common_name}'...")
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer) # Self-signed
        builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(seconds=300)) # 5 min clock skew tolerance
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())

        # CA-specific extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False
            ), critical=True # KeyCertSign and CRLSign are critical for a CA
        )
        # Subject Key Identifier - identifies the public key of the subject
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        # Authority Key Identifier - identifies the public key of the issuer (for self-signed, this is the same as SKI)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False
        )

        logger.info(f"Signing CA certificate with {digest_algo.name}...")
        try:
            certificate = builder.sign(private_key, digest_algo, default_backend())
        except Exception as e:
            logger.error(f"Error signing CA certificate: {e}")
            raise PKIToolError(f"Failed to sign CA certificate: {e}")

        # Handle password for key encryption
        key_password_bytes = None
        if password is None: # Password not pre-supplied, prompt the user
            key_password_bytes = self._get_password_for_encryption(f"Enter new encryption password for CA '{common_name}' private key:")
            if key_password_bytes is None and self.gui_mode: # GUI user cancelled
                 raise PKIToolError("Password entry cancelled. CA key encryption required.")
            # If CLI user confirmed no password, key_password_bytes remains None

        else: # Password pre-supplied
            key_password_bytes = password.encode() if isinstance(password, str) else password

        # Determine encryption algorithm
        encryption_algo = serialization.BestAvailableEncryption(key_password_bytes) if key_password_bytes else serialization.NoEncryption()

        logger.info(f"Saving CA private key to {key_path}...")
        try:
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8, # PKCS8 is generally preferred
                    encryption_algorithm=encryption_algo
                ))
        except Exception as e:
            logger.error(f"Error saving CA private key: {e}")
            raise PKIToolError(f"Failed to save CA private key: {e}")


        logger.info(f"Saving CA certificate to {cert_path}...")
        try:
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving CA certificate: {e}")
            raise PKIToolError(f"Failed to save CA certificate: {e}")


        # Cache the loaded CA objects
        self.ca_certs[common_name] = {
            "certificate_obj": certificate, "private_key_obj": private_key, # Store key object in cache
            "cert_path": cert_path, "key_path": key_path
        }
        logger.info(f"CA '{common_name}' created successfully. Key: {key_path}, Cert: {cert_path}")
        return {"cert_path": cert_path, "key_path": key_path, "ca_name": common_name}

    def _load_ca(self, ca_name):
        """Loads CA certificate and private key into memory, prompting for password if needed."""
        # Check cache first
        if ca_name in self.ca_certs and self.ca_certs[ca_name].get("private_key_obj"):
            logger.debug(f"CA '{ca_name}' found in cache.")
            return self.ca_certs[ca_name]["certificate_obj"], self.ca_certs[ca_name]["private_key_obj"]

        ca_dir = os.path.join(self.config["ca_path"], ca_name.replace(" ", "_").replace("/", "_").lower())
        key_path = os.path.join(ca_dir, "ca_key.pem")
        cert_path = os.path.join(ca_dir, "ca_cert.pem")

        if not (os.path.exists(key_path) and os.path.exists(cert_path)):
            raise PKIToolError(f"CA '{ca_name}' files not found at {ca_dir}")

        logger.info(f"Loading CA certificate from {cert_path}...")
        try:
            with open(cert_path, "rb") as f:
                ca_cert_obj = x509.load_pem_x509_certificate(f.read(), default_backend())
        except Exception as e:
            logger.error(f"Failed to load CA certificate '{cert_path}': {e}")
            raise PKIToolError(f"Failed to load CA certificate '{cert_path}': {e}")

        logger.info(f"Loading CA private key from {key_path}...")
        ca_key_obj = None
        key_data = None
        try:
            with open(key_path, "rb") as f:
                key_data = f.read()
        except Exception as e:
             logger.error(f"Failed to read CA private key file '{key_path}': {e}")
             raise PKIToolError(f"Failed to read CA private key file '{key_path}': {e}")

        # Attempt to load the key, potentially prompting for password
        password_bytes_for_load = b'' # Start with empty password attempt
        try:
            ca_key_obj = serialization.load_pem_private_key(key_data, password=password_bytes_for_load, backend=default_backend())
            logger.info(f"CA key {key_path} loaded without password.")
        except TypeError: # Indicates password is required
            logger.info(f"CA key {key_path} appears to be encrypted. Prompting for password.")
            # Keep prompting until success or cancellation/error
            while ca_key_obj is None:
                password_bytes_for_load = self._get_password_for_decryption(key_path)
                if password_bytes_for_load is None and self.gui_mode: # GUI user cancelled
                    raise PKIToolError(f"Password entry cancelled for CA key '{key_path}'.")
                if password_bytes_for_load is None and not self.gui_mode: # CLI user entered empty for decryption
                     logger.info(f"Attempting to load CA key {key_path} with an empty password.")
                     password_bytes_for_load = b'' # Use empty bytes for load attempt

                try:
                    ca_key_obj = serialization.load_pem_private_key(key_data, password=password_bytes_for_load, backend=default_backend())
                    logger.info(f"CA key {key_path} loaded successfully.")
                except ValueError:
                    logger.error(f"Incorrect password for CA key '{key_path}'.")
                    if not self.gui_mode:
                        print("Incorrect password. Please try again.")
                except Exception as e:
                    logger.error(f"An unexpected error occurred while loading key '{key_path}': {e}")
                    raise PKIToolError(f"Failed to load CA private key '{key_path}': {e}")


        if ca_key_obj is None:
             # This case should ideally not be reached if prompting loop works,
             # but as a safeguard:
             raise PKIToolError(f"Failed to load CA private key '{key_path}' after attempts.")


        # Cache the loaded CA objects
        self.ca_certs[ca_name] = {
            "certificate_obj": ca_cert_obj, "private_key_obj": ca_key_obj,
            "cert_path": cert_path, "key_path": key_path
        }
        return ca_cert_obj, ca_key_obj


    def issue_certificate(self, ca_name, common_name,
                          key_type=None, rsa_key_size=None, ec_curve=None,
                          validity_days=None, san_dns=None, san_ip=None,
                          org_name=None, country_name=None, state_province_name=None,
                          locality_name=None, email_address=None,
                          encrypt_key=False, key_password=None): # key_password can be pre-supplied
        """Issues a new certificate signed by the specified CA."""
        logger.info(f"Attempting to issue certificate for '{common_name}' using CA '{ca_name}'")

        try:
            ca_cert_obj, ca_key_obj = self._load_ca(ca_name)
            logger.info(f"CA '{ca_name}' loaded successfully.")
        except PKIToolError as e:
            logger.error(f"Failed to load CA '{ca_name}': {e}")
            raise PKIToolError(f"Failed to load CA '{ca_name}': {e}")


        # Use provided parameters or fall back to config defaults
        key_type = key_type or self.config.get("default_key_type", "rsa")
        rsa_key_size = rsa_key_size or self.config.get("default_cert_rsa_key_size", 2048)
        ec_curve = ec_curve or self.config.get("default_cert_ec_curve", "SECP256R1")
        validity_days = validity_days or self.config.get("default_cert_validity_days", 365)
        org_name = org_name or self.config.get("default_organization_name_user", "My PKI Tool User")
        country_name = country_name or self.config.get("default_country_name", "US")
        state_province_name = state_province_name or self.config.get("default_state_province_name", "California")
        locality_name = locality_name or self.config.get("default_locality_name", "San Francisco")
        email_address = email_address or self.config.get("default_email_address", "pki-tool-user@example.com") # Specific default for user email
        digest_algo = self._get_digest_algorithm()

        # Sanitize common name for directory creation
        cert_dir_name = common_name.replace("*", "wildcard").replace(" ", "_").replace("/", "_").lower()
        cert_dir = os.path.join(self.config["cert_path"], cert_dir_name)
        os.makedirs(cert_dir, exist_ok=True)

        key_path = os.path.join(cert_dir, "key.pem")
        cert_path = os.path.join(cert_dir, "cert.pem")
        chain_path = os.path.join(cert_dir, "chain.pem") # Leaf + CA
        fullchain_path = os.path.join(cert_dir, "fullchain.pem") # Leaf + Intermediates (if any) + CA

        # Optional: Check if certificate already exists and prompt to overwrite
        # if os.path.exists(cert_path):
        #     logger.warning(f"Certificate for '{common_name}' already exists at {cert_path}.")
        #     # Add logic to prompt user in GUI/CLI if overwrite is desired

        logger.info(f"Generating private key for certificate '{common_name}'...")
        private_key = self._generate_private_key(key_type, rsa_key_size, ec_curve)

        # Build the subject name
        subject_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        ]
        if state_province_name:
             # Corrected OID name
             subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_province_name))
        if locality_name:
             subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name))
        if email_address:
             subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

        subject = x509.Name(subject_attributes)

        logger.info(f"Building certificate for '{common_name}'...")
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert_obj.subject) # Signed by the CA
        builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(seconds=300)) # 5 min clock skew tolerance
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())

        # Standard certificate extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        # Subject Key Identifier - identifies the public key of this certificate
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        # Authority Key Identifier - identifies the public key of the CA that issued this certificate
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert_obj.public_key()), critical=False
        )
        # Key Usage (typical for TLS server/client)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
            ), critical=True
        )
        # Extended Key Usage (typical for TLS server/client)
        ekus = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)

        # Subject Alternative Name (SAN) extension
        san_entries = []
        if san_dns:
            for dns_name in san_dns:
                san_entries.append(x509.DNSName(dns_name))
        if san_ip:
            for ip_str in san_ip:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
                except ValueError as e:
                    raise PKIToolError(f"Invalid IP address in SAN: {ip_str} - {e}")
        if san_entries:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

        logger.info(f"Signing certificate '{common_name}' with CA '{ca_name}' using {digest_algo.name}...")
        try:
            certificate = builder.sign(ca_key_obj, digest_algo, default_backend())
        except Exception as e:
             logger.error(f"Error signing certificate: {e}")
             raise PKIToolError(f"Failed to sign certificate: {e}")

        # Handle password for key encryption
        key_password_bytes = None
        encryption_algo = serialization.NoEncryption()
        if encrypt_key:
            if key_password is None: # Password not pre-supplied, prompt the user
                key_password_bytes = self._get_password_for_encryption(f"Enter new encryption password for '{common_name}' private key:")
                if key_password_bytes is None and self.gui_mode: # GUI user cancelled
                    raise PKIToolError("Password entry cancelled. Key encryption required by selection.")
                 # If CLI user confirmed no password, key_password_bytes remains None

            else: # Password pre-supplied
                key_password_bytes = key_password.encode() if isinstance(key_password, str) else key_password

            if key_password_bytes: # Will be None if user chose unencrypted in CLI
                encryption_algo = serialization.BestAvailableEncryption(key_password_bytes)
            elif encrypt_key and not self.gui_mode:
                 logger.warning(f"Encryption requested for key '{common_name}', but no password provided/confirmed. Saving unencrypted.")
            elif encrypt_key and self.gui_mode and key_password_bytes is None:
                 # This case should be caught by the GUI cancellation check above, but as a safeguard:
                 raise PKIToolError("Encryption requested but no password provided.")


        logger.info(f"Saving private key to {key_path}...")
        try:
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption_algo
                ))
        except Exception as e:
            logger.error(f"Error saving private key: {e}")
            raise PKIToolError(f"Failed to save private key: {e}")


        logger.info(f"Saving certificate to {cert_path}...")
        try:
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving certificate: {e}")
            raise PKIToolError(f"Failed to save certificate: {e}")


        logger.info(f"Saving chain file to {chain_path} (Leaf + CA)...")
        try:
            with open(chain_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
                f.write(b"\n") # Add newline between certs
                f.write(ca_cert_obj.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving chain file: {e}")
            # Non-critical error, continue
            pass # Or raise PKIToolError if chain file is essential

        logger.info(f"Saving fullchain file to {fullchain_path} (Leaf + CA)...")
        # Note: This assumes a simple two-tier hierarchy (Leaf + CA).
        # For intermediate CAs, you would need to load and include them here.
        try:
            with open(fullchain_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
                f.write(b"\n")
                f.write(ca_cert_obj.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving fullchain file: {e}")
            pass # Non-critical error


        logger.info(f"Certificate for '{common_name}' issued successfully.")
        return {"cert_path": cert_path, "key_path": key_path, "chain_path": chain_path, "fullchain_path": fullchain_path, "cert_name": common_name}

    def _extract_extensions(self, cert):
        """Extracts and formats certificate extensions."""
        extensions_data = {}
        for ext in cert.extensions:
            ext_name = ext.oid._name if hasattr(ext.oid, '_name') else ext.oid.dotted_string
            try:
                if isinstance(ext.value, x509.BasicConstraints):
                    extensions_data[ext_name] = f"CA={ext.value.ca}, Path Length={ext.value.path_length}"
                elif isinstance(ext.value, x509.KeyUsage):
                    # Dynamically get boolean attributes that are True
                    attrs = [name for name, val in vars(ext.value).items() if isinstance(val, bool) and val is True and not name.startswith("_")]
                    extensions_data[ext_name] = ", ".join(attrs) if attrs else "None"
                elif isinstance(ext.value, x509.ExtendedKeyUsage):
                    extensions_data[ext_name] = ", ".join([oid._name for oid in ext.value])
                elif isinstance(ext.value, x509.SubjectAlternativeName):
                    # Extract different name types from SAN
                    names = []
                    for name in ext.value:
                        if isinstance(name, x509.DNSName):
                            names.append(f"DNS:{name.value}")
                        elif isinstance(name, x509.IPAddress):
                            names.append(f"IP:{name.value}")
                        elif isinstance(name, x509.UniformResourceIdentifier):
                             names.append(f"URI:{name.value}")
                        elif isinstance(name, x509.DirectoryName):
                             names.append(f"DirName:{name.value.rfc4514_string()}")
                        elif isinstance(name, x509.RegisteredID):
                             names.append(f"RegisteredID:{name.value}")
                        elif isinstance(name, x509.OtherName):
                             names.append(f"OtherName:{name.type.dotted_string}={name.value}")
                        # Add other SAN types if needed
                        else:
                            names.append(str(name)) # Fallback
                    extensions_data[ext_name] = ", ".join(names) if names else "None"
                elif isinstance(ext.value, x509.SubjectKeyIdentifier):
                    extensions_data[ext_name] = ext.value.digest.hex()
                elif isinstance(ext.value, x509.AuthorityKeyIdentifier):
                    aki_parts = []
                    if ext.value.key_identifier: aki_parts.append(f"KeyID={ext.value.key_identifier.hex()}")
                    if ext.value.authority_cert_issuer:
                         # authority_cert_issuer is a list of GeneralNames
                         issuers = [str(name) for name in ext.value.authority_cert_issuer]
                         aki_parts.append(f"Issuer={';'.join(issuers)}")
                    if ext.value.authority_cert_serial_number:
                         aki_parts.append(f"Serial={ext.value.authority_cert_serial_number}")
                    extensions_data[ext_name] = ", ".join(aki_parts) if aki_parts else "None"
                elif isinstance(ext.value, x509.AuthorityInformationAccess) or \
                     isinstance(ext.value, x509.SubjectInformationAccess):
                    access_descs = []
                    for ad in ext.value:
                         # access_method is an OID, access_location is a GeneralName
                         method_name = ad.access_method._name if hasattr(ad.access_method, '_name') else ad.access_method.dotted_string
                         access_descs.append(f"{method_name}: {str(ad.access_location)}")
                    extensions_data[ext_name] = "; ".join(access_descs) if access_descs else "None"
                elif isinstance(ext.value, x509.CRLDistributionPoints):
                    points = []
                    for point in ext.value:
                        # DistributionPointName can be FullName or RelativeName
                        name_parts = []
                        if point.full_name:
                             name_parts.append(f"Full Name: {[str(n) for n in point.full_name]}")
                        if point.relative_name:
                             name_parts.append(f"Relative Name: {point.relative_name.rfc4514_string()}")
                        if point.crl_issuer:
                             # crl_issuer is a list of GeneralNames
                             issuers = [str(n) for n in point.crl_issuer]
                             name_parts.append(f"CRL Issuer: {';'.join(issuers)}")
                        if point.reasons:
                             reasons = [reason._name for reason in point.reasons]
                             name_parts.append(f"Reasons: {','.join(reasons)}")

                        points.append(f"[{', '.join(name_parts)}]")
                    extensions_data[ext_name] = "; ".join(points) if points else "None"

                elif isinstance(ext.value, x509.CertificatePolicies):
                     policies = []
                     for policy in ext.value:
                          policy_info = f"PolicyID: {policy.policy_identifier.dotted_string}"
                          if policy.qualifiers:
                               qualifiers = []
                               for qual in policy.qualifiers:
                                    if isinstance(qual, x509.PolicyQualifierInfo):
                                         # qualifier_id is an OID, qualifier is usually a string or object
                                         qual_id_name = qual.qualifier_id._name if hasattr(qual.qualifier_id, '_name') else qual.qualifier_id.dotted_string
                                         qualifiers.append(f"{qual_id_name}: {str(qual.qualifier)}")
                               policy_info += f" ({', '.join(qualifiers)})"
                          policies.append(policy_info)
                     extensions_data[ext_name] = "; ".join(policies) if policies else "None"


                else:
                    # Generic fallback for other extension types
                    try:
                        # Attempt a simple string representation first
                        extensions_data[ext_name] = str(ext.value)
                    except Exception:
                        # If string conversion fails, provide OID and raw data info
                        extensions_data[ext_name] = f"Opaque data (OID: {ext.oid.dotted_string}, Critical: {ext.critical})"
            except Exception as e:
                logger.warning(f"Could not parse extension {ext_name} (OID: {ext.oid.dotted_string}): {e}", exc_info=True)
                extensions_data[ext_name] = f"Error parsing extension (OID: {ext.oid.dotted_string})"
        return extensions_data


    def check_certificate(self, cert_path):
        """Check a certificate's validity and details."""
        logger.info(f"Checking certificate: {cert_path}")
        try:
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            now_utc = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware datetime
            not_valid_before_utc = cert.not_valid_before_utc
            not_valid_after_utc = cert.not_valid_after_utc

            # Calculate remaining days, handle expired case
            time_until_expiry = not_valid_after_utc - now_utc
            days_until_expiry = max(0, time_until_expiry.days) # Don't show negative days

            info = {
                "File Path": os.path.abspath(cert_path),
                "Subject": cert.subject.rfc4514_string(),
                "Issuer": cert.issuer.rfc4514_string(),
                "Serial Number": f"{cert.serial_number:X}", # Format as Hex for clarity
                "Version": f"v{cert.version.value + 1}", # Version is 0-indexed enum
                "Not Valid Before (UTC)": not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "Not Valid After (UTC)": not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S %Z"),
                "Expired": not_valid_after_utc < now_utc,
                "Days Until Expiry": days_until_expiry,
                "Public Key Algorithm": self._get_key_type(cert),
                "Key Size (bits)": self._get_key_size(cert),
                "Signature Algorithm": cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else cert.signature_algorithm_oid.dotted_string,
                "Fingerprint (SHA-1)": cert.fingerprint(hashes.SHA1()).hex(), # SHA-1 still common for fingerprint display
                "Fingerprint (SHA-256)": cert.fingerprint(hashes.SHA256()).hex(),
                "Extensions": self._extract_extensions(cert)
            }

            if info["Expired"]:
                 logger.warning(f"Certificate {cert_path} has expired as of {info['Not Valid After (UTC)']}.")
            elif 0 < info["Days Until Expiry"] <= 30:
                 logger.warning(f"Certificate {cert_path} will expire in {info['Days Until Expiry']} days.")
            else:
                 logger.info(f"Certificate {cert_path} is valid.")


            # Log basic info
            log_info_display = {k: v for k, v in info.items() if k != "Extensions"}
            logger.info(f"Certificate details for {os.path.basename(cert_path)}: {json.dumps(log_info_display, default=str, indent=2)}")
            # Log extensions separately for better readability
            if info["Extensions"]:
                 logger.info(f"Extensions for {os.path.basename(cert_path)}: {json.dumps(info['Extensions'], indent=2, default=str)}")
            else:
                 logger.info(f"No extensions found for {os.path.basename(cert_path)}.")

            return info

        except FileNotFoundError:
            logger.error(f"Certificate file not found: {cert_path}")
            raise PKIToolError(f"Certificate file not found: {cert_path}")
        except Exception as e:
            logger.error(f"Error checking certificate {cert_path}: {e}", exc_info=True)
            raise PKIToolError(f"Error checking certificate {cert_path}: {e}")


    def _get_key_type(self, cert_or_csr_or_key):
        """Determines the public key type (RSA or ECC) from a cert, csr, or key object."""
        if isinstance(cert_or_csr_or_key, (x509.Certificate, x509.CertificateSigningRequest)):
            public_key = cert_or_csr_or_key.public_key()
        elif hasattr(cert_or_csr_or_key, 'public_bytes'): # Assume it's a private key object
             public_key = cert_or_csr_or_key.public_key()
        else: # Assume it's a public key object
            public_key = cert_or_csr_or_key

        if isinstance(public_key, rsa.RSAPublicKey): return "RSA"
        if isinstance(public_key, ec.EllipticCurvePublicKey): return "ECC"
        return "Unknown"

    def _get_key_size(self, cert_or_csr_or_key):
        """Determines the key size in bits from a cert, csr, or key object."""
        if isinstance(cert_or_csr_or_key, (x509.Certificate, x509.CertificateSigningRequest)):
            public_key = cert_or_csr_or_key.public_key()
        elif hasattr(cert_or_csr_or_key, 'public_bytes'): # Assume it's a private key object
             public_key = cert_or_csr_or_key.public_key()
        else: # Assume it's a public key object
            public_key = cert_or_csr_or_key

        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            # Map curve name to bit size
            curve_name = public_key.curve.name
            # Common NIST curves
            if curve_name == "secp256r1": return 256
            if curve_name == "secp384r1": return 384
            if curve_name == "secp521r1": return 521
            # Add other curves if needed, e.g., brainpool, secp256k1
            try:
                 # Attempt to get key size if available via another method
                 return public_key.key_size # Some EC implementations might have this
            except NotImplementedError:
                 pass # key_size not available for this EC type

            return f"EC ({curve_name})" # Fallback if curve size is unknown
        return "N/A" # Unknown key type

    def generate_csr(self, common_name, key_path=None, key_password=None,
                     key_type=None, rsa_key_size=None, ec_curve=None,
                     org_name=None, country_name=None, state_province_name=None,
                     locality_name=None, email_address=None, san_dns=None, san_ip=None,
                     save_key=True, encrypt_key=False):
        """Generates a Certificate Signing Request (CSR) and optionally a new private key."""
        logger.info(f"Attempting to generate CSR for '{common_name}'")

        private_key = None
        generated_key_path = None

        if key_path:
            logger.info(f"Loading existing private key from {key_path}...")
            try:
                with open(key_path, "rb") as f:
                    key_data = f.read()

                password_bytes_for_load = None
                try:
                    private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
                    logger.info(f"Key {key_path} loaded without password.")
                except TypeError: # Password required
                    logger.info(f"Key {key_path} appears to be encrypted. Prompting for password.")
                    if key_password is None: # Password not pre-supplied
                         password_bytes_for_load = self._get_password_for_decryption(key_path)
                         if password_bytes_for_load is None and self.gui_mode: # GUI user cancelled
                              raise PKIToolError(f"Password entry cancelled for key '{key_path}'.")
                         if password_bytes_for_load is None and not self.gui_mode: # CLI user entered empty
                              password_bytes_for_load = b'' # Attempt with empty password

                    else: # Password pre-supplied
                         password_bytes_for_load = key_password.encode() if isinstance(key_password, str) else key_password

                    try:
                        private_key = serialization.load_pem_private_key(key_data, password=password_bytes_for_load, backend=default_backend())
                        logger.info(f"Key {key_path} loaded successfully.")
                    except ValueError:
                         raise PKIToolError(f"Incorrect password for key '{key_path}'.")
                    except Exception as e:
                         logger.error(f"An unexpected error occurred while loading key '{key_path}': {e}")
                         raise PKIToolError(f"Failed to load private key '{key_path}': {e}")

            except FileNotFoundError:
                 raise PKIToolError(f"Private key file not found: {key_path}")
            except Exception as e:
                 logger.error(f"Error loading private key {key_path}: {e}")
                 raise PKIToolError(f"Error loading private key {key_path}: {e}")

        else:
            logger.info("Generating a new private key for the CSR...")
            # Use cert defaults for key generation
            key_type = key_type or self.config.get("default_key_type", "rsa")
            rsa_key_size = rsa_key_size or self.config.get("default_cert_rsa_key_size", 2048)
            ec_curve = ec_curve or self.config.get("default_cert_ec_curve", "SECP256R1")
            private_key = self._generate_private_key(key_type, rsa_key_size, ec_curve)

            if save_key:
                # Determine key path for the new key
                cert_dir_name = common_name.replace("*", "wildcard").replace(" ", "_").replace("/", "_").lower()
                cert_dir = os.path.join(self.config["cert_path"], "csr", cert_dir_name)
                os.makedirs(cert_dir, exist_ok=True)
                generated_key_path = os.path.join(cert_dir, "csr_key.pem")

                # Handle password for key encryption if saving
                key_password_bytes = None
                encryption_algo = serialization.NoEncryption()
                if encrypt_key:
                    if key_password is None: # Password not pre-supplied, prompt the user
                        key_password_bytes = self._get_password_for_encryption(f"Enter new encryption password for '{common_name}' CSR private key:")
                        if key_password_bytes is None and self.gui_mode: # GUI user cancelled
                            raise PKIToolError("Password entry cancelled. Key encryption required by selection.")
                         # If CLI user confirmed no password, key_password_bytes remains None
                    else: # Password pre-supplied
                        key_password_bytes = key_password.encode() if isinstance(key_password, str) else key_password

                    if key_password_bytes:
                        encryption_algo = serialization.BestAvailableEncryption(key_password_bytes)
                    elif encrypt_key and not self.gui_mode:
                         logger.warning(f"Encryption requested for CSR key '{common_name}', but no password provided/confirmed. Saving unencrypted.")
                    elif encrypt_key and self.gui_mode and key_password_bytes is None:
                         raise PKIToolError("Encryption requested but no password provided.")


                logger.info(f"Saving new private key to {generated_key_path}...")
                try:
                    with open(generated_key_path, "wb") as f:
                        f.write(private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=encryption_algo
                        ))
                except Exception as e:
                    logger.error(f"Error saving new private key: {e}")
                    # Non-critical, continue with CSR generation if key is in memory
                    generated_key_path = None # Indicate save failed
                    # raise PKIToolError(f"Failed to save new private key: {e}") # Or stop if key saving is mandatory


        # Build the subject name for the CSR
        subject_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
        # Add optional subject attributes if provided or in config
        org_name = org_name or self.config.get("default_organization_name_user", "My PKI Tool User")
        country_name = country_name or self.config.get("default_country_name", "US")
        state_province_name = state_province_name or self.config.get("default_state_province_name", "California")
        locality_name = locality_name or self.config.get("default_locality_name", "San Francisco")
        email_address = email_address or self.config.get("default_email_address", "pki-tool-csr@example.com")

        if org_name: subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name))
        if country_name: subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
        if state_province_name:
             # Corrected OID name
             subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_province_name))
        if locality_name: subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name))
        if email_address: subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

        subject = x509.Name(subject_attributes)

        logger.info(f"Building CSR for '{common_name}'...")
        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        # Add SAN extension to CSR if specified
        san_entries = []
        if san_dns:
            for dns_name in san_dns:
                san_entries.append(x509.DNSName(dns_name))
        if san_ip:
            for ip_str in san_ip:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
                except ValueError as e:
                    raise PKIToolError(f"Invalid IP address in SAN for CSR: {ip_str} - {e}")
        if san_entries:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

        # Add Subject Key Identifier to CSR (optional but good practice)
        builder = builder.add_extension(
             x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )

        digest_algo = self._get_digest_algorithm()
        logger.info(f"Signing CSR with {digest_algo.name}...")
        try:
            csr = builder.sign(private_key, digest_algo, default_backend())
        except Exception as e:
             logger.error(f"Error signing CSR: {e}")
             raise PKIToolError(f"Failed to sign CSR: {e}")


        # Determine CSR save path
        csr_dir_name = common_name.replace("*", "wildcard").replace(" ", "_").replace("/", "_").lower()
        csr_dir = os.path.join(self.config["cert_path"], "csr", csr_dir_name)
        os.makedirs(csr_dir, exist_ok=True)
        csr_path = os.path.join(csr_dir, "request.csr")

        logger.info(f"Saving CSR to {csr_path}...")
        try:
            with open(csr_path, "wb") as f:
                f.write(csr.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving CSR: {e}")
            raise PKIToolError(f"Failed to save CSR: {e}")


        logger.info(f"CSR for '{common_name}' generated successfully.")
        result = {"csr_path": csr_path, "csr_name": common_name}
        if generated_key_path:
             result["key_path"] = generated_key_path # Include key path if a new key was generated and saved
        return result

    def sign_csr(self, ca_name, csr_path, validity_days=None,
                 san_dns=None, san_ip=None, # Allow overriding SANs from CSR if needed
                 org_name=None, country_name=None, state_province_name=None,
                 locality_name=None, email_address=None, # Allow overriding Subject from CSR if needed
                 encrypt_key=False, key_password=None): # Password for the *issued cert's* key if it's provided separately (unlikely for CSR signing)
        """Signs a Certificate Signing Request (CSR) using the specified CA."""
        logger.info(f"Attempting to sign CSR '{csr_path}' using CA '{ca_name}'")

        try:
            ca_cert_obj, ca_key_obj = self._load_ca(ca_name)
            logger.info(f"CA '{ca_name}' loaded successfully.")
        except PKIToolError as e:
            logger.error(f"Failed to load CA '{ca_name}': {e}")
            raise PKIToolError(f"Failed to load CA '{ca_name}': {e}")

        logger.info(f"Loading CSR from {csr_path}...")
        try:
            with open(csr_path, "rb") as f:
                csr_data = f.read()
            csr = x509.load_pem_x509_csr(csr_data, default_backend())
        except FileNotFoundError:
             raise PKIToolError(f"CSR file not found: {csr_path}")
        except Exception as e:
             logger.error(f"Error loading CSR '{csr_path}': {e}")
             raise PKIToolError(f"Failed to load CSR '{csr_path}': {e}")

        # Verify the CSR signature
        logger.info("Verifying CSR signature...")
        try:
            if not csr.is_signature_valid:
                raise PKIToolError("CSR signature is invalid.")
            logger.info("CSR signature is valid.")
        except Exception as e:
             logger.error(f"Error verifying CSR signature: {e}")
             # Depending on policy, you might sign it anyway, but usually you shouldn't.
             raise PKIToolError(f"CSR signature verification failed: {e}")


        # Use parameters or fall back to config defaults, then fall back to CSR subject/SANs
        validity_days = validity_days or self.config.get("default_cert_validity_days", 365)
        digest_algo = self._get_digest_algorithm()

        # Use provided subject attributes, otherwise use CSR subject
        subject_attributes = []
        if org_name: subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name))
        if country_name: subject_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
        if state_province_name:
             # Corrected OID name
             subject_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_province_name))
        if locality_name: subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name))
        if email_address: subject_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

        if not subject_attributes: # If no subject attributes provided, use CSR subject
             subject = csr.subject
             common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "Unknown"
             logger.info(f"Using subject from CSR: {subject.rfc4514_string()}")
        else: # Use provided subject attributes
             subject = x509.Name(subject_attributes)
             common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(NameOID.COMMON_NAME) else "Unknown"
             logger.info(f"Using provided subject: {subject.rfc4514_string()}")


        # Use provided SANs, otherwise try to get SANs from CSR
        san_entries = []
        if san_dns:
            for dns_name in san_dns:
                san_entries.append(x509.DNSName(dns_name))
        if san_ip:
            for ip_str in san_ip:
                try:
                    san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
                except ValueError as e:
                    raise PKIToolError(f"Invalid IP address in provided SANs for signing: {ip_str} - {e}")

        # If no SANs were provided as arguments, try to get them from the CSR
        if not san_entries:
             try:
                  csr_san_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALT_NAME)
                  san_entries = list(csr_san_ext.value) # Copy SAN entries from CSR
                  logger.info(f"Using SANs from CSR: {', '.join([str(name) for name in san_entries])}")
             except x509.ExtensionNotFound:
                  logger.info("No SAN extension found in CSR.")
             except Exception as e:
                  logger.warning(f"Could not extract SANs from CSR: {e}")


        logger.info(f"Building certificate from CSR for '{common_name}'...")
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert_obj.subject) # Signed by the CA
        builder = builder.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(seconds=300)) # 5 min clock skew tolerance
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr.public_key()) # Use public key from CSR

        # Standard certificate extensions (can copy from CSR or add new ones)
        # Copy extensions from CSR (excluding Subject Key Identifier as it's regenerated
        # and BasicConstraints, KeyUsage, EKU, SAN which are handled explicitly below)
        extensions_to_copy = [
             ext for ext in csr.extensions
             if ext.oid not in [
                  x509.SubjectKeyIdentifier.oid, # Corrected OID reference
                  x509.AuthorityKeyIdentifier.oid, # Corrected OID reference
                  x509.BasicConstraints.oid, # Corrected OID reference
                  x509.KeyUsage.oid, # Corrected OID reference
                  x509.ExtendedKeyUsage.oid, # Corrected OID reference
                  x509.SubjectAlternativeName.oid # Corrected OID reference
             ]
        ]
        for ext in extensions_to_copy:
            try:
                builder = builder.add_extension(ext.value, critical=ext.critical)
                logger.debug(f"Copied extension from CSR: {ext.oid._name}")
            except Exception as e:
                 logger.warning(f"Failed to copy extension {ext.oid._name} from CSR: {e}")


        # Add/Override extensions that are typically generated by the CA or are standard
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        # Subject Key Identifier - identifies the public key of this certificate (from CSR)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
        )
        # Authority Key Identifier - identifies the public key of the CA that issued this certificate
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert_obj.public_key()), critical=False
        )
        # Key Usage (typical for TLS server/client)
        # Prefer KeyUsage from CSR if present, otherwise add default
        try:
            csr_ku_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            key_usage_value = csr_ku_ext.value
            key_usage_critical = csr_ku_ext.critical
            logger.debug("Using Key Usage from CSR.")
        except x509.ExtensionNotFound:
            # Add default Key Usage if not in CSR
            key_usage_value = x509.KeyUsage(
                 digital_signature=True, content_commitment=False, key_encipherment=True, data_encipherment=False,
                 key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
            )
            key_usage_critical = True
            logger.debug("Adding default Key Usage extension.")

        builder = builder.add_extension(key_usage_value, critical=key_usage_critical)


        # Extended Key Usage (typical for TLS server/client)
        # Prefer EKU from CSR if present, otherwise add default
        try:
             csr_eku_ext = csr.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
             eku_value = csr_eku_ext.value
             eku_critical = csr_eku_ext.critical
             logger.debug("Using EKU from CSR.")
        except x509.ExtensionNotFound:
             # Add default EKU if not in CSR
             eku_value = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
             eku_critical = False
             logger.debug("Adding default EKU extension.")

        builder = builder.add_extension(eku_value, critical=eku_critical)


        # Add SAN extension if entries were collected (either from provided args or CSR)
        # Provided args take precedence over CSR SANs
        if san_entries: # san_entries was populated from provided args or CSR earlier
             try:
                  # Check if SAN is already added (e.g., copied from CSR before explicit handling)
                  # This check might be redundant now that we filter explicitly, but keep for safety
                  builder.extensions.get_extension_for_oid(x509.SubjectAlternativeName.oid) # Corrected OID reference
                  logger.debug("SAN extension already present (from CSR or provided args). Overwriting with collected SANs.")
                  # If it exists, remove it to add the new combined list
                  # Note: Modifying builder.extensions directly is not standard.
                  # A better approach is to rebuild the extensions list.
                  # For simplicity here, we assume the check is enough and the add_extension
                  # call below will handle it, but this is a potential area for refinement.
                  # The standard way is to collect all desired extensions and add them in one go.
                  pass # The add_extension below will likely handle replacement or error if critical

             except x509.ExtensionNotFound:
                  logger.debug("Adding SAN extension with collected entries.")

             # Add the collected SAN entries
             builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        else:
             logger.debug("No SAN entries to add.")


        logger.info(f"Signing certificate for '{common_name}' using CA '{ca_name}' with {digest_algo.name}...")
        try:
            certificate = builder.sign(ca_key_obj, digest_algo, default_backend())
        except Exception as e:
             logger.error(f"Error signing certificate from CSR: {e}")
             raise PKIToolError(f"Failed to sign certificate from CSR: {e}")

        # Determine save paths
        # Use CSR filename base if possible, otherwise common name
        csr_base_name = os.path.splitext(os.path.basename(csr_path))[0]
        cert_dir_name = common_name.replace("*", "wildcard").replace(" ", "_").replace("/", "_").lower()
        # Save signed certs in the main certificates directory, not in 'csr' subdir
        cert_dir = os.path.join(self.config["cert_path"], cert_dir_name)
        os.makedirs(cert_dir, exist_ok=True)

        cert_path = os.path.join(cert_dir, "cert.pem")
        chain_path = os.path.join(cert_dir, "chain.pem") # Leaf + CA
        fullchain_path = os.path.join(cert_dir, "fullchain.pem") # Leaf + Intermediates (if any) + CA

        # Note: This function does NOT generate or save a private key.
        # The private key corresponding to the CSR's public key must be managed separately.
        # If you need to save the *issued certificate* paired with its private key
        # (which was used to generate the CSR), you would need that key here
        # and potentially export a PFX/PKCS12 file. This function only saves the certificate(s).

        logger.info(f"Saving signed certificate to {cert_path}...")
        try:
            with open(cert_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving signed certificate: {e}")
            raise PKIToolError(f"Failed to save signed certificate: {e}")

        logger.info(f"Saving chain file to {chain_path} (Leaf + CA)...")
        try:
            with open(chain_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
                f.write(b"\n") # Add newline between certs
                f.write(ca_cert_obj.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving chain file: {e}")
            pass # Non-critical error

        logger.info(f"Saving fullchain file to {fullchain_path} (Leaf + CA)...")
        try:
            with open(fullchain_path, "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))
                f.write(b"\n")
                f.write(ca_cert_obj.public_bytes(serialization.Encoding.PEM))
        except Exception as e:
            logger.error(f"Error saving fullchain file: {e}")
            pass # Non-critical error


        logger.info(f"Certificate signed successfully from CSR '{csr_path}'. Cert: {cert_path}")
        return {"cert_path": cert_path, "chain_path": chain_path, "fullchain_path": fullchain_path, "cert_name": common_name}


    # TODO: Add functions for:
    # - Revoking certificates (CRL generation/management)
    # - Verifying certificate chains
    # - Exporting certificates/keys in different formats (e.g., PFX/PKCS12)
    # - Integrating with Cloud HSMs (AWS KMS, Azure Key Vault, GCP Cloud HSM) - requires respective SDKs


# --- GUI Application ---
class GUIApp:
    """Main GUI application class."""
    def __init__(self, root, pki_tool_instance):
        self.root = root
        self.pki_tool = pki_tool_instance
        self.root.title("PKI Tool")

        # Configure logging to the GUI text widget
        self.log_text = scrolledtext.ScrolledText(root, state='disabled', height=15, width=80)
        self.log_text.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # Remove default console handler if present
        for handler in logger.handlers[:]:
             if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                  logger.removeHandler(handler)

        # Add GUI text handler
        self.gui_handler = TextHandler(self.log_text)
        self.gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(self.gui_handler)

        # Signal to the handler that the GUI is ready to receive messages
        self.gui_handler.set_gui_ready()

        # Create Notebook (tabs) for different operations
        self.notebook = ttk.Notebook(root)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # --- CA Tab ---
        self.ca_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.ca_frame, text='Create CA')
        self._setup_ca_tab(self.ca_frame)

        # --- Issue Cert Tab ---
        self.issue_cert_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.issue_cert_frame, text='Issue Certificate')
        self._setup_issue_cert_tab(self.issue_cert_frame)

        # --- Check Cert Tab ---
        self.check_cert_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.check_cert_frame, text='Check Certificate')
        self._setup_check_cert_tab(self.check_cert_frame)

        # --- Generate CSR Tab ---
        self.generate_csr_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.generate_csr_frame, text='Generate CSR')
        self._setup_generate_csr_tab(self.generate_csr_frame)

        # --- Sign CSR Tab ---
        self.sign_csr_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.sign_csr_frame, text='Sign CSR')
        self._setup_sign_csr_tab(self.sign_csr_frame)


        # Configure grid weights
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1) # Log area expands vertically
        root.grid_rowconfigure(1, weight=2) # Notebook area expands vertically

    def _setup_ca_tab(self, frame):
        """Sets up the widgets for the Create CA tab."""
        frame.columnconfigure(1, weight=1) # Allow entry fields to expand

        ttk.Label(frame, text="Common Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_cn_entry = ttk.Entry(frame, width=40)
        self.ca_cn_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
        self.ca_cn_entry.insert(0, "MyRootCA") # Default value

        ttk.Label(frame, text="Validity (days):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_validity_entry = ttk.Entry(frame, width=10)
        self.ca_validity_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        self.ca_validity_entry.insert(0, str(self.pki_tool.config.get("default_ca_validity_days", 3650)))

        ttk.Label(frame, text="Key Type:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_key_type_var = tk.StringVar(value=self.pki_tool.config.get("default_key_type", "rsa"))
        self.ca_key_type_rsa = ttk.Radiobutton(frame, text="RSA", variable=self.ca_key_type_var, value="rsa")
        self.ca_key_type_ec = ttk.Radiobutton(frame, text="EC", variable=self.ca_key_type_var, value="ec")
        self.ca_key_type_rsa.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        self.ca_key_type_ec.grid(row=2, column=1, sticky=tk.W, padx=80, pady=2)

        ttk.Label(frame, text="RSA Key Size:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_rsa_size_entry = ttk.Entry(frame, width=10)
        self.ca_rsa_size_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        self.ca_rsa_size_entry.insert(0, str(self.pki_tool.config.get("default_rsa_key_size", 4096)))

        ttk.Label(frame, text="EC Curve:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_ec_curve_var = tk.StringVar(value=self.pki_tool.config.get("default_ec_curve", "SECP384R1"))
        self.ca_ec_curve_combo = ttk.Combobox(frame, textvariable=self.ca_ec_curve_var, values=["SECP256R1", "SECP384R1", "SECP521R1"], state="readonly")
        self.ca_ec_curve_combo.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Organization Name:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_org_entry = ttk.Entry(frame, width=40)
        self.ca_org_entry.grid(row=5, column=1, sticky="ew", padx=5, pady=2)
        self.ca_org_entry.insert(0, self.pki_tool.config.get("default_organization_name_ca", "My PKI Tool CA"))

        ttk.Label(frame, text="Country (2-letter):").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_country_entry = ttk.Entry(frame, width=5)
        self.ca_country_entry.grid(row=6, column=1, sticky=tk.W, padx=5, pady=2)
        self.ca_country_entry.insert(0, self.pki_tool.config.get("default_country_name", "US"))

        ttk.Label(frame, text="State/Province:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_state_entry = ttk.Entry(frame, width=40)
        self.ca_state_entry.grid(row=7, column=1, sticky="ew", padx=5, pady=2)
        self.ca_state_entry.insert(0, self.pki_tool.config.get("default_state_province_name", "California"))

        ttk.Label(frame, text="Locality:").grid(row=8, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_locality_entry = ttk.Entry(frame, width=40)
        self.ca_locality_entry.grid(row=8, column=1, sticky="ew", padx=5, pady=2)
        self.ca_locality_entry.insert(0, self.pki_tool.config.get("default_locality_name", "San Francisco"))

        ttk.Label(frame, text="Email Address:").grid(row=9, column=0, sticky=tk.W, padx=5, pady=2)
        self.ca_email_entry = ttk.Entry(frame, width=40)
        self.ca_email_entry.grid(row=9, column=1, sticky="ew", padx=5, pady=2)
        self.ca_email_entry.insert(0, self.pki_tool.config.get("default_email_address", "pki-tool-ca@example.com"))


        ttk.Button(frame, text="Create CA", command=self._on_create_ca).grid(row=10, column=0, columnspan=2, pady=10)

    def _on_create_ca(self, event=None): # Added event=None for potential binding
        """Handler for the Create CA button."""
        cn = self.ca_cn_entry.get().strip()
        validity_str = self.ca_validity_entry.get().strip()
        key_type = self.ca_key_type_var.get()
        rsa_size_str = self.ca_rsa_size_entry.get().strip()
        ec_curve = self.ca_ec_curve_var.get()
        org = self.ca_org_entry.get().strip()
        country = self.ca_country_entry.get().strip()
        state = self.ca_state_entry.get().strip()
        locality = self.ca_locality_entry.get().strip()
        email = self.ca_email_entry.get().strip()


        if not cn:
            messagebox.showerror("Input Error", "Common Name is required.")
            return
        if not validity_str.isdigit() or int(validity_str) <= 0:
             messagebox.showerror("Input Error", "Validity must be a positive integer.")
             return
        validity_days = int(validity_str)

        rsa_key_size = None
        if key_type == "rsa":
             if not rsa_size_str.isdigit() or int(rsa_size_str) < 1024:
                  messagebox.showerror("Input Error", "RSA Key Size must be a positive integer >= 1024.")
                  return
             rsa_key_size = int(rsa_size_str)


        # Run the CA creation in a separate thread to keep the GUI responsive
        def run_create():
            try:
                logger.info(f"GUI: Starting CA creation for '{cn}'...")
                result = self.pki_tool.create_ca(
                    common_name=cn,
                    key_type=key_type,
                    rsa_key_size=rsa_key_size,
                    ec_curve=ec_curve,
                    validity_days=validity_days,
                    org_name=org,
                    country_name=country,
                    state_province_name=state,
                    locality_name=locality,
                    email_address=email,
                    password=None # Prompt via dialog inside the method
                )
                logger.info(f"GUI: CA '{cn}' created successfully.")
                messagebox.showinfo("Success", f"CA '{cn}' created successfully!\nKey: {result['key_path']}\nCert: {result['cert_path']}")
            except PKIToolError as e:
                logger.error(f"GUI: PKI Tool Error during CA creation: {e}")
                messagebox.showerror("PKI Tool Error", f"Failed to create CA: {e}")
            except Exception as e:
                logger.error(f"GUI: An unexpected error occurred during CA creation: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=run_create).start()


    def _setup_issue_cert_tab(self, frame):
        """Sets up the widgets for the Issue Certificate tab."""
        frame.columnconfigure(1, weight=1) # Allow entry fields to expand

        ttk.Label(frame, text="Signing CA Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_ca_name_entry = ttk.Entry(frame, width=40)
        self.issue_ca_name_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="Common Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_cn_entry = ttk.Entry(frame, width=40)
        self.issue_cn_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="Validity (days):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_validity_entry = ttk.Entry(frame, width=10)
        self.issue_validity_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        self.issue_validity_entry.insert(0, str(self.pki_tool.config.get("default_cert_validity_days", 365)))

        ttk.Label(frame, text="Key Type:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_key_type_var = tk.StringVar(value=self.pki_tool.config.get("default_key_type", "rsa"))
        self.issue_key_type_rsa = ttk.Radiobutton(frame, text="RSA", variable=self.issue_key_type_var, value="rsa")
        self.issue_key_type_ec = ttk.Radiobutton(frame, text="EC", variable=self.issue_key_type_var, value="ec")
        self.issue_key_type_rsa.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        self.issue_key_type_ec.grid(row=3, column=1, sticky=tk.W, padx=80, pady=2)


        ttk.Label(frame, text="RSA Key Size:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_rsa_size_entry = ttk.Entry(frame, width=10)
        self.issue_rsa_size_entry.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)
        self.issue_rsa_size_entry.insert(0, str(self.pki_tool.config.get("default_cert_rsa_key_size", 2048)))

        ttk.Label(frame, text="EC Curve:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_ec_curve_var = tk.StringVar(value=self.pki_tool.config.get("default_cert_ec_curve", "SECP256R1"))
        self.issue_ec_curve_combo = ttk.Combobox(frame, textvariable=self.issue_ec_curve_var, values=["SECP256R1", "SECP384R1", "SECP521R1"], state="readonly")
        self.issue_ec_curve_combo.grid(row=5, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="SAN DNS (comma-sep):").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_san_dns_entry = ttk.Entry(frame, width=40)
        self.issue_san_dns_entry.grid(row=6, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="SAN IP (comma-sep):").grid(row=7, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_san_ip_entry = ttk.Entry(frame, width=40)
        self.issue_san_ip_entry.grid(row=7, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="Organization Name:").grid(row=8, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_org_entry = ttk.Entry(frame, width=40)
        self.issue_org_entry.grid(row=8, column=1, sticky="ew", padx=5, pady=2)
        self.issue_org_entry.insert(0, self.pki_tool.config.get("default_organization_name_user", "My PKI Tool User"))

        ttk.Label(frame, text="Country (2-letter):").grid(row=9, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_country_entry = ttk.Entry(frame, width=5)
        self.issue_country_entry.grid(row=9, column=1, sticky=tk.W, padx=5, pady=2)
        self.issue_country_entry.insert(0, self.pki_tool.config.get("default_country_name", "US"))

        ttk.Label(frame, text="State/Province:").grid(row=10, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_state_entry = ttk.Entry(frame, width=40)
        self.issue_state_entry.grid(row=10, column=1, sticky="ew", padx=5, pady=2)
        self.issue_state_entry.insert(0, self.pki_tool.config.get("default_state_province_name", "California"))

        ttk.Label(frame, text="Locality:").grid(row=11, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_locality_entry = ttk.Entry(frame, width=40)
        self.issue_locality_entry.grid(row=11, column=1, sticky="ew", padx=5, pady=2)
        self.issue_locality_entry.insert(0, self.pki_tool.config.get("default_locality_name", "San Francisco"))

        ttk.Label(frame, text="Email Address:").grid(row=12, column=0, sticky=tk.W, padx=5, pady=2)
        self.issue_email_entry = ttk.Entry(frame, width=40)
        self.issue_email_entry.grid(row=12, column=1, sticky="ew", padx=5, pady=2)
        self.issue_email_entry.insert(0, self.pki_tool.config.get("default_email_address", "pki-tool-user@example.com"))


        self.issue_encrypt_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Encrypt Private Key", variable=self.issue_encrypt_key_var).grid(row=13, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)

        ttk.Button(frame, text="Issue Certificate", command=self._on_issue_certificate).grid(row=14, column=0, columnspan=2, pady=10)

    def _on_issue_certificate(self, event=None): # Added event=None for potential binding
        """Handler for the Issue Certificate button."""
        ca_name = self.issue_ca_name_entry.get().strip()
        cn = self.issue_cn_entry.get().strip()
        validity_str = self.issue_validity_entry.get().strip()
        key_type = self.issue_key_type_var.get()
        rsa_size_str = self.issue_rsa_size_entry.get().strip()
        ec_curve = self.issue_ec_curve_combo.get()
        san_dns_str = self.issue_san_dns_entry.get().strip()
        san_ip_str = self.issue_san_ip_entry.get().strip()
        org = self.issue_org_entry.get().strip()
        country = self.issue_country_entry.get().strip()
        state = self.issue_state_entry.get().strip()
        locality = self.issue_locality_entry.get().strip()
        email = self.issue_email_entry.get().strip()
        encrypt_key = self.issue_encrypt_key_var.get()


        if not ca_name:
            messagebox.showerror("Input Error", "Signing CA Name is required.")
            return
        if not cn:
            messagebox.showerror("Input Error", "Common Name is required.")
            return
        if not validity_str.isdigit() or int(validity_str) <= 0:
             messagebox.showerror("Input Error", "Validity must be a positive integer.")
             return
        validity_days = int(validity_str)

        rsa_key_size = None
        if key_type == "rsa":
             if not rsa_size_str.isdigit() or int(rsa_size_str) < 1024:
                  messagebox.showerror("Input Error", "RSA Key Size must be a positive integer >= 1024.")
                  return
             rsa_key_size = int(rsa_size_str)

        san_dns = [s.strip() for s in san_dns_str.split(',') if s.strip()] if san_dns_str else None
        san_ip = [s.strip() for s in san_ip_str.split(',') if s.strip()] if san_ip_str else None


        # Run in a separate thread
        def run_issue():
            try:
                logger.info(f"GUI: Starting certificate issuance for '{cn}' using CA '{ca_name}'...")
                result = self.pki_tool.issue_certificate(
                    ca_name=ca_name,
                    common_name=cn,
                    key_type=key_type,
                    rsa_key_size=rsa_key_size,
                    ec_curve=ec_curve,
                    validity_days=validity_days,
                    san_dns=san_dns,
                    san_ip=san_ip,
                    org_name=org,
                    country_name=country,
                    state_province_name=state,
                    locality_name=locality,
                    email_address=email,
                    encrypt_key=encrypt_key,
                    key_password=None # Prompt via dialog inside the method if encrypt_key is True
                )
                logger.info(f"GUI: Certificate for '{cn}' issued successfully.")
                messagebox.showinfo("Success", f"Certificate for '{cn}' issued successfully!\nCert: {result['cert_path']}\nKey: {result['key_path']}")
            except PKIToolError as e:
                logger.error(f"GUI: PKI Tool Error during certificate issuance: {e}")
                messagebox.showerror("PKI Tool Error", f"Failed to issue certificate: {e}")
            except Exception as e:
                logger.error(f"GUI: An unexpected error occurred during certificate issuance: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=run_issue).start()


    def _setup_check_cert_tab(self, frame):
        """Sets up the widgets for the Check Certificate tab."""
        frame.columnconfigure(1, weight=1) # Allow entry fields to expand

        ttk.Label(frame, text="Certificate File:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.check_cert_path_entry = ttk.Entry(frame, width=40)
        self.check_cert_path_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Button(frame, text="Browse...", command=self._browse_cert_file).grid(row=0, column=2, padx=5, pady=2)

        ttk.Button(frame, text="Check Certificate", command=self._on_check_certificate).grid(row=1, column=0, columnspan=3, pady=10)

        # Optional: Add a text area to display detailed check results (beyond logs)
        # self.check_result_text = scrolledtext.ScrolledText(frame, state='disabled', height=10, width=60)
        # self.check_result_text.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

    def _browse_cert_file(self):
        """Opens a file dialog to select a certificate file."""
        filepath = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=(("PEM files", "*.pem"), ("CRT files", "*.crt"), ("All files", "*.*"))
        )
        if filepath:
            self.check_cert_path_entry.delete(0, tk.END)
            self.check_cert_path_entry.insert(0, filepath)

    def _on_check_certificate(self, event=None): # Added event=None for potential binding
        """Handler for the Check Certificate button."""
        cert_path = self.check_cert_path_entry.get().strip()

        if not cert_path:
            messagebox.showerror("Input Error", "Please specify a certificate file path.")
            return
        if not os.path.exists(cert_path):
             messagebox.showerror("Input Error", f"File not found: {cert_path}")
             return


        # Run in a separate thread
        def run_check():
            try:
                logger.info(f"GUI: Starting certificate check for '{cert_path}'...")
                info = self.pki_tool.check_certificate(cert_path)
                logger.info(f"GUI: Certificate check completed for '{cert_path}'. Details logged.")
                # Optionally display summary in a message box or dedicated text area
                # messagebox.showinfo("Certificate Details", json.dumps(info, indent=2, default=str))
            except PKIToolError as e:
                logger.error(f"GUI: PKI Tool Error during certificate check: {e}")
                messagebox.showerror("PKI Tool Error", f"Failed to check certificate: {e}")
            except Exception as e:
                logger.error(f"GUI: An unexpected error occurred during certificate check: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=run_check).start()

    def _setup_generate_csr_tab(self, frame):
        """Sets up the widgets for the Generate CSR tab."""
        frame.columnconfigure(1, weight=1) # Allow entry fields to expand

        ttk.Label(frame, text="Common Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_cn_entry = ttk.Entry(frame, width=40)
        self.csr_cn_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="Existing Key Path (Optional):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_key_path_entry = ttk.Entry(frame, width=40)
        self.csr_key_path_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        ttk.Button(frame, text="Browse...", command=self._browse_key_file_csr).grid(row=1, column=2, padx=5, pady=2)

        ttk.Label(frame, text="Key Type (if generating new):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_key_type_var = tk.StringVar(value=self.pki_tool.config.get("default_key_type", "rsa"))
        self.csr_key_type_rsa = ttk.Radiobutton(frame, text="RSA", variable=self.csr_key_type_var, value="rsa")
        self.csr_key_type_ec = ttk.Radiobutton(frame, text="EC", variable=self.csr_key_type_var, value="ec")
        self.csr_key_type_rsa.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        self.csr_key_type_ec.grid(row=2, column=1, sticky=tk.W, padx=80, pady=2)

        ttk.Label(frame, text="RSA Key Size (if generating new):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_rsa_size_entry = ttk.Entry(frame, width=10)
        self.csr_rsa_size_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        self.csr_rsa_size_entry.insert(0, str(self.pki_tool.config.get("default_cert_rsa_key_size", 2048)))

        ttk.Label(frame, text="EC Curve (if generating new):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_ec_curve_var = tk.StringVar(value=self.pki_tool.config.get("default_cert_ec_curve", "SECP256R1"))
        self.csr_ec_curve_combo = ttk.Combobox(frame, textvariable=self.csr_ec_curve_var, values=["SECP256R1", "SECP384R1", "SECP521R1"], state="readonly")
        self.csr_ec_curve_combo.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="SAN DNS (comma-sep):").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_san_dns_entry = ttk.Entry(frame, width=40)
        self.csr_san_dns_entry.grid(row=5, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="SAN IP (comma-sep):").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_san_ip_entry = ttk.Entry(frame, width=40)
        self.csr_san_ip_entry.grid(row=6, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="Organization Name:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_org_entry = ttk.Entry(frame, width=40)
        self.csr_org_entry.grid(row=7, column=1, sticky="ew", padx=5, pady=2)
        self.csr_org_entry.insert(0, self.pki_tool.config.get("default_organization_name_user", "My PKI Tool User"))

        ttk.Label(frame, text="Country (2-letter):").grid(row=8, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_country_entry = ttk.Entry(frame, width=5)
        self.csr_country_entry.grid(row=8, column=1, sticky=tk.W, padx=5, pady=2)
        self.csr_country_entry.insert(0, self.pki_tool.config.get("default_country_name", "US"))

        ttk.Label(frame, text="State/Province:").grid(row=9, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_state_entry = ttk.Entry(frame, width=40)
        self.csr_state_entry.grid(row=9, column=1, sticky="ew", padx=5, pady=2)
        # Corrected OID name
        self.csr_state_entry.insert(0, self.pki_tool.config.get("default_state_province_name", "California"))

        ttk.Label(frame, text="Locality:").grid(row=10, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_locality_entry = ttk.Entry(frame, width=40)
        self.csr_locality_entry.grid(row=10, column=1, sticky="ew", padx=5, pady=2)
        self.csr_locality_entry.insert(0, self.pki_tool.config.get("default_locality_name", "San Francisco"))

        ttk.Label(frame, text="Email Address:").grid(row=11, column=0, sticky=tk.W, padx=5, pady=2)
        self.csr_email_entry = ttk.Entry(frame, width=40)
        self.csr_email_entry.grid(row=11, column=1, sticky="ew", padx=5, pady=2)
        self.csr_email_entry.insert(0, self.pki_tool.config.get("default_email_address", "pki-tool-csr@example.com"))


        self.csr_save_key_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Save Private Key (if new)", variable=self.csr_save_key_var).grid(row=12, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)

        self.csr_encrypt_key_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Encrypt Private Key (if new and saved)", variable=self.csr_encrypt_key_var).grid(row=13, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)


        ttk.Button(frame, text="Generate CSR", command=self._on_generate_csr).grid(row=14, column=0, columnspan=3, pady=10)


    def _browse_key_file_csr(self):
        """Opens a file dialog to select a private key file for CSR."""
        filepath = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=(("PEM files", "*.pem"), ("Key files", "*.key"), ("All files", "*.*"))
        )
        if filepath:
            self.csr_key_path_entry.delete(0, tk.END)
            self.csr_key_path_entry.insert(0, filepath)

    def _on_generate_csr(self, event=None): # Added event=None for potential binding
        """Handler for the Generate CSR button."""
        cn = self.csr_cn_entry.get().strip()
        key_path = self.csr_key_path_entry.get().strip()
        key_type = self.csr_key_type_var.get()
        rsa_size_str = self.csr_rsa_size_entry.get().strip()
        ec_curve = self.csr_ec_curve_combo.get()
        san_dns_str = self.csr_san_dns_entry.get().strip()
        san_ip_str = self.csr_san_ip_entry.get().strip()
        org = self.csr_org_entry.get().strip()
        country = self.csr_country_entry.get().strip()
        state = self.csr_state_entry.get().strip()
        locality = self.csr_locality_entry.get().strip()
        email = self.csr_email_entry.get().strip()
        save_key = self.csr_save_key_var.get()
        encrypt_key = self.csr_encrypt_key_var.get()


        if not cn:
            messagebox.showerror("Input Error", "Common Name is required.")
            return

        rsa_key_size = None
        if key_type == "rsa":
             if not rsa_size_str.isdigit() or int(rsa_size_str) < 1024:
                  messagebox.showerror("Input Error", "RSA Key Size must be a positive integer >= 1024.")
                  return
             rsa_key_size = int(rsa_size_str)

        san_dns = [s.strip() for s in san_dns_str.split(',') if s.strip()] if san_dns_str else None
        san_ip = [s.strip() for s in san_ip_str.split(',') if s.strip()] if san_ip_str else None

        # Run in a separate thread
        def run_generate():
            try:
                logger.info(f"GUI: Starting CSR generation for '{cn}'...")
                result = self.pki_tool.generate_csr(
                    common_name=cn,
                    key_path=key_path if key_path else None, # Pass None if empty string
                    key_password=None, # Password for existing key will be prompted by the method
                    key_type=key_type,
                    rsa_key_size=rsa_key_size,
                    ec_curve=ec_curve,
                    org_name=org,
                    country_name=country,
                    state_province_name=state,
                    locality_name=locality,
                    email_address=email,
                    san_dns=san_dns,
                    san_ip=san_ip,
                    save_key=save_key,
                    encrypt_key=encrypt_key,
                    # key_password for encrypting *new* key is handled internally
                )
                logger.info(f"GUI: CSR for '{cn}' generated successfully.")
                msg = f"CSR for '{cn}' generated successfully!\nCSR: {result['csr_path']}"
                if 'key_path' in result:
                     msg += f"\nPrivate Key: {result['key_path']}"
                messagebox.showinfo("Success", msg)
            except PKIToolError as e:
                logger.error(f"GUI: PKI Tool Error during CSR generation: {e}")
                messagebox.showerror("PKI Tool Error", f"Failed to generate CSR: {e}")
            except Exception as e:
                logger.error(f"GUI: An unexpected error occurred during CSR generation: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=run_generate).start()


    def _setup_sign_csr_tab(self, frame):
        """Sets up the widgets for the Sign CSR tab."""
        frame.columnconfigure(1, weight=1) # Allow entry fields to expand

        ttk.Label(frame, text="Signing CA Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.sign_ca_name_entry = ttk.Entry(frame, width=40)
        self.sign_ca_name_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        ttk.Label(frame, text="CSR File:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.sign_csr_path_entry = ttk.Entry(frame, width=40)
        self.sign_csr_path_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
        ttk.Button(frame, text="Browse...", command=self._browse_csr_file).grid(row=1, column=2, padx=5, pady=2)

        ttk.Label(frame, text="Validity (days):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.sign_validity_entry = ttk.Entry(frame, width=10)
        self.sign_validity_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        self.sign_validity_entry.insert(0, str(self.pki_tool.config.get("default_cert_validity_days", 365)))

        # Optional: Allow overriding SANs or Subject from CSR
        # ttk.Label(frame, text="Override SAN DNS (comma-sep):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        # self.sign_san_dns_entry = ttk.Entry(frame, width=40)
        # self.sign_san_dns_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=2)

        # ttk.Label(frame, text="Override SAN IP (comma-sep):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        # self.sign_san_ip_entry = ttk.Entry(frame, width=40)
        # self.sign_san_ip_entry.grid(row=4, column=1, sticky="ew", padx=5, pady=2)

        ttk.Button(frame, text="Sign CSR", command=self._on_sign_csr).grid(row=5, column=0, columnspan=3, pady=10)


    def _browse_csr_file(self):
        """Opens a file dialog to select a CSR file."""
        filepath = filedialog.askopenfilename(
            title="Select CSR File",
            filetypes=(("CSR files", "*.csr"), ("PEM files", "*.pem"), ("All files", "*.*"))
        )
        if filepath:
            self.sign_csr_path_entry.delete(0, tk.END)
            self.sign_csr_path_entry.insert(0, filepath)

    def _on_sign_csr(self, event=None): # Added event=None for potential binding
        """Handler for the Sign CSR button."""
        ca_name = self.sign_ca_name_entry.get().strip()
        csr_path = self.sign_csr_path_entry.get().strip()
        validity_str = self.sign_validity_entry.get().strip()

        if not ca_name:
            messagebox.showerror("Input Error", "Signing CA Name is required.")
            return
        if not csr_path:
            messagebox.showerror("Input Error", "Please specify a CSR file path.")
            return
        if not os.path.exists(csr_path):
             messagebox.showerror("Input Error", f"File not found: {csr_path}")
             return
        if not validity_str.isdigit() or int(validity_str) <= 0:
             messagebox.showerror("Input Error", "Validity must be a positive integer.")
             return
        validity_days = int(validity_str)

        # san_dns_str = self.sign_san_dns_entry.get().strip()
        # san_ip_str = self.sign_san_ip_entry.get().strip()
        # san_dns = [s.strip() for s in san_dns_str.split(',') if s.strip()] if san_dns_str else None
        # san_ip = [s.strip() for s in san_ip_str.split(',') if s.strip()] if san_ip_str else None


        # Run in a separate thread
        def run_sign():
            try:
                logger.info(f"GUI: Starting CSR signing for '{csr_path}' using CA '{ca_name}'...")
                result = self.pki_tool.sign_csr(
                    ca_name=ca_name,
                    csr_path=csr_path,
                    validity_days=validity_days,
                    san_dns=None, # Use SANs from CSR unless override fields are added and used
                    san_ip=None,
                    org_name=None, # Use subject from CSR unless override fields are added and used
                    country_name=None,
                    state_province_name=None,
                    locality_name=None,
                    email_address=None,
                )
                logger.info(f"GUI: CSR '{csr_path}' signed successfully.")
                messagebox.showinfo("Success", f"CSR '{csr_path}' signed successfully!\nSigned Cert: {result['cert_path']}")
            except PKIToolError as e:
                logger.error(f"GUI: PKI Tool Error during CSR signing: {e}")
                messagebox.showerror("PKI Tool Error", f"Failed to sign CSR: {e}")
            except Exception as e:
                logger.error(f"GUI: An unexpected error occurred during CSR signing: {e}\n{traceback.format_exc()}")
                messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")

        threading.Thread(target=run_sign).start()


# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="PKI Tool for generating and managing certificates.")
    parser.add_argument("--config", help="Path to a YAML configuration file.")
    parser.add_argument("--gui", action="store_true", help="Run the tool with a graphical user interface.")

    # Subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Create CA command
    parser_create_ca = subparsers.add_parser("create-ca", help="Create a new Certificate Authority.")
    parser_create_ca.add_argument("common_name", help="Common Name (CN) for the CA.")
    parser_create_ca.add_argument("--key-type", choices=["rsa", "ec"], help="Key type (rsa or ec).")
    parser_create_ca.add_argument("--rsa-size", type=int, help="RSA key size in bits.")
    parser_create_ca.add_argument("--ec-curve", help="EC curve name (e.g., SECP256R1).")
    parser_create_ca.add_argument("--validity-days", type=int, help="Validity period in days.")
    parser_create_ca.add_argument("--org", help="Organization Name (O).")
    parser_create_ca.add_argument("--country", help="Country Name (C, 2-letter code).")
    parser_create_ca.add_argument("--state", help="State or Province Name (ST).")
    parser_create_ca.add_argument("--locality", help="Locality Name (L).")
    parser_create_ca.add_argument("--email", help="Email Address.")
    parser_create_ca.add_argument("--password", help="Password to encrypt the CA private key (use with caution).")


    # Issue Certificate command
    parser_issue_cert = subparsers.add_parser("issue-cert", help="Issue a new certificate signed by a CA.")
    parser_issue_cert.add_argument("ca_name", help="Common Name of the issuing CA.")
    parser_issue_cert.add_argument("common_name", help="Common Name (CN) for the new certificate.")
    parser_issue_cert.add_argument("--key-type", choices=["rsa", "ec"], help="Key type for the new certificate (rsa or ec).")
    parser_issue_cert.add_argument("--rsa-size", type=int, help="RSA key size in bits for the new certificate.")
    parser_issue_cert.add_argument("--ec-curve", help="EC curve name for the new certificate.")
    parser_issue_cert.add_argument("--validity-days", type=int, help="Validity period in days.")
    parser_issue_cert.add_argument("--san-dns", help="Comma-separated list of Subject Alternative Names (DNS).")
    parser_issue_cert.add_argument("--san-ip", help="Comma-separated list of Subject Alternative Names (IP Addresses).")
    parser_issue_cert.add_argument("--org", help="Organization Name (O).")
    parser_issue_cert.add_argument("--country", help="Country Name (C, 2-letter code).")
    parser_issue_cert.add_argument("--state", help="State or Province Name (ST).")
    parser_issue_cert.add_argument("--locality", help="Locality Name (L).")
    parser_issue_cert.add_argument("--email", help="Email Address.")
    parser_issue_cert.add_argument("--encrypt-key", action="store_true", help="Encrypt the new certificate's private key.")
    parser_issue_cert.add_argument("--password", help="Password to encrypt the certificate private key (use with caution).")


    # Check Certificate command
    parser_check_cert = subparsers.add_parser("check-cert", help="Check details and validity of a certificate.")
    parser_check_cert.add_argument("cert_path", help="Path to the certificate file (PEM format).")

    # Generate CSR command
    parser_generate_csr = subparsers.add_parser("generate-csr", help="Generate a Certificate Signing Request (CSR).")
    parser_generate_csr.add_argument("common_name", help="Common Name (CN) for the CSR.")
    parser_generate_csr.add_argument("--key-path", help="Path to an existing private key file to use for the CSR.")
    parser_generate_csr.add_argument("--key-password", help="Password for the existing private key (use with caution).")
    parser_generate_csr.add_argument("--key-type", choices=["rsa", "ec"], help="Key type for a new private key (if --key-path is not used).")
    parser_generate_csr.add_argument("--rsa-size", type=int, help="RSA key size for a new private key.")
    parser_generate_csr.add_argument("--ec-curve", help="EC curve name for a new private key.")
    parser_generate_csr.add_argument("--san-dns", help="Comma-separated list of Subject Alternative Names (DNS) for the CSR.")
    parser_generate_csr.add_argument("--san-ip", help="Comma-separated list of Subject Alternative Names (IP Addresses) for the CSR.")
    parser_generate_csr.add_argument("--org", help="Organization Name (O).")
    parser_generate_csr.add_argument("--country", help="Country Name (C, 2-letter code).")
    parser_generate_csr.add_argument("--state", help="State or Province Name (ST).")
    parser_generate_csr.add_argument("--locality", help="Locality Name (L).")
    parser_generate_csr.add_argument("--email", help="Email Address.")
    parser_generate_csr.add_argument("--no-save-key", action="store_false", dest="save_key", help="Do not save the generated private key.")
    parser_generate_csr.add_argument("--encrypt-key", action="store_true", help="Encrypt the new private key if saved.")
    # Note: --password argument for encrypting *new* key is handled by _get_password_for_encryption


    # Sign CSR command
    parser_sign_csr = subparsers.add_parser("sign-csr", help="Sign a Certificate Signing Request (CSR) using a CA.")
    parser_sign_csr.add_argument("ca_name", help="Common Name of the issuing CA.")
    parser_sign_csr.add_argument("csr_path", help="Path to the CSR file (PEM format).")
    parser_sign_csr.add_argument("--validity-days", type=int, help="Validity period in days for the issued certificate.")
    # Optional: Add arguments to override SANs or Subject from CSR if needed


    args = parser.parse_args()

    if args.gui:
        root = tk.Tk()
        # Need to instantiate PKITool with the root window for password dialogs
        pki_tool = PKITool(config_path=args.config, gui_mode=True, gui_root=root)
        app = GUIApp(root, pki_tool)
        root.mainloop()
    else:
        # CLI Mode
        # Ensure console handler is present if not in GUI mode
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            ch = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        pki_tool = PKITool(config_path=args.config, gui_mode=False)

        if args.command == "create-ca":
            try:
                # Pass password directly if provided via CLI arg (less secure)
                # Otherwise, the method will prompt using getpass
                password_arg = args.password.encode() if args.password else None
                pki_tool.create_ca(
                    common_name=args.common_name,
                    key_type=args.key_type,
                    rsa_key_size=args.rsa_size,
                    ec_curve=args.ec_curve,
                    validity_days=args.validity_days,
                    org_name=args.org,
                    country_name=args.country,
                    state_province_name=args.state,
                    locality_name=args.locality,
                    email_address=args.email,
                    password=password_arg # Use password from arg if provided
                )
            except PKIToolError as e:
                logger.error(f"CLI Error: {e}")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"CLI Unexpected Error: {e}", exc_info=True)
                 sys.exit(1)


        elif args.command == "issue-cert":
            try:
                san_dns = [s.strip() for s in args.san_dns.split(',') if s.strip()] if args.san_dns else None
                san_ip = [s.strip() for s in args.san_ip.split(',') if s.strip()] if args.san_ip else None
                # Pass password directly if provided via CLI arg (less secure) AND encrypt-key is true
                # Otherwise, the method will prompt using getpass if encrypt-key is true
                password_arg = args.password.encode() if args.password and args.encrypt_key else None

                pki_tool.issue_certificate(
                    ca_name=args.ca_name,
                    common_name=args.common_name,
                    key_type=args.key_type,
                    rsa_key_size=args.rsa_size,
                    ec_curve=args.ec_curve,
                    validity_days=args.validity_days,
                    san_dns=san_dns,
                    san_ip=san_ip,
                    org_name=args.org,
                    country_name=args.country,
                    state_province_name=args.state,
                    locality_name=args.locality,
                    email_address=args.email,
                    encrypt_key=args.encrypt_key,
                    key_password=password_arg # Use password from arg if provided and encryption requested
                )
            except PKIToolError as e:
                logger.error(f"CLI Error: {e}")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"CLI Unexpected Error: {e}", exc_info=True)
                 sys.exit(1)

        elif args.command == "check-cert":
            try:
                pki_tool.check_certificate(cert_path=args.cert_path)
            except PKIToolError as e:
                logger.error(f"CLI Error: {e}")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"CLI Unexpected Error: {e}", exc_info=True)
                 sys.exit(1)

        elif args.command == "generate-csr":
            try:
                san_dns = [s.strip() for s in args.san_dns.split(',') if s.strip()] if args.san_dns else None
                san_ip = [s.strip() for s in args.san_ip.split(',') if s.strip()] if args.san_ip else None

                # Pass password for *existing* key if provided via CLI arg (less secure)
                # Otherwise, the method will prompt using getpass
                existing_key_password_arg = args.key_password.encode() if args.key_password else None

                # Password for *new* key encryption is handled by _get_password_for_encryption inside the method

                pki_tool.generate_csr(
                    common_name=args.common_name,
                    key_path=args.key_path,
                    key_password=existing_key_password_arg, # Pass password for existing key
                    key_type=args.key_type,
                    rsa_key_size=args.rsa_size,
                    ec_curve=args.ec_curve,
                    org_name=args.org,
                    country_name=args.country,
                    state_province_name=args.state,
                    locality_name=args.locality,
                    email_address=args.email,
                    san_dns=san_dns,
                    san_ip=san_ip,
                    save_key=args.save_key,
                    encrypt_key=args.encrypt_key,
                    # key_password for encrypting *new* key is handled internally
                )
            except PKIToolError as e:
                logger.error(f"CLI Error: {e}")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"CLI Unexpected Error: {e}", exc_info=True)
                 sys.exit(1)

        elif args.command == "sign-csr":
            try:
                # SANs and Subject overrides are not implemented in CLI args yet
                pki_tool.sign_csr(
                    ca_name=args.ca_name,
                    csr_path=args.csr_path,
                    validity_days=args.validity_days,
                    # Pass None for overrides, so it uses CSR values
                    san_dns=None, san_ip=None,
                    org_name=None, country_name=None, state_province_name=None,
                    locality_name=None, email_address=None,
                )
            except PKIToolError as e:
                logger.error(f"CLI Error: {e}")
                sys.exit(1)
            except Exception as e:
                 logger.error(f"CLI Unexpected Error: {e}", exc_info=True)
                 sys.exit(1)


        elif args.command is None:
            logger.info("No command specified. Use --help for usage.")
            if not args.gui: # Only show usage if not starting GUI
                 parser.print_help()
            sys.exit(1)


if __name__ == "__main__":
    main()
