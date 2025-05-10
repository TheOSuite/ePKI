## ePKI Tool - Certificate Authority and Certificate Management Utility

**Overview:**  
This versatile ePKI tool enables users to create and manage a Public Key Infrastructure (PKI) environment, including creating CAs, issuing certificates, generating CSRs, signing CSRs, and verifying certificates. It offers both command-line and GUI interfaces for flexible operation.

---

## Features & Capabilities

### Core Functions
- **Create Certificate Authorities (CAs):** Generate self-signed root CAs with customizable attributes, key types (RSA or EC), and validity periods.
- **Issue Certificates:** Sign certificates using an existing CA, supporting SAN extensions, custom attributes, and different key types.
- **Generate CSRs:** Create Certificate Signing Requests with support for existing private keys, SANs, and custom subject attributes.
- **Sign CSRs:** Sign submitted CSRs with an existing CA, with optional SAN and subject overrides.
- **Certificate Validation:** Check the details, expiry, and extensions of existing certificates.
- **Key Management:** Generate, encrypt, and decrypt private keys with password prompts, supporting both GUI and CLI interactions.
- **Certificate Extensions Extraction:** Parse and display detailed extension data, including SANs, Key Usage, EKU, CRL Distribution Points, etc.
- **Flexible Configuration:** Load default parameters and attributes from YAML files, allowing easy customization.
- **Logging & Auditing:** Detailed logs of all operations, available in both CLI output and GUI logs.
- **GUI Interface:** An intuitive Tkinter-based GUI for creating CAs, issuing certificates, generating CSRs, and viewing certificate details interactively.
- **Extensibility:** Designed with placeholders for future expansion such as CRL management, chain validation, exporting in various formats, and cloud/HSM integrations.

---

## How to Use

### 1. As a Command-Line Tool

**Basic Usage:**

```bash
python ePKI.py --help
```

**Sample commands:**

- **Create a CA:**

```bash
python ePKI.py create-ca MyRootCA --validity-days 3650 --key-type rsa --rsa-size 4096
```

- **Issue a Certificate:**

```bash
python ePKI.py issue-cert --ca-name MyRootCA --common-name www.example.com --san-dns www.example.com,api.example.com --validity-days 365
```

- **Check a Certificate:**

```bash
python ePKI.py check-cert --cert-path ./certificates/www_example_com/cert.pem
```

- **Generate a CSR:**

```bash
python ePKI.py generate-csr --common-name myapp.example.com --rsa-size 2048 --save-key
```

- **Sign a CSR:**

```bash
python ePKI.py sign-csr --ca-name MyRootCA --csr-path ./certificates/myapp/csr/request.csr --validity-days 365
```

Many parameters are configurable via CLI options or config files for automation.

---

### 2. Using the Graphical User Interface (GUI)

Start the GUI:

```bash
python ePKI.py --gui
```

This opens a window with tabs for:

- *Create CA*: Fill in details and generate a new CA.
- *Issue Certificate*: Generate certificates with SANs, key options, and validity.
- *Check Certificate*: Browse and verify certificate details.
- *Generate CSR*: Create CSRs with optional existing keys and SANs.
- *Sign CSR*: Sign CSRs with a selected CA.

---

## How to Run the Script

### 1. Prerequisites

- Python 3.x installed.
- Install dependencies:

```bash
pip install cryptography pyyaml
```

- Save your script as `ePKI.py`.

### 2. Running

#### a) CLI Mode

- Show help:

```bash
python ePKI.py --help
```

- Example: create a CA:

```bash
python ePKI.py create-ca MyRootCA --validity-days 3650 --key-type rsa --rsa-size 4096
```

- Example: issue cert:

```bash
python ePKI.py issue-cert --ca-name MyRootCA --common-name www.example.com --san-dns www.example.com,api.example.com --validity-days 365
```

- Example: check cert:

```bash
python ePKI.py check-cert --cert-path ./certificates/www_example_com/cert.pem
```

- Example: generate CSR:

```bash
python ePKI.py generate-csr --common-name myapp.example.com --save-key
```

- Example: sign CSR:

```bash
python ePKI.py sign-csr --ca-name MyRootCA --csr-path ./certificates/myapp/csr/request.csr --validity-days 365
```

#### b) GUI Mode

- Launch GUI:

```bash
python ePKI.py --gui
```

---

## Important Notes

- Run the script from a terminal or command prompt.
- Dependencies must be installed.
- Passwords are securely handled via dialogs or CLI prompts.
- For scripting, use configuration files or command-line options.

---
