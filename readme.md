# Secure Local Password Manager

![Go Logo](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Fyne Logo](https://img.shields.io/badge/Fyne-333333?style=for-the-badge&logo=fyne&logoColor=white)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)

A minimalist yet secure password manager application built with Go, focusing on robust local encryption and a clean user interface. This project serves as a foundational demonstration of secure credential management, emphasizing cryptographic principles over complex network-based authentication for its initial iteration.

## 🌟 Key Features

- **Robust Encryption:** All sensitive vault data (usernames, passwords, URLs, notes) is encrypted using **AES-256 in GCM (Galois/Counter Mode)**, providing both confidentiality and integrity.

- **Strong Key Derivation:** A user's master password is never stored directly. Instead, a cryptographically strong **Master Encryption Key** is derived using **PBKDF2 (Password-Based Key Derivation Function 2)** with a unique salt and high iteration count.

- **Zero-Knowledge Principle:** The application adheres to a zero-knowledge architecture, meaning only the user, with their master password, can decrypt and access their vault. The master password itself is never stored or transmitted.

- **Local File Storage:** Encrypted vault data is stored securely in a local file (`vault.dat`), dedicated to each user.

- **Memory Security Focus:** Efforts are made to minimize the plaintext exposure of sensitive data in memory, with active scrubbing of the Master Encryption Key and decrypted credentials upon session termination.

- **Core Credential Management:** Users can securely:

    - **Sign Up** and create their personal encrypted vault.

    - **Log In** and decrypt their vault.

    - **Add** new website credentials (URL, username, password, notes).

    - **List** all stored credentials (passwords are masked by default).

    - **Logout** to clear sensitive data from memory.

- **Go-Powered Backend:** The core logic for encryption, decryption, user management, and vault operations is built entirely in Go.

- **Web-Based UI (Local Host):** For a quick and accessible interface, the application serves a simple HTML/CSS/JavaScript frontend locally, allowing interaction via a web browser.

## 🔒 Security Highlights (The Core Focus)

This project places a strong emphasis on the cryptographic security of the stored data:

- **Master Password to Key Derivation:**

    - When you set your master password, a unique, random **salt** is generated and stored alongside your user profile.

    - This master password and the salt are fed into **PBKDF2** (a computationally intensive process) to derive a robust **Master Encryption Key**. This key is the _only_ thing capable of decrypting your vault.

    - This process ensures that even if an attacker obtains your salt, they cannot easily reverse-engineer your master password or the encryption key.

- **Vault Encryption (AES-256-GCM):**

    - Your entire vault content (all credentials serialized as JSON) is encrypted as a single block using the derived **Master Encryption Key** and a **unique Initialization Vector (IV)** for each encryption operation.

    - AES-GCM provides **authenticated encryption**, meaning any tampering with the encrypted data will be detected upon decryption, preventing malicious modification.

- **Memory Management:**

    - Upon successful login, the entire vault is decrypted into the application's RAM.

    - The **Master Encryption Key** is held in memory for the duration of the active session to facilitate quick encryption/decryption for operations like adding new credentials.

    - Upon logout or application exit, the application actively attempts to **overwrite (scrub)** sensitive data (the Master Encryption Key and decrypted credentials) in memory with zeros, mitigating risks from memory forensics.

## 🚀 How to Run

1. **Clone the repository:**
   git clone https://github.com/caspgin/PasswordManager.git

2. **Install Go dependencies:**
   go mod tidy

3. **Run the application:**
   go run main.go

The application will start a local web server, typically on `http://localhost:8080`.

4. **Open in your browser:**
   Navigate to `http://localhost:8080` in your web browser.

## 📈 Future Enhancements (Roadmap)

This MVP demonstrates the core secure storage principles. To evolve into a production-grade, competitive password manager, the following features and security enhancements are planned:

- **Enhanced Memory Protection:** Deeper integration with OS-level memory locking (e.g., `VirtualLock` on Windows) to prevent sensitive data from being swapped to disk.

- **Robust Session Management:** Implement secure, server-side session tokens to manage user sessions, moving beyond simple `globalApp` state for multi-user or more complex scenarios.

- **OS-Level Session Persistence:** Leverage native OS secure storage (Windows Credential Manager, macOS Keychain) for "Remember Me" functionality across reboots, avoiding repeated master password entry.

- **Multi-Factor Authentication (MFA):** Full implementation of TOTP (Time-based One-Time Password) 2FA for login.

- **Biometric Authentication:** Integration with OS biometric features (e.g., Windows Hello) for quick and secure vault unlocks.

- **Credential Search & Filtering:** Implement dynamic search functionality within the vault.

- **Secure Copy to Clipboard:** Provide a UI button to copy passwords to the clipboard with automatic clearing after a short duration.

- **Password Generator Enhancements:** More configurable options for strong password generation.

- **Password Health Audit:** Identify reused, weak, or potentially compromised passwords (without sending actual passwords to external services).

- **Native Desktop Application:** Transition from a local web UI to a native desktop application using a Go GUI toolkit like Fyne, providing a more integrated user experience.

- **Browser Extensions:** Develop extensions for popular browsers (Chrome, Firefox) to enable autofill, auto-save, and direct password generation on websites.

- **Secure Sharing:** Implement end-to-end encrypted sharing of credentials with trusted individuals.

- **Cloud Synchronization:** Secure, end-to-end encrypted synchronization of the vault across multiple devices via a cloud service.

- **Comprehensive Error Handling & Logging:** Robust error management and secure logging practices.

- **Security Audits:** Conduct professional security audits and penetration testing.
