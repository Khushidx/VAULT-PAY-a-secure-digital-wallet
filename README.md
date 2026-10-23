# VaultPay — Secure Digital Wallet & Cryptographic Security Architecture

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.0+-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-lightblue?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM%20AEAD-blueviolet?logo=lock&logoColor=white)](https://cryptography.io/)
[![Hashing](https://img.shields.io/badge/Hashing-Salted%20SHA--256-indigo?logo=shield&logoColor=white)](app/utils/password_sha256.py)
[![Tests](https://img.shields.io/badge/Tests-87%2F87%20Passing%20(100%25)-brightgreen?logo=pytest&logoColor=white)](tests/)
[![Currency](https://img.shields.io/badge/Currency-INR%20(%E2%82%B9)%20Integer%20Paise-orange)](app/utils/money_integer_cents.py)
[![Design](https://img.shields.io/badge/Design-Restrained%20Editorial-2563EB)](app/static/css/styles.css)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

**VaultPay** is an enterprise-grade digital wallet, double-entry financial ledger, and applied cryptographic security platform engineered with defense-in-depth security principles. It features authenticated **AES-256-GCM** encryption for stored payment metadata, **Salted SHA-256** password hashing with 256-bit random salts, step-up two-factor authentication with 4-digit PIN context binding (AAD), atomic financial transactions in exact 64-bit integer paise (₹), active counter-surveillance **Chameleon Cards** (single-use cards that morph into honeypot tripwires with deceptive adversary tarpitting), an authenticated **Cryptographic Architecture Specification**, and an interactive **Security Lab & Chameleon Simulator** demonstrating real-time cryptographic verification and zero-loss breach containment.

---

## Visual Design & User Interface

VaultPay uses a **restrained professional editorial design system** inspired by modern institutional fintech platforms (such as Stripe, Wise, and Mercury):

- **Color Palette**:
  - **Background**: `#F8F7F4` (warm off-white canvas)
  - **Primary Text**: `#17202A` (deep charcoal for high-contrast headings and prominent text)
  - **Secondary Text**: `#4B5563` (muted gray for descriptions, subheadings, and secondary labels)
  - **Accent**: `#2563EB` (professional blue for primary actions and focus states)
  - **Accent Hover**: `#1D4ED8`
  - **Cards / Surfaces**: `#FFFFFF` (crisp white elevated cards)
  - **Elevated Surfaces**: `#F9FAFB` (light neutral for table headers, code blocks, and chips)
  - **Borders**: `#E5E7EB` (`#D1D5DB` strong)
- **Typography**:
  - **Headings**: **Inter** (semibold/bold, tight `-0.02em` tracking)
  - **Body**: **Inter** (regular, line-height `1.5` to `1.6`)
  - **Monospace**: **JetBrains Mono** for monetary amounts (`₹`), token IDs, hashes, and masked PANs
- **Restrained Aesthetics**:
  - **No Gradients**: Clean, solid surfaces with crisp structural borders.
  - **No Excessive Radii**: Disciplined corner rounding (`4px` sm, `6px` md, `8px` lg).
  - **No Neon Colors or Glowing Shadows**: Subtle, standard shadows (`0 1px 2px rgba(0,0,0,0.04)`) and muted, semantic status fills.
  - **No Emojis**: Replaced with standardized, pixel-aligned inline SVG vector icons.

---

## 4-Pillar Security Architecture

VaultPay is structured around four primary cryptographic and architectural pillars:

### 1. Identity & Access Control
- **Salted SHA-256 Password Hashing**: Passwords are never stored in plaintext. Each account receives a unique 256-bit cryptographically secure random salt (`secrets.token_hex(32)`), verified via constant-time comparison (`hmac.compare_digest`) to prevent timing side-channel attacks (`app/utils/password_sha256.py`).
- **Sliding-Window Rate Limiting**: In-memory rate limiting locks authentication attempts after 5 consecutive failed attempts within a 5-minute sliding window (`app/utils/rate_limiter_sliding_window.py`).
- **Session Security**: Session cookies configured with `HttpOnly` (mitigates XSS token theft), `SameSite=Lax` (mitigates CSRF), and session ID regeneration upon login (prevents session fixation).
- **IDOR Protection**: All wallet, card, and payment method operations are strictly bounded to the authenticated session (`session['user_id']`). Access to another user's resources is blocked.

### 2. Sensitive Credential Vault (AEAD at Rest)
- **AES-256-GCM Authenticated Encryption**: Sensitive payment metadata is encrypted at rest using AES-256-GCM AEAD (NIST SP 800-38D) with a fresh 12-byte cryptographically secure random nonce (`os.urandom(12)`) and a 16-byte GMAC authentication tag per record (`app/utils/crypto_aes_gcm.py`).
- **Cryptographic PIN Binding (Additional Authenticated Data - AAD)**: When saving a payment method, users define a 4-digit security PIN. The PIN hash is bound directly to the AES-256-GCM ciphertext as AAD. The ciphertext cannot be decrypted without the exact 4-digit PIN, preventing ciphertext transplant attacks between accounts.
- **Step-Up Reveal Gate**: Decrypting or inspecting payment method metadata requires step-up two-factor verification: re-entering the account password and the 4-digit security PIN.
- **Zero CVV & Full Credential Policy**: In compliance with PCI-DSS 4.0 Requirement 3, CVVs, CVCs, and full card numbers (PANs) are strictly rejected and never stored. Only masked identifiers (`**** **** **** 4242`) and opaque tokens are retained.
- **Zero Presentation Leakage**: Passwords, password hashes, cryptographic salts, and master encryption keys are audited and verified to never appear in any HTML response.

### 3. Financial Precision & Ledger Integrity
- **Zero Floating-Point Arithmetic**: All monetary amounts are converted and stored on the server as 64-bit integer smallest currency units (**paise**). Eliminates IEEE-754 floating-point rounding errors ($0.1 + 0.2 \neq 0.3$) (`app/utils/money_integer_cents.py`).
- **Database Non-Negative Invariant**: An SQLite database-level `CHECK (balance_cents >= 0)` constraint guarantees that balances can never become negative, even under race conditions.
- **Atomic Double-Entry Transactions**: Transfers execute atomically within database transactions. Sender debit and recipient credit either commit together or roll back completely on failure.
- **Canonical JSON SHA-256 Fingerprinting**: Financial transactions can be deterministically serialized and hashed to provide non-repudiation and tamper-evident audit logs.

### 4. Active Counter-Surveillance & Canary Honeypot Defense
- **Single-Use Chameleon Cards**: Provisioned for a specific merchant and spend limit in integer paise; automatically collapses spend limit to ₹0.00 upon legitimate purchase and morphs into a dormant honeypot (`ARMED_CANARY`).
- **Zero Financial Loss**: Replayed transactions against armed canaries are rejected with ₹0.00 debit.
- **Deceptive Tarpitting**: 1,200ms anti-adversary artificial delay returning a deceptive `200 OK (Insufficient Funds)` gateway response to keep automated botnets in the dark.
- **Forensic Telemetry & Autonomous Quarantine**: Remote IP, User-Agent, and JA3 signatures are captured into `canary_incidents`, while the user vault transitions to `QUARANTINED` with emergency UI lockdown until docket resolution.

---

## Interactive Security Lab (Active Tamper Simulator)

The **Security Lab** (`/security-lab`) is an interactive demonstration environment simulating the **actual VaultPay security architecture** for technical interviews, student demonstrations, and cryptographic auditing.

It operates on **completely isolated demo data** (never touching real balances, production payment methods, or database records) and guides the user through:

1. **Transaction Initialization**: Creating a customizable demo payment (Sender, Recipient, Amount, Card, and AAD Context).
2. **Cryptographic Protection**:
   - Converts amount to exact integer paise.
   - Computes canonical JSON SHA-256 integrity fingerprint (64-character hex).
   - Encrypts sensitive card data via AES-256-GCM with an isolated session key, 12-byte nonce, 16-byte GMAC tag, and AAD binding.
3. **Attacker's View**: Exposes only what an intercepting adversary sees: Nonce, Ciphertext, Tag, and AAD.
4. **5 Active Adversarial Attack Vectors**:
   - **Vector 1: Ciphertext Bit-Flipping / Byte Mutation** (Tests payload alteration $\rightarrow$ `InvalidTag` rejection).
   - **Vector 2: Authentication Tag Alteration** (Tests GMAC polynomial authentication failure).
   - **Vector 3: Nonce Modification** (Tests replay/IV verification failure).
   - **Vector 4: AAD Context Spoofing** (Tests user ID / PIN context mismatch).
   - **Vector 5: Financial Ledger Tampering** (Tests canonical SHA-256 integrity mismatch).
5. **Real-Time Dynamic Validation**:
   - **When Tampered**: Displays **`🚨 ATTACK DETECTED`** and **`✕ INVALID`** with an inline byte-level difference locator (`^^ CHANGED`) explaining the cryptographic failure.
   - **When Authentic / Restored**: Displays **`✓ AUTHENTICATION VALID`** and **`✓ VALID`** with a green verification panel confirming GMAC authentication match and successful decryption.

---

## Cryptographic Architecture Specification (`/crypto-architecture`)

Accessible exclusively to authenticated users via the top navigation bar, the **Architecture** tab provides a concise, engineering-focused specification of VaultPay's cryptographic data pipeline:

- **Flow 1: User Identity & Password Storage**: Salt generation, SHA-256 digest computation, constant-time verification, and zero plaintext retention.
- **Flow 2: Sensitive Payment Methods at Rest**: AES-256-GCM AEAD pipeline, nonce freshness, GMAC polynomial tags, and AAD context binding.
- **Flow 3: Decryption & Step-Up Reveal Gate**: Two-tier verification challenge, AAD reconstruction, GCM authentication check, and immediate `InvalidTag` abort.
- **Flow 4: Financial Precision & Ledger Integrity**: 64-bit integer paise ledger, reciprocal double-entry bookkeeping (`TRANSFER_IN` / `TRANSFER_OUT`), and SHA-256 fingerprinting.
- **Cryptographic Architecture Reference Matrix**: Comprehensive table summarizing algorithms, primitives, keys, storage locations, and security objectives.

---

## Active Counter-Surveillance: Chameleon Cards & Canary Tripwire Lab (`/chameleon-simulator`)

Unlike conventional wallets (Apple Pay, Google Wallet, PayPal) that passively wait for fraudulent charges to hit a bank statement after a merchant database breach, **VaultPay introduces proactive counter-surveillance**:

1. **Phase 1: Single-Use Burner (`ACTIVE_BURNER`)**: Provisioned with a strict integer paise limit (e.g., ₹1,499.00) and bound to a merchant domain (e.g., `AudioGearShop.in`).
2. **Phase 2: The Morph (`ARMED_CANARY`)**: The moment the legitimate transaction completes, the spend limit drops to **₹0.00** and the card automatically morphs into a dormant honeypot tripwire stored inside the merchant's database.
3. **Phase 3: Zero-Tolerance Intrusion Intercept (`TRIPPED`)**: If the merchant suffers a database breach months later and an attacker/botnet tests the leaked token:
   - **Deceptive Tarpit**: VaultPay delays the HTTP response by 1,200ms and returns a deceptive `200 OK (Insufficient Funds)` payload so the attacker suspects nothing.
   - **Zero Financial Loss**: Exactly ₹0.00 is charged.
   - **Forensic Capture**: Captures attacker IP, geolocation, User-Agent, and simulated TLS/JA3 fingerprint.
   - **Autonomous Quarantine**: Immediately quarantines the victim's vault, displaying an app-wide lockdown banner until reviewed.
4. **Phase 4: Threat Neutralization (`NEUTRALIZED`)**: User reviews the forensic evidence docket, permanently purges the breached token, and restores vault status to `NORMAL`.

---

## Algorithmic Module Structure

Key modules are explicitly named according to the cryptographic algorithms and computational principles they implement:

| Module | Algorithm / Concept | Purpose |
|:---|:---|:---|
| `app/utils/crypto_aes_gcm.py` | AES-256-GCM AEAD | Authenticated encryption, decryption, and AAD verification |
| `app/utils/password_sha256.py` | Salted SHA-256 & HMAC | 256-bit salted hashing & constant-time digest comparison |
| `app/utils/money_integer_cents.py` | 64-bit Integer Arithmetic | Eliminates binary floating-point rounding errors |
| `app/utils/rate_limiter_sliding_window.py` | Sliding-Window Algorithm | In-memory brute-force authentication protection |
| `app/services/security_demo_service.py` | Cryptographic Tamper Simulator | Isolated attack vector simulation and validation engine |
| `app/services/chameleon_service.py` | Honeypot Tripwire & Tarpit Engine | Single-use morphing, adversary probe interception, and quarantine |

---

## Project Structure

```text
secure_wallet/
├── app/
│   ├── __init__.py              # Application factory & automatic schema migration
│   ├── config.py                # Configuration classes (Dev, Testing, Prod)
│   ├── crypto.py                # Backward compatibility crypto exports
│   ├── crypto_aes_gcm.py        # Top-level AES-256-GCM facade
│   ├── errors.py                # Custom error handlers (400, 404, 500, CSRF)
│   ├── extensions.py            # Flask extensions (SQLAlchemy, CSRFProtect)
│   ├── forms/                   # WTForms form definitions with validation
│   │   ├── auth.py              # Login & Registration forms
│   │   ├── card.py              # Card vault form
│   │   ├── payment_method.py    # Payment Method & Step-Up Reveal forms
│   │   └── wallet.py            # Deposit & Transfer forms
│   ├── models/                  # SQLAlchemy database models
│   │   ├── card.py              # DemoCard model with AES-256-GCM
│   │   ├── chameleon_card.py    # ChameleonCard & CanaryIncident models
│   │   ├── payment_method.py    # PaymentMethod model with AAD PIN binding
│   │   ├── transaction.py       # Transaction ledger model
│   │   ├── user.py              # User model with salted SHA-256 & security_status
│   │   └── wallet.py            # Wallet model with integer paise & CHECK constraint
│   ├── routes/                  # Blueprint route controllers
│   │   ├── auth.py              # Register, Login, Logout, Profile
│   │   ├── cards.py             # Cards Vault management
│   │   ├── chameleon_lab.py     # Chameleon Card & Canary Simulator controller
│   │   ├── main.py              # Landing page, /health, & /crypto-architecture
│   │   ├── payment_methods.py   # Payment methods & Step-Up Reveal challenge
│   │   ├── security_lab.py      # Interactive VaultPay Security Lab controller
│   │   └── wallet.py            # Dashboard, Deposit, Transfer, History
│   ├── services/                # Business logic layer
│   │   ├── card_service.py      # Demo card creation & reveal operations
│   │   ├── chameleon_service.py # Chameleon morphing, botnet tarpit, & quarantine
│   │   ├── payment_method_service.py # Tokenization & payment method operations
│   │   ├── security_demo_service.py  # Isolated Security Lab attack & crypto simulator
│   │   └── wallet_service.py    # Atomic deposit, transfer, & ledger operations
│   ├── static/
│   │   └── css/
│   │       └── styles.css       # Restrained professional editorial design system
│   ├── templates/               # Jinja2 templates (VaultPay theme)
│   │   ├── auth/                # login.html, register.html, profile.html
│   │   ├── base.html            # Global base template with clean navbar & footer
│   │   ├── cards/               # index.html, new.html, reveal.html
│   │   ├── chameleon_lab/       # index.html (4-stage interactive tripwire lab)
│   │   ├── errors/              # 400.html, 404.html, 500.html, csrf_error.html
│   │   ├── main/                # index.html (landing page), architecture.html
│   │   ├── payment_methods/     # index.html, new.html, reveal.html, verify_reveal.html
│   │   ├── security_lab/        # index.html (interactive attack & crypto lab)
│   │   └── wallet/              # dashboard.html, deposit.html, transfer.html, history.html
│   └── utils/                   # Algorithmic & helper modules
│       ├── crypto_aes_gcm.py    # AES-256-GCM AEAD encryption & decryption engine
│       ├── password_sha256.py   # Salted SHA-256 hashing & constant-time verification
│       ├── rate_limiter_sliding_window.py # In-memory sliding-window brute-force limiter
│       ├── money_integer_cents.py # Integer-cent precision currency arithmetic
│       ├── decorators.py        # @login_required route decorator
│       └── validators.py        # Input sanitation & registration validation
├── instance/                    # SQLite database storage (wallet.sqlite)
├── scripts/                     # Operational & verification scripts
│   └── verify_e2e_live.py       # 20-step automated live verification script
├── tests/                       # Automated test suite (87 tests)
│   ├── conftest.py              # Isolated in-memory SQLite fixtures
│   ├── test_auth.py             # Authentication & salt tests (12 tests)
│   ├── test_basic.py            # Routes, health, architecture, & headers (8 tests)
│   ├── test_chameleon_card.py   # Chameleon morphing, probe tarpit, & quarantine (9 tests)
│   ├── test_crypto.py           # AES-256-GCM & tamper rejection tests (10 tests)
│   ├── test_e2e.py              # End-to-end user journeys & crawl audit (4 tests)
│   ├── test_payment_methods.py  # Step-up challenge, PIN, & IDOR tests (8 tests)
│   ├── test_security_lab.py     # Security Lab real crypto & attack simulation (17 tests)
│   └── test_wallet.py           # Atomic ledger, transfer, & money tests (17 tests)
├── Crypto Rep Dr 2.docx         # Technical Project Report Document
├── user_formatted_poster.pptx   # Presentation Poster (PowerPoint)
├── user_formatted_poster.png    # High-Resolution Presentation Poster Preview
├── END_TO_END_TEST_REPORT.md    # Comprehensive end-to-end test verification report
├── PROJECT_PLAN.md              # Architectural roadmap & milestone plan
├── SECURITY.md                  # Cryptographic controls & threat model documentation
├── pyrightconfig.json           # Pyright / Type-checking configuration
├── pytest.ini                   # Pytest configuration
├── requirements.txt             # Python package dependencies
├── run.py                       # Development server entry point
├── .env.example                 # Environment variables template
└── .gitignore                   # Git ignore patterns
```

---

## Getting Started

### Prerequisites
- **Python 3.10, 3.11, or 3.12** installed on your system.
- On Windows, ensure **"Add Python to PATH"** was checked during installation.

### 1. Clone or Copy the Repository
```bash
git clone https://github.com/your-username/VaultPay.git
cd VaultPay
```

### 2. Create and Activate a Virtual Environment
- **Windows (Command Prompt / PowerShell):**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\activate
  ```
  *(If PowerShell displays an execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

- **macOS / Linux:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy `.env.example` to create your local `.env` file:

- **Windows:**
  ```powershell
  copy .env.example .env
  ```
- **macOS / Linux:**
  ```bash
  cp .env.example .env
  ```

The default `.env` includes a development 256-bit AES encryption key. To generate a unique 256-bit key for production, run:
```bash
python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
```

### 5. Start the Application
```bash
python run.py
```

The server will start on port `5000`:
```text
[*] Starting VaultPay (development mode)...
[*] Server running at: http://127.0.0.1:5000
```

Open your browser and navigate to **`http://127.0.0.1:5000`**.

---

## Testing & Verification

VaultPay includes a comprehensive automated test suite with **87 tests** covering authentication, cryptographic integrity, integer currency calculations, double-entry ledger invariants, IDOR defenses, active tamper detection, Chameleon honeypot tripwire lifecycle, and full user workflows.

### Run All Tests with Pytest
```bash
pytest -v
```

**Test Suite Coverage (87/87 Passed in <2.0s):**
```text
tests/test_auth.py ............                                          [ 13%]
tests/test_basic.py ........                                             [ 22%]
tests/test_chameleon_card.py .........                                   [ 33%]
tests/test_crypto.py ..........                                          [ 44%]
tests/test_e2e.py ....                                                   [ 49%]
tests/test_payment_methods.py ........                                   [ 58%]
tests/test_security_lab.py .................                             [ 78%]
tests/test_wallet.py .................                                    [100%]

============================= 87 passed in 1.79s ==============================
```

### Run Live End-to-End Verification
Execute the 20-step verification script simulating complete user journeys for Alice and Bob:
```bash
python scripts/verify_e2e_live.py
```

**All 20 Checks Covered:**
- Step 1: User Registration with Salted SHA-256 and automatic wallet provisioning
- Step 2: Login authentication & session fixation defense
- Step 3: Atomic deposit in Indian Rupees (`₹150.00` / 15,000 paise)
- Step 4: Payment method creation with 4-digit PIN, AES-256-GCM encryption, and step-up challenge verification
- Step 5: Balance verification on dashboard
- Step 6: Second user registration (Bob)
- Step 7: Atomic peer-to-peer transfer from Alice to Bob (`₹40.00`)
- Step 8-10: Bob login, balance verification (`₹40.00`), and transaction history audit
- Step 11: Alice logout and session invalidation
- Step 12: Unauthorized access attempts redirected to login
- Step 13: Wrong password rejection
- Step 14: Invalid deposit amounts rejected (zero, negative, non-numeric, fractional cents)
- Step 15: Invalid transfer amounts rejected
- Step 16: Insufficient balance transfer rejected
- Step 17: Unknown recipient transfer rejected
- Step 18: Self-transfer rejected
- Step 19: IDOR unauthorized access rejection
- Step 20: Data privacy audit (zero plaintext passwords, hashes, salts, or AES keys in responses)

---

## Application Endpoints

| Method | Endpoint | Description | Auth Required |
|:---|:---|:---|:---:|
| `GET` | `/` | Landing page | No |
| `GET` | `/health` | JSON health & database status | No |
| `GET` | `/security-lab` | Interactive Cryptographic Security Lab | No |
| `POST` | `/security-lab/api/protect` | Protect simulated transaction with SHA-256 & AES-GCM | No |
| `POST` | `/security-lab/api/attack/<type>` | Simulate controlled cryptographic attack vector | No |
| `POST` | `/security-lab/api/verify` | Verify authentication tags, nonces, and digests | No |
| `POST` | `/security-lab/api/restore` | Restore baseline demo record | No |
| `GET` | `/chameleon-simulator` | Interactive Chameleon Card & Canary Tripwire Lab | Yes |
| `POST` | `/chameleon-simulator/api/create-card` | Issue custom Chameleon Card (Name, Merchant, Limit) | Yes |
| `GET` | `/chameleon-simulator/api/cards/<id>` | Query details and forensic state for a specific card | Yes |
| `POST` | `/chameleon-simulator/api/purchase` | Simulate legitimate purchase and card morphing | Yes |
| `POST` | `/chameleon-simulator/api/probe` | Simulate adversary botnet probe on leaked card | Yes |
| `POST` | `/chameleon-simulator/api/resolve` | Neutralize breached token & lift vault quarantine | Yes |
| `POST` | `/chameleon-simulator/api/reset` | Reset Chameleon simulation scenario | Yes |
| `GET`, `POST` | `/register` | Create a new user account | No |
| `GET`, `POST` | `/login` | Authenticate user session | No |
| `GET` | `/logout` | Invalidate active session | Yes |
| `GET` | `/profile` | Account details & active security controls | Yes |
| `GET` | `/crypto-architecture` | Cryptographic Architecture Specification | Yes |
| `GET` | `/wallet/dashboard` | Main wallet dashboard & balance | Yes |
| `GET`, `POST` | `/wallet/deposit` | Deposit funds (integer paise) | Yes |
| `GET`, `POST` | `/wallet/transfer` | P2P transfer to another user | Yes |
| `GET` | `/wallet/history` | Double-entry transaction audit history | Yes |
| `POST` | `/wallet/transactions/<id>/delete` | Delete transaction record (IDOR protected) | Yes |
| `GET` | `/payment-methods/` | List saved payment methods | Yes |
| `GET`, `POST` | `/payment-methods/new` | Add payment method with 4-digit PIN | Yes |
| `GET`, `POST` | `/payment-methods/<id>/reveal` | Step-up auth challenge & metadata reveal | Yes |
| `POST` | `/payment-methods/<id>/delete` | Remove a saved payment method | Yes |

---

## Project Documentation & Deliverables

- **Project Report**: [Crypto Rep Dr 2.docx](Crypto%20Rep%20Dr%202.docx) — Complete technical specification, threat modeling, architecture diagrams, and academic findings.
- **Conference Presentation Poster**: [user_formatted_poster.pptx](user_formatted_poster.pptx) — High-impact presentation poster formatted for academic and industrial review.
- **Poster Visual Preview**: [user_formatted_poster.png](user_formatted_poster.png) — High-resolution rendered preview of the conference poster.
- **End-to-End Verification Report**: [END_TO_END_TEST_REPORT.md](END_TO_END_TEST_REPORT.md) — Detailed execution log of the 20-step verification suite.
- **Security Architecture & Threat Model**: [SECURITY.md](SECURITY.md) — Comprehensive cryptographic specifications and vulnerability mitigation documentation.
- **Project Roadmap & Implementation Plan**: [PROJECT_PLAN.md](PROJECT_PLAN.md) — Milestone tracking and engineering deliverables.

---

## References & Cryptographic Standards

1. **NIST SP 800-38D**: Dworkin, M., *"Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"*, National Institute of Standards and Technology, 2007.
2. **NIST FIPS PUB 180-4**: *"Secure Hash Standard (SHS) — SHA-256 Specifications"*, Federal Information Processing Standards Publication, 2015.
3. **PCI Security Standards Council**: *"Payment Card Industry Data Security Standard (PCI-DSS) v4.0 — Requirement 3: Protecting Stored Cardholder Account Data"*, 2022.
4. **McGrew, D. A., & Viega, J. (2004)**: *"The Security and Performance of the Galois/Counter Mode (GCM) of Operation"*, Fast Software Encryption (FSE 2004), Springer LNCS.
5. **Bellare, M. & Namprempre, C. (2000)**: *"Authenticated Encryption: Relations Among Notions and Analysis of the Generic Composition Paradigm"*, ASIACRYPT 2000, Springer.
6. **RFC 2898 / PKCS #5**: Kaliski, B., *"Password-Based Cryptography Specification Version 2.0 (PBKDF2)"*, Internet Engineering Task Force (IETF), 2000.
7. **OWASP ASVS v4.0.3**: *"Application Security Verification Standard — V6: Stored Cryptography Verification Requirements"*, Open Web Application Security Project, 2021.

---

## License

This project is licensed under the MIT License.

##Contributors

This project was collaboratively developed by:
Khushidx (https://github.com/Khushidx)
Anushka Roy (https://github.com/royanushka2307)
