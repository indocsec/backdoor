# CSEC Shell 0.5 — Secure PHP File Manager

> Hardened, modular, and sessionless PHP file manager for self-hosted servers you own.

![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Made with PHP](https://img.shields.io/badge/Made%20with-PHP-informational)

---

## ⚠️ DISCLAIMER

This tool is for **authorized, legal use only**. Do **not** use this on systems you don't own or control.  
Misuse of this tool may result in violation of computer crime laws.

---

## ✨ Features

- ✅ No PHP sessions — uses HMAC token with optional cookie
- ✅ Secure base directory jail (path-safe join + symlink escape prevention)
- ✅ Clean dark UI with mobile-friendly responsive layout
- ✅ Zip/Unzip to current folder
- ✅ Chmod (with optional recursive)
- ✅ Create, Rename, Move, Copy, Edit, Delete files/folders
- ✅ Bulk select + delete/zip
- ✅ CSRF protection on all mutations
- ✅ Optional IP binding
- ✅ Fully self-contained in 1 file (`backup.php`)

---

## 🛠️ Requirements

- PHP 7.2 or higher
- `ZipArchive` PHP extension enabled

---

## 🚀 Quickstart

```bash
# Upload to your server
cp backup.php /var/www/html

# Open in browser
https://yourdomain.com/backup.php

# Default password: enteraja

📦 Deployment Tips

Protect with .htpasswd or VPN
Host inside subfolder (e.g. /admin/backup.php)
Change filename regularly
Use HTTPS to protect credentials

🔐 Security

All operations are jailed to BASE_DIR, preventing directory escape.
Script does not rely on PHP sessions and is compatible with hardened environments.
See SECURITY.md for responsible disclosure and limitations.
