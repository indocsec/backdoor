# CSEC Shell 0.5 — Secure PHP File Manager

> A hardened, modular, and sessionless PHP file manager for **self-hosted servers you own**.

![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)
![Made with PHP](https://img.shields.io/badge/Made%20with-PHP-informational)

---

## ⚠️ Disclaimer

This tool is intended for **authorized, legal use only**.  
Do **not** use this on systems you do not own or control.

Misuse of this tool may violate computer crime laws in your jurisdiction. The author is **not responsible** for any misuse or damage caused by unauthorized deployment.

---

## ✨ Features

- ✅ No PHP sessions — uses short-lived HMAC token (optional HttpOnly cookie)
- ✅ Secure base directory jail (path-safe join + symlink escape protection)
- ✅ Fully self-contained in a single file (`backup.php`)
- ✅ Clean dark UI with responsive layout
- ✅ Upload, Edit, Delete, Rename, Move, Copy, New File, Mkdir
- ✅ Zip/Unzip support (to current folder)
- ✅ CHMOD with optional recursion
- ✅ Bulk select + delete or zip
- ✅ Built-in CSRF protection
- ✅ Optional IP binding for token
- ✅ Works on hardened environments

---

## 🛠️ Requirements

- PHP 7.2 or higher
- `ZipArchive` PHP extension must be enabled

---

## 🚀 Quickstart

```bash
# Upload to your server
cp backup.php /var/www/html

# Open in browser
https://yourdomain.com/backup.php

# Default password: enteraja
