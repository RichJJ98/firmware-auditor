# 🛡️ firmware-auditor  

> Fast, static security auditor for unpacked IoT & embedded Linux rootfs images. Designed for DevSecOps pipelines and firmware posture auditing.

[![License: MIT](https://img.shields.io/badge/License-MIT-00FF41.svg?style=flat-square&labelColor=000000)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-00FF41.svg?style=flat-square&labelColor=000000)](https://www.python.org/)
[![SARIF: 2.1.0](https://img.shields.io/badge/SARIF-v2.1.0-00FF41.svg?style=flat-square&labelColor=000000)](https://sarifweb.azurewebsites.net/)

---

## 📖 About

`firmware-auditor` is an automated, zero-emulation static security analysis framework built to inspect extracted Linux firmware images (SquashFS, ext4, etc.) before deployment or flashing.

### Core Analyzers
- **ELF Binary Hardening:** Scans executables for missing modern compiler mitigations (**NX/DEP**, **PIE/ASLR**, **Stack Canaries**, **RELRO**).
- **Filesystem Hygiene & Secrets:** Detects leaked SSH/TLS private keys, permissive file/directory permissions, and unhardened `/etc/shadow` configurations.
- **CI/CD Quality Gates:** Native SARIF v2.1.0 output for seamless integration with GitHub Advanced Security and customizable exit code thresholds (`--fail-on`).

---

##  Quick Start 🚀

### Installation
```bash
git clone https://github.com/RichJJ98/firmware-auditor.git
cd firmware-auditor
pip install -e .