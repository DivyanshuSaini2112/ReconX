# ReconX — Automated Reconnaissance Tool

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
</p>

A CLI-first reconnaissance toolkit that automates security reconnaissance sweeps on targets (IP, CIDR, or domain). ReconX aggregates outputs from multiple security tools and produces structured JSON, text, and HTML reports.

> ⚠️ **Legal Disclaimer**: For authorized security testing and educational purposes only. Unauthorized network scanning is illegal. Use only on systems you own or have explicit permission to test.

---

## 🌟 Features

- **Multi-Tool Integration** — Nmap, Subfinder, Gobuster, ffuf, WhatWeb, Nikto, SQLMap
- **Modular Architecture** — Run specific modules or combine them as needed
- **Multiple Output Formats** — JSON, plain text, and HTML reports
- **Concurrent Execution** — Fast parallel scanning
- **AI-Powered Summaries** — Optional local AI analysis via Ollama
- **Preview Mode** — Dry-run to see commands before execution
- **Flexible Profiles** — Fast, default, or deep scan modes

---

## 📁 File Structure

```
recony/
├── README.md
├── config.ini.example          # API keys configuration
├── setup.py
├── requirements.txt
├── reconx/
│   ├── __init__.py
│   ├── __main__.py             # CLI entrypoint
│   ├── lib/
│   │   ├── config.py           # Config & API keys
│   │   └── output.py           # Report generation
│   └── modules/                # Scanner modules
│       ├── nmap.py
│       ├── subenum.py
│       ├── dirfuzz.py
│       ├── ffuf.py
│       ├── whatweb.py
│       ├── nikto.py
│       ├── sqlmap.py
│       └── urlscan.py
├── results/                    # Output directory
└── tests/                      # Unit tests
```

---

## 🚀 Installation

### 1. Install System Tools

```bash
sudo apt update
sudo apt install -y nmap gobuster ffuf whatweb nikto sqlmap
```

Install Subfinder:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### 2. Clone & Install ReconX

```bash
git clone https://github.com/DivyanshuSaini2112/recony.git
cd recony
pip install .
```

### 3. Verify Installation

```bash
reconx --help
```

---

## ⚙️ Configuration (Optional)

For modules requiring API keys (URLScan, etc.):

```bash
cp config.ini.example config.ini
# Edit config.ini with your API keys
```

**For AI Summaries** (Optional):

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3

# Start Ollama server
ollama serve
```

---

## 📖 Usage

### Basic Syntax

```bash
reconx -t <TARGET> [OPTIONS]
```

### Key Arguments

| Argument | Description |
|----------|-------------|
| `-t, --target` | Target IP, domain, or CIDR (required) |
| `--modules` | Comma-separated modules: `nmap,subenum,dirfuzz,whatweb,nikto` |
| `--profile` | Scan profile: `fast`, `default`, `deep` |
| `--fuzzer` | Directory fuzzer: `gobuster` or `ffuf` |
| `--threads` | Number of concurrent threads |
| `--wordlist` | Custom wordlist path |
| `--out` | Output directory (default: `./results`) |
| `--html` | Generate HTML report |
| `--ai-summary` | Generate AI summary (requires Ollama) |
| `--no-exec` | Preview commands without execution |

### Examples

**Basic Scan:**
```bash
reconx -t example.com
```

**Full Scan with Reports:**
```bash
reconx -t example.com --profile default --modules nmap,subenum,dirfuzz,whatweb,nikto --html --ai-summary
```

**Fast Scan:**
```bash
reconx -t 192.168.1.100 --profile fast --modules nmap,dirfuzz
```

**Preview Commands:**
```bash
reconx -t example.com --no-exec
```

**Custom Configuration:**
```bash
reconx -t example.com --modules nmap,dirfuzz --threads 50 --wordlist /path/to/wordlist.txt --out ./my_results
```

---

## 📄 Output Files

Each scan creates a timestamped directory with:

```
results/example.com-2025-11-03_15-15-25/
├── reconx_results.json         # Main aggregated results (JSON)
├── summary.txt                 # Human-readable summary
├── report.html                 # HTML report (if --html)
├── ai_summary.txt              # AI analysis (if --ai-summary)
├── nmap_quick_scan.xml         # Nmap quick scan
├── nmap_detailed_scan.xml      # Nmap detailed scan
├── subdomains.txt              # Discovered subdomains
├── dirfuzz.txt                 # Directory fuzzing results
├── whatweb.json                # Technology detection
└── nikto.txt                   # Vulnerability scan
```

---

## 🔄 How It Works

```
CLI Input → Parse Arguments → Initialize Modules → Execute Scans (Parallel)
    ↓
Raw Tool Outputs → Parse Results → Aggregate Data
    ↓
Generate Reports (JSON + Text + HTML + AI Summary)
```

**Module System**: Each module (`modules/*.py`) implements:
- `get_command()` — Builds shell command
- `run_scan()` — Executes tool via subprocess
- `parse_results()` — Parses output into structured data

---

## 🧪 Testing

```bash
# Run all tests
python -m unittest discover -v

# Or with pytest
pytest -q
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Add tests for new functionality
4. Commit changes: `git commit -m 'Add amazing feature'`
5. Push to branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **Nmap** - Gordon Lyon
- **Subfinder** - ProjectDiscovery
- **Gobuster** - OJ Reeves
- **ffuf** - Joona Hoikkala
- **WhatWeb** - Andrew Horton
- **Nikto** - Chris Sullo & David Lodge
- **SQLMap** - Bernardo Damele & Miroslav Stampar
- **Ollama** - Local AI serving

---

**Made by [Divyanshu Saini](https://github.com/DivyanshuSaini2112)**

Remember: Always get authorization before scanning! 🔒
