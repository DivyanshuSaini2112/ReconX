# ReconX: Automated Reconnaissance Tool

ReconX is a CLI-first reconnaissance tool for Kali Linux that performs an automated initial reconnaissance sweep on a single target (IP, CIDR, or domain) and outputs aggregated, easy-to-parse results and an initial attack vector summary.

## Legal Disclaimer

> This tool is intended for authorized security testing and educational purposes only. Unauthorized scanning of networks is illegal. The author is not responsible for any misuse or damage caused by this tool. By using this tool, you agree to the terms of the MIT License included in this repository.

## Installation

### Prerequisites

ReconX is designed to run on Kali Linux and relies on the following tools being installed and available in your PATH:

- [Nmap](https://nmap.org/)
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Gobuster](https://github.com/OJ/gobuster)
- [ffuf](https://github.com/ffuf/ffuf)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [Nikto](https://github.com/sullo/nikto)
- [SQLMap](https://sqlmap.org/)

You can install these tools on Kali Linux using the following command:

```bash
sudo apt-get update && sudo apt-get install nmap subfinder gobuster ffuf whatweb nikto sqlmap
```

### Installation from Source

1.  Clone this repository:
    ```bash
    git clone https://github.com/your-username/reconx.git
    cd reconx
    ```

2.  Install the Python dependencies:
    ```bash
    pip install .
    ```

### AI Summary Setup (Optional)

The `--ai-summary` feature uses a local AI model through [Ollama](https://ollama.ai/). This is **100% free, private, and works offline.**

>**Important:** `reconx` uses your **local** installation of Ollama. It does not connect to the Ollama cloud service. You do not need an online account, API keys, or a paid subscription to use this feature.

1.  **Install Ollama:** Follow the official instructions to download and install Ollama on your system.
2.  **Download a Model:** Pull a model for the summary generation. `llama3` is recommended:
    ```bash
    ollama pull llama3
    ```
3.  **Run the Ollama Server:** Before using the `--ai-summary` flag, make sure the Ollama server is running in the background.

## Usage

```
usage: reconx [-h] -t TARGET [--modules MODULES] [--profile {fast,default,deep}] [--threads THREADS] [--wordlist WORDLIST]
              [--fuzzer {gobuster,ffuf}] [--out OUT] [--html] [--ai-summary] [--nmap-args NMAP_ARGS]
              [--gobuster-args GOBUSTER_ARGS] [--ffuf-args FFuf_ARGS] [--sqlmap] [--no-exec]

A CLI-first reconnaissance tool for Kali Linux.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        The target IP, domain, or CIDR.
  --modules MODULES     Comma-separated list of modules to run (e.g., nmap,subenum,dirfuzz).
  --profile {fast,default,deep}
                        Scan profile (fast, default, deep).
  --threads THREADS     Number of concurrent threads for fuzzing/discovery.
  --wordlist WORDLIST   Path to a custom wordlist for directory fuzzing.
  --fuzzer {gobuster,ffuf}
                        Choose the directory fuzzer to use.
  --out OUT             Directory to save results to.
  --html                Generate an HTML report.
  --ai-summary          Generate a summary using a local Ollama model.
  --nmap-args NMAP_ARGS
                        Custom arguments for Nmap.
  --gobuster-args GOBUSTER_ARGS
                        Custom arguments for Gobuster.
  --ffuf-args FFuf_ARGS
                        Custom arguments for ffuf.
  --sqlmap              Explicitly enable the SQLMap module.
  --no-exec             Print planned commands without executing them.

Example: reconx -t example.com --profile default --modules nmap,subenum,dirfuzz --fuzzer ffuf --html --ai-summary
```

## Output

ReconX produces the following outputs in a timestamped directory:

-   `reconx_results.json`: A JSON file containing all the aggregated results.
-   `summary.txt`: A plain-text summary of the findings.
-   `report.html`: An HTML report of the findings (if `--html` is specified).
-   Raw output files from each of the tools (`nmap_scan.xml`, `subdomains.txt`, etc.).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
