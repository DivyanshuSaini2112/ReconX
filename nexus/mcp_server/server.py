"""MCP tool layer over the existing ReconX scanners.

Zero changes to reconx/ — every tool here is a thin wrapper that
constructs the existing scanner class and calls its existing run_scan().
This module is usable two ways:

  1. Standalone MCP server (stdio transport), for a real external
     LangGraph process or any other MCP client:
         python -m nexus.mcp_server.server

  2. In-memory, by importing `mcp` and connecting a fastmcp.Client(mcp)
     directly to the object (no subprocess) — this is what
     nexus/graph/nodes/recon_dispatcher.py does today.
"""

import os

from fastmcp import FastMCP

from reconx.modules import ffuf, httpx, lab, nmap, nuclei, sqlmap, subenum, subfuzz, urlscan, whatweb

mcp = FastMCP("reconx-agent")

DEFAULT_TIMEOUT = 600


@mcp.tool
def run_nmap(
    target: str,
    output_dir: str,
    profile: str = "fast",
    nmap_args: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Run the two-stage ReconX Nmap scan and return parsed host/port results."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = nmap.NmapScanner(target, profile, output_dir, nmap_args)
    return {"module": "nmap", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_subenum(target: str, output_dir: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Passive subdomain enumeration via subfinder."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = subenum.SubdomainScanner(target, output_dir)
    return {"module": "subenum", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_subfuzz(
    target: str,
    output_dir: str,
    wordlist: str = "",
    threads: int = 10,
    ffuf_args: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Active subdomain bruteforce via ffuf."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = subfuzz.SubdomainFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return {"module": "subfuzz", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_whatweb(target: str, output_dir: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Fingerprint web technology stack via WhatWeb."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = whatweb.WhatWebScanner(target, output_dir)
    return {"module": "whatweb", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_dirfuzz(
    target: str,
    output_dir: str,
    wordlist: str = "",
    threads: int = 10,
    ffuf_args: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Directory/file discovery via ffuf (ReconX's gobuster-based dirfuzz was retired upstream)."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = ffuf.FfufFuzzer(target, wordlist, threads, output_dir, ffuf_args)
    return {"module": "dirfuzz", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_httpx(target: str, output_dir: str, httpx_args: str = "", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Probe live hosts and collect metadata (status, title, tech) via httpx."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = httpx.HttpxScanner(target, output_dir, httpx_args or None)
    return {"module": "httpx", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_nuclei(target: str, output_dir: str, nuclei_args: str = "", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Template-based vulnerability scan via nuclei (ReconX's Nikto wrapper was retired upstream)."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = nuclei.NucleiScanner(target, output_dir, nuclei_args or None)
    return {"module": "nuclei", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_lab(
    target: str,
    output_dir: str,
    wordlist: str = "",
    threads: int = 10,
    extra_args: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Gobuster-based subdomain/DNS enumeration for internal/HTB-style lab targets."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = lab.LabSubdomainScanner(target, output_dir, wordlist or None, threads, extra_args or None)
    return {"module": "lab", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_sqlmap(target: str, output_dir: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """SQL injection probing via sqlmap. Caller must confirm a parameterized URL first."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = sqlmap.SqlmapScanner(target, output_dir)
    return {"module": "sqlmap", "results": scanner.run_scan(timeout=timeout)}


@mcp.tool
def run_urlscan(target: str, output_dir: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Passive OSINT lookup via urlscan.io."""
    os.makedirs(output_dir, exist_ok=True)
    scanner = urlscan.UrlScanScanner(target, output_dir)
    return {"module": "urlscan", "results": scanner.run_scan(timeout=timeout)}


if __name__ == "__main__":
    mcp.run()
