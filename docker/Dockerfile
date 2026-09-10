FROM kalilinux/kali-rolling:latest

LABEL maintainer="ReconX / NEXUS"
LABEL description="Autonomous penetration testing environment"

RUN apt-get update -q && apt-get install -yq \
    nmap whatweb ffuf gobuster sqlmap \
    subfinder httpx-toolkit nuclei \
    python3 python3-pip seclists \
    && apt-get clean

RUN pip3 install playwright && playwright install chromium --with-deps

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

ENTRYPOINT ["python3", "-m", "nexus.main"]
