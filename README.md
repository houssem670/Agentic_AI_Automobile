# Agentic AI for Automotive CAN Security

An AI-assisted automotive cybersecurity platform for detecting suspicious CAN bus traffic, assessing potential threats, supporting diagnostics, and generating structured security reports.

## Overview

This project combines deterministic CAN traffic analysis with LLM-assisted security assessment. The detection layer identifies suspicious patterns, while AI agents help interpret the evidence and organize diagnostic findings.

The project is designed for **controlled experiments on a virtual CAN interface (`vcan0`)**, not for deployment on a real vehicle.

## Key Features

- **CAN traffic analysis:** analyzes traffic over configurable time windows.
- **Frequency anomaly detection:** identifies traffic rates exceeding a configurable threshold.
- **Replay-suspicion detection:** flags rapid repetitions of identical consecutive CAN frames.
- **Security Agent:** uses Google Gemini as the primary LLM and Ollama as a fallback.
- **Retrieval-Augmented Generation (RAG):** retrieves relevant automotive security and diagnostic knowledge.
- **Diagnostic Agent:** produces structured diagnostic findings and records uncertainties.
- **Report Agent:** generates Markdown security reports.
- **Orchestration:** coordinates agent execution and handles failures.
- **Automated tests:** validates detector behavior, fallback handling, orchestration, and reporting.

> Repeated CAN frames are an indicator for investigation, not proof of a malicious replay attack.

## Architecture

```text
Virtual CAN traffic (vcan0)
            |
            v
     CAN Traffic Analyzer
            |
            v
   Deterministic Detectors
   - Frequency anomalies
   - Replay suspicion
            |
            v
       Security Agent
       /            \
   Gemini          Ollama
            |
            v
      RAG Knowledge Base
            |
            v
      Diagnostic Agent
            |
            v
        Report Agent
            |
            v
   Markdown Security Report
```

The repository also contains a LangGraph-based orchestrator for coordinating agent execution. The current `main.py` entry point runs the analysis and agent workflow directly.

## Technology Stack

- Python
- Linux and SocketCAN
- `python-can` and `can-utils`
- Google Gemini API
- Ollama
- LangChain
- LangGraph
- Retrieval-Augmented Generation (RAG)
- Unit testing with `unittest`

## Requirements

- Python 3.12 recommended
- Linux or WSL2 with Ubuntu
- SocketCAN utilities (`can-utils`)
- A virtual CAN interface (`vcan0`)
- Ollama with the `llama3.2:3b` model
- A Gemini API key for the primary LLM (optional if using Ollama only)

## Installation

Clone the repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd agentic-automotive-security
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Install `can-utils` if needed:

```bash
sudo apt update
sudo apt install can-utils
```

## Virtual CAN Setup

Load the required kernel modules and create a virtual CAN interface:

```bash
sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

If `vcan0` already exists, skip the `ip link add` command.

Verify the interface:

```bash
ip link show vcan0
```

**Safety:** use only virtual CAN interfaces and synthetic traffic during development. Do not connect experimental detection or replay scripts to a real vehicle.

## Configuration

Create a local `.env` file:

```bash
cp .env.example .env
```

Configure the required variables:

```dotenv
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Keep `.env` private. Never commit API keys or other secrets. If no Gemini key is configured, the Security Agent can use the configured Ollama fallback.

Install and start Ollama separately, then download the model:

```bash
ollama pull llama3.2:3b
```

## Running the Project

Activate the virtual environment and run:

```bash
python main.py
```

The application analyzes CAN traffic and processes detected anomalies. Generated reports are saved locally under `reports/`.

For meaningful results, send synthetic test traffic through `vcan0` while the analyzer is running.

## Running Tests

Run the complete unit test suite:

```bash
python -m unittest discover -s tests -v
```

The current test suite covers anomaly detection, replay detection, agent orchestration, security assessment fallback behavior, and report generation.

## Limitations

- A replay-suspicion alert does not establish attacker intent.
- LLM-generated assessments depend on model output and available evidence.
- Diagnostic results are advisory and should not be treated as confirmed root causes unless explicitly supported by evidence.
- This is a research and educational prototype, not a production automotive security system.

## Future Improvements

- Expand the CAN dataset with normal and attack scenarios.
- Add integration tests using synthetic SocketCAN traffic.
- Improve event correlation across CAN identifiers and time windows.
- Add a dashboard for alerts and diagnostic results.
- Evaluate detection precision and false-positive rates against labeled datasets.

## Disclaimer

This project is intended for education and authorized security research in isolated test environments. Use virtual CAN interfaces and simulated traffic only.

## Author

**Houssem Fkih**
Telecommunications Engineering — Automotive Networking and Embedded Systems