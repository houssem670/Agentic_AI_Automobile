# Agentic AI for Automotive CAN Security

An AI-assisted automotive cybersecurity platform for detecting suspicious CAN bus traffic, assessing potential threats, supporting diagnostics, and generating structured security reports.

## Overview

This project combines deterministic CAN traffic analysis with Large Language Model (LLM)-assisted security assessment.

The detection layer identifies suspicious traffic patterns using predefined rules. AI agents then help interpret the collected evidence, assess potential threats, support diagnostic analysis, and generate structured security reports.

The project is designed for **controlled experiments on a virtual CAN interface (`vcan0`)**. It is an educational and research prototype, not a production system for deployment on real vehicles.

## Key Features

- **CAN traffic analysis:** Captures and analyzes CAN messages over configurable time windows.
- **Frequency anomaly detection:** Identifies traffic rates exceeding a configurable threshold.
- **Replay-suspicion detection:** Flags rapid repetitions of identical consecutive CAN frames.
- **Security Agent:** Uses Google Gemini as the primary LLM, with Ollama as a fallback.
- **Retrieval-Augmented Generation (RAG):** Retrieves relevant knowledge to support security assessment and diagnostic reasoning.
- **Diagnostic Agent:** Produces structured diagnostic findings and records uncertainties.
- **Report Agent:** Generates Markdown security reports from the available findings.
- **Orchestration:** Includes a LangGraph-based orchestration component for coordinating agent execution and handling failures.
- **Automated tests:** Covers detector behavior, fallback handling, orchestration, and report generation.

> Repeated CAN frames are an indicator for investigation, not proof of a malicious replay attack.

## Architecture

The general workflow is illustrated below. The exact execution path depends on the entry point used.

```text
Virtual CAN Traffic (vcan0)
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
   Google Gemini   Ollama
            |
            v
  Retrieved Knowledge (RAG)
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

- Python 3.12
- Linux / Ubuntu / WSL2
- SocketCAN and virtual CAN (`vcan0`)
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
- SocketCAN support
- `can-utils`
- A configured virtual CAN interface (`vcan0`)
- Ollama with the `llama3.2:3b` model for local fallback
- A Gemini API key for the primary LLM (optional if using Ollama only)

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/houssem670/Agentic_AI_Automobile.git
cd Agentic_AI_Automobile
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Install `can-utils` if it is not already installed:

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

If `vcan0` already exists, skip the `ip link add` command and ensure the interface is up.

Verify the interface:

```bash
ip link show vcan0
```

**Safety:** Use only virtual CAN interfaces and synthetic traffic during development. Do not connect experimental detection or replay scripts to a real vehicle.

## Configuration

Create a local `.env` file from the example:

```bash
cp .env.example .env
```

Configure the relevant environment variables:

```dotenv
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Keep `.env` private. Never commit API keys, credentials, or other secrets to version control.

If no Gemini API key is configured, the Security Agent can use the configured Ollama fallback, provided Ollama is installed, running, and the required model is available.

Install Ollama separately and download the model:

```bash
ollama pull llama3.2:3b
```

## Running the Project

Activate the virtual environment and run:

```bash
python main.py
```

The application analyzes CAN traffic and processes detected anomalies. Generated security reports are saved locally under `reports/`.

For meaningful results, send synthetic CAN traffic through `vcan0` while the analyzer is running.

## Running Tests

Execute the unit test suite with:

```bash
python -m unittest discover -s tests -v
```

The test suite covers anomaly detection, replay detection, agent orchestration, security assessment fallback behavior, and report generation


  
Telecommunications Engineering  
Specialization: Automotive Networking and Embedded Systems
