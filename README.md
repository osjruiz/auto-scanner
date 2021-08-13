# auto-scanner

Python masscan -> nmap automation.
## Requirements
- python3
- masscan
- nmap

## Installation

    python3 -m virtualenv .venv
    source .venv/bin/activate
    python3 -m pip install -r requirements.txt

## Usage

    python3 scanner.py --target 10.10.10.3 --interface eth0
