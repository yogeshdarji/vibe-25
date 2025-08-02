# vibe-25

CTF Social Engineering Challenge Tool

## Description

This tool is designed for educational CTF (Capture The Flag) challenges that involve social engineering AI-controlled teams to reveal their flags.

## Main Script

- `attack.py` - Enhanced CTF client with logging, retry logic, and automated attack capabilities

## Features

- Automated attack mode with multiple social engineering strategies
- Flag pattern detection and extraction
- Conversation history tracking
- Rate limiting to prevent server overload
- Comprehensive logging
- Interactive and automated modes

## Usage

```bash
python attack.py
```

Then choose:
- Press a number to select a specific team
- Press 'a' for auto-attack all teams
- Press 's' to save conversation history
- Press 'q' to quit

## Educational Purpose

This tool is created for educational purposes to understand social engineering vulnerabilities in CTF environments.