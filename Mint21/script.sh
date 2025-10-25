#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "❌ This script must be run with sudo privileges."
  exit 1
fi

if ! command -v python3 &> /dev/null; then
  echo "🐍 Installing Python3..."
  apt update && apt install -y python3
fi

if ! command -v pip3 &> /dev/null; then
  echo "📦 Installing pip3..."
  apt install -y python3-pip
fi

pip3 install rich typer

echo "📥 Downloading Python script from GitHub..."
wget https://raw.githubusercontent.com/saineela/ScriptsCyberpatriot/main/Mint21/mint21-auto.py

chmod +x mint21-auto.py
echo "🚀 Launching Tool..."
python3 mint21-auto.py
