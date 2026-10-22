# Pegasus-Suite on macOS Catalina (Intel)

## Requirements
- macOS 10.15 (Catalina), Intel x86_64
- A compatible **Python 3.8–3.12** installation with `venv` and `pip`
- Network connectivity for installing Python dependencies

**Important:** This repository includes offensive-security features and unfinished/simulated modules. Use only against systems you own or are expressly authorized to test. The installation script does not invoke any scanners or attacks.

## Install

In Terminal, from the cloned repository:

```sh
sh install-macos.sh
```

The installer checks that it is running on macOS, checks Python, then creates an isolated `.venv` environment. It never uses `sudo` or changes global Python.

## Run

```sh
./.venv/bin/python Pegasus-Suite.py
```

## Offline syntax check

```sh
./.venv/bin/python -m py_compile Pegasus-Suite.py pegasus_imports.py osint.py
./.venv/bin/python -m unittest discover -s tests -v
```

Some commands invoked by optional modules (e.g. `dig` and `whois`) may not be present. They must be installed separately if needed. Not every advertised menu feature is implemented. A passing smoke test does **not** verify real network or mobile analysis.
