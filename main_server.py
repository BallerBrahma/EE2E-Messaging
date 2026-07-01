#!/usr/bin/env python3
"""Entrypoint: run the E2EE relay server.

Usage: python main_server.py [--host HOST] [--port PORT] [--db PATH]
"""
from server.server import main

if __name__ == "__main__":
    main()
