#!/usr/bin/env python3
"""Run the API server."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Setup path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

import argparse

import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Start OJS Attack Detection API")
    parser.add_argument("--host", default="0.0.0.0", help="API host")
    parser.add_argument("--port", type=int, default=8000, help="API port")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    
    args = parser.parse_args()
    
    print(f"""
    ╔════════════════════════════════════════╗
    ║  OJS Attack Detection API (FastAPI)    ║
    ║  Starting server...                    ║
    ╚════════════════════════════════════════╝
    
    Host: {args.host}
    Port: {args.port}
    Docs: http://{args.host}:{args.port}/docs
    """)
    
    uvicorn.run(
        "src.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level="info",
    )


if __name__ == "__main__":
    main()
