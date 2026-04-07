#!/usr/bin/env python3
"""Example client for testing API endpoints via HTTP."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Optional

import httpx


class APIClient:
    """HTTP client for OJS Attack Detection API."""
    
    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
    
    async def health_check(self) -> dict:
        """Check API health."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(f"{self.base_url}/health")
            resp.raise_for_status()
            return resp.json()
    
    async def predict_single(
        self,
        method: str,
        uri: str,
        status: int = 200,
        bytes_sent: int = 0,
        request_time: float = 0.0,
        user_agent: str = "",
        **kwargs
    ) -> dict:
        """Predict single log."""
        payload = {
            "method": method,
            "uri": uri,
            "status": status,
            "bytes_sent": bytes_sent,
            "request_time": request_time,
            "user_agent": user_agent,
            **kwargs
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/predict/single",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    
    async def predict_batch(
        self,
        logs: list[dict],
        threshold: float = 0.5,
    ) -> dict:
        """Predict batch of logs."""
        payload = {
            "logs": logs,
            "threshold": threshold,
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/predict/batch",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()
    
    async def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        attack_count: int = 0,
    ) -> dict:
        """Send alert via Telegram."""
        payload = {
            "title": title,
            "message": message,
            "severity": severity,
            "attack_count": attack_count,
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/alert",
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()


async def demo():
    """Demo API usage."""
    client = APIClient()
    
    print("\n╔════════════════════════════════════════╗")
    print("║  OJS Attack Detection API - Demo       ║")
    print("╚════════════════════════════════════════╝")
    
    try:
        # Check health
        print("\n1️⃣  Health Check...")
        health = await client.health_check()
        print(f"   Status: {health['status']}")
        print(f"   Model loaded: {health['model_loaded']}")
        
        # Single prediction - normal
        print("\n2️⃣  Predict single (NORMAL request)...")
        result = await client.predict_single(
            method="GET",
            uri="/index.php/",
            user_agent="Mozilla/5.0",
        )
        print(f"   Prediction: {'🔴 ATTACK' if result['prediction'] else '🟢 NORMAL'}")
        print(f"   Probability: {result['attack_probability']:.4f}")
        print(f"   Confidence: {result['confidence']:.4f}")
        
        # Single prediction - suspicious
        print("\n3️⃣  Predict single (SUSPICIOUS request)...")
        result = await client.predict_single(
            method="GET",
            uri="/index.php/article/view?id=1' OR '1'='1",
            status=403,
            bytes_sent=512,
            request_time=0.5,
            user_agent="curl/7.0",
            rule_count=3,
            severity_score=7.5,
        )
        print(f"   Prediction: {'🔴 ATTACK' if result['prediction'] else '🟢 NORMAL'}")
        print(f"   Probability: {result['attack_probability']:.4f}")
        print(f"   Severity: {result['severity']}")
        
        # Batch prediction
        print("\n4️⃣  Batch prediction (multiple logs)...")
        logs = [
            {"method": "GET", "uri": "/index.php/"},
            {"method": "GET", "uri": "/index.php/user/login"},
            {"method": "POST", "uri": "/index.php/article/submit"},
            {"method": "GET", "uri": "/admin.php", "status": 403},
        ]
        
        result = await client.predict_batch(logs)
        print(f"   Total logs: {result['total_logs']}")
        print(f"   Normal: {result['summary']['normal_count']}")
        print(f"   Attacks: {result['summary']['attack_count']}")
        print(f"   Attack %: {result['summary']['attack_percentage']:.2f}%")
        
        print("\n✓ Demo completed successfully!")
        
    except httpx.ConnectError:
        print("✗ Could not connect to API")
        print("  Make sure server is running: python scripts/run_api.py")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()


async def main():
    parser = argparse.ArgumentParser(description="OJS API Client")
    parser.add_argument("--url", default="http://localhost:8000", help="API URL")
    parser.add_argument("--health", action="store_true", help="Check health only")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    client = APIClient(base_url=args.url)
    
    if args.health:
        try:
            result = await client.health_check()
            print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            print(f"Error: {e}")
    elif args.demo or not any([args.health]):
        await demo()


if __name__ == "__main__":
    asyncio.run(main())
