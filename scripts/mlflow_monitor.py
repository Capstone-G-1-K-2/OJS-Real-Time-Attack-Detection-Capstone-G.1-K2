#!/usr/bin/env python3
"""
Helper script untuk monitor dan query MLflow runs.

Kegunaan:
- View latest runs dari "daily-retraining" experiment
- Compare metrics antar version
- Check run status
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timedelta
import sys

import mlflow
from tabulate import tabulate
from mlflow.tracking import MlflowClient


def get_experiment_by_name(name: str) -> dict | None:
    """Get experiment by name."""
    client = MlflowClient()
    experiments = client.search_experiments()
    for exp in experiments:
        if exp.name == name:
            return dict(exp)
    return None


def list_latest_runs(
    experiment_name: str = "daily-retraining",
    limit: int = 10,
    order_by: str = "start_time DESC"
) -> list[dict]:
    """
    List latest N runs dari experiment.
    
    Args:
        experiment_name: Experiment untuk query
        limit: Jumlah runs yang diambil
        order_by: Order runs (default: newest first)
    
    Returns:
        List of run dictionaries dengan metrics
    """
    client = MlflowClient()
    
    # Find experiment
    exp = get_experiment_by_name(experiment_name)
    if not exp:
        print(f"❌ Experiment '{experiment_name}' tidak ditemukan!")
        return []
    
    exp_id = exp['experiment_id']
    
    # Search runs
    runs = client.search_runs(
        experiment_ids=[exp_id],
        order_by=[order_by],
        max_results=limit
    )
    
    results = []
    for run in runs:
        results.append({
            "run_id": run.info.run_id[:8],  # Short ID
            "status": run.info.status,
            "accuracy": run.data.metrics.get("accuracy", "-"),
            "f1": run.data.metrics.get("f1", "-"),
            "samples": run.data.params.get("total_samples", "-"),
            "timestamp": datetime.fromtimestamp(
                run.info.start_time / 1000
            ).strftime("%Y-%m-%d %H:%M:%S"),
            "version": run.data.tags.get("model_version", "-"),
        })
    
    return results


def compare_runs(
    experiment_name: str = "daily-retraining",
    last_n: int = 5
) -> None:
    """
    Compare latest N runs - show performa trend.
    """
    runs = list_latest_runs(experiment_name, limit=last_n)
    
    if not runs:
        print(f"❌ Tidak ada runs untuk '{experiment_name}'")
        return
    
    print("\n" + "="*80)
    print(f"📊 LATEST {len(runs)} RUNS - {experiment_name}")
    print("="*80)
    
    headers = ["Rank", "Date", "Version", "Accuracy", "F1", "Samples", "Status"]
    table_data = []
    
    for i, run in enumerate(runs, 1):
        acc = f"{float(run['accuracy']):.4f}" if run['accuracy'] != "-" else "-"
        f1 = f"{float(run['f1']):.4f}" if run['f1'] != "-" else "-"
        table_data.append([
            f"#{i}",
            run['timestamp'],
            f"v{run['version']}",
            acc,
            f1,
            run['samples'],
            run['status'],
        ])
    
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Simple trend analysis
    if len(runs) >= 2:
        latest_acc = float(runs[0]['accuracy']) if runs[0]['accuracy'] != "-" else None
        prev_acc = float(runs[1]['accuracy']) if runs[1]['accuracy'] != "-" else None
        
        if latest_acc and prev_acc:
            trend = latest_acc - prev_acc
            symbol = "📈" if trend > 0 else "📉" if trend < 0 else "➡️"
            print(f"\n{symbol} Trend: {trend:+.4f} (latest vs previous)")


def show_run_details(run_id: str, experiment_name: str = "daily-retraining") -> None:
    """Show detail untuk specific run."""
    client = MlflowClient()
    
    # Find experiment
    exp = get_experiment_by_name(experiment_name)
    if not exp:
        print(f"❌ Experiment '{experiment_name}' tidak ditemukan!")
        return
    
    try:
        run = client.get_run(run_id)
    except Exception as e:
        print(f"❌ Run '{run_id}' tidak ditemukan: {e}")
        return
    
    print("\n" + "="*80)
    print(f"📋 RUN DETAILS: {run_id}")
    print("="*80)
    
    print("\n📊 METRICS:")
    for metric_name, metric_value in run.data.metrics.items():
        print(f"  {metric_name}: {metric_value:.4f}")
    
    print("\n⚙️ PARAMETERS:")
    for param_name, param_value in run.data.params.items():
        print(f"  {param_name}: {param_value}")
    
    print("\n🏷️ TAGS:")
    for tag_name, tag_value in run.data.tags.items():
        print(f"  {tag_name}: {tag_value}")
    
    print("\n📦 ARTIFACTS:")
    artifacts = client.list_artifacts(run_id)
    for artifact in artifacts:
        print(f"  - {artifact.path}")


def export_metrics_to_json(
    experiment_name: str = "daily-retraining",
    output_file: str = "mlflow_export.json",
    limit: int = 100
) -> None:
    """Export semua runs ke JSON file."""
    runs = list_latest_runs(experiment_name, limit=limit, order_by="start_time DESC")
    
    if not runs:
        print(f"❌ Tidak ada runs untuk export")
        return
    
    # Convert timestamps untuk JSON serializable
    export_data = {
        "experiment": experiment_name,
        "exported_at": datetime.now().isoformat(),
        "total_runs": len(runs),
        "runs": runs
    }
    
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    print(f"✅ Exported {len(runs)} runs ke {output_file}")


def main():
    """CLI interface."""
    parser = argparse.ArgumentParser(
        description="Monitor MLflow daily retraining runs"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # list command
    list_parser = subparsers.add_parser("list", help="List latest runs")
    list_parser.add_argument(
        "--limit", type=int, default=10,
        help="Number of runs to show (default: 10)"
    )
    list_parser.add_argument(
        "--experiment", default="daily-retraining",
        help="Experiment name (default: daily-retraining)"
    )
    
    # compare command
    compare_parser = subparsers.add_parser("compare", help="Compare latest runs")
    compare_parser.add_argument(
        "--last", type=int, default=5,
        help="Compare last N runs (default: 5)"
    )
    compare_parser.add_argument(
        "--experiment", default="daily-retraining",
        help="Experiment name (default: daily-retraining)"
    )
    
    # details command
    details_parser = subparsers.add_parser("details", help="Show run details")
    details_parser.add_argument(
        "run_id", help="Run ID (can be partial)"
    )
    details_parser.add_argument(
        "--experiment", default="daily-retraining",
        help="Experiment name (default: daily-retraining)"
    )
    
    # export command
    export_parser = subparsers.add_parser("export", help="Export runs to JSON")
    export_parser.add_argument(
        "--output", default="mlflow_export.json",
        help="Output file (default: mlflow_export.json)"
    )
    export_parser.add_argument(
        "--limit", type=int, default=100,
        help="Number of runs to export (default: 100)"
    )
    export_parser.add_argument(
        "--experiment", default="daily-retraining",
        help="Experiment name (default: daily-retraining)"
    )
    
    args = parser.parse_args()
    
    if args.command == "list":
        runs = list_latest_runs(args.experiment, args.limit)
        if runs:
            print("\n" + "="*80)
            print(f"✅ {len(runs)} LATEST RUNS - {args.experiment}")
            print("="*80)
            headers = ["#", "Date", "Version", "Accuracy", "F1", "Samples"]
            table_data = []
            for i, run in enumerate(runs, 1):
                acc = f"{float(run['accuracy']):.4f}" if run['accuracy'] != "-" else "-"
                f1 = f"{float(run['f1']):.4f}" if run['f1'] != "-" else "-"
                table_data.append([
                    i,
                    run['timestamp'],
                    f"v{run['version']}",
                    acc,
                    f1,
                    run['samples'],
                ])
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    elif args.command == "compare":
        compare_runs(args.experiment, args.last)
    
    elif args.command == "details":
        show_run_details(args.run_id, args.experiment)
    
    elif args.command == "export":
        export_metrics_to_json(args.experiment, args.output, args.limit)
    
    else:
        # Default: list latest 10
        compare_runs()


if __name__ == "__main__":
    main()
