from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

from src.preprocessing.modsec_parser import load_dataset


def predict(model_path: str, input_path: str, output_path: str, threshold: float) -> None:
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    df = load_dataset(input_path)

    # Remove label if present in input data to avoid data leakage during inference.
    if "label" in df.columns:
        df = df.drop(columns=["label"])

    probabilities = model.predict_proba(df)[:, 1]
    predictions = (probabilities >= threshold).astype(int)

    result = df.copy()
    result["attack_probability"] = probabilities
    result["prediction"] = predictions

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output, index=False)

    summary = {
        "total_logs": int(len(result)),
        "predicted_attack": int((result["prediction"] == 1).sum()),
        "predicted_normal": int((result["prediction"] == 0).sum()),
        "output_path": str(output),
    }
    print(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run inference on ModSecurity logs.")
    parser.add_argument("--model", default="models/trained_models/modsec_xgb.pkl")
    parser.add_argument("--input", required=True, help="Path ke file log/dataset.")
    parser.add_argument("--output", default="data/processed/predictions.csv")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    predict(args.model, args.input, args.output, args.threshold)


if __name__ == "__main__":
    main()
