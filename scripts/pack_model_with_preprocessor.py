"""Pack existing trained pipeline into a wrapper that accepts raw JSON transactions.

Usage: python scripts/pack_model_with_preprocessor.py
Creates: models/trained_models/modsec_xgb_with_preproc.pkl
"""

import pickle
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.inference.model_wrapper import ModelWrapper


def main():
    in_path = Path("models/trained_models/modsec_xgb.pkl")
    out_path = Path("models/trained_models/modsec_xgb_with_preproc.pkl")

    if not in_path.exists():
        print(f"Input model not found: {in_path}")
        return

    print(f"Loading pipeline from {in_path}...")
    wrapper = ModelWrapper.from_pickle(str(in_path))

    print(f"Saving wrapped model to {out_path}...")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        pickle.dump(wrapper, f)

    print("Done.")


if __name__ == "__main__":
    main()
