import warnings
import os
import sys

warnings.filterwarnings("ignore")

_backend_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(_backend_dir)
sys.path.insert(0, _backend_dir)

from scan_engine import DS1_FEATURE_COLS, REAL_MODELS, predict_ds1, extract_ds1_features

print("Models loaded:", list(REAL_MODELS.keys()))
print("DS1_FEATURE_COLS count:", len(DS1_FEATURE_COLS))

df = extract_ds1_features(sys.executable)
if df is None:
    print("FAIL: PE parse returned None for", sys.executable)
    sys.exit(1)

print("Features extracted:", df.shape)
print("Columns match expected:", list(df.columns) == list(DS1_FEATURE_COLS))

for key in list(REAL_MODELS.keys()):
    pred = predict_ds1(df, key, 0.5)
    if pred:
        print(
            f"  {key}: score={pred['score']} label={pred['label']} real_model={pred['using_real_model']}"
        )
    else:
        print(f"  {key}: returned None")

print("\nRepeat run (determinism check):")
for key in list(REAL_MODELS.keys()):
    pred = predict_ds1(df, key, 0.5)
    if pred:
        print(f"  {key}: score={pred['score']} label={pred['label']}")
