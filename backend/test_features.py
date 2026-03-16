import warnings
import os
import sys

warnings.filterwarnings("ignore")
os.chdir(r"C:\Users\user\Desktop\уник 3 курс\CyberScan Portal\backend")
sys.path.insert(0, r"C:\Users\user\Desktop\уник 3 курс\CyberScan Portal\backend")

from main import extract_ds1_features, DS1_FEATURE_COLS, REAL_MODELS, predict_ds1

print("Models loaded:", list(REAL_MODELS.keys()))
print("DS1_FEATURE_COLS count:", len(DS1_FEATURE_COLS))

df = extract_ds1_features(sys.executable)
if df is None:
    print("FAIL: PE parse returned None for", sys.executable)
    sys.exit(1)

print("Features extracted:", df.shape)
print("Columns match RF:", list(df.columns) == list(DS1_FEATURE_COLS))

for key in list(REAL_MODELS.keys()):
    res = predict_ds1(df, key, 0.5)
    if res:
        print(f"  {key}: score={res['score']} label={res['label']} real={res['using_real_model']}")
    else:
        print(f"  {key}: returned None")

# Run twice to confirm determinism
print("\nRunning again (should be identical):")
for key in list(REAL_MODELS.keys()):
    res = predict_ds1(df, key, 0.5)
    if res:
        print(f"  {key}: score={res['score']} label={res['label']}")
