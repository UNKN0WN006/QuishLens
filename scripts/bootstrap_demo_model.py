from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split

from app.analysis.url_features import MODEL_FEATURES, extract_url_features, model_vector
from app.config import MODEL_META_PATH, MODEL_PATH

# This model exists only so a fresh clone demonstrates the complete ML path.
# Replace it before reporting benchmark results; real evaluation scripts are
# intentionally separate from this bootstrap generator.
RNG = random.Random(42)
LEGIT = [
    "wikipedia.org", "github.com", "openai.com", "python.org", "mozilla.org",
    "microsoft.com", "google.com", "apple.com", "amazon.in", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "flipkart.com", "phonepe.com", "paytm.com",
]
WORDS = ["login", "verify", "secure", "account", "update", "billing", "wallet", "password", "support", "auth"]


def make_rows():
    rows=[]
    for _ in range(1200):
        domain=RNG.choice(LEGIT); path=RNG.choice(["/", "/about", "/docs", "/search?q=security", "/help", "/account"])
        rows.append((f"https://{domain}{path}",0))
    for i in range(1200):
        brand=RNG.choice(["microsoft","google","paypal","sbi","amazon","apple","paytm"])
        token="-".join(RNG.sample(WORDS, k=RNG.randint(2,4)))
        host=f"{brand}-{token}-{i}.example.invalid"
        path=f"/{RNG.choice(WORDS)}/{RNG.choice(WORDS)}?session={RNG.randint(100000,999999)}"
        rows.append((f"http{'s' if RNG.random()>.3 else ''}://{host}{path}",1))
    RNG.shuffle(rows)
    return rows


def main():
    rows=make_rows(); X=np.asarray([model_vector(extract_url_features(url)) for url,_ in rows]); y=np.asarray([label for _,label in rows])
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,stratify=y,random_state=42)
    model=RandomForestClassifier(n_estimators=180,min_samples_leaf=2,class_weight="balanced",random_state=42,n_jobs=-1)
    model.fit(Xtr,ytr); pred=model.predict(Xte)
    MODEL_PATH.parent.mkdir(parents=True,exist_ok=True); joblib.dump(model,MODEL_PATH)
    meta={"model":"RandomForestClassifier (bootstrap demo)","feature_names":MODEL_FEATURES,"training_source":"procedurally generated SAFE demo corpus — replace for competition benchmark","rows":len(rows),"bootstrap_only":True,"demo_f1":float(f1_score(yte,pred))}
    MODEL_META_PATH.write_text(json.dumps(meta,indent=2),encoding="utf-8")
    print(json.dumps(meta,indent=2))

if __name__=="__main__": main()
