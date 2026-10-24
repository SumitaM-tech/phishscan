# PhishScan

A hybrid graph + semantic phishing URL investigator: a FastAPI backend
(DNS/RDAP/TLS/HTTP/CT collectors → Transformer + GNN + adaptive fusion
→ risk verdict) paired with a Next.js analyst console.

```
phishscan-project/
├── backend/      FastAPI + ML pipeline — see backend/README.md
└── frontend/     Next.js console — connects to the backend by default
```

## Run both

**Terminal 1 — backend** (http://localhost:8000)
```bash
cd backend
python -m venv venv && source venv/bin/activate   # or use conda
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --port 8000
```

**Terminal 2 — frontend** (http://localhost:3000)
```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The frontend talks to `http://localhost:8000/api`
out of the box — no `.env` needed for local dev. To point it somewhere
else, set `NEXT_PUBLIC_API_URL` in `frontend/.env.local`, and update
`CORS_ORIGINS` in `backend/.env` to match the frontend's origin.

URL scoring uses **models trained on a synthetic URL dataset**
(`backend/datasets/synthetic/`) as the primary scorer; the original
real-data models in `backend/artifacts/` are kept as an automatic backup
(and the real datasets remain untouched in `backend/datasets/`). Pretrained
artifacts for both are included, so everything works right after
`pip install`. See the top of `backend/README.md` for how to regenerate the
dataset, retrain, switch back to the original models
(`USE_SYNTHETIC_MODELS=false`), and an honest note on synthetic vs real-world
accuracy.

## Datasets: what is used vs. what is kept

| Folder | Role |
|---|---|
| `backend/datasets/synthetic/` | **Used.** 80,000 generated URLs (50/50 phishing/legitimate, 33 URL families, domain-disjoint train/val/test). Training data for the primary RF / XGBoost / SVM scorer in `backend/artifacts/synthetic/`. Regenerate with `python -m datasets.synthetic_generator`. |
| `backend/datasets/historical_sources/` | **Kept for reference only.** The original real datasets (PhishTank export, UCI Phishing Websites, PhiUSIIL). The running app does not read them, and the synthetic models were not fitted on them. They remain so the original training pipeline (`build_training_corpus.py`, `train_baselines.py`, ...) can still be re-run. |
| `backend/datasets/hard_negatives.csv` | 67 real branded login/redirect URLs used as a read-only false-positive sanity check. |

## Design

The frontend uses a dark, single-accent visual identity — obsidian/graphite
surfaces with a smoked-violet accent reserved for primary actions and
active states, Space Grotesk for UI text and JetBrains Mono for
evidence/data (both self-hosted in `frontend/public/fonts`, OFL-licensed).
Semantic risk colors (malicious/suspicious/clean) stay muted so they read
as data, not alarm. All theming lives in CSS custom properties in
`frontend/app/globals.css`, including a lighter alternate theme toggleable
from Settings.
