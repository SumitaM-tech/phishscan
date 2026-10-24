# PhishScan Backend

FastAPI backend implementing the hybrid graph + semantic phishing
detector, built directly against the frontend's `Investigation`
contract (`lib/types.ts`). Two independent signals feed every
verdict: an ML model (semantic + structural + classical baselines)
and a real-time threat-intelligence feed match — combined, not just
concatenated (see "Two signals" below).

## Synthetic-data models are now the primary scorer (original models kept as backup)

**What changed.** URL scoring now uses Random Forest / XGBoost / SVM models trained on a
fully **synthetic URL dataset** (`datasets/synthetic/synthetic_urls.csv`, 80,000 URLs,
50/50 phishing/legitimate). The original real-data models in `artifacts/*.pkl` are
**unchanged and kept as the backup**, and the real datasets in
`datasets/historical_sources/` are left exactly as they were (they are no longer used
for fitting the primary models). Everything else -- threat-feed signal, evidence
collectors, graph, findings, reports, database, API contract, frontend -- works as before.

**Scoring order** (`app/models/classifier.py`):

| # | Source | Used when |
|---|--------|-----------|
| 1 | **Synthetic models** (`artifacts/synthetic/`) | default |
| 2 | **Original real-data models** (`artifacts/rf.pkl`, `xgboost.pkl`, `svm.pkl`) | synthetic files missing / corrupt / erroring, or `USE_SYNTHETIC_MODELS=false` |
| 3 | Rule-based heuristic | no trained artifacts at all |

`GET /api/health` reports `synthetic_loaded`, `backup_models_loaded` and
`active_model_source` (`synthetic` / `original_backup` / `heuristic`). Each scored URL also
carries `model_source`, and the investigation rationale shows `ML model mode: synthetic`
(or `baseline` when the backup is serving).

**Files added**

| File | Purpose |
|------|---------|
| `datasets/synthetic_generator.py` | Deterministic generator (seed 42). 16 legitimate + 17 phishing URL families, domain-disjoint train/val/test split |
| `datasets/synthetic/synthetic_urls.csv` | The generated dataset (`url,label,category,split`) |
| `app/features/synthetic_features.py` | 20 original host features + 35 path/query/brand-ownership features (typosquats, leetspeak, brand on unofficial domain, lure words, redirect-to-other-domain, free hosting, cheap TLDs...). `url_features.py` is untouched because the backup models depend on it |
| `training/train_synthetic.py` | Trains + evaluates; writes `artifacts/synthetic/` only |
| `artifacts/synthetic/` | `rf.pkl`, `xgboost.pkl`, `svm.pkl`, `scaler.pkl`, `model_metadata.json`, `synthetic_results.csv`, `per_category_test_accuracy.csv` |
| `tests/test_synthetic_detection.py` | Detection + fallback + split-leakage tests |

**Regenerate / retrain**

```bash
cd backend
python -m datasets.synthetic_generator --n 80000 --seed 42   # rewrites datasets/synthetic/synthetic_urls.csv
python -m training.train_synthetic                          # rewrites artifacts/synthetic/
python tests/test_synthetic_detection.py                    # or: python -m pytest tests -q
```

**Measured results** (ensemble = mean of the 3 models, threshold chosen on validation only):

| Evaluation set | n | Accuracy | FPR | FNR |
|---|---|---|---|---|
| Synthetic test, **domain-disjoint** (no domain seen in training) | 11,443 | 97.9% | 2.5% | 1.7% |
| Second synthetic corpus, different seed (new names/paths) | 30,000 | 97.2% | 3.8% | 1.8% |
| 67 real branded URLs in `hard_negatives.csv` (read-only sanity check) | 67 | 0 false positives | 0% | -- |

Per-family accuracy is in `artifacts/synthetic/per_category_test_accuracy.csv`. Known weak
spots *by construction*: bare URL shorteners (`bit.ly/xxxx` carries no information, so they
score mid-range), legitimate sites on free hosting, and "clean domain + login path" pages
that look identical to ordinary login pages.

### Read this: synthetic accuracy is not real-world accuracy

The numbers above measure how well the models learned the synthetic generator's patterns.
As a one-off read-only check (not shipped, not used for training), 3,000 real URLs sampled
from the bundled PhishTank export were scored: the synthetic models flagged **~50%**
(>= 45/100) versus **~76%** for the original backup models, which were trained on that
kind of data. Most of the real misses are phishing pages hosted on legitimate platforms
(Google Docs/Forms/Sites, QR-code and link shorteners, Adobe Express, Box, Jotform, Wix) --
a URL string alone cannot separate those from benign links. If real-world detection
matters, keep the live PhishTank/OpenPhish feed enabled (a verified feed hit still forces
the verdict to malicious regardless of the model) and consider switching
`USE_SYNTHETIC_MODELS=false`, or blending in the backup, for production traffic.

**Environment note.** The original pickles were saved with scikit-learn 1.8.x and
XGBoost 3.x, so `requirements.txt` now pins `scikit-learn>=1.8,<1.9` and
`xgboost>=3.0,<4.0` (it previously said `<1.8` / `<3.0`, which could not load them cleanly).
The synthetic models were trained on those same versions.

---

## Latest pass: a crafted malicious-looking URL was scoring "clean" — fixed, plus a bonus false-positive fix found along the way

Reported bug: `https://www.netflix.com/scM?ogin?nextpage=https%3A%2F%2Fwww.netflix.com%2Fbrowse`
scored 18.9/100 "clean". The host genuinely is `netflix.com`, so the
host-only feature set (see "Feature set narrowed to host/scheme only"
below) had no way to see anything wrong — the attack is entirely in
the path/query. Added exactly one new, narrowly-scoped feature rather
than reopening path/query features generally (which is what caused
the *previous* false-positive bug documented below):

- **`malformed_query_syntax`**: raw URL contains more than one `?`.
  Well-formed URLs (browsers, servers, every standard framework) only
  ever produce one; additional params are joined with `&`. This
  crafted URL has two `?` because of the doubled/mangled
  `scM?ogin?nextpage=` path — a real syntax anomaly, not "has a path."
  Verified against 783 real phishing URLs that have it vs. 0 real
  legitimate ones in the corpus, and against all 67
  `datasets/hard_negatives.csv` real login/redirect URLs (0 trigger
  it) and standard single-`?` redirect patterns (`?next=`,
  `?returnUrl=`, `?redirect_uri=` — none trigger it either).

Found a second, unrelated real bug while verifying the fix didn't
regress anything: `https://accounts.google.com/signin?continue=...`
(a real Google URL) scored 55.8/100 "suspicious", because the
`suspicious_word_count` feature did raw substring matching and
`accounts` contains `account` as a substring. Fixed to exact
dot/hyphen-token matching instead — `accounts.google.com` now scores
0 for that feature (`"accounts" != "account"`), while
`secure-login-verify-account.tk` still matches 4 of the real
suspicious tokens correctly. This is a genuine, if partial, fix:
`account.microsoft.com`-style hosts where "account" is the domain's
own *exact* subdomain token still match once, since that pattern is
genuinely used by both real login portals and phishing — see the
docstring on `_suspicious_word_count` in `app/features/url_features.py`
for the honest limitation. Side benefit, measured: SVM's hard-negative
false-positive rate dropped from 20.9% to 10.45% as a result.

Retrained RF/XGBoost/SVM on the full real corpus with both fixes.
Verified end-to-end via the live classifier, not just the unit-level
feature checks above:

| URL | Score |
|---|---|
| the reported crafted URL | 18.9 clean → **80.3 malicious** |
| netflix.com (plain) | 17.7 clean |
| accounts.google.com (real redirect) | 55.8 suspicious → **14.0 clean** |
| github.com/login (real) | 13.3 clean |
| ip-based phishing test | 95.3 malicious |
| classic phishing pattern | 95.3 malicious |

## This pass: fixed a real false-positive bug, hit a real training failure, documenting both

Testing the live app surfaced a genuine bug: `https://www.netflix.com/`
scored 46.3/100 "suspicious". Root-caused it (see
`datasets/brand_imbalance.py` for the full writeup and a reproducible
measurement script) to the semantic Transformer branch outputting a
0.97 phishing-probability for that exact URL, driven by the token
`netflix` — which appears in 51 phishing URLs in this real corpus but
only 2 legitimate ones (25:1). Same pattern for `paypal` (42:1),
`google` (366:1), `amazon` (20:1), and other famous brands: they're
impersonated far more often than their own real domain shows up in a
generic web crawl, so the model correctly-but-harmfully learned "this
brand name = phishing."

**Fix attempt:** built a data-driven correction (`brand_sample_weight()`
in `datasets/brand_imbalance.py`) that up-weights legitimate training
rows containing a curated list of well-known brand tokens, plus ~60
real (not fabricated) brand-domain URLs folded into training
(`build_brand_correction_set()`). The standalone semantic model
retrained cleanly this way (87% test accuracy, up from a version that
misfired on exactly these cases). **The joint fusion fine-tune
(`training/train_hybrid.py`) did not handle this well** — it collapsed
to predicting "legitimate" for almost everything (val F1 stuck at 0.0
for 5 straight epochs on the smaller brand-corrected training sample),
and its checkpoint logic (`if val_metrics["f1"] > best_f1`, starting
from `best_f1 = -1`) was about to save that collapsed model over the
working standalone semantic checkpoint, since 0.0 > -1. Killed the run
before that finished.

**What's actually shipping right now:** the hybrid (Transformer+GNN+
fusion) scoring path is disabled — `artifacts/fusion_model.pt` and
`gnn_model.pt` were moved to `artifacts/disabled_broken_20260924/`
rather than left in place, so `PhishScanModel.has_trained_hybrid` is
`False` and every score comes from the baseline ensemble (RF/XGBoost/
SVM) alone, which was never broken. Verified this is a real
improvement, not just a smaller number:

| URL | Before this pass | After this pass |
|---|---|---|
| `netflix.com` | 46.3 **suspicious** | 17.2 **clean** |
| `google.com` | (untested, same code path) | 18.8 **clean** |
| `paypal.com` | (untested, same code path) | 13.3 **clean** |
| `github.com` | (untested, same code path) | 13.2 **clean** |
| a real phishing test URL | — | 94.8 **malicious** (still caught) |

**Known follow-up, not done in this pass:** the joint fusion trainer's
instability itself is unfixed. Likely causes, in rough order of
suspicion: too little data for a from-scratch fusion gate + GNN head
to learn on (7,028 training rows after the domain-disjoint split of a
10k sample), a per-sample (unbatched) SGD loop at `lr=5e-4` with no
gradient clipping, and the `best_f1 = -1` checkpoint floor accepting
any non-negative F1 as "best" instead of requiring some minimum bar
before saving. Don't drop new checkpoints into `artifacts/` without
re-running the netflix/google/paypal/github spot-check above first —
`python -m app.models.classifier` doesn't exist as a CLI, but the
one-liner is in `datasets/brand_imbalance.py`'s module docstring history
or just:
```bash
python -c "
from app.models.classifier import get_model
m = get_model()
for u in ['https://www.netflix.com/', 'https://www.google.com/', 'https://www.paypal.com/', 'http://secure-login-verify-account.tk/reset']:
    r = m.score_url(u, [], [])
    print(u, r['score'], r['verdict'])
"
```

**Also fixed this pass:** the Reports page (`components/reports-view.tsx`)
only ever listed investigations that already had a manually-created
report, so it showed "No reports yet" even after real scans. Rewrote
it to list every past investigation automatically (same data
`/history` uses) with a one-click "Generate PDF" / "Download PDF"
button per row (`components/investigation-report-row.tsx`) — no
separate "create report" step required first.

## Quick start

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --reload-dir app --port 8000
```

Works immediately with SQLite and pretrained artifacts already in
`artifacts/` (see "Real training data" below for where those came
from). Point the frontend at it via
`frontend/.env.local` → `NEXT_PUBLIC_API_URL=http://localhost:8000/api`.
Interactive docs at `http://localhost:8000/docs`.

For Postgres instead of SQLite: `docker compose up -d db`, then set
`DATABASE_URL` per `.env.example`.

## Troubleshooting

**`ModuleNotFoundError: No module named 'sqlalchemy'` (or any other
package) right after `pip install -r requirements.txt` appeared to
run** — it didn't fully succeed. pip resolves every line in
`requirements.txt` before installing *any* of them; if one exact
version pin doesn't have a wheel for your Python version/OS (this
happened with `scikit-learn==1.8.0` on Python 3.10 — 1.8.0 has no
Windows/3.10 build), the whole install aborts and nothing gets
installed, even packages that logged as "Collecting" successfully
above the error. `requirements.txt` uses version ranges instead of
exact pins specifically to avoid this. If you still hit it, re-run
`pip install -r requirements.txt` and read the *first* error near
the top of the output, not just the last line — and confirm with
`pip show sqlalchemy` (or whatever package) afterward.

**Frontend shows "Failed to fetch" / `ECONNREFUSED` on
`localhost:8000`** — this just means the backend isn't running (or
crashed on startup, per above). Fix the backend first; the frontend
error resolves itself once `uvicorn` is actually up. Confirm with
`curl http://localhost:8000/api/health` (or open it in a browser)
before troubleshooting the frontend at all.

## Real training data vs. mocked test data

This section exists because it matters: **nothing that ships in
`artifacts/` was trained on synthetic or fabricated URLs.**

### Real data, used for training

| Source | Where | Rows | Used for |
|---|---|---|---|
| PhishTank bulk CSV export (real, user-provided) | `datasets/historical_sources/phishtank_online_valid.csv` | 76,334 | Phishing class, URL-level corpus |
| PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024; real, user-provided) | `datasets/historical_sources/phiusiil_phishing_url_dataset2.zip` | 235,795 | Both classes, URL-level corpus |
| UCI "Phishing Websites" (Mohammad et al.; real, user-provided) | `datasets/historical_sources/phishing_websites_dataset1_.zip` | 11,055 | Standalone baseline only (30 pre-extracted features, no raw URL — can't feed the Transformer/GNN) |
| Live PhishTank feed | synced into `ThreatIntelRecord` by `app/scheduler.py` | grows over time | Real-time `/threat-intelligence/check`, and optionally folded into training via `datasets/export_raw.py` |
| Live OpenPhish feed | same | grows over time | same |

The three files in `datasets/historical_sources/` are copied
byte-for-byte from what was uploaded — nothing in this codebase opens
them for writing. Verified with `md5sum` before/after.

**These datasets are kept deliberately separate from the live
real-time sync pipeline**, per how this project is scoped:

- `datasets/build_training_corpus.py` reads only `historical_sources/`
  → writes `datasets/raw/historical_*.csv`
- `datasets/export_raw.py` reads only the live-synced `ThreatIntelRecord`
  table (+ a fresh Tranco pull) → writes `datasets/raw/live_*.csv`
- `datasets/preprocess.py` auto-discovers and combines whichever of
  the two pairs are present, but the files themselves are never
  confused with each other, and the live sync scheduler keeps running
  against the real PhishTank/OpenPhish feeds on its own schedule
  regardless of whether you've ever touched the historical corpus.

### Mocked data — used only in tests, never shipped as a file

While building this, the PhishTank/OpenPhish CSV/feed parsers were
unit-tested against small hand-written mock responses (fake CSV
text, fake feed text) purely to verify the parsing logic without
depending on network access. **No mock/synthetic data is committed
anywhere in this repo or shipped in `artifacts/`.** The synthetic
sample CSVs an earlier version of this project bundled
(`datasets/external/sample_*.csv`) have been deleted entirely.

### A real bug this data surfaced (worth knowing about)

Training on the real corpus caught two genuine issues that synthetic
data had been hiding:

1. **Train/inference mismatch**: features were being extracted from
   raw, inconsistently-formatted source URLs during training, but
   live inference always scores the *normalized* form (which forces
   a trailing `/` on bare domains). Fixed — `preprocess.py` now
   extracts features from the normalized URL, matching inference
   exactly.
2. **Dataset class bias**: PhiUSIIL's legitimate URLs are
   overwhelmingly `www.`-prefixed, while the phishing sources are
   overwhelmingly bare-apex domains. Left alone, the model learned
   "missing `www.`" as a phishing shortcut — which misclassified real
   sites like `github.com` as 100% phishing. Fixed in
   `build_training_corpus.py` by augmenting the corpus with the
   bare-apex form of every `www.`-prefixed legitimate URL already in
   the real dataset (not fabricated domains — the same real sites'
   other valid form).
3. **Scheme-less input defaulted to HTTP**: `normalize_url()` was
   prepending `http://` to a bare hostname like `github.com` typed
   with no scheme. Since `has_https` is a heavily-weighted feature
   and virtually all real legitimate traffic is HTTPS today, this
   silently downgraded every scheme-less legitimate query toward
   "missing TLS" = phishing-looking — reproducing the exact
   `github.com` false positive above even after fix #2, until traced
   to this. Fixed to default to `https://`, matching both modern
   browser behavior and the frontend's own `normalizeUrl()` in
   `lib/utils.ts`, which already did this correctly.

All three fixes verified together against 8 real sites through the
**actual live `POST /api/investigations` pipeline** (not just the
classifier in isolation) — github.com, google.com, wikipedia.org,
stackoverflow.com, python.org, cloudflare.com scored clean (1.5–15.3/100);
two real phishing-pattern URLs scored malicious (99.2–99.4/100). 8/8 correct.

### More real bugs the data (and real usage) surfaced

Four more issues turned up from testing against real login pages and
repeated real-world usage, not synthetic test cases:

4. **`brand_token_count` flagged a brand's own real domain as
   impersonating itself.** It matched a brand name anywhere in the
   host, so `netflix.com` itself scored as "impersonating Netflix".
   Fixed in `url_features.py`: a brand token exactly matching the
   host's own second-level label (e.g. "netflix" in "netflix.com") is
   the brand's real site and is no longer counted; a token embedded in
   a longer label ("netflix-login.com") or used as a subdomain in
   front of an unrelated domain ("netflix.evil.tk") still is.
5. **A structural dataset bias via path presence.** PhiUSIIL's
   legitimate class is domain-level only — 0% of its ~135k legitimate
   URLs have any path beyond the bare domain, versus ~44% of the
   phishing corpus. `path_length`, `path_entropy`, and `num_subdirs`
   all became near-perfect (but spurious) phishing predictors as a
   result, flagging real login/checkout/article pages on any real
   site. Since fabricating legitimate deep-link URLs to counter this
   would itself be synthetic training data, these three features were
   removed from `url_features.py` instead (see the note at the top of
   that file). The hybrid model's semantic (Transformer) branch has a
   softer version of the same bias through text tokens ("login",
   "verify" never appear in any legitimate training example's token
   stream, only phishing ones) that can't be fixed the same way
   without real legitimate deep-link *text* to train on — the
   ensemble blend in `classifier.py` was rebalanced to weight the
   (less-affected, post-fix) baselines over the hybrid score
   specifically to reduce this residual effect. Documented as a known
   limitation rather than hidden; a real login page on a well-known
   brand can still land as "suspicious" rather than confidently
   "clean" — see "Known limitations" below.
6. **Investigations stuck at "Running" forever.** Root cause: running
   `uvicorn --reload` from `backend/` makes it watch the *entire*
   directory by default, including `phishscan.db` — every investigation
   writing to the database looked like a code change and restarted the
   server mid-request, killing the investigation and leaving its row
   stuck. Fixed three ways: the recommended run command now scopes
   `--reload` to `--reload-dir app` (source only); a startup sweep
   (`InvestigationRepository.sweep_orphaned`) marks anything still
   "running"/"queued" at boot as failed with a clear message, so a
   crash or restart never leaves a permanently-stuck row again; and a
   related bug where the failure-cleanup path itself crashed (see #8)
   is fixed too.
7. **Investigating the same domain twice crashed with a `UNIQUE
   constraint failed: graph_nodes.id`.** Graph node ids were
   deterministic strings like `domain::amazon.com` — global across the
   whole table, not scoped per investigation, so re-scanning a domain
   (or scanning two domains sharing infrastructure, like a nameserver)
   collided with a previous investigation's rows. Fixed in
   `graph_service.build_graph()` by salting every node id with the
   investigation id.
8. **The crash-recovery path itself could crash.** When #7 (or
   anything else) failed mid-transaction, the exception handler in
   `investigation_service.run_investigation` tried to write the
   "failed" status without first rolling back the broken transaction —
   SQLAlchemy rejects that, so the cleanup raised a second, unrelated
   error, which is the actual reason investigations were ending up
   stuck instead of cleanly marked failed. Fixed with an explicit
   `db.rollback()` before the cleanup writes. Verified by forcing a
   simulated mid-investigation crash and confirming it now resolves to
   `status: "failed"` with a clear rationale instead of hanging.

Fixes #4–#8 verified together: repeated real scans of the same domain
(`classroom.google.com` x3), a forced mid-investigation crash, and a
12-site real-world sweep (8 legitimate incl. two real branded login
pages, 4 phishing patterns) — 12/12 correct verdicts, zero crashes,
zero stuck rows, reports generate and list correctly.

### Known limitations

- A real login/account page on a well-known brand (e.g.
  `paypal.com/signin`, `github.com/login`) can land as "suspicious"
  (~40-55/100) rather than confidently "clean". This is the residual
  effect of fix #5 above — the semantic (Transformer) branch's
  text-token bias can't be fully corrected without real legitimate
  deep-link training text, which isn't available without fabricating
  data. It does not affect bare-domain queries (the common case) and
  does not cause phishing to be missed.
- GNN-only sits at chance (see below) — synthetic training graphs, not
  a data-quality issue.
- **Hard-negative false-positive rate is 8.9%-20.9%** on a 66-URL set
  of real branded login/account/payment pages (measured, see above) —
  driven by "secure"/"login"-type tokens legitimately appearing in a
  brand's own subdomains. Not fixed in this pass: doing so properly
  needs either a real, larger corpus of legitimate deep-link URLs (not
  available here) or a verified brand-owned-subdomain allowlist
  service (itself a new, carefully-scoped piece of work, not a quick
  patch) — hardcoding these 66 domains as exceptions would just be a
  narrower version of the same shortcut this project has been actively
  removing.
- **GNN was not retrained on real infrastructure data in this pass.**
  Building it needs live DNS/RDAP/TLS/Certificate-Transparency lookups
  per training URL (`app/collectors/*`), which requires sustained,
  unrestricted outbound network access this environment does not have
  (only package registries are reachable here). Run
  `python -m training.train_gnn --live` on a machine with normal
  internet access, then `python -m training.train_hybrid` to fold the
  real graph signal into the fusion model. Until then, the honest
  status stays what it already was: GNN-only at chance, contributing
  ~0 to the fusion result.
- The domain-disjoint split (see above) uses a hand-maintained list of
  ~2-label public suffixes (`co.uk`, `com.br`, ...) rather than a real,
  regularly-updated Public Suffix List, because fetching one needs
  network access this environment doesn't have. Good enough for
  leakage-safe grouping; swap in `tldextract` (`pip install
  tldextract`) for production-grade eTLD+1 parsing.

### Feature set narrowed to host/scheme only (fix #9)

A deeper pass on fix #5 above: `num_params` (query-string presence)
turned out to carry the *identical* dataset bias as the path features
already removed — PhiUSIIL's legitimate URLs have 0% query strings
too, so `?token=...` or `?nextpage=...` was just as spurious a
"phishing" signal as having a path. Verified concretely: a real
Netflix post-login redirect URL
(`netflix.com/in/login?nextpage=https%3A%2F%2Fwww.netflix.com%2Fbrowse`)
scored 99.6% malicious from all three baselines being >98% confident
on this alone.

Rather than keep finding and removing individual biased features one
at a time, `url_features.py` was narrowed on principle to **only
compute features from the host/scheme portion of the URL** — the one
part of the corpus where real, balanced examples of both classes
actually exist. `url_length`, `num_params`, `num_fragments`, and
`has_double_slash_redirect` were dropped; `num_hyphens`,
`num_underscores`, and `suspicious_word_count` were rescoped from
whole-URL to host-only (so "secure-login-verify.tk" as a *domain*
still flags, but "/login" in a *path* no longer does). 19 features
remain, down from 26 originally.

This trades headline accuracy for honesty: baseline accuracy dropped
to ~87-90% (from a peak of ~96% that was measuring the bias, not real
skill — see the table below) and the ensemble blend in
`classifier.py` was rebalanced 65% baselines / 35% hybrid, since the
baselines are now bias-free and the hybrid's semantic branch still
has a softer residual version of the same issue. Verified: the exact
Netflix URL above dropped from 99.6% to 45% ("suspicious", not a
false accusation of malice); four real phishing patterns still scored
90-95% malicious; a 12-site real-world sweep scored 12/12 correct
(counting "suspicious" as an acceptable hedge, not a wrong answer).

## Domain-disjoint, leakage-safe evaluation (this pass)

The pipeline above trained/evaluated on a **plain random URL-level
split**, and (per the corpus audit below) the real corpus has 9,042
registrable domains contributing more than one URL each — one single
domain (`google.com`) contributes 7,767 URLs on its own, and several
free-hosting platforms (`weebly.com`, `web.app`, `firebaseapp.com`,
`repl.co`, `wixstudio.com`, ...) host thousands more. A random split
puts URLs from the *same* domain on both sides, so a model can partly
memorize "this domain = this label" instead of learning a genuinely
generalizable phishing pattern, and the random-split test number
overstates real-world performance by an unknown amount.

Run the audit yourself:
```bash
python -m datasets.audit_corpus     # writes datasets/processed/audit_report.json
```
Measured on the real corpus (312,129 raw rows → 308,509 after
cleaning/dedup): 173,663 phishing / 134,846 legitimate; 182,554
unique registrable domains; 337 registrable domains carry **both**
labels (shared/compromised/free-hosting domains — expected, not a data
error); 23.7% of all URLs have a path (42.1% of phishing vs. **0.0%**
of legitimate — confirms fix #9 above was the right call); 5.6% have a
query string.

`datasets/preprocess.py` now builds a **domain-disjoint split** by
default (`GroupShuffleSplit` grouped by registrable domain, with known
shared-hosting platforms grouped by full host instead — see
`SHARED_HOSTING_SUFFIXES` — so `evil.weebly.com` and `other.weebly.com`
can still land on different sides while `google.com`'s 7,767 URLs
cannot straddle train/test). The split is verified in code to share
zero groups across train/val/test before anything is written; it
aborts rather than write a leaking split. The old random split is
still available (`--also-random`) purely so the two can be compared
head-to-head:

```bash
python -m datasets.preprocess --also-random --also-temporal
python -m training.train_baselines
```

**Honest result:** for these 19 host/scheme-only features, domain-disjoint
vs. random splitting changed accuracy by only ~0.2-1.6 points (Random
Forest 89.98% domain-disjoint vs. 90.20%-when-random-trained-then-
domain-disjoint-tested; XGBoost 89.26% vs. 90.86%). That's a small,
honest gap, not a dramatic one — because fix #9 already removed the
path/query features that were the real memorization risk. The value of
this change isn't a big number swing; it's that the reported numbers
are now provably leakage-free, and it matters more as URL-string-level
features (the Transformer branch) or more granular hostnames are added
later. Full before/after numbers, per model, per split, are in
`artifacts/old_vs_new_comparison.csv` and `artifacts/model_metadata.json`.

**Temporal holdout** (train on older PhishTank submissions, test on
newer ones — a zero-day proxy): Random Forest 89.96% accuracy / 0.860
F1, in line with the domain-disjoint number, i.e. no evidence of
temporal decay in this snapshot. Caveat: only the phishing class has
real timestamps (PhiUSIIL carries none), so this measures "does the
model still catch newer real phishing" and not full temporal drift in
legitimate-site structure — see `build_temporal_split()` docstring.

**Hard negatives** (`datasets/hard_negatives.csv` — 66 real, hand-
verified URLs: `accounts.google.com/signin`, `github.com/login`,
`www.chase.com/personal/credit-cards`, `www.irs.gov/payments`, and
similar login/account/payment pages across banks, universities, cloud
providers, government sites, and SaaS, chosen because no larger real
legitimate-deep-link dataset or live crawl was available in this
environment — fabricating more would violate the no-synthetic-data
rule): **false-positive rate 8.9%-20.9% depending on model** (RF/XGB
8.96%, SVM 20.9%). This is real signal, not test noise: several of
these real login subdomains (`secure01a.chase.com`,
`connect.secure.wellsfargo.com`, `login.microsoftonline.com`) contain
tokens (`secure`, `login`) that the host-level `suspicious_word_count`
feature was designed to catch on *attacker* domains, and it doesn't yet
distinguish "brand's own known subdomain" from "lookalike domain" at
the classical-feature level (the dedicated brand-impersonation check in
`url_features.py`'s `_brand_token_count` only looks at SLD-embedding and
subdomain-in-front-of-unrelated-domain patterns, not this case). Recorded
here as a genuine, unresolved limitation — see below — rather than
patched by adding these 66 domains as hardcoded exceptions, which
would just move the shortcut rather than fix it.

**Threshold selection**: `training/train_baselines.py` now picks three
operating points per model on validation data only (never on any test
set), then locks the "balanced" (max-F1) threshold before evaluating.
High-precision and high-recall thresholds are recorded in
`artifacts/model_metadata.json` for anyone who wants to trade recall
for a near-zero false-positive rate or vice versa in production.

## Infrastructure graph now includes real subdomains (this pass)

`app/services/graph_service.py` gathered Certificate Transparency
evidence (`app/collectors/certificate.py`, via crt.sh) but never used
it to build graph nodes — the graph showed DOMAIN/IP/ASN/REGISTRAR/
NAMESERVER/TLS-CERTIFICATE only, no subdomains, even though the raw
CT data (which subdomains actually had a certificate issued for them)
was already being fetched and thrown away. Fixed: `build_graph()` now
parses every CT log entry's SAN names, keeps only real subdomains of
the investigated registrable domain (drops wildcards, drops unrelated
domains that happen to share a multi-domain cert), de-duplicates, caps
at 20, and adds them as a new `SUBDOMAIN` node type (frontend:
`lib/types.ts`, `components/infrastructure-graph.tsx`) with an edge to
the target domain. A subdomain containing a login/verify/secure-style
token is flagged `risk: medium` in the graph, same idea as the
existing brand-impersonation check. Verified end-to-end with a mocked
crt.sh response (see "Sandboxed development environment" below for
why it's mocked, not live, in this pass):

```
Subdomain nodes found: 4
 - api.github.com   | risk: None
 - gist.github.com  | risk: None
 - pages.github.com | risk: None
 - www.github.com   | risk: None
```
`login.microsoftonline.com`, `*.github.io`, and `secure-github.com`
(all present in the mock CT response, none of them real subdomains of
`github.com`) were correctly excluded — the last one in particular is
exactly the kind of lookalike-domain-on-a-shared-cert case this needed
to get right.

## Sandboxed development environment (read this before trusting any "live" claim)

This pass was built and tested inside Anthropic's coding sandbox, which
has real constraints worth knowing if you're deciding what to trust as
"verified live" vs. "verified against real data but not live-tested
here":

- **Plain DNS resolution genuinely works** in this sandbox (real A/NS
  records were resolved live against `github.com` while building
  this) — `app/collectors/dns.py` is verified working end-to-end.
- **crt.sh (Certificate Transparency) and rdap.org are blocked** by
  this sandbox's outbound egress proxy (HTTP 403, not a code bug) — so
  `certificate.py` and `rdap.py` could not be live-tested here. The
  subdomain-graph fix above was verified against a realistic *mocked*
  CT response instead.
- **The TLS collector (`app/collectors/tls.py`) is actively
  MITM'd inside this sandbox**: a raw socket connection to
  `github.com:443` here returns a certificate issued by "Egress
  Gateway SDS Issuing CA, O=Anthropic" — not GitHub's real
  certificate. This is Anthropic's sandbox intercepting all outbound
  TLS, not a bug in this project. It means: never trust TLS-collector
  output that was generated by running this code inside a Claude
  coding-sandbox session — it will report Anthropic's proxy cert, not
  the real one, for every domain.
- None of this affects you running the app normally on your own
  machine with a normal internet connection — DNS, RDAP, TLS, and CT
  all use standard outbound connections with no special requirements,
  and the code paths themselves are real (not mocked/stubbed). It only
  affects what could be *verified live* from within this specific
  development session.
- This is also why the GNN still cannot be trained on a real
  infrastructure graph from this session (Phase 8 of the original
  spec) — building that training set needs exactly the RDAP/CT
  collection that's blocked here, at bulk scale, across the training
  corpus. Run `python -m training.train_gnn --live` on your own
  machine to do this for real.

## Training the models

```bash
# 1. Build the historical corpus from datasets/historical_sources/
python -m datasets.build_training_corpus

# 2. (Optional) Snapshot whatever's currently live-synced too
python -m datasets.export_raw

# 3. Combine + split
python -m datasets.preprocess                    # full corpus (443k rows) -- baselines
python -m datasets.preprocess --sample-size 6000  # stratified sample -- semantic/GNN/hybrid

# 4. Train
python -m training.train_baselines    # RF/XGBoost/SVM -- run against the full-corpus split
python -m training.train_semantic     # Transformer-only -- run against the sampled split
python -m training.train_gnn          # GNN-only (--live for real infra graphs instead of synthetic)
python -m training.train_hybrid       # full fusion model
python -m training.evaluate           # consolidates into artifacts/ablation_comparison.csv

# Optional, separate benchmark (not part of the app's training data):
python -m training.evaluate_uci_baseline
```

**Why two different preprocess runs?** RF/XGBoost handle the full
443k-row real corpus fine (a few minutes). SVM's RBF kernel doesn't
scale past ~20k rows, so `train_baselines.py` subsamples just for
SVM. The Transformer/GNN/fusion training loops in this project are
simple per-sample loops (no batching), so a full 443k-row run would
take hours — `--sample-size 6000` keeps it to a few minutes while
still being a stratified sample of the same real corpus. Removing
this limitation (adding batched training) is the natural next
improvement if you have GPU time to spend.

### Results actually achieved on this real data

From `artifacts/ablation_comparison.csv` (test set, held out from
training):

| Model | Accuracy | F1 | ROC-AUC |
|---|---|---|---|
| Random Forest | 0.900 | 0.864 | 0.932 |
| XGBoost | 0.905 | 0.868 | 0.941 |
| SVM | 0.869 | 0.822 | 0.887 |
| Transformer-only | 0.879 | 0.819 | 0.927 |
| GNN-only | 0.609 | 0.000 | 0.500 |
| **Hybrid (fusion)** | **0.936** | **0.911** | **0.972** |

These are lower still than the pass reported in an earlier version of
this README (~94.7-95.9%), for the same reason as before, one level
deeper: `num_params` (query-string presence) turned out to carry the
identical bias as the path features already removed — see "Feature
set narrowed to host/scheme only" above. Recall in particular is now
honest rather than inflated (~75-83% depending on model, vs. the
high-90s that came from a feature that was really just detecting
"which dataset did this row come from"). This is the trade for a
model that doesn't confidently misclassify a real login page.

GNN-only sits at chance (ROC-AUC 0.5) because `train_gnn.py` defaults
to **synthetic infrastructure graphs** (a deterministic hash of the
hostname) rather than real DNS/RDAP/TLS/CT collection per training
URL — collecting real infrastructure graphs for hundreds of thousands
of training URLs needs sustained unrestricted network access and
takes a long time. Run `python -m training.train_gnn --live` (then
retrain `train_hybrid.py`) on a machine with normal internet access
for genuine structural signal. The fusion layer still improves over
either branch alone even with a synthetic graph branch, because the
aux hand-crafted URL features and the (real) semantic branch carry
the real signal.

Once trained, restart the API and check `/api/health`:
```json
{"status": "ok", "baselines_loaded": true, "hybrid_loaded": true}
```

**Model versioning**: every `train_baselines.py` run writes
`artifacts/model_metadata.json` — training date, feature version,
split strategy, random seed, per-model thresholds, and every
evaluation (domain-disjoint/random/temporal/hard-negative) with full
metrics and confusion matrices. Treat it as the source of truth for
"what's actually deployed right now"; `artifacts/old_vs_new_comparison.csv`
is the flat-table version of the same data for spreadsheet use.

## Two signals: ML + real-time threat intelligence

Every investigation combines two independent signals rather than
relying on the ML model alone:

- **Signal A (ML)**: does this URL structurally/semantically look
  like phishing? (`app/models/classifier.py`)
- **Signal B (threat intel)**: has this exact URL or domain already
  been observed on PhishTank or OpenPhish? (`app/services/threat_intel_service.py`)

A verified feed match is treated as ground truth and wins outright —
no ML score can talk a confirmed phish back down to "clean"
(`investigation_service._combine_signals`). This is tested: seeding a
fake verified PhishTank match for an otherwise-clean-looking domain
correctly forces the verdict to malicious, with a finding explaining
why.

### Real-time feed sync (PhishTank + OpenPhish)

`app/scheduler.py` runs both feeds on a schedule (`APScheduler`,
configurable via `PHISHTANK_SYNC_INTERVAL_MINUTES` /
`OPENPHISH_SYNC_INTERVAL_MINUTES` in `.env`) so `ThreatIntelRecord`
stays current with **no manual dataset uploads**. An immediate sync
also fires on startup (`SYNC_ON_STARTUP=true`) so a fresh install has
data within seconds rather than waiting a full interval. A manual
trigger is also available for demos: `POST /api/threat-intelligence/sync`.

No credentials are hardcoded — `PHISHTANK_APP_KEY` and
`OPENPHISH_API_KEY` are optional env vars (see `.env.example`); both
feeds work with no key at all, just a lower PhishTank rate limit.

This sandbox's network is restricted to package registries, so the
actual live sync against `data.phishtank.com`/`openphish.com` could
only be verified against realistic mocked feed responses here (see
"What was tested"), not the real endpoints. It's the same collector
code either way — verify it once against the real feeds when you have
normal network access, same as any other collector in this project.

## What was tested

- `POST/GET /api/investigations`, `GET /api/investigations/{id}`,
  `GET/POST /api/reports`, `GET /api/reports/{id}/download`,
  `GET /api/threat-intelligence/check`, `POST /api/threat-intelligence/sync`,
  `GET /api/threat-intelligence/status`, `/api/health` — all verified
  via `TestClient` returning correctly-shaped responses.
- Signal A + Signal B combination tested end-to-end: seeded a fake
  verified threat-intel match and confirmed the investigation verdict,
  score, rationale, and findings all reflect it correctly.
- Full training pipeline run on the real 443k-row historical corpus;
  all six models trained and evaluated (table above).
- All three fixes above verified together against 8 real sites
  through the actual live investigation pipeline — 8/8 correct
  (see the fix list above for specifics).
- PhishTank CSV and OpenPhish feed parsers unit-tested against
  realistic mocked responses (network to the real feeds is blocked
  from this sandbox; same code path either way).

What was **not** exercised against live network here (should be
re-verified before your demo, same collector code, just untested
against the real endpoint from this sandbox): actual sync against
`data.phishtank.com`/`openphish.com`, and the DNS/RDAP/TLS/HTTP/CT/ASN
evidence collectors against an arbitrary live target URL (they were
tested earlier in this project against `github.com`, `wikipedia.org`,
and similar reachable domains).

## Architecture

```
backend/
├── app/
│   ├── main.py                  FastAPI app, CORS, router + scheduler startup
│   ├── config.py                Settings (env-driven; nothing hardcoded)
│   ├── scheduler.py              APScheduler: automatic PhishTank/OpenPhish sync
│   │
│   ├── api/
│   │   ├── investigations.py
│   │   ├── reports.py
│   │   ├── threat_intelligence.py   /check, /sync, /status
│   │   └── health.py
│   │
│   ├── services/
│   │   ├── investigation_service.py   full POST /investigations flow, Signal A+B fusion
│   │   ├── threat_intel_service.py    sync_phishtank/openphish, check_url
│   │   ├── url_service.py, evidence_service.py, graph_service.py, report_service.py, serializers.py
│   │
│   ├── collectors/
│   │   ├── dns.py, rdap.py, tls.py, http.py, certificate.py, asn.py   (per-investigation evidence)
│   │   └── threat_feeds/
│   │       ├── phishtank.py      live feed CSV parser (env-configurable URL/key)
│   │       └── openphish.py      live feed text parser (env-configurable URL/key)
│   │
│   ├── features/                 url_features.py, text_features.py, graph_features.py
│   ├── models/                   semantic_model.py, gnn_model.py, fusion_model.py, classifier.py
│   ├── schemas/                  investigation.py, threat_intelligence.py
│   └── database/
│       ├── models.py              investigations/evidence/findings/graph/reports/
│       │                          ThreatIntelRecord/FeedSyncRun/Prediction
│       ├── database.py            SQLite by default, Postgres via DATABASE_URL
│       └── repository.py
│
├── datasets/
│   ├── historical_sources/       your uploaded files, verbatim, read-only
│   │   ├── phishtank_online_valid.csv
│   │   ├── phiusiil_phishing_url_dataset2.zip
│   │   └── phishing_websites_dataset1_.zip
│   ├── loaders.py                reads historical_sources/ + UCI baseline + Tranco fallback
│   ├── build_training_corpus.py  historical_sources/ -> datasets/raw/historical_*.csv
│   ├── export_raw.py             live ThreatIntelRecord DB -> datasets/raw/live_*.csv
│   ├── preprocess.py             combines both -> datasets/processed/{train,val,test}.csv
│   ├── raw/, processed/          generated, not shipped (regenerate with the commands above)
│
├── training/
│   ├── train_baselines.py, train_semantic.py, train_gnn.py, train_hybrid.py, evaluate.py
│   └── evaluate_uci_baseline.py  standalone, uses UCI's own features -- not part of the main pipeline
│
├── artifacts/                    trained model files (.pkl / .pt) + result CSVs (real data, see above)
├── docker-compose.yml            Postgres (+ optional containerized API)
├── requirements.txt
├── Dockerfile
└── .env.example
```

## API surface (matches `investigation-service.ts`)

| Method | Path | Frontend call |
|---|---|---|
| `POST` | `/api/investigations` | `createInvestigation(target)` |
| `GET` | `/api/investigations` | `listInvestigations()` |
| `GET` | `/api/investigations/{id}` | `getInvestigation(id)` |
| `GET` | `/api/reports` | `listReports()` |
| `POST` | `/api/reports` | `createReport(id, format)` |
| `GET` | `/api/reports/{id}/download` | file download |
| `GET` | `/api/threat-intelligence/check?url=` | not called by the frontend yet — available for direct use |
| `POST` | `/api/threat-intelligence/sync` | manual feed sync trigger (demo convenience) |
| `GET` | `/api/threat-intelligence/status` | sync history + record counts per source |
| `GET` | `/api/health` | model/readiness check |

The frontend contract (`lib/types.ts`) was not changed — all new
endpoints are additive.

`POST /api/investigations` runs synchronously end-to-end and returns
the completed investigation in one response. For the `queued →
running → complete` polling flow with Redis, wrap the call in a
background job; `investigation_service.run_investigation` doesn't
need to change, only how it's invoked.

## Database

Defaults to SQLite (zero setup). For Postgres:
```bash
docker compose up -d db
# then set in .env: DATABASE_URL=postgresql+psycopg2://phishscan:phishscan@localhost:5432/phishscan
```
Tables: `investigations`, `evidence`, `findings`, `provider_diagnostics`,
`graph_nodes`, `graph_edges`, `timeline_events`, `reports`,
`threat_intel_records`, `feed_sync_runs`, `predictions`.

## Swap-in notes for a stronger research result

- **Real Transformer weights**: swap `SemanticEncoder` for a
  `sentence-transformers`/DistilBERT wrapper if you have internet
  access for the download; the rest of the pipeline only needs
  `embed_url()` to return a fixed-size vector.
- **torch-geometric**: `GraphEncoder` is a manual GCN (no PyG
  dependency). `torch_geometric.nn.GCNConv` is a drop-in replacement
  for `GCNLayer` if you have it installed.
- **Batched neural training**: the current per-sample loops are the
  main scaling limit for using the full 443k-row corpus on the
  Transformer/GNN/fusion models — worth adding if you have GPU time.
- **Neo4j**: not needed at this project's scale (per-investigation
  graphs are a few dozen nodes) — Postgres is sufficient unless you
  need cross-investigation graph queries.
