# historical_sources (kept for reference)

Original real-world datasets from the pre-synthetic version of PhishScan:

- `phishtank_online_valid.csv`           PhishTank verified-online export
- `phishing_websites_dataset1_.zip`      UCI Phishing Websites
- `phiusiil_phishing_url_dataset2.zip`   PhiUSIIL Phishing URL dataset

The live API does **not** read this folder, and the primary (synthetic) models
were not trained on it. It is retained so the original pipeline can be re-run:

    python -m datasets.build_training_corpus
    python -m training.train_baselines

Those commands write the *backup* models (`artifacts/rf.pkl`, `xgboost.pkl`,
`svm.pkl`), which take over automatically if the synthetic models are missing
or `USE_SYNTHETIC_MODELS=false`.
