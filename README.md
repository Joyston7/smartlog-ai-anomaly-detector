# SMARTLOG — AI Log Anomaly Detector

A full-stack portfolio MVP with FastAPI, a responsive dashboard and an Isolation Forest anomaly detector.

## Run locally (Python 3.10+)
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
Open http://127.0.0.1:8000 and click **Try sample logs** or upload a `.log`, `.txt`, or `.csv` file.

## Deploy on Render
1. Push the project folder to a GitHub repository.
2. In Render choose **New → Blueprint**, connect the repository and deploy the detected `render.yaml` service.
3. Open the generated `onrender.com` URL. Free instances may sleep when idle.

## How detection works
A trained Isolation Forest model scores numerical features extracted from log lines: severity, message length, operational keywords, severity frequency, digit ratio and HTTP 5xx indicators. Critical and error severity entries are also flagged for review. Scores indicate statistical unusualness, not proof of an incident or root cause.

## Limitations & privacy
This is an educational MVP. Its baseline is synthetic; parser support is for common severity labels. Production systems need log-format-specific parsing, representative baseline training, evaluation and alert tuning. Do not upload confidential, personal, credential-bearing or production logs to a public demo.
