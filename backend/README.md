# Sentinel AI – Backend Stage 1

## Files included
- `backend/main.py`: FastAPI backend with model-status and controlled dataset simulation endpoints.
- `backend/requirements.txt`: Python dependencies.

## Expected project layout
Place the `backend` folder inside your existing `Suspicious-Process-Detection` project.
The following files must remain in the project root (one level above `backend`):

- `hybrid_process_detector.pkl`
- `process_scaler.pkl`
- `Obfuscated-MalMem2022.csv`

## Install and run (PowerShell)
From the project root:

```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

## Test endpoints
Open these URLs in your browser:

- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/api/model-status`
- `http://127.0.0.1:8000/api/processes`
- `http://127.0.0.1:8000/docs`

In `/docs`, use `POST /api/simulate` with one of:

```json
{"threat_type": "Ransomware"}
```

```json
{"threat_type": "Spyware"}
```

```json
{"threat_type": "Trojan"}
```

## Important technical note
`GET /api/processes` reports real Windows process telemetry and deliberately labels processes as `Unclassified`.
`POST /api/simulate` selects a real row from the supplied research dataset, scales its 55 features, and passes it to the trained model. It does not execute malware and is not a live malware scan.

The reported 84.85% accuracy is returned as a README-reported metric; this API does not independently recompute it.
