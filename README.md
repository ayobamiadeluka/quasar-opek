# QUASAR-OPEK NIG LTD — Demo Investment Portal

This is a **demo/prototype** of the requested QUASAR-OPEK website. It does not process real money, connect to a bank/payment gateway, or promise investment returns. Deposits and the ₦2,000 registration fee are represented as demo payment requests that an admin can approve/reject.

## Run on Windows PowerShell

```powershell
cd C:\path\to\quasar_opek_demo
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
python -m uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Demo admin

Use the values from `.env` (or the defaults in `.env.example` after you copy it). Change the admin password before any real deployment.

## Structure

- `app/main.py` — FastAPI routes and SQLite database
- `templates/` — pages
- `static/` — CSS and browser JavaScript
- `.env.example` — configuration template

## Before any real-money launch

Get the appropriate Nigerian legal/regulatory advice for the exact business model, verify the required authorization, and replace demo payment handling with a compliant payment/verification workflow. Do not publish the demo's illustrative return as a guaranteed investment outcome.
