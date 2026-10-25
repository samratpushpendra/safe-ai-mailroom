# Mailroom agent
```
pip install fastapi "uvicorn[standard]" httpx
export LLM_PROVIDER=openai LLM_BASE_URL=https://api.openai.com/v1 LLM_API_KEY=... LLM_MODEL=gpt-4o-mini
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1      # ONE worker
```
Submit your public HTTPS URL (any path works; no redirects). Keep `DB_PATH` on persistent disk.
Local test: `LLM_PROVIDER=mock uvicorn app:app --workers 1 &` then `python selftest.py`.

All guessed field names are in the CONTRACT ADAPTER block at the top of app.py.
Guards (plain code): evidence must exist in the dossier, no canary/secret strings in any output,
send/update targets must come from the dossier, thin-approval sends are downgraded, model failure => non-executable fallback.
