#!/bin/sh
# CP-DFIR Investigation Console (Linux / macOS).  Use sudo to include auth.log in live triage.
cd "$(dirname "$0")"
python3 -c "import networkx, Evtx, boto3, psutil, flask, waitress" 2>/dev/null || python3 -m pip install -r requirements.txt
exec python3 webapp/app.py "$@"
