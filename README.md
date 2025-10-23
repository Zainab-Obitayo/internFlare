# Internflare Backend (Flask)

Requirements
- Windows with Python 3.10+
- Recommended: use a virtualenv

Setup (Windows PowerShell)
1. cd backend
2. python -m venv .venv
3. .\\.venv\\Scripts\\Activate.ps1
4. pip install -r requirements.txt
5. copy .env .env.local  # edit JWT_SECRET in .env.local for production
6. set DATABASE_URL=sqlite:///internflare.db  (optional)
7. python app.py

Run tests
- pytest

API endpoints
- POST /api/v1/auth/signup  { email, password, name? }
- POST /api/v1/auth/login   { email, password } -> returns access_token
- POST /api/v1/feedback     (Bearer token) { message, rating? }
- GET /api/v1/interns       (Bearer token) list interns
- PUT /api/v1/interns/:id/progress (Bearer token) { progress }

Notes
- This is a minimal scaffold intended for intern collaboration. Extend models, add migrations, and secure secrets for production.

# create project folder
mkdir backend
cd backend

# create & activate venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# install deps
pip install -r requirements.txt

# set env vars for this session (or edit .env)
$env:DATABASE_URL = "sqlite:///internflare.db"
$env:JWT_SECRET = "INTERN_FLARE"

# run the app (app.py creates the DB on first run)
python app.py

# in a separate terminal: run tests
.\.venv\Scripts\Activate.ps1
pytest