# NEXORA Unified Digital Risk Protection Project

This project combines the NEXORA dashboard, app-risk detection and social-account impersonation detection into one frontend + backend application.

## Project structure

- `frontend/` - React + Vite dashboard
- `backend/` - FastAPI API
- `run_backend.bat` - Windows backend launcher
- `run_frontend.bat` - Windows frontend launcher

## Windows run steps

1. Install Python 3.10+ and Node.js LTS.
2. Open PowerShell in this folder.
3. Backend:
   ```powershell
   cd backend
   python -m pip install -r requirements.txt
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
4. Keep the backend terminal open.
5. Open a second PowerShell:
   ```powershell
   cd frontend
   npm install
   npm run dev
   ```
6. Open `http://localhost:5173/`.

## Main API endpoints

- `GET /health`
- `POST /apps/scan`
- `GET /apps`
- `POST /social/scan`
- `GET /docs`

## Dashboard features

- Brand profiles
- App Risk Scanner connected to `/apps/scan`
- Social Account Scanner connected to `/social/scan`
- Live backend status indicator
- Risk score and reasons display
- Mobile-friendly responsive UI

## Important interpretation

App and social scans are risk assessments based on the project's current local data and comparison logic. They do not prove that an app or account is definitely fake or genuine. For a production-grade detector, connect verified store metadata, package signatures/certificates, developer ownership, live platform data and other trusted sources.

## Instagram public-profile comparison (updated)

The Social Account Scanner now has a **Public Profile Comparison** mode for Profile A and Profile B. Enter the publicly visible username, display name, bio and optional visible counts for each profile. You can also record whether you observed a verification badge or found the profile linked from a known official website. The comparison returns separate heuristic risk indicators, reasons, reported supporting evidence, confidence and explicit limitations.

### Important limitations

- This implementation does **not** log in to Instagram, scrape profile pages, or fetch live profile data. Profile fields, counts, badge observations and official-site-link observations are manually entered and are not independently validated.
- It must not label an account definitely fake or genuine. Without strong external evidence, it returns **Insufficient evidence** or a relative-risk assessment.
- A verification badge, profile similarity, follower counts and suspicious bio wording are signals, not proof. For stronger verification, navigate independently to the person's/organisation's known official website and use the Instagram link published there; do not rely on links sent by the account being checked.
- New endpoint: `POST /social/compare`. Existing `POST /social/scan` remains available.
