# Security Implications Flask App

Flask application with SQLite3 for studying security implications of direct user file uploads to cloud storage.

## Features
- Admin and user authentication
- User registration with 6 fields
- Admin dashboard, upload flow, file listing, performance reports, and logs
- User dashboard, profile, search, decrypt-key download, results graphs, and personal logs
- SQLite storage for users, uploads, training metrics, and logs
- UI with attribute color theme, background image, and icons
- `static/css/style.css` and `static/js/charts.js`

## Run
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open: `http://127.0.0.1:5000`

Default admin:
- Username: `admin`
- Password: `admin123`
