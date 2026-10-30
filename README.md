# DeepfakeGuard backend

1. `pip install -r requirements.txt` (also install **ffmpeg** for audio files)
2. Copy `.env.example` values into your environment (SECRET_KEY, ADMIN_EMAILS, SMTP_*, ALLOWED_ORIGIN)
3. `python app.py` (local) or `gunicorn app:app` (hosting)
4. Put the backend URL in `index.html` (`DEFAULT_API`) or in "Server settings" on the login screen

Without SMTP_HOST the OTP is printed in the server console (development only).
Admins are the emails listed in ADMIN_EMAILS; they see the Admin tab.
