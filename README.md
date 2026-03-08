# Manitec Mail

A multi-user webmail client for Zoho Mail360 with PWA support.

## Features

- 🔐 Multi-user authentication
- 📱 Mobile-responsive PWA
- ✉️ Send, receive, reply, forward emails
- 👤 Admin panel for user management
- ⚙️ Password change functionality
- 🚀 Rate limiting and security headers
- 💾 SQLite database per user

## Quick Start

### Local Development

```bash
# 1. Clone and setup
cd manitec_mail
pip install -r requirements.txt

# 2. Copy environment variables
cp .env.example .env
# Edit .env with your Zoho credentials

# 3. Initialize database
python init_users.py
# Follow prompts to create your admin user

# 4. Run the app
uvicorn main:app --reload

# 5. Open http://127.0.0.1:8000
```

### Deploy to Render

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/manitec-mail.git
   git push -u origin main
   ```

2. **Create Web Service on Render**
   - Go to [dashboard.render.com](https://dashboard.render.com)
   - New Web Service → Connect your GitHub repo
   - Settings:
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`

3. **Environment Variables**
   Add these in Render dashboard:
   - `CLIENT_ID` - from Zoho Developer Console
   - `CLIENT_SECRET` - from Zoho Developer Console
   - `REFRESH_TOKEN` - from Zoho OAuth flow

4. **Persistent Database (Optional but Recommended)**
   - Create a Render Disk (Settings → Disks)
   - Mount path: `/opt/render/project/src/data`
   - Set environment variable: `DB_PATH=/opt/render/project/src/data/users.db`

5. **Initialize First User**
   - Use Render Shell:
     ```bash
     python init_users.py
     ```

## Security Features

- ✅ Rate limiting (100 requests/minute per IP)
- ✅ Security headers (HSTS, XSS protection, etc.)
- ✅ Input sanitization
- ✅ Email validation
- ✅ Strong password requirements
- ✅ HTTPS enforcement in production
- ✅ Session-based authentication

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main email client |
| GET/POST | `/login` | Login page |
| GET | `/logout` | Logout |
| GET | `/admin` | Add new users web UI |
| POST | `/admin/add-user` | API to add user |
| GET | `/settings` | Change password UI |
| POST | `/settings/change-password` | API to change password |
| GET | `/me` | Get current user info |
| GET | `/inbox` | List inbox emails |
| GET | `/message/{id}` | Get email content |
| POST | `/send` | Send new email |
| POST | `/reply/{id}` | Reply to email |
| POST | `/forward` | Forward email |
| DELETE | `/message/{id}` | Delete email |

## PWA Installation

Users can install the app on mobile/desktop:
1. Open the app in Chrome/Edge/Safari
2. Click "Add to Home Screen" or "Install App"
3. App works offline for cached pages

## Icons

Replace the placeholder icon in `static/icons/` with your logo:
- Recommended: 192x192 and 512x512 PNGs
- Or edit `static/icons/logo.svg` and convert to PNG

## License

MIT
