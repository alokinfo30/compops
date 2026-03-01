# CompOps Platform - Production Deployment Guide

## Overview
This guide covers deploying the CompOps SBOM Vulnerability Management Platform to production.

## Prerequisites
- Python 3.11+
- SQLite3
- Git
- GitHub Token (for auto-upgrade features)
-(Optional) Ollama for AI-powered reachability analysis

## Local Development Setup

### 1. Clone and Setup
```
bash
git clone <repository-url>
cd compops
```

### 2. Create Virtual Environment
```
bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 3. Install Dependencies
```
bash
pip install -r backend/requirements.txt
```

### 4. Run Development Server
```
bash
cd backend
python app.py
```
Access at: http://localhost:5000

## Production Deployment

### Option 1: Using Gunicorn (Recommended)

#### Windows (using gunicorn)
```
bash
# Install gunicorn (already in requirements.txt)
pip install gunicorn

# Run with gunicorn
cd backend
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Linux/macOS
```
bash
cd backend
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 app:app
```

### Option 2: Using Docker

#### Create Dockerfile
```
dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
COPY frontend ./frontend

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

#### Build and Run
```
bash
docker build -t compops .
docker run -p 5000:5000 -e GITHUB_TOKEN=your_token compops
```

### Option 3: Cloud Deployment (AWS EC2)

#### 1. Launch EC2 Instance
- Ubuntu 22.04 LTS
- t2.micro (free tier) or larger
- Security group: Open port 5000

#### 2. SSH and Setup
```
bash
ssh -i your-key.pem ubuntu@your-ec2-ip

# Install Python and dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv
git clone <repo>
cd compops
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

#### 3. Run with Systemd
```
bash
sudo nano /etc/systemd/system/compops.service
```

```
ini
[Unit]
Description=CompOps Platform
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/compops/backend
Environment="PATH=/home/ubuntu/compops/venv/bin"
Environment="GITHUB_TOKEN=your_github_token"
ExecStart=/home/ubuntu/compops/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```
bash
sudo systemctl enable compops
sudo systemctl start compops
```

#### 4. Setup Nginx Reverse Proxy
```
bash
sudo apt install nginx

sudo nano /etc/nginx/sites-available/compops
```

```
nginx
server {
    listen 80;
    server_name your-ec2-ip;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```
bash
sudo ln -s /etc/nginx/sites-available/compops /etc/nginx/sites-enabled
sudo systemctl restart nginx
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| GITHUB_TOKEN | GitHub personal access token for PR creation | Yes (for auto-upgrade) |
| FLASK_ENV | Set to "production" for production mode | No |
| DATABASE_PATH | Path to SQLite database | No (default: database/sbom.db) |

## Optional: AI Analysis (Ollama)

For AI-powered vulnerability reachability analysis:

```
bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull codellama:7b

# Start Ollama service
ollama serve
```

## Testing the Deployment

```
bash
# Test API endpoints
curl http://localhost:5000/api/projects

# Create a test project
curl -X POST http://localhost:5000/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "test-project", "repo_url": "https://github.com/owner/repo"}'

# Check vulnerabilities
curl http://localhost:5000/api/vulnerabilities
```

## Monitoring & Maintenance

### Logs
```
bash
# Systemd logs
sudo journalctl -u compops -f

# Gunicorn logs
tail -f /home/ubuntu/compops/backend/logs/gunicorn.log
```

### Backup Database
```
bash
cp backend/database/sbom.db backup/sbom-$(date +%Y%m%d).db
```

### Update Application
```
bash
git pull origin main
pip install -r backend/requirements.txt
sudo systemctl restart compops
```

## Security Considerations

1. **Never commit GITHUB_TOKEN** - Use environment variables
2. **Use HTTPS** - Install SSL certificate (Let's Encrypt)
3. **Firewall** - Only allow ports 80, 443, and 22
4. **Regular updates** - Keep dependencies updated
5. **Database backups** - Schedule regular backups

## SSL/HTTPS Setup (Let's Encrypt)

```
bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Free Hosting - Render.com (Easiest!)

### Quick Deploy (No environment variables needed):

1. **Push to GitHub**
```
git add .
git commit -m "Ready for deployment"
git push origin main
```

2. **Deploy on Render**
   - Go to https://render.com
   - Sign up with GitHub
   - Click "New" → "Web Service"
   - Select your repository
   - Build Command: `pip install -r backend/requirements.txt`
   - Start Command: `gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app`
   - Select **Free** tier
   - Click "Deploy Web Service"

3. **Done!** Your app is live at `https://your-app-name.onrender.com`

## Summary

| Step | Command |
|------|---------|
| Install | `pip install -r requirements.txt` |
| Run Dev | `python app.py` |
| Run Prod (Windows) | `python -m waitress --host 0.0.0.0:5000 app:app` |
| Run Prod (Linux) | `gunicorn -w 4 -b 0.0.0.0:5000 app:app` |
| Render | `gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app` |
| Docker | `docker build -t compops . && docker run -p 5000:5000 compops` |
