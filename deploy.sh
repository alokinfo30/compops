#!/bin/bash

# CompOps Platform - Windows/Git Bash Deployment Script
# Optimized for Windows environments using Git Bash

echo "🚀 Starting CompOps Platform Deployment (Windows Compatibility Mode)"

# 1. Install Python dependencies
echo "📦 Installing Python dependencies..."
# Using 'python -m pip' ensures the correct Windows path is used
python -m pip install -r backend/requirements.txt || {
    echo "❌ ERROR: pip failed. Ensure Python is installed and 'Add to PATH' was checked during installation."
    exit 1
}

# 2. Initialize database
echo "🗄️ Initializing database..."
# Create directory if missing and run initial DB setup
mkdir -p backend/database
if [ -f "backend/app.py" ]; then
    python -c "import sys; sys.path.append('backend'); from app import init_db; init_db()" || echo "⚠️ Database initialization skipped (init_db not found in app.py)"
else
    echo "⚠️ backend/app.py not found. Skipping DB init."
fi

# 3. AI Check (Ollama)
echo "🤖 Checking Ollama..."
# On Windows, you must install Ollama via the .exe from ollama.com
if command -v ollama >/dev/null 2>&1; then
    echo "✅ Ollama is detected."
    # Optional: Ensure the model is available
    # ollama pull codellama:7b
else
    echo "❌ ERROR: Ollama not found."
    echo "👉 Please download the Windows installer from: https://ollama.com/download/windows"
fi

# 4. AWS Check
echo "☁️ Checking AWS Infrastructure..."
# AWS CLI must be installed via the Windows MSI installer
if ! command -v aws >/dev/null 2>&1; then
    echo "⚠️ AWS CLI not found. Cloud deployment steps will be skipped."
    echo "👉 Install AWS CLI for Windows: https://aws.amazon.com/cli/"
else
    echo "✅ AWS CLI is ready. Proceeding with configuration checks..."
    # Note: Ensure you have run 'aws configure' before deploying
fi

echo "------------------------------------------------"
echo "✅ Local Environment Preparation Complete!"
echo "------------------------------------------------"
echo ""
echo "To start your backend locally (Development):"
echo "cd backend && python app.py"
echo ""
echo "To start your backend in production (Windows):"
echo "cd backend && python -m waitress --host 0.0.0.0 --port 5000 --threads 4 app:app"
echo ""
echo "To start your backend in production (Linux/macOS):"
echo "cd backend && gunicorn -w 4 -b 0.0.0.0:5000 app:app"
echo ""
echo "🌐 Frontend Access: Open frontend/index.html in your browser"
echo ""
echo "🔗 API Base URL: http://localhost:5000"
