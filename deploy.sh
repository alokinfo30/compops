#!/bin/bash

# CompOps Platform - Zero-Cost Deployment Script
# Deploys to AWS Free Tier [citation:5][citation:10]

echo "🚀 Starting CompOps Platform Deployment"

# 1. Install dependencies
echo "📦 Installing Python dependencies..."
pip install -r backend/requirements.txt

# 2. Initialize database
echo "🗄️ Initializing database..."
cd backend
python -c "from app import init_db; init_db()"

# 3. Start Ollama for AI (if not running)
echo "🤖 Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull codellama:7b
fi

# 4. Deploy to AWS (requires AWS CLI configured)
echo "☁️ Deploying to AWS..."

# Create EC2 instance (t3.micro - free tier eligible) [citation:5]
aws ec2 run-instances \
    --image-id ami-0c55b159cbfafe1f0 \
    --instance-type t3.micro \
    --key-name compops-key \
    --security-group-ids sg-12345678 \
    --user-data file://user-data.sh \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=CompOpsPlatform}]'

# Deploy frontend to Amplify Hosting (free) [citation:5]
cd ../frontend
aws amplify create-app \
    --name compops \
    --repository https://github.com/alokinfo30/compops \
    --platform WEB \
    --environment-variables '{"REACT_APP_API_URL": "http://your-ec2-ip:5000"}'

# Deploy backend to Elastic Beanstalk (free tier)
cd ../backend
zip -r ../deploy.zip .
aws elasticbeanstalk create-application-version \
    --application-name compops \
    --version-label v1 \
    --source-bundle S3Bucket=compops-deploy,S3Key=deploy.zip

echo "✅ Deployment complete!"
echo "🌐 Frontend: https://compops-platform.amplifyapp.com"
echo "🔌 Backend API: http://your-ec2-ip:5000"