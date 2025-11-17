#!/bin/bash
# Camera Dashboard Installation Script for Linux/Mac

echo "=== Camera Dashboard Installation ==="
echo ""

# Check Python installation
echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "✓ $PYTHON_VERSION"
else
    echo "✗ Python 3 not found. Please install Python 3.9 or higher."
    exit 1
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d ".venv" ]; then
    echo "✓ Virtual environment already exists"
else
    python3 -m venv .venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo ""
echo "Installing dependencies..."
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi

# Check if database exists
echo ""
echo "Checking database..."
if [ -f "instance/cameras.db" ]; then
    echo "✓ Database already exists"
else
    echo "Creating database..."
    python3 -c "from app import app, db; app.app_context().push(); db.create_all(); print('✓ Database created')"
fi

# Generate secure secret key
echo ""
echo "Generating secure secret key..."
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i.bak "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
echo "✓ Secure secret key generated"

echo ""
echo "=== Installation Complete ==="
echo ""
echo "To start the application:"
echo "  1. Activate virtual environment: source .venv/bin/activate"
echo "  2. Run: python3 app.py"
echo ""
echo "Default login credentials:"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Access the dashboard at: http://localhost:5000"
echo ""
