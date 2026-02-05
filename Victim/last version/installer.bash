# Create virtual environment
python -m venv fsociety_env
source fsociety_env/bin/activate  # On Windows: fsociety_env\Scripts\activate

# Install core dependencies
pip install pycryptodome cryptography rsa
pip install pillow pygame qrcode
pip install psutil requests

# Windows-specific additional installs
pip install pywin32 wmi comtypes

# For compilation to executable
pip install pyinstaller nuitka
