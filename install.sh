#!/usr/bin/env bash
# SkillHub - One-Line Installer for Linux / Kali
set -e

INSTALL_DIR="${HOME}/.skillhub"
BIN_PATH="/usr/local/bin/skillhub"

echo "[*] Installing SkillHub..."

# Check prerequisites
command -v git >/dev/null 2>&1 || { echo "[!] git is required. Install with: sudo apt install -y git"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[!] python3 is required. Install with: sudo apt install -y python3"; exit 1; }

# Clone or pull latest
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Updating existing installation at $INSTALL_DIR..."
    git -C "$INSTALL_DIR" pull --quiet
else
    echo "[*] Cloning into $INSTALL_DIR..."
    git clone --depth 1 https://github.com/abhishek1kr/SkillHub.git "$INSTALL_DIR"
fi

chmod +x "$INSTALL_DIR/skillhub.py"

# Symlink to /usr/local/bin
if [ -w "/usr/local/bin" ]; then
    ln -sf "$INSTALL_DIR/skillhub.py" "$BIN_PATH"
else
    echo "[*] Adding symlink to $BIN_PATH (requires sudo)..."
    sudo ln -sf "$INSTALL_DIR/skillhub.py" "$BIN_PATH"
fi

echo "[+] Installation complete! You can now run 'skillhub' from anywhere."
echo ""
skillhub status
