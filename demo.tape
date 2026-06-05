# systop demo — render with charmbracelet/vhs:
#   vhs demo.tape   ->   assets/demo.gif
#
# Install vhs: https://github.com/charmbracelet/vhs
# Requires `systop` on PATH (e.g. `uv tool install . --force`).

Output assets/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

# --- 1. Network info: interfaces, gateway, public IP ---
Type "systop info"
Enter
Sleep 4s

# --- 2. Per-interface bandwidth snapshot ---
Type "systop bw"
Enter
Sleep 4s

# --- 3. TLS certificate check ---
Type "systop tls google.com"
Enter
Sleep 4s

# --- 4. Scriptable JSON output ---
Type "systop tls google.com --json | head -8"
Enter
Sleep 3s

# --- 5. The interactive dashboard ---
Type "systop"
Enter
Sleep 6s

# Toggle theme, then quit the TUI.
Type "d"
Sleep 2s
Type "q"
Sleep 1s
