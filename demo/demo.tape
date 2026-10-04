# vhs script for gspy demo
Output demo.gif

Require gspy
Require go

Set FontSize 18
Set Width 1200
Set Height 600

# Start target in background
Hide
Type "go build -o target target.go && ./target &"
Enter
Type "TARGET_PID=\$!"
Enter
Sleep 2s
Show

Type "sudo gspy \"
Sleep 1s
Enter

# Show initial view
Sleep 4s

# Filter for network
Type "f"
Sleep 500ms
Type "net"
Sleep 500ms
Enter

Sleep 3s

# Switch to I/O
Type "f"
Sleep 500ms
Backspace 3
Type "io"
Enter

Sleep 3s

# Quit
Type "q"
Sleep 1s

Hide
Type "kill \"
Enter
