Output demo.gif
Set FontSize 15
Set Width 1100
Set Height 640
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set TypingSpeed 20ms
Set Framerate 24
Set Padding 18
Set WindowBar Colorful
Set Shell bash
Hide
Type `cd "$REDDOCK_DEMO_HOME"`
Enter
Type `export PATH="$REDDOCK_DEMO_HOME:$PATH"`
Enter
Type `export PS1='demo$ '`
Enter
Type `clear`
Enter
Show

Type `./demo_api.sh version`
Enter
Sleep 1.0s

Type `./demo_api.sh settings`
Enter
Sleep 1.4s

Type `./demo_api.sh create-dockyard`
Enter
Sleep 1.6s

Type `./demo_api.sh add-scope 1 127.0.0.1`
Enter
Sleep 1.4s

Type `./demo_api.sh evaluate 1 127.0.0.1`
Enter
Sleep 2.0s

Type `./demo_api.sh add-scope 1 0.0.0.0/0`
Enter
Sleep 1.6s

Type `./demo_api.sh evaluate 1 169.254.169.254`
Enter
Sleep 2.5s

Sleep 1.2s
