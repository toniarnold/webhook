#!/bin/sh
# execute all commands in debug mock mode
set -x
./webhook.py -md "wake"
./webhook.py -md "suspend"
./webhook.py -md "poweroff"
./webhook.py -md "poweroff_linux"
./webhook.py -md "reboot_linux"
./webhook.py -md "unknown_comand"
