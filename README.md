# IFTTT Webhook SSL server
[IFTTT](https://ifttt.com/) Webhook SSL server to suspend/wake on lan a Windows-PC.

## Prerequisites

1. Windows ssh server with key authentication to logon, e.g. [Bitvise SSH Server](https://www.bitvise.com/winsshd).
2. [Sysinternals PsShutdown](https://docs.microsoft.com/en-us/sysinternals/downloads/psshutdown) configured to run as administrator.
3. Windows and NIC configured for Wake On Lan (WOL) with a magic packet.
4. Linux server with systemd and Python 3.5+, e.g. a [Raspberry Pi](https://www.raspberrypi.org/learning/hardware-guide/components/raspberry-pi/).
5. Public IP address and name with a valid SSL certificate, a [Let’s Encrypt](https://letsencrypt.org/)  certificate for a DDNS name will do.


## Configuration/Installation

1. Copy the example configuration to `webhook.ini` and fill in your credentials.
2. Test the two commands with `sudo webhook.py -v suspend` and `sudo webhook.py -v wake` without IFTTT connectivity.
3. Create two IFTTT applets with an `if this`-Button Widget and a `then that`-Webhook with method `POST` and Content Type `application/json` and the respective `wake` and `suspend` commands in the `example.json` format.
4. Run the server in verbose mock mode (no communication with the Windows-PC) with `sudo webhook.py -m -v` and check the IFTTT applets.
5. To double check run the server in production mode with just `sudo webhook.py`.
6. Run `sudo make install` to install the `webhook.service` as a system service.
