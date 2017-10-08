# Makefile for a systemd service installation

.PHONY: install uninstall

install:
	cp webhook.py /etc/network/
	cp webhook.ini /etc/network/
	cp webhook.service /etc/systemd/system 
	systemctl enable webhook.service
	systemctl start webhook.service

uninstall:
	-systemctl stop webhook.service
	-systemctl disable webhook.service
	-rm /etc/systemd/system/webhook.service 
	-rm /etc/network/webhook.ini
	-rm /etc/network/webhook.py
