#!/bin/bash
echo "Clearing Iptables rules..."
sudo iptables -F
sudo iptables -X
echo "Access cleared!"
