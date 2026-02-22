def block_ip(ip):
    print(f"Blocking IP: {ip}")
    # In real system use firewall command
    # Windows:
    # netsh advfirewall firewall add rule name="BlockIP" dir=in action=block remoteip=IPADDRESS

if __name__ == "__main__":
    from detector import detect_ddos

    attackers = detect_ddos()
    for ip in attackers:
        block_ip(ip)
