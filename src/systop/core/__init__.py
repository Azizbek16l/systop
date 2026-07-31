"""Core measurement logic — independent of the TUI, usable on its own.

Modules:
    netinfo   — local interfaces, default gateway, public IP
    ping      — ICMP ping (local + global, IPv6, --watch stream), built on icmplib
    speed     — internet bandwidth (Cloudflare endpoints, httpx async, warmup)
    topology  — traceroute + LAN host discovery (ping sweep + ARP)
    ports     — TCP port scanner (asyncio connect, stdlib)
    dns       — DNS diagnostics (resolve + latency comparison across servers)
"""
