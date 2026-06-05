"""Core o'lchov mantig'i — TUI'dan mustaqil, alohida ham ishlatsa bo'ladi.

Modullar:
    netinfo   — lokal interfeyslar, default gateway, public IP
    ping      — ICMP ping (lokal + global, IPv6, --watch oqimi), icmplib asosida
    speed     — internet bandwidth (Cloudflare endpointlari, httpx async, warmup)
    topology  — traceroute + LAN host discovery (ping sweep + ARP)
    ports     — TCP port skaner (asyncio connect, stdlib)
    dns       — DNS diagnostika (resolve + serverlar latency taqqoslash)
"""
