"""O'rnatilgan kichik OUI -> vendor jadvali (offline MAC vendor lookup uchun).

Bu IEEE OUI registrining JUDA kichik qism to'plami — uy/ofis tarmoqlarida eng
ko'p uchraydigan ~60 ta vendor. To'liq IEEE bazasi (~30k yozuv) emas; maqsad —
qo'shimcha bog'liqlik va katta fayl yuklamasdan ko'p hostlarni taniб olish.

Kalit — OUI ning birinchi 3 okteti, KATTA harfli hex, ajratuvchisiz (masalan
``"A4B1C2"``). Qiymat — vendor nomi. Bir vendorda bir nechta OUI bo'lishi normal.

Manba: ochiq IEEE MA-L assignment registri (jamoatchilikka ochiq).
"""

from __future__ import annotations

# OUI (aynan 6 ta hex belgi, separatorsiz, UPPER) -> vendor nomi.
OUI_VENDORS: dict[str, str] = {
    # --- Apple ---
    "A4B1C2": "Apple",
    "F0DBE2": "Apple",
    "3C0754": "Apple",
    "8866A5": "Apple",
    "BC9FEF": "Apple",
    "D0817A": "Apple",
    "AC87A3": "Apple",
    # --- Cisco ---
    "00000C": "Cisco",
    "001A2F": "Cisco",
    "0024C4": "Cisco",
    "00264A": "Cisco",
    "F4CFE2": "Cisco",
    "E0D173": "Cisco",
    # --- Cisco Meraki ---
    "0018BB": "Cisco Meraki",
    "E0CB4E": "Cisco Meraki",
    # --- Samsung ---
    "001632": "Samsung",
    "0021D1": "Samsung",
    "5CF6DC": "Samsung",
    "BC851F": "Samsung",
    "E8508B": "Samsung",
    # --- Huawei ---
    "00259E": "Huawei",
    "48435A": "Huawei",
    "70723C": "Huawei",
    "ACE215": "Huawei",
    # --- TP-Link ---
    "50C7BF": "TP-Link",
    "A42BB0": "TP-Link",
    "C006C3": "TP-Link",
    "EC086B": "TP-Link",
    "1027F5": "TP-Link",
    # --- Intel ---
    "001B21": "Intel",
    "3C970E": "Intel",
    "7C7A91": "Intel",
    "A0A8CD": "Intel",
    "E4A471": "Intel",
    # --- Raspberry Pi ---
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    # --- Microsoft ---
    "0017FA": "Microsoft",
    "00125A": "Microsoft",
    "7C1E52": "Microsoft",
    "C83F26": "Microsoft",
    # --- Dell ---
    "00146C": "Dell",
    "F8BC12": "Dell",
    "B8CA3A": "Dell",
    "18DBF2": "Dell",
    # --- HP / Hewlett Packard ---
    "001321": "HP",
    "3CD92B": "HP",
    "9457A5": "HP",
    "70106F": "HP",
    # --- Xiaomi ---
    "286C07": "Xiaomi",
    "640980": "Xiaomi",
    "F8A45F": "Xiaomi",
    "FC64BA": "Xiaomi",
    # --- Hikvision ---
    "4CBD8F": "Hikvision",
    "C0560E": "Hikvision",
    "BCAD28": "Hikvision",
    # --- MikroTik ---
    "4C5E0C": "MikroTik",
    "6C3B6B": "MikroTik",
    "E48D8C": "MikroTik",
    "CC2DE0": "MikroTik",
    # --- Ubiquiti ---
    "0418D6": "Ubiquiti",
    "245A4C": "Ubiquiti",
    "788A20": "Ubiquiti",
    "FCECDA": "Ubiquiti",
    # --- Netgear ---
    "20E52A": "Netgear",
    "A040A0": "Netgear",
    "9CD36D": "Netgear",
    # --- ASUS ---
    "001BFC": "ASUS",
    "2C56DC": "ASUS",
    "AC220B": "ASUS",
    # --- Google ---
    "F4F5E8": "Google",
    "3C5AB4": "Google",
    "DAA119": "Google",
    # --- Amazon ---
    "FCA183": "Amazon",
    "44650D": "Amazon",
    "68543D": "Amazon",
    # --- Sony ---
    "FCF152": "Sony",
    "D8D43C": "Sony",
    # --- LG Electronics ---
    "00E091": "LG Electronics",
    "C4438F": "LG Electronics",
    # --- Espressif (ESP8266/ESP32 IoT) ---
    "240AC4": "Espressif",
    "3C71BF": "Espressif",
    "A4CF12": "Espressif",
    # --- VMware (virtual NIC) ---
    "005056": "VMware",
    "000C29": "VMware",
    # --- Juniper Networks ---
    "3C8AB0": "Juniper",
    "F0A335": "Juniper",
    # --- Aruba (HPE) ---
    "186472": "Aruba",
    "9C1C12": "Aruba",
}
