#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════╗
║          EXTRACTION TOTALE LIVEBOX 5 - Version 1.1                    ║
║                                                                        ║
║  Extrait TOUTES les données de votre Livebox Orange en une fois       ║
║  - DHCP IPv4/IPv6 (options 60,77,90,125 / 11,15,16,17)               ║
║  - Infos ONT/GPON (serial, vendor, débit)                            ║
║  - Configuration réseau complète                                      ║
║  - WiFi, Firewall, NAT, QoS, VoIP, IPTV, etc.                        ║
║  - Décodage automatique du FTI Orange                                 ║
║                                                                        ║
║  Auteur  : Claude Sonnet 4.5 + Communauté lafibre.info               ║
║  Version : 1.1                                                         ║
║  Date    : 2026-01-02                                                 ║
║  Licence : Open Source - Usage personnel                              ║
╚═══════════════════════════════════════════════════════════════════════╝
"""

import requests
import json
import sys
from datetime import datetime

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


class LiveboxFullExtractor:
    def __init__(self, host="192.168.1.1", password="admin"):
        self.host = host
        self.url = f"http://{host}/ws"
        self.password = password
        self.context = None
        self.session = requests.Session()

    def auth(self):
        """Authentification"""
        payload = {
            "service": "sah.Device.Information",
            "method": "createContext",
            "parameters": {
                "applicationName": "webui",
                "username": "admin",
                "password": self.password
            }
        }
        headers = {
            "Content-Type": "application/x-sah-ws-4-call+json",
            "Authorization": "X-Sah-Login"
        }

        print(f"[*] Connexion à {self.host}...")
        try:
            r = self.session.post(self.url, headers=headers, json=payload, timeout=10)
            data = r.json()
            if "data" in data and "contextID" in data["data"]:
                self.context = data["data"]["contextID"]
                print(f"[+] Authentifié: {self.context}")
                return True
        except Exception as e:
            print(f"[!] Erreur: {e}")
        return False

    def call(self, service, method, params=None):
        """Appel API"""
        if not self.context:
            return None

        payload = {
            "service": service,
            "method": method,
            "parameters": params or {}
        }
        headers = {
            "Content-Type": "application/x-sah-ws-4-call+json",
            "X-Context": self.context
        }

        try:
            r = self.session.post(self.url, headers=headers, json=payload, timeout=10)
            return r.json()
        except:
            return None

    def extract_everything(self):
        """Extrait TOUT"""
        print("\n" + "="*70)
        print("EXTRACTION TOTALE EN COURS")
        print("="*70)

        all_data = {
            "extraction_date": datetime.now().isoformat(),
            "extraction_host": self.host,
            "extraction_version": "1.1"
        }

        # Liste de TOUS les appels à faire (extraction TOTALE)
        calls = [
            # ═══════════════════════════════════════════════════════════════
            # DEVICE & SYSTEM
            # ═══════════════════════════════════════════════════════════════
            ("DeviceInfo", "get", {}),
            ("DeviceInfo", "getDeviceLog", {}),
            ("DeviceInfo", "getDeviceCapabilities", {}),
            ("System", "get", {}),
            ("DeviceManagement", "get", {}),
            ("MemoryStatus", "get", {}),
            ("ProcessStatus", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # TIME & NTP
            # ═══════════════════════════════════════════════════════════════
            ("Time", "getTime", {}),
            ("NTP", "get", {}),
            ("NTP.Server", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # WAN - Connexion Internet
            # ═══════════════════════════════════════════════════════════════
            ("NMC", "getWANStatus", {}),
            ("NMC", "getWANConfig", {}),
            ("NMC", "getDHCPStatus", {}),
            ("NMC.WANStatus", "get", {}),
            ("NMC.IPv6", "get", {}),
            ("NMC.NetworkConfig", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # DHCP IPv4
            # ═══════════════════════════════════════════════════════════════
            ("NeMo.Intf.data", "getMIBs", {}),
            ("NeMo.Intf.data", "getMIBs", {"mibs": "dhcp"}),
            ("NeMo.Intf.data", "getMIBs", {"mibs": "dhcp", "traverse": "down"}),
            ("NeMo.Intf.data", "get", {}),
            ("DHCPv4", "get", {}),
            ("DHCPv4.Client", "get", {}),
            ("DHCPv4.Server", "get", {}),
            ("DHCPv4.Server.Pool", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # DHCPv6
            # ═══════════════════════════════════════════════════════════════
            ("NeMo.Intf.data", "getMIBs", {"mibs": "dhcpv6"}),
            ("NeMo.Intf.data", "getMIBs", {"mibs": "dhcpv6", "traverse": "down"}),
            ("DHCPv6", "get", {}),
            ("DHCPv6.Client", "get", {}),
            ("DHCPv6.Server", "get", {}),
            ("DHCPv6.Server.Pool", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # DNS
            # ═══════════════════════════════════════════════════════════════
            ("DNS", "get", {}),
            ("DNS.Client", "get", {}),
            ("DNS.Client.Server", "get", {}),
            ("DNS.Relay", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # INTERFACES - Toutes
            # ═══════════════════════════════════════════════════════════════
            # ONT/GPON
            ("NeMo.Intf.veip0", "get", {}),
            ("NeMo.Intf.veip0", "getMIBs", {"mibs": "gpon"}),

            # LAN
            ("NeMo.Intf.lan", "get", {}),
            ("NeMo.Intf.lan", "getLANIP", {}),

            # WAN
            ("NeMo.Intf.wanwan", "get", {}),

            # Ethernet ports
            ("NeMo.Intf.eth0", "get", {}),
            ("NeMo.Intf.eth1", "get", {}),
            ("NeMo.Intf.eth2", "get", {}),
            ("NeMo.Intf.eth3", "get", {}),

            # WiFi interfaces
            ("NeMo.Intf.wl0", "get", {}),  # 2.4 GHz
            ("NeMo.Intf.wl1", "get", {}),  # 5 GHz

            # Bridge
            ("NeMo.Intf.br0", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # WIFI
            # ═══════════════════════════════════════════════════════════════
            ("NMC.Wifi", "get", {}),
            ("NMC.Wifi", "getStats", {}),
            ("WiFi", "get", {}),
            ("WiFi.Radio", "get", {}),
            ("WiFi.SSID", "get", {}),
            ("WiFi.AccessPoint", "get", {}),
            ("WiFi.AccessPoint.Security", "get", {}),
            ("WiFi.AccessPoint.WPS", "get", {}),
            ("WiFi.EndPoint", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # FIREWALL
            # ═══════════════════════════════════════════════════════════════
            ("Firewall", "get", {}),
            ("Firewall", "getPortForwarding", {}),
            ("Firewall", "getDMZ", {}),
            ("Firewall", "getIPv6Firewall", {}),
            ("Firewall", "getPingResponder", {}),
            ("Firewall.Level", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # NAT
            # ═══════════════════════════════════════════════════════════════
            ("NAT", "get", {}),
            ("NAT", "getPortMappings", {}),
            ("UPnP", "get", {}),
            ("UPnP.Device", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # ROUTING
            # ═══════════════════════════════════════════════════════════════
            ("Routing", "get", {}),
            ("Routing.Router", "get", {}),
            ("Routing.Router.IPv4Forwarding", "get", {}),
            ("Routing.Router.IPv6Forwarding", "get", {}),
            ("Routing.RouteInformation.InterfaceSetting", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # QoS
            # ═══════════════════════════════════════════════════════════════
            ("QoS", "get", {}),
            ("QoS.Classification", "get", {}),
            ("QoS.Queue", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # VoIP (si configuré)
            # ═══════════════════════════════════════════════════════════════
            ("VoiceService", "get", {}),
            ("VoiceService.VoiceProfile", "get", {}),
            ("VoiceService.VoiceProfile.Line", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # IPTV (si configuré)
            # ═══════════════════════════════════════════════════════════════
            ("IPTV", "get", {}),
            ("IPTV.MulticastChannel", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # USB
            # ═══════════════════════════════════════════════════════════════
            ("USBHost", "get", {}),
            ("USBHost.Device", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # DIAGNOSTICS
            # ═══════════════════════════════════════════════════════════════
            ("TopologyDiagnostics", "buildTopology", {"SendXmlFile": False}),
            ("IPPing", "get", {}),
            ("TraceRoute", "get", {}),
            ("DownloadDiagnostics", "get", {}),
            ("UploadDiagnostics", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # HOSTS & DEVICES
            # ═══════════════════════════════════════════════════════════════
            ("Hosts", "getDevices", {}),
            ("Hosts", "get", {}),
            ("Hosts.Host", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # USER INTERFACE & REMOTE ACCESS
            # ═══════════════════════════════════════════════════════════════
            ("UserInterface", "getInfo", {}),
            ("UserInterface", "get", {}),
            ("RemoteAccess", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # SCHEDULER
            # ═══════════════════════════════════════════════════════════════
            ("Scheduler", "get", {}),
            ("Scheduler.ScheduledRule", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # PARENTAL CONTROL
            # ═══════════════════════════════════════════════════════════════
            ("ParentalControl", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # DYNDNS
            # ═══════════════════════════════════════════════════════════════
            ("DynamicDNS", "get", {}),
            ("DynamicDNS.Client", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # STORAGE & DLNA
            # ═══════════════════════════════════════════════════════════════
            ("Storage", "get", {}),
            ("DLNA", "get", {}),

            # ═══════════════════════════════════════════════════════════════
            # AUTRES SERVICES
            # ═══════════════════════════════════════════════════════════════
            ("LED", "get", {}),
            ("PPP", "get", {}),
            ("PPP.Interface", "get", {}),
        ]

        total = len(calls)
        for i, (service, method, params) in enumerate(calls, 1):
            key = f"{service}.{method}"
            if params:
                key += f"({json.dumps(params, sort_keys=True)})"

            print(f"  [{i}/{total}] {service}.{method}...", end=" ")

            result = self.call(service, method, params)

            if result:
                # Vérifier si erreur
                if "errors" in result and result["errors"]:
                    error = result["errors"][0].get("description", "Unknown")
                    print(f"✗ {error}")
                    all_data[key] = {"_error": error, "_raw": result}
                else:
                    print("✓")
                    all_data[key] = result
            else:
                print("✗ No response")
                all_data[key] = {"_error": "No response"}

        # Générer le résumé des appels API pour le JSON
        api_summary = []
        for key in sorted(all_data.keys()):
            if key in ["extraction_date", "extraction_host", "extraction_version", "_api_summary"]:
                continue

            # Parser le nom
            parts = key.split(".")
            service = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
            method = parts[-1].split("(")[0] if len(parts) > 0 else ""

            # Statut
            if isinstance(all_data[key], dict):
                if "_error" in all_data[key]:
                    status = "error"
                    error = all_data[key]["_error"]
                else:
                    status = "success"
                    error = None
            else:
                status = "unknown"
                error = None

            api_summary.append({
                "service": service,
                "method": method,
                "status": status,
                "error": error
            })

        all_data["_api_summary"] = api_summary

        return all_data


def main():
    print("╔" + "═"*68 + "╗")
    print("║" + " "*15 + "EXTRACTION TOTALE LIVEBOX 5 - v1.0" + " "*18 + "║")
    print("╚" + "═"*68 + "╝")
    print()
    print("Ce script va extraire TOUTES les données possibles de la Livebox :")
    print("  • Device & System")
    print("  • DHCP (IPv4 + IPv6) - Options 60,77,90,125 / 11,15,16,17")
    print("  • Interfaces (ONT, LAN, WAN, Ethernet, WiFi)")
    print("  • Firewall & NAT")
    print("  • Routing & QoS")
    print("  • VoIP & IPTV")
    print("  • DNS, NTP, USB, Diagnostics")
    print("  • Et bien plus encore...")
    print()
    print("⚠️  Cela peut prendre 2-5 minutes (~97 appels API).")
    print()
    print("=" * 70)
    print()

    # Demander l'IP de la Livebox
    ip_input = input("Adresse IP de la Livebox [192.168.1.1]: ").strip()
    livebox_ip = ip_input if ip_input else "192.168.1.1"

    # Demander le mot de passe
    password = input("Mot de passe admin [admin]: ").strip() or "admin"

    print()

    extractor = LiveboxFullExtractor(host=livebox_ip, password=password)

    if not extractor.auth():
        print("\n[!] Échec authentification")
        print("[!] Vérifiez :")
        print("    - L'IP de la Livebox (ping test)")
        print("    - Le mot de passe admin")
        print("    - Que la Livebox est bien allumée et connectée")
        return

    # Extraction complète
    data = extractor.extract_everything()

    # Sauvegarder en JSON brut
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"livebox_FULL_extraction_{timestamp}.json"

    print("\n" + "="*70)
    print("💾 SAUVEGARDE")
    print("="*70)

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Extraction complète sauvegardée : {filename}")

    # Statistiques
    total_calls = len([k for k in data.keys() if k not in ["extraction_date", "extraction_host", "extraction_version"]])
    success = len([v for v in data.values() if isinstance(v, dict) and "_error" not in v])
    errors = total_calls - success

    print(f"\n📊 Statistiques :")
    print(f"   Total appels : {total_calls}")
    print(f"   Succès       : {success}")
    print(f"   Erreurs      : {errors}")

    # Chercher les données importantes
    print("\n🔍 Données trouvées :")

    # DHCP IPv4
    if any("dhcp" in k.lower() and "SentOption" in str(v) for k, v in data.items()):
        print("   ✅ Options DHCP IPv4 (SentOption)")
    else:
        print("   ❌ Options DHCP IPv4 manquantes")

    # DHCPv6
    if any("dhcpv6" in k.lower() and "SentOption" in str(v) for k, v in data.items()):
        print("   ✅ Options DHCPv6 (SentOption)")
    else:
        print("   ⚠️  Options DHCPv6 à vérifier")

    # ONT
    if any("veip0" in k.lower() for k, v in data.items()):
        print("   ✅ Informations ONT")

    # WAN
    if any("WANStatus" in k for k, v in data.items()):
        print("   ✅ Statut WAN")

    # Générer le rapport lisible
    print("\n📝 Génération du rapport lisible...")
    md_filename = generate_readable_report(data, timestamp)

    print("\n" + "="*70)
    print("✨ EXTRACTION TERMINÉE")
    print("="*70)
    print()
    print(f"📄 Fichier JSON brut : {filename}")
    print(f"📖 Rapport lisible   : {md_filename}")
    print()
    print("Ouvrez le fichier .md pour voir toutes les données formatées !")
    print()
    input("Appuyez sur Entrée pour quitter...")


def format_table_row(columns, widths):
    """Formate une ligne de tableau Markdown avec alignement"""
    parts = []
    for i, col in enumerate(columns):
        col_str = str(col)
        # Calculer le padding en tenant compte du markdown
        visible_len = len(col_str.replace("**", ""))
        padding = widths[i] - visible_len
        parts.append(col_str + " " * padding)
    return "| " + " | ".join(parts) + " |"


def format_table_separator(widths):
    """Génère la ligne de séparation du tableau"""
    parts = ["-" * w for w in widths]
    return "| " + " | ".join(parts) + " |"


def generate_readable_report(data, timestamp):
    """Génère un rapport markdown lisible"""
    filename = f"livebox_RAPPORT_{timestamp}.md"

    md = []
    md.append("# Extraction complète Livebox Orange")
    md.append("")
    md.append(f"**Date :** {data.get('extraction_date', 'N/A')}")
    md.append(f"**Host :** {data.get('extraction_host', 'N/A')}")
    md.append(f"**Version :** {data.get('extraction_version', 'N/A')}")
    md.append("")
    md.append("---")
    md.append("")

    # Device Info
    device_keys = [k for k in data.keys() if k.startswith("DeviceInfo.get")]
    if device_keys and "status" in data[device_keys[0]]:
        device = data[device_keys[0]]["status"]
        md.append("## 📦 Informations appareil")
        md.append("")

        # Extraire le FTI depuis l'option DHCP 90
        fti_value = "N/A"
        dhcp_opt_keys = [k for k in data.keys() if "dhcp" in k.lower() and "getMIBs" in k]
        for key in dhcp_opt_keys:
            if "status" in data[key] and "dhcp" in data[key]["status"]:
                dhcp_opt_data = data[key]["status"]["dhcp"].get("dhcp_data", {})
                if "SentOption" in dhcp_opt_data and "90" in dhcp_opt_data["SentOption"]:
                    try:
                        hex_data = dhcp_opt_data["SentOption"]["90"]["Value"]
                        fti_marker = "6674692f"  # "fti/" en hex
                        if fti_marker in hex_data:
                            idx = hex_data.index(fti_marker)
                            if idx >= 2:
                                length_hex = hex_data[idx-2:idx]
                                length = int(length_hex, 16)
                                fti_hex = hex_data[idx:idx + length * 2]
                                fti_bytes = bytes.fromhex(fti_hex)
                                # Filtrer : garder seulement alphanumériques + '/' après "fti/"
                                fti_value = ''
                                for b in fti_bytes:
                                    c = chr(b)
                                    if c.isalnum() or c == '/':
                                        fti_value += c
                                    else:
                                        break  # Arrêter au premier caractère bizarre
                    except:
                        pass
                    break

        device_rows = [
            ["Modèle", device.get('ModelName', 'N/A')],
            ["Classe produit", device.get('ProductClass', 'N/A')],
            ["Numéro de série", device.get('SerialNumber', 'N/A')],
            ["Version logicielle", device.get('SoftwareVersion', 'N/A')],
            ["MAC Address", f"**{device.get('BaseMAC', 'N/A')}**"],
            ["FTI Orange", f"**{fti_value}**"]
        ]

        device_headers = ["Paramètre", "Valeur"]
        device_widths = [len(h) for h in device_headers]
        for row in device_rows:
            for i, cell in enumerate(row):
                cell_len = len(str(cell).replace("**", ""))
                device_widths[i] = max(device_widths[i], cell_len)

        md.append(format_table_row(device_headers, device_widths))
        md.append(format_table_separator(device_widths))
        for row in device_rows:
            md.append(format_table_row(row, device_widths))
        md.append("")

    # WAN Status
    wan_key = [k for k in data.keys() if "getWANStatus" in k]
    if wan_key and "data" in data[wan_key[0]]:
        wan = data[wan_key[0]]["data"]
        md.append("## 🌐 Statut WAN")
        md.append("")

        # Extraire DNS IPv4 (seulement les 2 premiers si multiples)
        dns_servers = wan.get('DNSServers', 'N/A')
        if dns_servers and dns_servers != 'N/A':
            dns_list = [d.strip() for d in dns_servers.split(',')]
            # Séparer IPv4 et IPv6
            dns_ipv4 = [d for d in dns_list if ':' not in d]
            dns_ipv6 = [d for d in dns_list if ':' in d]
            dns_ipv4_str = ', '.join(dns_ipv4[:2]) if dns_ipv4 else 'N/A'
            dns_ipv6_str = ', '.join(dns_ipv6[:2]) if dns_ipv6 else wan.get('IPv6DNSServers', 'N/A')
        else:
            dns_ipv4_str = 'N/A'
            dns_ipv6_str = wan.get('IPv6DNSServers', 'N/A')

        wan_rows = [
            ["État", wan.get('WanState', 'N/A')],
            ["IP IPv4", wan.get('IPAddress', 'N/A')],
            ["Gateway IPv4", wan.get('RemoteGateway', 'N/A')],
            ["DNS IPv4", dns_ipv4_str],
            ["IP IPv6", wan.get('IPv6Address', 'N/A')],
            ["Préfixe IPv6", wan.get('IPv6DelegatedPrefix', 'N/A')],
            ["DNS IPv6", dns_ipv6_str]
        ]

        wan_headers = ["Paramètre", "Valeur"]
        wan_widths = [len(h) for h in wan_headers]
        for row in wan_rows:
            for i, cell in enumerate(row):
                cell_len = len(str(cell).replace("**", ""))
                wan_widths[i] = max(wan_widths[i], cell_len)

        md.append(format_table_row(wan_headers, wan_widths))
        md.append(format_table_separator(wan_widths))
        for row in wan_rows:
            md.append(format_table_row(row, wan_widths))
        md.append("")

    # ONT Info - Déplacé avant les options DHCP
    ont_key = [k for k in data.keys() if "veip0" in k]
    if ont_key and "status" in data[ont_key[0]]:
        ont = data[ont_key[0]]["status"]
        md.append("## 🔌 Informations ONT/GPON")
        md.append("")

        ont_rows = [
            ["Numéro de série", ont.get('SerialNumber', 'N/A')],
            ["Hardware Version", ont.get('HardwareVersion', 'N/A')],
            ["Vendor ID", ont.get('VendorId', 'N/A')],
            ["Equipment ID", ont.get('EquipmentId', 'N/A')],
            ["ONT Software Version 0", ont.get('ONTSoftwareVersion0', 'N/A')],
            ["ONT Software Version 1", ont.get('ONTSoftwareVersion1', 'N/A')],
            ["État GPON", ont.get('ONUState', 'N/A')],
            ["Débit down", f"{ont.get('DownstreamCurrRate', 0) // 1000} Mbps"],
            ["Débit up", f"{ont.get('UpstreamCurrRate', 0) // 1000} Mbps"]
        ]

        ont_headers = ["Paramètre", "Valeur"]
        ont_widths = [len(h) for h in ont_headers]
        for row in ont_rows:
            for i, cell in enumerate(row):
                cell_len = len(str(cell).replace("**", ""))
                ont_widths[i] = max(ont_widths[i], cell_len)

        md.append(format_table_row(ont_headers, ont_widths))
        md.append(format_table_separator(ont_widths))
        for row in ont_rows:
            md.append(format_table_row(row, ont_widths))
        md.append("")

    # DHCP IPv4 Options
    dhcp_keys = [k for k in data.keys() if "dhcp" in k.lower() and "getMIBs" in k]
    for key in dhcp_keys:
        if "status" in data[key] and "dhcp" in data[key]["status"]:
            dhcp_data = data[key]["status"]["dhcp"]["dhcp_data"]
            if "SentOption" in dhcp_data:
                md.append("## 🔐 Options DHCP IPv4")
                md.append("")

                # VLAN & QoS/CoS extraits de la Livebox
                nemo_data_key = [k for k in data.keys() if k == "NeMo.Intf.data.getMIBs"]
                if nemo_data_key and "status" in data[nemo_data_key[0]]:
                    nemo_status = data[nemo_data_key[0]]["status"]

                    # Tableau VLAN - Tous les VLANs configurés
                    if "vlan" in nemo_status:
                        vlan_data = nemo_status["vlan"]
                        md.append("### 🏷️ Configuration VLAN Orange")
                        md.append("")

                        # Mapping des VLANs connus Orange
                        vlan_services = {
                            "gvlan_data": "Internet/Data",
                            "gvlan_multi": "TV/Multicast",
                            "gvlan_voip": "VoIP/Téléphonie",
                            "gvlan_iptv1": "IPTV 1",
                            "gvlan_iptv2": "IPTV 2"
                        }

                        # Collecter les données du tableau
                        vlan_rows = []
                        for vlan_name, vlan_info in sorted(vlan_data.items()):
                            if isinstance(vlan_info, dict):
                                vlan_id = vlan_info.get("VLANID", "N/A")
                                vlan_prio = vlan_info.get("VLANPriority", "N/A")
                                service = vlan_services.get(vlan_name, "Autre")
                                vlan_rows.append([vlan_name, service, f"**{vlan_id}**", str(vlan_prio), "✅"])

                        # Calculer largeurs des colonnes
                        headers = ["Interface", "Service", "VLAN ID", "Priority", "État"]
                        widths = [len(h) for h in headers]
                        for row in vlan_rows:
                            for i, cell in enumerate(row):
                                # Enlever le markdown ** pour calculer la largeur
                                cell_len = len(cell.replace("**", ""))
                                widths[i] = max(widths[i], cell_len)

                        # Générer le tableau
                        md.append(format_table_row(headers, widths))
                        md.append(format_table_separator(widths))
                        for row in vlan_rows:
                            md.append(format_table_row(row, widths))

                        md.append("")
                        md.append("**ℹ️ VLANs Orange standards :** 832 (Internet), 838 (VoIP), 840 (TV)")
                        md.append("")

                    # Priorités CoS/DHCP extraites
                    dhcp_mibs_key = [k for k in data.keys() if "dhcp" in k.lower() and "getMIBs" in k and "traverse" not in k]
                    dhcp_priority = None
                    dhcp_dscp = None

                    for dhcp_key in dhcp_mibs_key:
                        if "status" in data[dhcp_key] and "dhcp" in data[dhcp_key]["status"]:
                            dhcp_status = data[dhcp_key]["status"]["dhcp"]
                            if "dhcp_data" in dhcp_status:
                                dhcp_info = dhcp_status["dhcp_data"]
                                dhcp_priority = dhcp_info.get("PriorityMark")
                                dhcp_dscp = dhcp_info.get("DSCPMark")
                                break

                    # Priorités 802.1p (CoS) - Pour chaque VLAN bcmvlan
                    if "bcmvlan" in nemo_status:
                        md.append("### 📊 Priorités 802.1p (CoS) configurées par Orange")
                        md.append("")

                        # Collecter les données du tableau
                        cos_rows = []

                        # DHCP (extrait des données DHCP)
                        if dhcp_priority is not None:
                            cos_rows.append(["DHCP", "UDP 67/68", f"**{dhcp_priority}**", str(dhcp_dscp) if dhcp_dscp else "N/A", "✅"])

                        # Parcourir tous les VLANs bcmvlan
                        for vlan_name, vlan_bcm_data in nemo_status["bcmvlan"].items():
                            if isinstance(vlan_bcm_data, dict) and "QoS" in vlan_bcm_data:
                                qos_data = vlan_bcm_data["QoS"]

                                # Afficher toutes les règles QoS de ce VLAN
                                for rule_name, rule_info in sorted(qos_data.items()):
                                    if isinstance(rule_info, dict) and rule_info.get("Enable"):
                                        pbits = rule_info.get("SetPbits", -1)
                                        if pbits >= 0:  # Seulement si CoS défini
                                            ethertype = rule_info.get("FilterEthertype", 0)
                                            protocol = "ARP (0x0806)" if ethertype == 2054 else f"Ethertype 0x{ethertype:04x}" if ethertype else "Tous"

                                            # Nom de service convivial
                                            service_name = {
                                                "arp_tx": "ARP TX",
                                                "arp_rx": "ARP RX",
                                                "default_tx": "Défaut TX",
                                                "default_rx": "Défaut RX",
                                                "dhcp_tx": "DHCP TX",
                                                "dhcp_rx": "DHCP RX"
                                            }.get(rule_name, rule_name)

                                            cos_rows.append([service_name, protocol, f"**{pbits}**", "-", "✅"])

                        # Calculer largeurs des colonnes
                        cos_headers = ["Service", "Protocole", "CoS (Pbits)", "DSCP", "État"]
                        cos_widths = [len(h) for h in cos_headers]
                        for row in cos_rows:
                            for i, cell in enumerate(row):
                                cell_len = len(str(cell).replace("**", ""))
                                cos_widths[i] = max(cos_widths[i], cell_len)

                        # Générer le tableau
                        md.append(format_table_row(cos_headers, cos_widths))
                        md.append(format_table_separator(cos_widths))
                        for row in cos_rows:
                            md.append(format_table_row(row, cos_widths))

                        md.append("")
                        md.append("**💡 Ces valeurs sont extraites de votre Livebox et doivent être reproduites sur votre routeur.**")
                        md.append("")
                        md.append("**⚠️ IMPORTANT :** Orange exige CoS 6 pour DHCP et ARP sur le VLAN Internet (832).")
                        md.append("")
                        md.append("---")
                        md.append("")

                    # Paramètres réseau (MTU, Lease Time)
                    md.append("### ⚙️ Paramètres réseau")
                    md.append("")

                    net_params_rows = []

                    # MTU - Chercher dans NeMo.Intf.veip0 (interface WAN)
                    veip0_key = [k for k in data.keys() if "NeMo.Intf.veip0.get" in k]
                    if veip0_key and "status" in data[veip0_key[0]]:
                        mtu = data[veip0_key[0]]["status"].get("MTU", "N/A")
                    else:
                        mtu = "N/A"

                    # DHCP Lease Time - Chercher dans les données DHCP
                    lease_time = "N/A"
                    for dhcp_key in dhcp_mibs_key:
                        if "status" in data[dhcp_key] and "dhcp" in data[dhcp_key]["status"]:
                            dhcp_status = data[dhcp_key]["status"]["dhcp"]
                            if "dhcp_data" in dhcp_status:
                                dhcp_net_info = dhcp_status["dhcp_data"]
                                lease_time = dhcp_net_info.get("LeaseTime", "N/A")
                                break

                    if lease_time != "N/A":
                        # Convertir secondes en jours/heures
                        lease_days = lease_time // 86400
                        lease_hours = (lease_time % 86400) // 3600
                        lease_str = f"{lease_time} sec ({lease_days}j {lease_hours}h)"
                    else:
                        lease_str = "N/A"

                    net_params_rows.append(["MTU WAN", str(mtu)])
                    net_params_rows.append(["DHCP Lease Time", lease_str])

                    if net_params_rows:
                        net_headers = ["Paramètre", "Valeur"]
                        net_widths = [len(h) for h in net_headers]
                        for row in net_params_rows:
                            for i, cell in enumerate(row):
                                cell_len = len(str(cell).replace("**", ""))
                                net_widths[i] = max(net_widths[i], cell_len)

                        md.append(format_table_row(net_headers, net_widths))
                        md.append(format_table_separator(net_widths))
                        for row in net_params_rows:
                            md.append(format_table_row(row, net_widths))

                        md.append("")
                        md.append("**💡 Important pour la config routeur :** Reproduisez le MTU 1540 sur votre interface WAN.")
                        md.append("")
                        md.append("---")
                        md.append("")

                sent = dhcp_data["SentOption"]
                for opt_num in sorted(sent.keys(), key=int):
                    opt = sent[opt_num]
                    md.append(f"### Option {opt_num}")
                    md.append("```")
                    md.append(f"Valeur HEX : {opt['Value']}")

                    # Essayer de décoder en ASCII
                    try:
                        ascii_val = bytes.fromhex(opt['Value']).decode('ascii', errors='ignore')
                        if ascii_val and ascii_val.isprintable():
                            md.append(f"ASCII      : {ascii_val}")
                    except:
                        pass

                    # Décoder l'option 90 pour extraire le FTI
                    if opt_num == "90":
                        try:
                            hex_data = opt['Value']
                            # Chercher le FTI dans la structure TLV
                            # Format: ...01<len>6674692f... où 6674692f = "fti/"
                            fti_marker = "6674692f"  # "fti/" en hex
                            if fti_marker in hex_data:
                                idx = hex_data.index(fti_marker)
                                # Remonter de 2 caractères pour avoir la longueur
                                if idx >= 2:
                                    length_hex = hex_data[idx-2:idx]
                                    length = int(length_hex, 16)
                                    # Extraire le FTI complet (fti/xxxxxx)
                                    fti_hex = hex_data[idx:idx + length * 2]
                                    fti_bytes = bytes.fromhex(fti_hex)
                                    # Filtrer : garder seulement alphanumériques + '/' après "fti/"
                                    fti_value = ''
                                    for b in fti_bytes:
                                        c = chr(b)
                                        if c.isalnum() or c == '/':
                                            fti_value += c
                                        else:
                                            break  # Arrêter au premier caractère bizarre
                                    if fti_value.startswith("fti/"):
                                        md.append(f"")
                                        md.append(f"🔑 FTI Orange : {fti_value}")
                        except:
                            pass

                    md.append(f"Mikrotik   : 0x{opt['Value']}")
                    md.append("```")
                    md.append("")
                break

    # DHCPv6 Options
    dhcpv6_keys = [k for k in data.keys() if "dhcpv6" in k.lower() and "getMIBs" in k]
    for key in dhcpv6_keys:
        if "status" in data[key] and "dhcpv6" in data[key]["status"]:
            dhcpv6_data = data[key]["status"]["dhcpv6"]["dhcpv6_data"]
            if "SentOption" in dhcpv6_data:
                md.append("## 🔐 Options DHCPv6")
                md.append("")

                sent = dhcpv6_data["SentOption"]
                for opt_num in sorted(sent.keys(), key=int):
                    opt = sent[opt_num]
                    md.append(f"### Option {opt_num}")
                    md.append("```")
                    md.append(f"Valeur HEX : {opt['Value']}")
                    md.append(f"Mikrotik   : 0x{opt['Value']}")
                    md.append("```")
                    md.append("")
                break

    # Footer
    md.append("---")
    md.append("")
    md.append("*Fichier généré automatiquement par FULL_extraction_LB5 v1.0*")
    md.append("")
    md.append("*💡 Le résumé des appels API est disponible dans le fichier JSON*")

    # Écrire le fichier
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))

    return filename


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interruption utilisateur")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n[!] Erreur inattendue : {e}")
        input("Appuyez sur Entrée pour quitter...")
        sys.exit(1)
