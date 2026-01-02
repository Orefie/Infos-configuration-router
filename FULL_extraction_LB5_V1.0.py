#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════╗
║          EXTRACTION TOTALE LIVEBOX 5 - Version 1.0                    ║
║                                                                        ║
║  Extrait TOUTES les données de votre Livebox Orange en une fois       ║
║  - DHCP IPv4/IPv6 (options 60,77,90,125 / 11,15,16,17)               ║
║  - Infos ONT/GPON (serial, vendor, débit)                            ║
║  - Configuration réseau complète                                      ║
║  - WiFi, Firewall, NAT, QoS, VoIP, IPTV, etc.                        ║
║                                                                        ║
║  Auteur  : Claude Sonnet 4.5 + Communauté lafibre.info               ║
║  Version : 1.0                                                         ║
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
            "extraction_version": "1.0"
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
    print("Vous pouvez maintenant débrancher la Livebox.")
    print("Ouvrez le fichier .md pour voir toutes les données formatées !")
    print()
    input("Appuyez sur Entrée pour quitter...")


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
        md.append("| Paramètre | Valeur |")
        md.append("|-----------|--------|")
        md.append(f"| Modèle | {device.get('ModelName', 'N/A')} |")
        md.append(f"| Classe produit | {device.get('ProductClass', 'N/A')} |")
        md.append(f"| Numéro de série | {device.get('SerialNumber', 'N/A')} |")
        md.append(f"| Version logicielle | {device.get('SoftwareVersion', 'N/A')} |")
        md.append(f"| MAC Address | **{device.get('BaseMAC', 'N/A')}** |")
        md.append("")

    # WAN Status
    wan_key = [k for k in data.keys() if "getWANStatus" in k]
    if wan_key and "data" in data[wan_key[0]]:
        wan = data[wan_key[0]]["data"]
        md.append("## 🌐 Statut WAN")
        md.append("")
        md.append("| Paramètre | Valeur |")
        md.append("|-----------|--------|")
        md.append(f"| État | {wan.get('WanState', 'N/A')} |")
        md.append(f"| État GPON | {wan.get('GponState', 'N/A')} |")
        md.append(f"| IP IPv4 | {wan.get('IPAddress', 'N/A')} |")
        md.append(f"| Gateway IPv4 | {wan.get('RemoteGateway', 'N/A')} |")
        md.append(f"| IP IPv6 | {wan.get('IPv6Address', 'N/A')} |")
        md.append(f"| Préfixe IPv6 | {wan.get('IPv6DelegatedPrefix', 'N/A')} |")
        md.append("")

    # DHCP IPv4 Options
    dhcp_keys = [k for k in data.keys() if "dhcp" in k.lower() and "getMIBs" in k]
    for key in dhcp_keys:
        if "status" in data[key] and "dhcp" in data[key]["status"]:
            dhcp_data = data[key]["status"]["dhcp"]["dhcp_data"]
            if "SentOption" in dhcp_data:
                md.append("## 🔐 Options DHCP IPv4")
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

    # ONT Info
    ont_key = [k for k in data.keys() if "veip0" in k]
    if ont_key and "status" in data[ont_key[0]]:
        ont = data[ont_key[0]]["status"]
        md.append("## 🔌 Informations ONT/GPON")
        md.append("")
        md.append("| Paramètre | Valeur |")
        md.append("|-----------|--------|")
        md.append(f"| Numéro de série | {ont.get('SerialNumber', 'N/A')} |")
        md.append(f"| Vendor ID | {ont.get('VendorId', 'N/A')} |")
        md.append(f"| Equipment ID | {ont.get('EquipmentId', 'N/A')} |")
        md.append(f"| État GPON | {ont.get('ONUState', 'N/A')} |")
        md.append(f"| Débit down | {ont.get('DownstreamCurrRate', 0) // 1000} Mbps |")
        md.append(f"| Débit up | {ont.get('UpstreamCurrRate', 0) // 1000} Mbps |")
        md.append("")

    # Résumé des appels
    md.append("---")
    md.append("")
    md.append("## 📊 Résumé des appels API")
    md.append("")
    md.append("| Service | Méthode | Statut |")
    md.append("|---------|---------|--------|")

    for key in sorted(data.keys()):
        if key in ["extraction_date", "extraction_host", "extraction_version"]:
            continue

        # Parser le nom
        parts = key.split(".")
        service = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
        method = parts[-1].split("(")[0] if len(parts) > 0 else ""

        # Statut
        if isinstance(data[key], dict):
            if "_error" in data[key]:
                status = f"❌ {data[key]['_error']}"
            else:
                status = "✅ OK"
        else:
            status = "❓"

        md.append(f"| {service} | {method} | {status} |")

    md.append("")
    md.append("---")
    md.append("")
    md.append("*Fichier généré automatiquement par FULL_extraction_LB5 v1.0*")

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
