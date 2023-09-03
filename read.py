import sys
import re
from scapy.all import *

def cesarDesincriptar(text, shift):
    textoDesincriptado = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            caracterDesincriptado = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            textoDesincriptado += caracterDesincriptado
        else:
            textoDesincriptado += char
    return textoDesincriptado

def Imprimircolor(text, color_code):
    print(f"\033[{color_code}m{text}\033[0m", end='')

def main():
    if len(sys.argv) != 2:
        print("Usage: python decrypt_pcap_scapy.py <file.pcapng>")
        return

    pcap_file = sys.argv[1]

    paquetes = rdpcap(pcap_file)
    Mensaje_Encriptado = ""

    for pkt in paquetes:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP Echo Request
            Mensaje_Encriptado+= chr(pkt[ICMP].load[-1])

    correct_shift = None

    for corrimiento in range(26):
        MensajeDesincriptado = cesarDesincriptar(Mensaje_Encriptado, corrimiento)
        palabras_a_buscar = ["el", "en", "de","es", "un", "una", "que", "por", "para", "con", "del", "lo", "los", "las", "al", "se", "su", "como", "más", "pero", "también", "si", "no"]

        # Utilizamos una expresión regular para buscar palabras completas
        patron = r'\b(?:' + '|'.join(re.escape(palabra) for palabra in palabras_a_buscar) + r')\b'

        if re.search(patron, MensajeDesincriptado , re.IGNORECASE):
            print(f"corrimiento {corrimiento:02d}: ", end='')
            Imprimircolor(MensajeDesincriptado , '32')
            print()
        else:
            print(f"corrimiento {corrimiento:02d}: {MensajeDesincriptado}")


if __name__ == "__main__":
    main()



    