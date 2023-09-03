import sys
import subprocess
import os
from scapy.all import *

# Genera un identificador incial para el primer paquete
id_identificador = 9
# Inicializa el número de secuencia para BE
seq_be = 1
#Contenido ping 8 bytes
ping=b'\x08\x00\xf7\xff'
def enviar_caracter_icmp(caracter):
    try:
        global id_identificador
        global seq_be
        #Relleno con valores hexadecimales
        padding= bytes([i for i in range(0x10,0x38)])[:(42-len(caracter))]
        bytes_adicionales=b'\xfa\x20\x13'
        payload=ping+padding+bytes_adicionales+caracter.encode()
        # Agrega el caracter en el byte menos significativo
        # Crea un paquete ICMP request con los datos
        icmp_packet = IP(dst="8.8.8.8") / ICMP(type=8,code=0,id=id_identificador,seq=seq_be) / Raw(load=payload)
        id_identificador+=1 #Se incrementa el identificador el paquete en 1
        seq_be+=1#Se incrementa en 1 el be y el le se incrementa automaticamente
        send(icmp_packet)#Se envia el paquete
    except Exception as e:
        print(f"Error al enviar el caracter '{caracter}': {str(e)}")

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 pingv4.py <texto>")
        sys.exit(1)

    texto = sys.argv[1]

    for caracter in texto:
        enviar_caracter_icmp(caracter)

if __name__ == "__main__":
    main()

