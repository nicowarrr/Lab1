import sys

def cifrar_cesar(texto, corrimiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.lower()
            codigo_ascii = ord(caracter)
            codigo_cifrado = ((codigo_ascii - ord('a') + corrimiento) % 26) + ord('a')
            if mayuscula:
                caracter_cifrado = chr(codigo_cifrado).upper()
            else:
                caracter_cifrado = chr(codigo_cifrado)
        else:
            caracter_cifrado = caracter
        texto_cifrado += caracter_cifrado
    return texto_cifrado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
        sys.exit(1)

    texto_original = sys.argv[1]
    corrimiento = int(sys.argv[2])

    texto_cifrado = cifrar_cesar(texto_original, corrimiento)
    print(texto_cifrado)

