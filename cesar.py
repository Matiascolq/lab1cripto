def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for i in range(len(texto)):
        char = texto[i]
        if char.isupper():
            resultado += chr((ord(char) + corrimiento - 65) % 26 + 65)
        else:
            resultado += chr((ord(char) + corrimiento - 97) % 26 + 97)
    return resultado

texto = "HolaMundo"
corrimiento = 4
print("Texto cifrado:", cifrado_cesar(texto, corrimiento))