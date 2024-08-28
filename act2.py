from scapy.all import IP, ICMP, send, Raw

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

def enviar_paquetes_icmp(mensaje, destino="8.8.8.8"):
    try:
        for char in mensaje:
            # Crear un paquete ICMP con el carácter en el campo de datos
            paquete = IP(dst=destino)/ICMP()/Raw(load=char.encode())
            send(paquete, verbose=False)
            print(f"Enviando carácter '{char}' en un paquete ICMP a {destino}")
        print("Mensaje enviado con éxito.")
    except PermissionError:
        print("Error: El script debe ejecutarse con privilegios de superusuario.")
    except Exception as e:
        print(f"Ocurrió un error: {e}")

# Cifrar el mensaje primero
mensaje_cifrado = cifrado_cesar("HolaMundo", 4) + "b"
enviar_paquetes_icmp(mensaje_cifrado)