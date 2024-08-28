import argparse
from scapy.all import rdpcap, IP, ICMP
from termcolor import colored

# Función para descifrar el texto usando todos los posibles corrimientos del cifrado César
def descifrar_cesar(texto_cifrado):
    resultados = []
    for corrimiento in range(1, 26):
        texto_descifrado = []
        for char in texto_cifrado:
            if char.isalpha():
                offset = 65 if char.isupper() else 97
                nuevo_char = chr((ord(char) - offset - corrimiento) % 26 + offset)
                texto_descifrado.append(nuevo_char)
            else:
                texto_descifrado.append(char)
        resultado = ''.join(texto_descifrado)
        resultados.append((corrimiento, resultado))
    return resultados

# Función para analizar los paquetes ICMP de un archivo pcapng
def procesar_archivo_pcap(archivo_pcap):
    paquetes = rdpcap(archivo_pcap)
    mensaje_cifrado = []

    for paquete in paquetes:
        if IP in paquete and ICMP in paquete:
            if paquete[ICMP].type == 8:  # ICMP echo request
                data = paquete[ICMP].payload.load.decode('utf-8', errors='ignore').strip()
                if data:
                    mensaje_cifrado.append(data)
    
    return ''.join(mensaje_cifrado)

# Función principal
def main():
    # Configurar argparse para manejar el archivo pcapng como argumento
    parser = argparse.ArgumentParser(description="Procesa un archivo .pcapng y descifra los mensajes ICMP.")
    parser.add_argument("archivo_pcap", help="Ruta del archivo .pcapng a analizar")
    args = parser.parse_args()

    # Procesa el archivo pcapng
    mensaje_cifrado_str = procesar_archivo_pcap(args.archivo_pcap)

    if mensaje_cifrado_str:
        print(f"\nMensaje cifrado capturado: {mensaje_cifrado_str}")
        
        # Descrifra el mensaje usando todos los corrimientos posibles
        posibles_descifrados = descifrar_cesar(mensaje_cifrado_str)
        
        # Muestra todos los posibles resultados y resalta en verde el más probable
        print("\nPosibles descifrados:")
        for corrimiento, resultado in posibles_descifrados:
            print(f"Corrimiento {corrimiento}: {resultado}")
    else:
        print("No se capturó ningún mensaje cifrado.")

if __name__ == "__main__":
    main()