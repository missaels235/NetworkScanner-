# NetworkScanner-
NetworkScanner - Escáner de Red Local con API de MAC Vendor

📡 NetworkScanner - Escáner de Red Local con API de MAC Vendor
Un escáner de red basado en Python y Scapy con una interfaz gráfica en Tkinter. Detecta dispositivos en la red local, obtiene su IP, dirección MAC, nombre de host, fabricante y escanea puertos abiertos.

🚀 Características
Escaneo de red local: Detecta dispositivos conectados en la subred /24.
Identificación de dispositivos: Obtiene dirección IP, dirección MAC y nombre del host.
Fabricante de hardware: Consulta la API de MAC Vendors para identificar la marca del dispositivo.
Escaneo de puertos abiertos: Verifica puertos comunes (21, 22, 23, 25, 53, 80, etc.).
Interfaz gráfica (GUI): Usa Tkinter y ttk para mostrar los resultados de forma visual.
📦 Requisitos
Instala las dependencias antes de ejecutar el script:

bash
Copiar
Editar
pip install scapy requests
⚡ Uso
Ejecuta el script con:

bash
Copiar
Editar
python scanner.py
🖥️ Captura de Pantalla
(Coloca aquí una captura de pantalla de la interfaz en ejecución)

⚠️ Advertencia
Este script está diseñado para pruebas en tus propias redes. No lo uses en redes ajenas sin autorización.

🛠️ Autor
iammissa 🛡️ | Proyecto creado por iammissa
