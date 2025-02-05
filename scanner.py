#echo por iammissa
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp
import socket
import requests

class NetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Red")
        self.root.geometry("900x500")
        
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Definición de columnas para mostrar más información:
        self.tree = ttk.Treeview(
            self.main_frame,
            columns=('IP', 'MAC', 'Hostname', 'Fabricante', 'Puertos Abiertos'),
            show='headings'
        )
        self.tree.heading('IP', text='Dirección IP')
        self.tree.heading('MAC', text='Dirección MAC')
        self.tree.heading('Hostname', text='Nombre del Host')
        self.tree.heading('Fabricante', text='Fabricante')
        self.tree.heading('Puertos Abiertos', text='Puertos Abiertos')
        
        self.tree.column('IP', width=150)
        self.tree.column('MAC', width=150)
        self.tree.column('Hostname', width=150)
        self.tree.column('Fabricante', width=200)
        self.tree.column('Puertos Abiertos', width=200)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        self.scan_button = ttk.Button(self.main_frame, text="Escanear Red", command=self.scan_network)
        self.scan_button.pack(pady=5)
        
        self.status_label = ttk.Label(self.main_frame, text="")
        self.status_label.pack(pady=5)
    
    def get_local_ip(self):
        try:
            # Se obtiene la IP local haciendo conexión a un DNS público
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return "192.168.1.1"  # Valor por defecto en caso de error
    
    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Desconocido"
    
    def get_vendor(self, mac):
        try:
            # Consulta sencilla a la API de macvendors.com
            url = "https://api.macvendors.com/" + mac
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
            else:
                return "Desconocido"
        except Exception:
            return "Desconocido"
    
    def scan_ports(self, ip, ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]):
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(str(port))
                s.close()
            except Exception:
                continue
        return ", ".join(open_ports) if open_ports else "Ninguno"
    
    def scan_network(self):
        try:
            # Limpiar resultados anteriores
            for item in self.tree.get_children():
                self.tree.delete(item)
                
            self.status_label.config(text="Escaneando red...")
            self.root.update()
            
            # Obtener IP local y construir el rango de subred (asumiendo /24)
            local_ip = self.get_local_ip()
            subnet = ".".join(local_ip.split('.')[:-1]) + ".0/24"
            
            # Construir el paquete ARP y enviarlo
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': self.get_hostname(received.psrc),
                    'fabricante': self.get_vendor(received.hwsrc),
                    'puertos': self.scan_ports(received.psrc)
                }
                devices.append(device)
            
            if not devices:
                self.status_label.config(text="No se encontraron dispositivos")
                return
            
            # Insertar cada dispositivo en la tabla
            for device in devices:
                self.tree.insert(
                    '', tk.END,
                    values=(
                        device['ip'],
                        device['mac'],
                        device['hostname'],
                        device['fabricante'],
                        device['puertos']
                    )
                )
            self.status_label.config(text=f"Dispositivos encontrados: {len(devices)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error: {str(e)}")
            self.status_label.config(text="Error en el escaneo")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScanner(root)
    root.mainloop()
