import os
import pyshark
import asyncio
from flask import current_app
from pyshark import tshark

UPLOAD_FOLDER = "static/uploads"

def count_total_protocols(file):
    """Cuenta los protocolos en un archivo .pcap"""
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file.filename)

    if not os.path.exists(file_path):
        return {"error1": "Archivo no encontrado"}

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cap = pyshark.FileCapture(file_path, use_json=True)
        
        protocols = {}  # Diccionario para contar los protocolos

        for packet in cap:
            try:

                if hasattr(packet, 'highest_layer') and packet.highest_layer:
                    protocol = packet.highest_layer  # Obtener la capa más alta
                    if protocol != 'None':  # Asegurarse de que no sea un valor vacío
                        if protocol in protocols:
                            protocols[protocol] += 1
                        else:
                            protocols[protocol] = 1


                print("pero si llega aqui, ?? > ", packet.transport_layer)
            except AttributeError:
                # Si no tiene una capa superior, se ignora
                continue
        
        cap.close()

        if not protocols:
            return {"error2": "No se encontraron protocolos en el archivo .pcap"}

        print("Resultado de los tipos de protocolo: ", protocols)
        return protocols  # Devuelve el diccionario de protocolos y sus cuentas
    except Exception as e:
        print(f"Error en count_protocols: {e}")
        return {"error3": str(e)}
