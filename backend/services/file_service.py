import os
from flask import current_app

def save_file(file):
    """Guarda el archivo en la carpeta de uploads."""
    try:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_folder, file.filename)
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        file.save(file_path)
        return file_path
    except Exception as e:
        if os.path.exists(file_path):
            return file_path
        else:
            return None  # Retorna None si el archivo no existe

def list_files():
    """Lista los archivos guardados en la carpeta de uploads."""
    upload_folder = current_app.config['UPLOAD_FOLDER']
    return [f for f in os.listdir(upload_folder) if f.endswith('.pcap') or f.endswith('.pcapng')]
