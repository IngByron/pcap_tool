import requests

VT_API_KEY = "3be17cdb722e5235fccd16cea6cc372ffbcf1ebff3ef111ea9397435c25ff245"
#VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_API = "https://www.virustotal.com/api/v3/urls"  # Para URL
VT_IP_API = "https://www.virustotal.com/api/v3/ip_addresses"  # Para IP

def analizar_con_virustotal(elemento):
    """Sube un archivo a VirusTotal para su análisis y devuelve el resultado."""
    headers = {"x-apikey": VT_API_KEY}
    
    if elemento.startswith("http://") or elemento.startswith("https://"):
        # Si es una URL, primero la codificamos en base64
        url_base64 = requests.utils.quote(elemento)
        response = requests.get(f"{VT_URL_API}/{url_base64}", headers=headers)

    elif elemento.count('.') == 3:  # Es una IP si tiene 3 puntos
        # Si es una IP, consultamos la API de VirusTotal para IPs (esto puede variar según la API de VT)
        response = requests.get(f"{VT_IP_API}/{elemento}", headers=headers)

    else:
        return None
    if response.status_code == 200:
        return response.json()  # Devuelve la respuesta JSON con el análisis
    else:
        return {"error": f"Error en la solicitud a VirusTotal: {response.status_code}"}



