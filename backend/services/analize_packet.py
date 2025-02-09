import os
import time
import pyshark
import asyncio
from collections import defaultdict
from flask import current_app
from pyshark import tshark
from services.analize_virustotal import analizar_con_virustotal


UPLOAD_FOLDER = "static/uploads"


def analyze_packets(file):
    """Cuenta la cantidad total de paquetes en un archivo .pcap"""
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, file.filename)

    if not os.path.exists(file_path):
        return {"error1": "Archivo no encontrado"}

    try:
        # Abrir el archivo una vez
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cap = pyshark.FileCapture(file_path, use_json=True)

        # Inicializar los contadores
        total_packets = 0
        capture_duration = 0
        protocols = {}
        seq_numbers = {}
        # 🔹 Diccionario para almacenar los 8 nuevos análisis
        additional_data = {
            "ip_traffic": defaultdict(int),         # Tráfico por IP
            "active_connections": defaultdict(int), # Conexiones activas
            "anomalous_traffic": defaultdict(int),
            "port_traffic": defaultdict(int),       # Tráfico por puertos
            "secure_protocols": defaultdict(int),   # Protocolos de seguridad
            "insecure_protocols": defaultdict(int), # Protocolos de inseguridad 
            "icmp_types": defaultdict(int),         # Tipos de ICMP
            "packet_sizes": {"small": 0, "medium": 0, "large": 0},  # Tamaños de paquetes
            "tcp_states": defaultdict(int),         # Estados TCP
            "network_errors": defaultdict(int)      # Errores y retransmisiones
        }
        TCP_FLAG_MAP = {
            "0x000": "No Flag",
            "0x001": "FIN",
            "0x002": "SYN",
            "0x004": "RST",
            "0x008": "PSH",
            "0x010": "ACK",
            "0x020": "URG",
            "0x040": "ECE",
            "0x080": "CWR",
            "0x012": "SYN-ACK",
            "0x011": "FIN-ACK",
            "0x014": "PSH-ACK",
            "0x018": "PSH-ACK"
        }
        ICMP_TYPE_MAP = {
            "0": "Echo Reply",
            "3": "Destination Unreachable",
            "4": "Source Quench (Obsoleto)",
            "5": "Redirect",
            "8": "Echo Request",
            "9": "Router Advertisement",
            "10": "Router Solicitation",
            "11": "Time Exceeded",
            "12": "Parameter Problem",
            "13": "Timestamp Request",
            "14": "Timestamp Reply"
        }

        scan_attempts = defaultdict(int)
        ddos_attempts = defaultdict(int)
        
        start_time = None
        end_time = None

        scan_time_window = 1  # 60 segundos
        threshold = 500 

        # Recorrer todos los paquetes una vez y almacenar la información
        ddos_attempts = defaultdict(lambda: {"count": 0, "timestamps": []})
        for packet in cap:
            total_packets += 1
            otros_protocolos = ""

            # 📌 Registrar tiempo de inicio y fin
            packet_time = float(packet.sniff_timestamp)
            
            if start_time is None:
                start_time = packet_time  # Primer paquete

            end_time = packet_time  # Último paquete (se actualiza en cada iteración)

            # 📌 1. Tipos de protocolos
            if hasattr(packet, 'highest_layer') and packet.highest_layer:
                    protocol = packet.highest_layer  # Obtener la capa más alta
                    otros_protocolos = packet.highest_layer  
                    
                    if protocol != 'None':  # Asegurarse de que no sea un valor vacío
                        if protocol in protocols:
                            protocols[protocol] += 1
                        else:
                            protocols[protocol] = 1

            # 📌 2. Distribución de tráfico por IP
            if hasattr(packet, 'ip') or hasattr(packet, 'ipv6'):
                if hasattr(packet, 'ip'):
                   src_ip = packet.ip.src
                   dst_ip = packet.ip.dst
                elif hasattr(packet, 'ipv6'):
                    src_ip = packet.ipv6.src
                    dst_ip = packet.ipv6.dst
                    

                # 📌 Actualizar el tráfico por IP
                if src_ip not in additional_data["ip_traffic"]:
                    additional_data["ip_traffic"][src_ip] = 0
                if dst_ip not in additional_data["ip_traffic"]:
                    additional_data["ip_traffic"][dst_ip] = 0
                
                additional_data["ip_traffic"][src_ip] += 1
                additional_data["ip_traffic"][dst_ip] += 1

                # 📌 Obtener puerto y protocolo (TCP o UDP)
                if 'TCP' in packet:
                    protocolo = "TCP"
                    puerto_o = packet.tcp.srcport  
                    puerto_d = packet.tcp.dstport  
                elif 'UDP' in packet:
                    protocolo = "UDP"
                    puerto_o = packet.udp.srcport  
                    puerto_d = packet.udp.dstport  
                else:
                    if hasattr(packet, 'highest_layer') and packet.highest_layer:
                        protocolo = packet.highest_layer
                        puerto_o = None
                        puerto_d = None
                    else:
                        protocolo = "OTRO"
                        puerto_o = None
                        puerto_d = None


                # 📌 Crear la clave para la conexión activa
                connection_key = f"{src_ip} -> {dst_ip}, Puerto Origen: {puerto_o}, Puerto Destino: {puerto_d} Protocolo: {protocolo}"

                # Inicializar si no existe
                if connection_key not in additional_data["active_connections"]:
                    additional_data["active_connections"][connection_key] = {
                        "ip_origen":src_ip,
                        "ip_destino": dst_ip,
                        "protocolo": protocolo,
                        "otros_protocolos": otros_protocolos,
                        "puerto_origen": puerto_o,
                        "puerto_destino": puerto_d,
                        "numero_conexiones": 1
                    }
                else:
                    # Incrementar el número de conexiones
                    additional_data["active_connections"][connection_key]["numero_conexiones"] += 1

                # 📌 Detectar escaneo de puertos
                if hasattr(packet, 'tcp'):
                    dst_port = packet.tcp.dstport
                    current_time = time.time()

                    # Usar una clave única que combine src_ip y dst_port
                    key = (src_ip, dst_port)

                    # Si la clave no existe en scan_attempts, inicializarla con una lista vacía
                    if key not in scan_attempts:
                        scan_attempts[key] = []

                    # Eliminar intentos fuera de la ventana de tiempo (en este caso, 60 segundos)
                    scan_attempts[key] = [timestamp for timestamp in scan_attempts[key] if current_time - timestamp <= scan_time_window]

                    # Agregar el intento actual
                    scan_attempts[key].append(current_time)

                    # Verifica si los intentos superan el umbral
                    if len(scan_attempts[key]) > threshold:
                        additional_data["anomalous_traffic"][f"Escaneo de puertos {src_ip}"] = {
                            "mensaje": f"Posible escaneo de puertos desde {src_ip} hacia el puerto {dst_port}."
                        }
                
                internal_network_prefix = "192.168."  # 🚨 Modifícalo según tu red
                if hasattr(packet, 'udp') or hasattr(packet, 'tcp'):
                    dst_port = packet.udp.dstport if hasattr(packet, 'udp') else packet.tcp.dstport
                    current_time = time.time()  # Obtener el tiempo actual

                    # Agregar el tiempo del nuevo intento
                    ddos_attempts[(dst_ip, dst_port)]["timestamps"].append(current_time)
                    ddos_attempts[(dst_ip, dst_port)]["count"] += 1

                    recent_attempts = [
                        t for t in ddos_attempts[(dst_ip, dst_port)]["timestamps"]
                        if current_time - t <= 1
                    ]
                    ddos_attempts[(dst_ip, dst_port)]["timestamps"] = recent_attempts

                    # Si hay más de 1000 intentos en 10 segundos, se detecta DDoS
                    if len(recent_attempts) > 1000:
                        additional_data["anomalous_traffic"][f"Ataque DDoS {dst_ip}"] = {
                            "mensaje": f"{len(recent_attempts)} intentos de ataque DDoS de la IP interna {src_ip} al puerto {dst_port} externo en los últimos 10 segundos."
                        }
                    
                    # 📌 2️⃣ Detectar intentos desde una IP externa hacia un puerto de la red interna (NUEVO)
                    if dst_ip.startswith(internal_network_prefix) and not src_ip.startswith(internal_network_prefix):
                        ddos_attempts[dst_port]["timestamps"].append(current_time)
                        ddos_attempts[dst_port]["count"] += 1

                        recent_attempts = [
                            t for t in ddos_attempts[dst_port]["timestamps"]
                            if current_time - t <= 1
                        ]
                        ddos_attempts[dst_port]["timestamps"] = recent_attempts

                        # 📌 Si más de 1000 intentos llegan a un puerto en 10 segundos, posible DDoS externo -> interno
                        if len(recent_attempts) > 1000:
                            additional_data["anomalous_traffic"][f"Ataque DDoS al puerto {dst_port}"] = {
                                "mensaje": f"{len(recent_attempts)} intentos de conexión detectados en el puerto {dst_port} en la IP {dst_ip} en los últimos 10 segundos, posible ataque DDoS."
                            }


                # 📌 Detectar transferencia de archivos por FTP
                if dst_port == "21":
                    additional_data["anomalous_traffic"][f"Transferencia FTP {src_ip}"] = {
                        "mensaje": f"Posible transferencia de archivos desde {src_ip} hacia {dst_ip} en el puerto 21."
                    }
            
                # 📌 Detectar paquetes con tamaño mayor a 1500 bytes
                if hasattr(packet, 'length') and int(packet.length) > 1500:
                    additional_data["anomalous_traffic"][f"Paquete número {packet.number}"] = {
                        "mensaje": f"Se detectó un paquete con tamaño inusual ({packet.length} bytes)."
                    }



            # 📌 4. Distribución de tráfico por puertos
            if hasattr(packet, 'tcp'):

                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport

                port_traffic_key_tcp = f"Puerto Origen {src_port}, Puerto Destino: {dst_port}"

                # Inicializar si no existe
                if port_traffic_key_tcp not in additional_data["port_traffic"]:
                    additional_data["port_traffic"][port_traffic_key_tcp] = {
                        "protocolo": "TCP",
                        "puerto_origen": src_port,
                        "puerto_destino": dst_port,
                        "suma_p_origen":1,
                        "suma_p_destino":1
                    }
                else:
                    additional_data["port_traffic"][port_traffic_key_tcp]["suma_p_origen"] += 1
                    additional_data["port_traffic"][port_traffic_key_tcp]["suma_p_destino"] += 1
            elif hasattr(packet, 'udp'):
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport

                port_traffic_key_udp = f"Puerto Origen {src_port}, Puerto Destino: {dst_port}"



                if port_traffic_key_udp not in additional_data["port_traffic"]:
                    additional_data["port_traffic"][port_traffic_key_udp] = {
                        "protocolo": "UDP",
                        "puerto_origen": src_port,
                        "puerto_destino": dst_port,
                        "suma_p_origen":1,
                        "suma_p_destino":1
                    }
                else:
                    additional_data["port_traffic"][port_traffic_key_udp]["suma_p_origen"] += 1
                    additional_data["port_traffic"][port_traffic_key_udp]["suma_p_destino"] += 1
                    

            # 📌 5. Detección de protocolos de seguridad
            secure_protocols = ["TLS", "SSL", "IPsec", "ESP", "ISAKMP", "HTTPS", "SSH", "IKE", "L2TP", "POP3S", "IMAPS", "SMTPS", "FTPES", "FTPS", "SFTP"]
            if any(proto in packet for proto in secure_protocols):
                detected_protocol = next(proto for proto in secure_protocols if proto in packet)
                additional_data["secure_protocols"][detected_protocol] += 1

            insecure_protocols = ["HTTP", "FTP", "Telnet", "SMTP", "POP3", "IMAP", "TFTP", "RDP"]
            if any(proto in packet for proto in insecure_protocols):
                detected_insecure_protocol = next(proto for proto in insecure_protocols if proto in packet)
                additional_data["insecure_protocols"][detected_insecure_protocol] += 1

            # 📌 6. Tipos de paquetes ICMP
            if hasattr(packet, 'icmp'):
                icmp_type = packet.icmp.type
                icmp_name = ICMP_TYPE_MAP.get(icmp_type, "Unknown Type")
                if icmp_type not in additional_data["icmp_types"]:
                    additional_data["icmp_types"][icmp_type] = {
                    'name': icmp_name,  # Guardamos el nombre asociado al código ICMP
                    'count': 1  # Inicializamos el contador a 0
                }
                else:
                    # Incrementamos el contador para ese tipo ICMP
                    additional_data["icmp_types"][icmp_type]['count'] += 1

            

            # 📌 7. Distribución de tamaños de paquetes
            packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            if packet_size < 500:
                additional_data["packet_sizes"]["small"] += 1
            elif packet_size <= 1500:
                additional_data["packet_sizes"]["medium"] += 1
            else:
                additional_data["packet_sizes"]["large"] += 1

            # 📌 8. Estados de conexiones TCP
            if hasattr(packet, 'tcp'):
                syn_requests = 0
                syn_ack_responses = 0
                close_wait_count = 0
                time_wait_count = 0
                max_syn_threshold = 100  # Número máximo de SYN para detectar SYN Flood

                if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                    # Extraemos la IP de origen y destino, y el puerto de destino
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    dst_port = packet.tcp.dstport
                    flags_hexadecimal = packet.tcp.flags
                    flags = int(flags_hexadecimal,16)
                    flags = f"0x{flags:03X}"
                    flags = TCP_FLAG_MAP.get(str(flags), "Desconocido")
                    
                    # Detección de SYN Flood (SYN sin ACK)
                    if 'SYN' in flags and 'ACK' not in flags:
                        syn_requests += 1
                        if syn_requests > max_syn_threshold:
                            additional_data["tcp_states"]["SYN Flood"] = {
                                "mensaje": f"Detectado posible ataque SYN Flood: Más de {syn_requests} intentos SYN sin respuesta ACK en el puerto {dst_port}. Origen: {src_ip}."
                            }
                    
                    # Detección de conexiones en CLOSE_WAIT (posible error en la red)
                    if 'CLOSE_WAIT' in flags:
                        close_wait_count += 1
                        additional_data["tcp_states"]["CLOSE_WAIT"] = {
                            "mensaje": f"Conexiones en estado CLOSE_WAIT detectadas: {close_wait_count} en el puerto {dst_port}. Origen: {src_ip}. Posible problema con la terminación de la conexión."
                        }
                    
                    # Detección de conexiones en TIME_WAIT (posible congestión o mal cierre)
                    if 'TIME_WAIT' in flags:
                        time_wait_count += 1
                        additional_data["tcp_states"]["TIME_WAIT"] = {
                            "mensaje": f"Conexiones en estado TIME_WAIT detectadas: {time_wait_count} en el puerto {dst_port}. Origen: {src_ip}. Puede ser indicativo de congestión o mal cierre de conexiones."
                        }
                    
                    # Detección de SYN-ACK (respuesta a SYN, debe ser parte del proceso de conexión)
                    # if 'SYN' in flags and 'ACK' in flags:
                    #     syn_ack_responses += 1
                    #     additional_data["tcp_states"]["SYN-ACK"] = {
                    #         "mensaje": f"Respuesta SYN-ACK detectada desde {src_ip} hacia {dst_ip}:{dst_port}. Total de respuestas SYN-ACK: {syn_ack_responses}."
                    #     }


            
            # 📌 9. Errores y retransmisiones
            if hasattr(packet, 'tcp'):
                seq = packet.tcp.seq  # Número de secuencia del paquete TCP
                ack = packet.tcp.ack  # Número de acuse de recibo del paquete TCP
                
                # Verificar si el paquete tiene el mismo número de secuencia que uno anterior (retransmisión)
                if seq in seq_numbers:
                    additional_data["network_errors"]["retransmissions"] += 1
                else:
                    seq_numbers[seq] = ack  # Guardar el número de secuencia y acuse de recibo

                # Verificar errores de checksum
                checksum = packet.tcp.checksum
                
                # Si el checksum es '0x0000', indicar que hubo un error de checksum
                if checksum == '0x0000':
                    additional_data["network_errors"]["checksum_errors"] += 1


        cap.close()  # Cerramos el archivo después de procesarlo

        # Calcular la duración de la captura
        if start_time and end_time:
            capture_duration = round(end_time - start_time, 2)
        else:
            capture_duration = 0


        cap = pyshark.FileCapture(file_path, use_json=True, display_filter="http or dns or tls")  # Filtrar por HTTP, DNS o TLS
        urls = set()  # Conjunto para evitar duplicados
        internal_network_prefix = "192.168."
        for packet in cap:
            try:
                # Extraer URLs de HTTP (GET/POST)
                if hasattr(packet, "http"):
                    if hasattr(packet.http, "host") and hasattr(packet.http, "request_uri"):
                        host = packet.http.host
                        uri = packet.http.request_uri
                        url = f"http://{host}{uri}"
                        urls.add(url)
                    if hasattr(packet, "ip"):
                        src_ip = packet.ip.src  # IP de origen
                        dst_ip = packet.ip.dst  # IP de destino
                        # Verificar si la IP de origen o destino es pública (no privada)
                        if src_ip.startswith(internal_network_prefix) and not dst_ip.startswith(internal_network_prefix):
                            # Solo la IP de destino es pública
                            urls.add(dst_ip)
                        elif dst_ip.startswith(internal_network_prefix) and not src_ip.startswith(internal_network_prefix):
                            # Solo la IP de origen es pública
                            urls.add(src_ip)
                        elif not src_ip.startswith(internal_network_prefix) and not dst_ip.startswith(internal_network_prefix):
                            # Ambos son públicos
                            urls.add(src_ip)
                            urls.add(dst_ip)


                # Extraer dominios de consultas DNS
                if hasattr(packet, "dns") and hasattr(packet.dns, "qry_name"):
                    urls.add(packet.dns.qry_name)

                # Extraer dominios en TLS/SSL (HTTPS) usando SNI
                if hasattr(packet, "tls") and hasattr(packet.tls, "handshake_extensions_server_name"):
                    urls.add(packet.tls.handshake_extensions_server_name)

            except AttributeError as e:
                continue  # Ignorar paquetes sin los atributos esperados


        cap.close()
        mi_lista = list(urls)
        if mi_lista:  # Verifica que la lista no esté vacía
            json_api_virus_total = analizar_con_virustotal(mi_lista[0])  # Llamada a la API
            if json_api_virus_total is None:
                result_virus_total = {"error": "No se pudo obtener resultados de VirusTotal"}
            else:
                # Procesar el resultado si es exitoso
                result_virus_total = procesar_resultado_virustotal(json_api_virus_total)
        else:
            result_virus_total = {"error": "Lista vacía, no se puede realizar análisis"}

        # Imprimir los datos
        # for key, value in additional_data.items():
        #     print(f"{key}:")
        #     if isinstance(value, dict):  # Si es un diccionario, recorrerlo
        #         for sub_key, sub_value in value.items():
        #             print(f"  {sub_key}: {sub_value}")
        #     else:  # Si no es un diccionario, simplemente imprimir el valor
        #         print(f"  {value}")
        #     print()


        if total_packets == 0:
            return {"error2": "No se encontraron paquetes en el archivo .pcap"}

        # Devolver los resultados
        return {
            "total_packets_result": total_packets,
            "duration_packet": capture_duration,
            "protocol_packets_result": protocols,
            "additional_data": additional_data,
            "extracted_urls": list(urls),
            "result_virus_total": result_virus_total
        }
        
    except Exception as e:
        return {"error3": str(e)}
    

def procesar_resultado_virustotal(result_virus_total):
    if result_virus_total is None:
        return {"error": "No se pudo obtener resultados de VirusTotal"}
    # Extraemos los datos básicos
    data = result_virus_total.get('data', {})
    ip = data.get('id', 'No disponible')
    tipo = data.get('type', 'No disponible')
    country = data.get('attributes', {}).get('country', 'No disponible')
    
    # Extracción de análisis
    last_analysis_stats = data.get('attributes', {}).get('last_analysis_stats', {})
    malicious = last_analysis_stats.get('malicious', 0)
    harmless = last_analysis_stats.get('harmless', 0)
    undetected = last_analysis_stats.get('undetected', 0)
    
    # Extraemos solo un motor de antivirus
    last_analysis_results = data.get('attributes', {}).get('last_analysis_results', {})
    first_motor = list(last_analysis_results.keys())[0] if last_analysis_results else None
    if first_motor:
        motor_details = last_analysis_results[first_motor]
        motor_name = motor_details.get('engine_name', 'No disponible')
        motor_category = motor_details.get('category', 'No disponible')
        motor_result = motor_details.get('result', 'No disponible')
        motor_method = motor_details.get('method', 'No disponible')
    else:
        motor_name = motor_category = motor_result = motor_method = 'No disponible'
    
    # Construcción del nuevo JSON
    virus_total_API = {
        "Ip": ip,
        "Tipo": tipo,
        "País": country,
        "Último análisis (Stats)": {
            "Malicioso": malicious,
            "Inofensivo": harmless,
            "No detectado": undetected
        },
        "Último Análisis (Motor Antivirus)": {
            first_motor: {
                "Motor antivirus": motor_name,
                "Categoría": motor_category,
                "Resultado": motor_result,
                "Método": motor_method
            }
        }
    }
    
    return virus_total_API