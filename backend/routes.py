from flask import Blueprint, request, jsonify
from flask_cors import cross_origin  
from services.file_service import save_file, list_files
from utils.validation import is_valid_pcap
from services.analize_packet import analyze_packets

bp = Blueprint('routes', __name__)

@bp.route('/upload', methods=['POST'])
@cross_origin()  # 🔥 Esto permite CORS en esta ruta específica
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se ha enviado un archivo'}), 400
        file = request.files['file']
        file_path = save_file(file)
        if file_path is None:  # Si ocurrió un error en save_file()
            return jsonify({'error': 'No se pudo guardar el archivo'}), 500

        return jsonify({'message': 'Archivo guardado exitosamente', 'path': file_path})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500  # Devolver el error en caso de excepción

@bp.route('/files', methods=['GET'])
@cross_origin()  # Esto permite CORS en esta ruta específica
def get_files():
    """Retorna la lista de archivos guardados"""
    files = list_files()
    return jsonify({'files': files})

@bp.route("/analyze", methods=["POST"])
@cross_origin()  # Esto permite CORS en esta ruta específica
def analyze():
    file = request.files['file']  # Por ejemplo, obtener el nombre del archivo
    if not file:
        return jsonify({"message": "Nombre de archivo no proporcionado"}), 400
    
    # Paso 1: Ejecutar la función count_total_packets
    
    try:
        analisis = analyze_packets(file)
        if "error1" in analisis: 
            print("mira dentro del if error 1")           
            return jsonify({"message": "Guarde el archivo y vuelva a intentarlo"}), 400
        
        if "error2" in analisis:
            return jsonify({"message": "No se encontraron paquetes en el archivo .pcap"}), 400
        
        if "error3" in analisis:
            return jsonify({"message": "Problemas al leer el archivo .pcap"}), 400

        return jsonify({
            "total_packets_result": analisis["total_packets_result"],
            "duration_packet": analisis["duration_packet"],
            "protocol_packets_result": analisis["protocol_packets_result"],
            "additional_data": analisis["additional_data"],
            "extracted_urls": analisis["extracted_urls"],
            "result_virus_total": analisis["result_virus_total"]
        }), 200
    
    except Exception as e:
        return jsonify({"message": f"Error al procesar el archivo: {str(e)}"}), 500


