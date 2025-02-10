from flask import Flask
from flask_cors import CORS
from routes import bp

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# Configuración básica
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Límite de 10 MB

# Configurar las rutas
app.register_blueprint(bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
