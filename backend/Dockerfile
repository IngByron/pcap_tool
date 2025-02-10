# Usar la imagen de Python 3.13.1
FROM python:3.13.1-slim

# Instalar dependencias del sistema necesarias para tshark
RUN apt-get update && apt-get install -y \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Configurar permisos para tshark
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/dumpcap

# Configurar el directorio de trabajo
WORKDIR /app

# Copiar y instalar las dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código fuente del backend
COPY . .

# Exponer el puerto del backend
EXPOSE 5000

# Ejecutar el servidor Flask
CMD ["python", "app.py"]
