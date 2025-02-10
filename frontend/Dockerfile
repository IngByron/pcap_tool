# Usar una imagen de Node.js 22
FROM node:22

# Configurar el directorio de trabajo
WORKDIR /app

# Copiar los archivos de configuración de dependencias
COPY package.json package-lock.json ./

# Instalar las dependencias
RUN npm install

# Copiar el código fuente del frontend
COPY . .

# Exponer el puerto del frontend
EXPOSE 3000

# Ejecutar la aplicación
CMD ["npm", "start"]
