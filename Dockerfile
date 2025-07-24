# Usa una imagen base oficial de Python para uvicorn
# Puedes elegir una versión específica de Python que uses (ej. 3.9-slim-buster)
FROM python:3.10-slim-buster

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de requisitos e instala las dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código de la aplicación
COPY ./app /app/app

# Expone el puerto que usará Uvicorn
EXPOSE 8000

# Comando para ejecutar la aplicación con Uvicorn
# '--host 0.0.0.0' es crucial para que sea accesible desde fuera del contenedor
# Puedes ajustar los workers según la CPU/RAM de tu tarea Fargate
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]