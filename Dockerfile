# Imagem oficial do Python 3.8
FROM python:3.8-slim-buster

#Instalar curl
RUN apt-get update && apt-get install -y curl

#Instalar ifconfig
RUN apt-get install -y net-tools

# Set the working directory in the container to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run analisador_trafego.py when the container launches
CMD ["python", "analisador_trafego.py", "eth0"]