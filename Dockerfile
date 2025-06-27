FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# port 5000
EXPOSE 5000

# Command to run the application, use gunicorn
CMD ["gunicorn", "runserver:app", "--bind", "0.0.0.0:5000", "--workers", "4"]
# CMD ["python", "runserver.py", "--host=0.0.0.0", "--port=5000"]
