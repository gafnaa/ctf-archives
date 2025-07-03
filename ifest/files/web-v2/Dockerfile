# Base lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install necessary dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app
COPY app/ .

# Expose the Flask port
EXPOSE 1337

# Run the app
CMD ["python", "main.py"]
