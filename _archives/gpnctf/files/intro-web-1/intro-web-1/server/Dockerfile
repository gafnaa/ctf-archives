FROM node:22-alpine AS node_love

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY templates ./templates
COPY static ./static

RUN npm run build

FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=node_love /app/static ./static
COPY  . .

EXPOSE 9222
CMD python setup.py; python main.py
