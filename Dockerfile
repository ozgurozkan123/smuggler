FROM node:20-bullseye

# Install system dependencies and Python for Smuggler
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip python3-venv git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Fetch Smuggler python script
RUN git clone https://github.com/defparam/smuggler /opt/smuggler

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN npm run build

ENV HOST=0.0.0.0
ENV PORT=3000
ENV PYTHON_BIN=python3
ENV SMUGGLER_PATH=/opt/smuggler/smuggler.py

EXPOSE 3000

CMD ["npm", "start"]
