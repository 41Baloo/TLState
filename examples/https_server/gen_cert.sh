openssl genrsa -out server.key 2048

openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"