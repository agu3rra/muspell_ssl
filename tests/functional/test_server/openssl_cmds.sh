openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
cat key.pem > localhost.pem
cat certificate.pem >> localhost.pem
