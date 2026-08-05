# Port 80 vhost for mail.dkim2.com — exists only to serve ACME http-01
# challenges via webroot so certbot can renew the Postfix SMTP TLS cert.
server {
    listen 80;
    server_name mail.dkim2.com;
    include snippets/acme-challenge.conf;
    location / { return 404; }
}
