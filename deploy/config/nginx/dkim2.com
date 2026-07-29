server {
    listen 80;
    server_name dkim2.com www.dkim2.com;
    include snippets/acme-challenge.conf;
    location / { return 301 https://dkim2.com$request_uri; }
}

server {
    listen 443 ssl;
    server_name www.dkim2.com;
    ssl_certificate     /etc/letsencrypt/live/dkim2.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dkim2.com/privkey.pem;
    return 301 https://dkim2.com$request_uri;
}

server {
    listen 443 ssl default_server;
    server_name dkim2.com;
    ssl_certificate     /etc/letsencrypt/live/dkim2.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dkim2.com/privkey.pem;
    root /var/www/dkim2.com;
    index index.html;

    location = /validate/api {
        client_max_body_size 512k;
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /usr/local/bin/dkim2-validate.cgi;
        fastcgi_pass unix:/run/fcgiwrap.socket;
    }

    location / { try_files $uri $uri/ =404; }
}
