server {
    listen 80;
    server_name mailman.dkim2.com;
    include snippets/acme-challenge.conf;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    server_name mailman.dkim2.com;

    ssl_certificate /etc/letsencrypt/live/mailman.dkim2.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mailman.dkim2.com/privkey.pem;

    location /static/ {
        alias /var/lib/mailman3/web/static/;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
