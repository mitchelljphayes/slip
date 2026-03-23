FROM nginx:alpine
# Override default config to add a /health endpoint
RUN echo 'server { listen 3000; location /health { return 200 "ok"; add_header Content-Type text/plain; } location / { return 200 "hello from slip test app"; add_header Content-Type text/plain; } }' > /etc/nginx/conf.d/default.conf
EXPOSE 3000
