external_url 'https://gitlab.example.com'

gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = YAML.load <<-EOS
main:
    label: 'IdM'
    host: 'idm.example.com'
    port: 389
    uid: 'uid'
    method: 'plain'
    bind_dn: 'uid=ldap_search,cn=users,cn=accounts,dc=example,dc=com'
    password: 'XXXXXXXXXXX'
    base: 'cn=accounts,dc=example,dc=com'
    group_base: 'cn=groups,cn=accounts,dc=example,dc=com'
    user_filter: 'memberOf=cn=gitlab-users,cn=groups,cn=accounts,dc=example,dc=com'
    allow_username_or_email_login: true
EOS

gitlab_rails['omniauth_enabled'] = false
gitlab_rails['backup_path'] = "/var/opt/gitlab/backups"
gitlab_rails['backup_archive_permissions'] = 0644
gitlab_rails['backup_keep_time'] = 604800

gitlab_rails['rack_attack_git_basic_auth'] = {
   'enabled' => true,
   'ip_whitelist' => ["127.0.0.1","127.0.0.2","127.0.0.3"],
   'maxretry' => 6,
   'findtime' => 60,
   'bantime' => 3600
}

gitlab_rails['rack_attack_protected_paths'] = [
   '/users/password',
   '/users/sign_in'
]

gitlab_rails['rate_limit_requests_per_period'] = 10
gitlab_rails['rate_limit_period'] = 60

gitlab_rails['smtp_enable'] = true
gitlab_rails['smtp_address'] = "smtp.gmail.com"
gitlab_rails['smtp_port'] = 587
gitlab_rails['smtp_user_name'] = "gitlab@example.com"
gitlab_rails['smtp_password'] = "XXXXXXXXXX"
gitlab_rails['smtp_domain'] = "smtp.gmail.com"
gitlab_rails['smtp_authentication'] = "login"
gitlab_rails['smtp_enable_starttls_auto'] = true
gitlab_rails['smtp_tls'] = false

gitlab_rails['smtp_openssl_verify_mode'] = 'peer'

nginx['client_max_body_size'] = "128m"
nginx['redirect_http_to_https'] = true
nginx['redirect_http_to_https_port'] = 80

nginx['ssl_certificate'] = "/etc/letsencrypt/live/gitlab.example.com/fullchain.pem"
nginx['ssl_certificate_key'] = "/etc/letsencrypt/live/gitlab.example.com/privkey.pem"

nginx['ssl_protocols'] = "TLSv1 TLSv1.1 TLSv1.2"
nginx['ssl_session_cache'] = "builtin:1000 shared:SSL:10m"
nginx['ssl_session_timeout'] = "10m"


nginx['custom_gitlab_server_config'] = "location ^~ /.well-known { root /usr/share/nginx/html/gitlab; }"

nginx['worker_processes'] = 4
nginx['worker_connections'] = 1024
nginx['sendfile'] = 'on'
nginx['tcp_nopush'] = 'on'
nginx['gzip'] = "on"
nginx['gzip_comp_level'] = "4"
nginx['gzip_types'] = [ "text/plain", "text/css", "application/x-javascript", "text/xml", "application/xml", "application/xml+rss", "text/javascript", "application/json" ]
nginx['keepalive_timeout'] = 60

nginx['status'] = {
  "enable" => true,
  "listen_addresses" => ["127.0.0.1"],
  "port" => 10061,
  "options" => {
    "stub_status" => "on", # Turn on stats
    "server_tokens" => "off", # Don't show the version of NGINX
    "access_log" => "off", # Disable logs for stats
    "allow" => "127.0.0.1", # Only allow access from localhost
  }
}
