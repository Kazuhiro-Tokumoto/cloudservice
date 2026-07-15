#!/bin/sh
# Let's Encrypt (certbot) の更新時に証明書をサービスへ配るデプロイフック。
#
# インストール:
#   sudo cp deploy/letsencrypt-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/cloudservice.sh
#   sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/cloudservice.sh
#   初回は手動で一度実行しておく: sudo /etc/letsencrypt/renewal-hooks/deploy/cloudservice.sh
#
# これで config.json は以下のように書ける:
#   { "cert_dir": "certs", "cert_name": "mail" }
#
# privkey.pem は root しか読めないため、サービス用ユーザーが読めるように
# コピーして所有者を変えるこの方式を推奨する。
set -eu

DOMAIN="mail.shudo-physics.com"
APP_DIR="/opt/cloudservice"
APP_USER="cloudservice"

install -o "$APP_USER" -g "$APP_USER" -m 644 \
  "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$APP_DIR/certs/mail.crt"
install -o "$APP_USER" -g "$APP_USER" -m 600 \
  "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$APP_DIR/certs/mail.key"

systemctl try-restart cloudservice || true
echo "証明書を $APP_DIR/certs/mail.{crt,key} へ配置しました"
