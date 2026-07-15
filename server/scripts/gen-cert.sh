#!/bin/sh
# 自己署名証明書を certs/ フォルダに生成するスクリプト(開発・身内利用向け)
# 使い方: ./scripts/gen-cert.sh <証明書名> [ホスト名またはIP]
# 例:     ./scripts/gen-cert.sh myserver 192.168.1.10
# 生成後、config.json の cert_name に <証明書名> を設定する。
set -eu

NAME="${1:?使い方: gen-cert.sh <証明書名> [ホスト名またはIP]}"
HOST="${2:-localhost}"
DIR="$(dirname "$0")/../certs"
mkdir -p "$DIR"

case "$HOST" in
  *[0-9].[0-9]*) SAN="IP:$HOST,DNS:localhost" ;;
  *)             SAN="DNS:$HOST,DNS:localhost" ;;
esac

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout "$DIR/$NAME.key" -out "$DIR/$NAME.crt" \
  -subj "/CN=$HOST" -addext "subjectAltName=$SAN"

chmod 600 "$DIR/$NAME.key"
echo "生成しました: $DIR/$NAME.crt / $DIR/$NAME.key"
echo "config.json の \"cert_name\" に \"$NAME\" を設定してください。"
