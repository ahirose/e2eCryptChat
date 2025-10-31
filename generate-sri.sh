#!/bin/bash

# SRI (Subresource Integrity) ハッシュ生成スクリプト
# JavaScriptファイルを更新した後に実行してください

echo "=== SRI ハッシュ生成 ==="
echo ""

# crypto.js のハッシュ生成
echo "crypto.js:"
CRYPTO_HASH=$(openssl dgst -sha384 -binary public/crypto.js | openssl base64 -A)
echo "  sha384-${CRYPTO_HASH}"
echo ""

# client.js のハッシュ生成
echo "client.js:"
CLIENT_HASH=$(openssl dgst -sha384 -binary public/client.js | openssl base64 -A)
echo "  sha384-${CLIENT_HASH}"
echo ""

echo "=== index.html に追加するコード ==="
echo ""
echo '<script src="crypto.js"'
echo "        integrity=\"sha384-${CRYPTO_HASH}\""
echo '        crossorigin="anonymous"></script>'
echo '<script src="client.js"'
echo "        integrity=\"sha384-${CLIENT_HASH}\""
echo '        crossorigin="anonymous"></script>'
echo ""

echo "✓ ハッシュ生成完了"
echo ""
echo "注意: JavaScriptファイルを変更した場合は、"
echo "      index.htmlのintegrity属性を上記の値に更新してください。"
