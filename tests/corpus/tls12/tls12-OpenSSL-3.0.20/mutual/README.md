# Вектор рукопожатия TLS 1.2

Издание: OpenSSL 3.0.20 7 Apr 2026 (Library: OpenSSL 3.0.20 7 Apr 2026)
Набор: ECDHE-ECDSA-AES128-GCM-SHA256
Кривая: X25519:P-256
Сертификат: ec256.crt
Дополнительно: -Verify 1 -CAfile tests/corpus/ec256.crt
EMS в обмене: да
Обмен ключами:  X25519, 253 bits
Расширение renegotiation_info: 1

Команда сервера:
openssl s_server -accept ПОРТ -tls1_2 -cert ec256.crt -key ec256.pem -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -curves X25519:P-256 -www -naccept 1 -Verify 1 -CAfile tests/corpus/ec256.crt

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -curves X25519:P-256 -CAfile ec256.crt -Verify 1 -CAfile tests/corpus/ec256.crt

Файлы: handshake-c2s.bin и handshake-s2c.bin - поток по проводу как шёл, до Finished включительно;
отдельные сообщения нарезаны из незашифрованной части, сообщения клиента с приставкой client-.
