# Вектор рукопожатия TLS 1.2

Издание: OpenSSL 3.3.1 4 Jun 2024 (Library: OpenSSL 3.3.1 4 Jun 2024)
Набор: ECDHE-ECDSA-CHACHA20-POLY1305
Кривая: X25519:P-256
Сертификат: ec256.crt
Дополнительно: нет
EMS в обмене: да
Обмен ключами:  X25519, 253 bits
Расширение renegotiation_info: 1

Команда сервера:
openssl s_server -accept ПОРТ -tls1_2 -cert ec256.crt -key ec256.pem -cipher ECDHE-ECDSA-CHACHA20-POLY1305 -curves X25519:P-256 -www -naccept 1 

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305 -curves X25519:P-256 -CAfile ec256.crt 

Файлы: handshake-c2s.bin и handshake-s2c.bin - поток по проводу как шёл, до Finished включительно;
отдельные сообщения нарезаны из незашифрованной части, сообщения клиента с приставкой client-.
