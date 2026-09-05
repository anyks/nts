# Вектор рукопожатия TLS 1.2

Издание: OpenSSL 3.5.0 8 Apr 2025 (Library: OpenSSL 3.5.0 8 Apr 2025)
Набор: ECDHE-RSA-CHACHA20-POLY1305
Кривая: X25519
Сертификат: rsa2048.crt
Дополнительно: нет
EMS в обмене: да
Обмен ключами:  X25519, 253 bits
Расширение renegotiation_info: 1

Команда сервера:
openssl s_server -accept ПОРТ -tls1_2 -cert rsa2048.crt -key rsa2048.pem -cipher ECDHE-RSA-CHACHA20-POLY1305 -curves X25519 -www -naccept 1 

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305 -curves X25519 -CAfile rsa2048.crt 

Файлы: handshake-c2s.bin и handshake-s2c.bin - поток по проводу как шёл, до Finished включительно;
отдельные сообщения нарезаны из незашифрованной части, сообщения клиента с приставкой client-.
