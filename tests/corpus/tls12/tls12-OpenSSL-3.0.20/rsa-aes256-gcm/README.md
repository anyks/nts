# Вектор рукопожатия TLS 1.2

Издание: OpenSSL 3.0.20 7 Apr 2026 (Library: OpenSSL 3.0.20 7 Apr 2026)
Набор: ECDHE-RSA-AES256-GCM-SHA384
Кривая: P-384
Сертификат: rsa2048.crt
Дополнительно: нет
EMS в обмене: да
Обмен ключами:  ECDH, secp384r1, 384 bits
Расширение renegotiation_info: 1

Команда сервера:
openssl s_server -accept ПОРТ -tls1_2 -cert rsa2048.crt -key rsa2048.pem -cipher ECDHE-RSA-AES256-GCM-SHA384 -curves P-384 -www -naccept 1 

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384 -curves P-384 -CAfile rsa2048.crt 

Файлы: handshake-c2s.bin и handshake-s2c.bin - поток по проводу как шёл, до Finished включительно;
отдельные сообщения нарезаны из незашифрованной части, сообщения клиента с приставкой client-.
