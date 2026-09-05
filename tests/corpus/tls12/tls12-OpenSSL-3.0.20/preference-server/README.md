# Вектор рукопожатия TLS 1.2

Издание: OpenSSL 3.0.20 7 Apr 2026 (Library: OpenSSL 3.0.20 7 Apr 2026)
Порядок наборов сервера: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256
Порядок наборов клиента: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384
Выбрано на деле: ECDHE-ECDSA-AES256-GCM-SHA384
Кто решает порядок: сервер (-serverpref)
Кривая: X25519:P-256 (обмен  X25519, 253 bits)
Сертификат: ec256.crt
EMS в обмене: да

Команда сервера:
openssl s_server -accept 127.0.0.1:ПОРТ -tls1_2 -cert ec256.crt -key ec256.pem -cipher ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256 -curves X25519:P-256 -www -naccept 1 -serverpref

Команда клиента:
openssl s_client -connect 127.0.0.1:ПОРТ -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384 -curves X25519:P-256 -CAfile ec256.crt
