# Вектор рукопожатия DTLS 1.2

Издание openssl: OpenSSL 3.0.15 3 Sep 2024 (Library: OpenSSL 3.0.15 3 Sep 2024)
Согласованное издание протокола: DTLSv1.2
Набор: ECDHE-ECDSA-AES128-GCM-SHA256 (выбрано ECDHE-ECDSA-AES128-GCM-SHA256)
Кривая: X25519:P-256
Сертификат: ec256.crt
Режим cookie (-listen у сервера): да
HelloVerifyRequest в обмене: да
EMS в обмене: да
Дополнительно: -Verify 1 -CAfile tests/corpus/ec256.crt

Команда сервера:
openssl s_server -accept 127.0.0.1:ПОРТ -dtls1_2 -listen -cert ec256.crt -key ec256.pem -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -curves X25519:P-256 -naccept 1 -Verify 1 -CAfile tests/corpus/ec256.crt

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -dtls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256 -curves X25519:P-256 -CAfile ec256.crt -Verify 1 -CAfile tests/corpus/ec256.crt

Файлы: c2s-NNN.bin и s2c-NNN.bin - КАЖДАЯ дейтаграмма отдельно, в порядке провода;
wire.txt - опись стороны, номера и длины; нарезанные сообщения взяты из открытых записей эпохи 0.
