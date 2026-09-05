# Вектор рукопожатия DTLS 1.2

Издание openssl: OpenSSL 3.0.20 7 Apr 2026 (Library: OpenSSL 3.0.20 7 Apr 2026)
Согласованное издание протокола: DTLSv1.2
Набор: ECDHE-RSA-AES128-GCM-SHA256 (выбрано ECDHE-RSA-AES128-GCM-SHA256)
Кривая: X25519
Сертификат: rsa2048.crt
Режим cookie (-listen у сервера): да
HelloVerifyRequest в обмене: да
EMS в обмене: да
Дополнительно: нет

Команда сервера:
openssl s_server -accept 127.0.0.1:ПОРТ -dtls1_2 -listen -cert rsa2048.crt -key rsa2048.pem -cipher ECDHE-RSA-AES128-GCM-SHA256 -curves X25519 -naccept 1 

Команда клиента (через съёмник провода):
openssl s_client -connect 127.0.0.1:ПОРТ -dtls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -curves X25519 -CAfile rsa2048.crt 

Файлы: c2s-NNN.bin и s2c-NNN.bin - КАЖДАЯ дейтаграмма отдельно, в порядке провода;
wire.txt - опись стороны, номера и длины; нарезанные сообщения взяты из открытых записей эпохи 0.
