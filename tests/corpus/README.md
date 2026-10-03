# Набор ключей для сличения A-NTS с openssl

Собран openssl 3.6.3 на macOS ARM64. Прогнан сборкой AWH с BoringSSL: 41 проверка из 41.

## Пароль

Пароль у всех `*.enc.pem` один: `Пароль-123`

Он **намеренно не из ASCII**: это кириллица в UTF-8, десять октетов при семи буквах.
Пароль в PBKDF2 идёт последовательностью октетов, а не текстом, и разбор,
который обрабатывает его как строку в местной кодировке, на таком пароле разойдётся,
а на `password` — нет.

## Состав

* `rsa2048`, `ec256`, `ec384`, `ed25519`, `x25519` — закрытый ключ (`.pem`, `.der`),
  открытый (`.pub.pem`, `.pub.der`) и закрытый под паролем в трёх разрядностях
  (`.aes-128-cbc.enc.pem`, `.aes-192-cbc.enc.pem`, `.aes-256-cbc.enc.pem`).
* `mldsa44`, `mldsa65`, `mldsa87` — самоподписанный сертификат ML-DSA (`.crt`) и его
  закрытый ключ PKCS #8 (`.pem`, форма «зерно и развёрнутый ключ»), выписаны местным
  openssl 3.6.3 (`openssl req -x509 -newkey ML-DSA-44/65/87`).
* `mldsa/` — контрольные примеры ML-DSA: записи ACVP и Wycheproof, переложенные
  сценарием `tools/sign/mldsa.py` из подмодуля OpenSSL (`keygen.txt`, `siggen.txt`,
  `sigver.txt`, `wycheproof{44,65,87}-{sign,verify}.txt`), и ключи шести видов записи
  из `15-test_ml_dsa_codecs_data` (`mldsaNN-seed-only`, `-priv-only`, `-seed-priv`,
  `-bare-seed`, `-bare-priv`, `-oqskeypair`, плюс открытый `-pub`).
* `ec256.sec1.pem` — SEC 1 ECPrivateKey, `rsa2048.pkcs1.pem` — PKCS #1 RSAPrivateKey.
* `chain-rsa.pem`, `chain-ec.pem` — цепочки из трёх звеньев: лист, промежуточный
  (`basicConstraints=critical,CA:TRUE`), корень. Звенья лежат и по отдельности.
* `chain-mldsa.pem` — такая же цепочка ML-DSA-65 по RFC 9881: лист
  (`test.anyks.com`), промежуточный, корень (`ca-mldsa.crt`, CA:TRUE, keyCertSign),
  выписана местным openssl 3.6.3; звенья и ключи — `ca-mldsa`, `mid-mldsa`,
  `leaf-mldsa` (`.crt`, `.pem`).
* `ca-long.crt` — корень со сроком 2015…2035, чтобы срок листа проверялся отдельно
  от срока издателя.
* `expired.crt` — лист со сроком 1…2 января 2020 года, издан `ca-long.crt`.
  Отвергается **только** по сроку: `openssl verify -no_check_time` его принимает.
* `future.crt` — лист, вступающий в силу в 2034 году, тот же издатель.

  Прежняя выдача `expired.crt` была с изъяном: лист 2020 года был издан корнем,
  действующим с 2026, и проверка спотыкалась о полномочия издателя раньше, чем
  о срок листа.
* `data.bin` и подписи по нему: `sig.rsa.sha256`, `sig.ec256.sha256`,
  `sig.ec384.sha384`, `sig.ed25519`, а также `sig.leaf-ec.sha256` и
  `sig.leaf-rsa.sha256` — ключами листьев цепочек, для подписи владения по TLS 1.3.
  Подпись листа EC — обычная ECDSA в DER, подпись листа RSA — **RSASSA-PSS**
  с солью в длину хеша: TLS 1.3 запрещает в `CertificateVerify` схему PKCS #1 v1.5,
  и разбор, принимающий там v1.5, нарушает RFC 8446 §4.4.3.

## Ответы и запросы OCSP (`ocsp/`)

Выработаны тем же openssl 3.6.3 4 сентября 2026 года для набора `tests/ocsp`; сроки
ответов — десять лет (`-ndays 3650`), кроме `leaf-ec.short.der` (`-ndays 1`) и
`leaf-ec.open.der` (без `-ndays`: `nextUpdate` отсутствует). Проверки судят сроки
заданным мигом, а не часами, оттого набор не стареет.

* Запросы: `leaf-ec.req.der` (`openssl ocsp -issuer mid-ec.crt -cert leaf-ec.crt -no_nonce
  -reqout`), `leaf-ec.sha256.req.der` (`-sha256` перед `-cert`), `leaf-ec.nonce.req.der`
  (с неповторимым значением `877D8EA1976289F08DDE9109E479CC21`), `leaf-rsa.req.der`,
  `ec256.req.der` (самоподписанный лист как свой издатель). `ocsp::request` сходится с ними
  байт в байт.
* Ответы по `leaf-ec.crt` издателем `mid-ec.crt` (`openssl ocsp -index … -rsigner mid-ec.crt
  -rkey mid-ec.key -CA mid-ec.crt -reqin … -respout …`): `leaf-ec.good.der`,
  `leaf-ec.revoked.der` (индекс с отзывом 1 сентября 2026), `leaf-ec.unknown.der` (пустой
  индекс), `leaf-ec.short.der`, `leaf-ec.open.der`, `leaf-ec.nonce.der`, `leaf-ec.sha256.der`.
  Индексы: `index-good.txt`, `index-revoked.txt`.
* Делегированный ответчик `ocsp-ec.crt` (издан `mid-ec.crt`, `extendedKeyUsage=OCSPSigning`):
  `leaf-ec.delegated.der` (назван именем) и `leaf-ec.delegated.rid.der` (`-resp_key_id`, назван
  хешем ключа). Ответчик без назначения `bogus-ec.crt`: `leaf-ec.unauthorized.der`. Чужой
  ответчик `ec256.crt`, издателем не изданный: `leaf-ec.foreign.der`.
* `leaf-rsa.good.der` — издателем `mid-rsa.crt` с `-rmd sha256`.
* Самоподписанные листы как свои издатели: `ec256.good.der`, `ec256.revoked.der`,
  `ec384.good.der`, `rsa2048.good.der`, `rsa2048.revoked.der`. Ответ ключом `ed25519` openssl
  выработать не умеет (`internalerror`): ветвь Ed25519 проверяется подписью ответчика лишь
  через `x509::verify`.
* `aia-ec.crt` — лист от `mid-ec.crt` с расширением сведений о доступе к издателю:
  `OCSP;URI:http://ocsp.anyks.com/ec` и `caIssuers`.

Ответ ГОСТ в наборе не лежит: он вырабатывается проверкой `OcspTest.Gost` своими средствами
на самоподписанном сертификате ГОСТ из `tests/identity.hpp` — движка ГОСТ у системного
openssl нет.

## Защита ключа под паролем

`openssl asn1parse` по любому `.enc.pem`: PBES2, PBKDF2, оборотов `0x0800` (2048),
PRF `hmacWithSHA256`, шифр по имени файла. Число оборотов брать **из файла**:
у openssl их 2048, а у нас в `awh::Crypto` для своего шифрования 100 000.

## Длины подписей

* ECDSA в DER — **переменная**: у P-256 от 70 до 72 октетов.
* Ed25519 — ровно 64, RSA-2048 — ровно 256.

## Сертификаты второго круга TLS 1.2 (правки по аудиту, 06.09.2026)

Проверка `Tls12Test.Feeble` судит пригодность сертификата сервера обмену по разделам 7.4.2
и 7.4.7.1 RFC 5246: длину ключа при обмене шифрованием RSA и назначение ключа.

* `rsa1024.pem`, `rsa1024.crt` — самоподписанный лист с ключом RSA-1024: клиент отвергает
  его при обмене шифрованием RSA (`bad_certificate`), нижняя граница 2048 разрядов.
  `openssl req -x509 -newkey rsa:1024 -nodes -keyout rsa1024.pem -out rsa1024.crt
  -subj "/CN=anyks-rsa1024" -days 3650 -sha256`
* `rsa2048-sign.crt` — лист на ключе `rsa2048.pem` с `keyUsage=critical,digitalSignature`:
  годен ECDHE_RSA (подписанный обмен), негоден обмену шифрованием RSA (нет keyEncipherment).
  `openssl req -x509 -key rsa2048.pem -out rsa2048-sign.crt -subj "/CN=anyks-rsa2048-sign"
  -days 3650 -sha256 -addext "keyUsage=critical,digitalSignature"`
* `rsa2048-encipher.crt` — тот же ключ с `keyUsage=critical,keyEncipherment`: наоборот, годен
  обмену RSA и негоден ECDHE_RSA.
  `openssl req -x509 -key rsa2048.pem -out rsa2048-encipher.crt
  -subj "/CN=anyks-rsa2048-encipher" -days 3650 -sha256 -addext "keyUsage=critical,keyEncipherment"`

`rsa2048.crt` расширения назначения ключа не несёт, и обоим обменам годен. Замер стойкости
обмена RSA ко времени (`bench/bench.cpp`) читает `rsa2048.pem` и `rsa2048.crt` отсюда же.
