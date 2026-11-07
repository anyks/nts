/**
 * @file engine.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл внутреннего модуля ведения связи протокола TLS 1.3 и TLS 1.2
 *
 * @section Намеренные решения
 *
 * 1. Обе роли ведёт один модуль. Клиент и сервер проходят одно и то же рукопожатие с
 *    разных его концов, и почти всё у них общее: расписание ключей, защита записей,
 *    переписка и проверки. Две отдельные связи пришлось бы держать согласованными вручную.
 *
 * 2. Пора ключей записи берётся до объявления сообщения ходу рукопожатия. Приветствие
 *    сервера уходит открытым, а защита появляется лишь за ним: объяви сообщение раньше -
 *    и приветствие ушло бы ключами, которых у встречной стороны ещё нет.
 *
 * 3. Цепочка сертификатов собеседника не проверяется на доверие. Связь сличает подпись
 *    владения ключом с ключом предъявленного сертификата - этим рукопожатие и привязано к
 *    той стороне, - а вот доверие к издателю решается запасом доверенных сертификатов,
 *    которого у связи нет и который принадлежит тому, кто связь ведёт.
 *
 * 4. Ключи завершения рукопожатия снимаются сразу за выводом ступени рукопожатия.
 *    Переход к ступени прикладных данных значения направлений связи переписывает, а
 *    завершение клиента идёт уже после этого перехода.
 *
 * 5. Отказ связи необратим. Всякий отказ рукопожатия смертелен по разделу 6.2 RFC 8446, и
 *    единственное, что после него делают, - отправляют извещение и рвут связь.
 *
 * 6. Перенос по уровням (RFC 9001) ведёт тот же ход рукопожатия, что и записи. Различие
 *    лежит в одном лишь месте складывания и подачи: сообщение уходит в накопитель уровня
 *    своей поры ключей вместо записи, а принимается с пометкой уровня и сверяется с порой
 *    ключей собеседника. Защита записей в этом переносе не заводится вовсе: ключи уровней
 *    выдаются наружу значениями направлений, а шифрует ими тот, кто связь ведёт.
 *
 * 7. Извещение в переносе по уровням не складывается никуда. Раздел 4.8 RFC 9001 велит
 *    нести его кодом закрытия связи QUIC, и код этот берётся из описания извещения,
 *    которым связь оборвана.
 *
 * 8. Издание TLS 1.2 ведёт тот же движок, но своей ступенью, а не ходом рукопожатия
 *    flow: порядок сообщений там иной (RFC 5246, раздел 7.3), защита включается сменой
 *    набора шифрования, а ключи выводятся порождающей функцией, а не расписанием HKDF.
 *    Издание согласуется по supported_versions (раздел 4.2.1 RFC 8446) либо по заголовку
 *    приветствия (приложение D), и предлагается лишь тогда, когда у связи есть наборы
 *    этого издания. Только ECDHE, только AEAD, расширенный главный секрет (RFC 7627)
 *    предлагается всегда, а требуется по настройке (решение 16), пересогласование (RFC 5746)
 *    отвергается, билетов и возобновления нет.
 *
 * 9. Заслон понижения (раздел 4.1.3 RFC 8446) сервер кладёт по своей способности к 1.3,
 *    а не по предложению клиента, и способность эта складывается из предела издания и
 *    наличия хоть одного набора 1.3: сервер одного лишь 1.2 - по пределу либо по наборам -
 *    его не кладёт, ибо клиент издания 1.3 (openssl в том числе) счёл бы законный выбор
 *    1.2 подменой. Клиент судит заслон 1.3 лишь тогда, когда сам предлагал 1.3.
 *
 * 10. В издании 1.2 схема ECDSA именует лишь хеш (раздел 7.4.1.4.1 RFC 5246): подпись
 *    ecdsa_sha256 ключом P-384 законна, и сличение кривой схемы с кривой ключа ведётся
 *    лишь изданием 1.3. Схемы PKCS #1 v1.5 объявляются приветствием лишь при предложении
 *    1.2 и в подписи владения ключом 1.3 не признаются.
 *
 * 11. Предел записей на ключе изданием 1.2 не сменить: KeyUpdate там нет. Дойдя своим
 *    направлением до предела набора (2^24.5 записей у AES-GCM по разделу 5.5 RFC 8446)
 *    либо до порога, поставленного ручкой renewal, связь шлёт close_notify и отвечает
 *    отказом EXHAUSTED; записи собеседника за пределом отвергаются защитой как есть.
 *
 * 12. Пересогласование изданием 1.2 отвергается предупреждением, а не обрывом: раздел 7.2.2
 *    RFC 5246 велит слать no_renegotiation уровня предупреждения, и связь продолжается
 *    прежними ключами - как на HelloRequest у клиента, так и на приветствие клиента у
 *    сервера. Обрывает связь после этого лишь сам собеседник, если сочтёт отказ роковым.
 *
 * 13. За согласованием издания 1.2 всякая запись собеседника обязана нести в заголовке
 *    издание 0x0303 (приложение E.1 RFC 5246), иначе - protocol_version; первому
 *    приветствию клиента у сервера дозволены и меньшие издания заголовка. Издание
 *    заголовка входит в связанные данные защищённой записи таким, каким пришло.
 *
 * 14. Издание DTLS 1.2 (RFC 6347) - то же рукопожатие 1.2 поверх переноса дейтаграммами:
 *    пределы versions распространяются на дейтаграммы (0x0303 - DTLS 1.2 0xFEFD, 0x0304 -
 *    DTLS 1.3 0xFEFC), клиент предлагает оба издания по пределу, сервер выбирает высшее
 *    общее. Сервер без состояния отвечает на первое приветствие HelloVerifyRequest с
 *    изданием DTLS 1.0 в теле и в заголовке записи (по букве раздела 4.2.1, как у openssl)
 *    и меткой по адресу и хешу приветствия; приветствие с негодной меткой отбрасывается
 *    молча, дроблёное собирается под пределами (решение 13 переноса), а у строгого
 *    сервера (strict) отбрасывается. Просьба и первое приветствие в
 *    переписку не ложатся, а сама переписка ведётся сообщениями в обвязке DTLS без учёта
 *    дробления (раздел 4.2.6). Смена набора шифрования идёт записью в залпе и повышает
 *    пору; последний залп сервера повторяется лишь по повтору завершения клиента. Билетов,
 *    SRTP, опознавателя связи и пересогласования у DTLS 1.2 нет.
 *
 * 15. Расширение перечня изданий (supported_versions, раздел 4.2.1 RFC 8446) клиент кладёт в
 *    приветствие лишь когда перечень несёт сведения сверх заголовка: предлагается издание 1.3
 *    либо DTLS 1.0 наравне с 1.2 (BoringSSL кладёт 1.0 в перечень). При одном лишь издании 1.2
 *    - versions(0x0303, 0x0303) - приветствие идёт без 0x002B, как у openssl: издание сервер
 *    берёт из заголовка. Установлено
 *    независимым щупом эталоном одной разницы: LibreSSL 3.6.1 в DTLS обрывает связь
 *    protocol_version на самом расширении, а без него ведёт рукопожатие обычным ходом.
 *
 * 16. Расширенный главный секрет (RFC 7627) предлагается клиентом и подтверждается сервером
 *    всегда, но ТРЕБУЕТСЯ лишь по настройке master(true): умолчанием, как у openssl и
 *    BoringSSL, собеседник без расширения ведёт связь обычным главным секретом (раздел 8.1
 *    RFC 5246 - метка «master secret» и случайные значения сторон), а сервер эхом отвечает
 *    расширением лишь клиенту, его предложившему (раздел 5.2 RFC 7627). Прежняя безусловная
 *    обязательность выделяла нас среди эталонов: LibreSSL 3.6.1 RFC 7627 не ведёт вовсе, и
 *    издание 1.2 с ним не сходилось ни в одну сторону (независимый щуп на DragonFly).
 *    Обязательность закрывает тройное рукопожатие и остаётся доступной настройкой.
 * 17. Ключевой материал, живущий МЕЖДУ вызовами, лежит не в обычной куче, а в укрытом
 *    хранилище процесса (sys::Vault): главный секрет издания 1.2, ключи завершения,
 *    ключи и векторы прикладных данных, ключи имитовставки CBC и значения направлений
 *    - одной структурой keys_t в одном участке; общее значение обмена и заранее
 *    разделённый ключ - наборами sys::bytes_t над тем же хранилищем; так же значения
 *    расписания (session::Secrets) и ключи билетов (ticket::Keeper). Хранилищу запрещена
 *    подкачка (mlock/VirtualLock), оно укрыто от снимков памяти (MADV_DONTDUMP/NOCORE, где
 *    есть), а потомку процесса достаётся затёртым (MADV_WIPEONFORK, INHERIT_ZERO либо
 *    обработчик pthread_atfork); освобождённый участок затирается в момент возврата.
 *    Хранилище одно на процесс, а не своё у связи: право на запрет подкачки ограничено
 *    RLIMIT_MEMLOCK, и страница на связь исчерпала бы его на десятке связей. Понижение
 *    укрытия умолчанием не отказ, а честный доклад Vault::shelter(); кому понижение
 *    непозволительно, зовёт Vault::demand(true) - тогда связь без укрытого участка негодна
 *    с рождения (FAILED, MEMORY). Значения, живущие вызовом (буферы открытого текста,
 *    промежуточные общие значения на стеке и в местных наборах), укрытия не требуют и
 *    затираются по-прежнему. Заказ - требование 2а AWH-KEY-EMBEDDING.md по карте сроков
 *    жизни ключевого материала.
 *
 * 18. Секретный ключ подлинности готовится один раз, а не на каждой подписи. До круга 29
 *    (22.09.2026) всякая подпись владения ключом и всякое расшифрование обмена RSA
 *    разбирали запись PKCS #8 заново и заводили ключ в модуле подписи с его проверками
 *    и предвычислениями: у RSA-2048 это стоило вдвое дороже самой подписи, у ECDSA -
 *    вдвое дороже всего рукопожатия. Теперь подлинность несёт подготовленный ключ
 *    (keys::Signer) общим указателем: потребитель готовит его вызовом prepare() один
 *    раз, и все связи с этой подлинностью делят его; подпись и расшифрование состояния
 *    ключа не меняют, потому разделение между потоками безопасно. Связь сличает
 *    отпечаток подготовки с байтами ключа и сертификата и устаревшую подготовку не
 *    использует, а без подготовки готовит ключ сама в своей копии подлинности при
 *    первой надобности - верно, но дорого. Закреплено проверками ContextTest.Prepared
 *    и ContextTest.Outdated.
 * 19. Умолчания связи - наибольшая совместимость, а ГОСТ включает потребитель. До круга
 *    30 (23.09.2026) перечни умолчаний шли с ГОСТ впереди: клиент слал долю ключа лишь
 *    по GC512C, и всякий собеседник без ГОСТ (OpenSSL, браузеры) отвечал просьбой о
 *    повторе - лишний круг по сети, зря выработанная пара на кривой 512 бит и потеря
 *    упреждающих данных. Теперь умолчания - классика, как у браузеров и OpenSSL 3.5:
 *    группы X25519MLKEM768, X25519, secp256r1, secp384r1 с долями по гибриду и по
 *    X25519 (сервер без ML-KEM берёт долю кривой без повтора), наборы AES-256-GCM,
 *    ChaCha20-Poly1305, AES-128-GCM и наборы издания 1.2, схемы подписи ECDSA, RSA-PSS,
 *    Ed25519, RSA PKCS #1. Кривых, наборов и схем ГОСТ в умолчаниях нет вовсе: кому
 *    нужен ГОСТ, тот объявляет их сам перечнями groups(), suites() и schemes() - как
 *    поддержку рядом с классикой либо как единственный вариант; связь с подлинностью
 *    ГОСТ без объявленных схем ГОСТ подписать ничего не сможет, и это не дефект, а
 *    отсутствие объявления. Порядок перечня - это и есть предпочтение: без назначения
 *    долей клиент шлёт долю по первой группе и по первой группе каждого ещё не
 *    представленного рода (кривые ГОСТ, гибриды с ML-KEM, классические кривые), потому
 *    у клиента с объявленным ГОСТ доля ГОСТ есть всегда, а сервер выбирает набор и
 *    кривую своим порядком (ручка preference(true), умолчание) либо порядком клиента
 *    (preference(false)) - изданиями 1.3 и 1.2 одинаково. Так сервер с ГОСТ впереди
 *    своего перечня берёт у всякого клиента с поддержкой ГОСТ именно ГОСТ, а у клиента
 *    без ГОСТ - классику, и всё без просьбы о повторе. Закреплено проверками
 *    ContextTest.Defaults, ContextTest.Compatible, ContextTest.Gost и
 *    ContextTest.Preference.
 *
 * 20. Что связь затирает - выбирает потребитель классами context::wiping_t (круг 32,
 *    23.09.2026). Затирание секретов на путях движка идёт единственным входом purge()
 *    по классу SECRETS (умолчание); затирание накопителей открытого текста принятых
 *    записей (_plain, _opened, содержимое снятых дейтаграмм) - входом cleanse() по
 *    классу PLAINTEXT, умолчанием выключенному: оно стоит на каждую запись, а защищает
 *    лишь окно до следующей записи - копия, выданная потребителю вызовом read, ему
 *    недоступна. У OpenSSL то же самое - SSL_OP_CLEANSE_PLAINTEXT, умолчанием
 *    выключенная; BoringSSL открытый текст записей не затирает вовсе. Классов не
 *    касаются затирания по договору своего объекта: укрытое хранилище при возврате
 *    участка, разрушители значений (Exchange, билет, PSK), примитивы при сбросе
 *    состояния и во временных буферах вызова (защита записей ГОСТ и CBC). Голых
 *    вызовов wipe() в движке нет: всякое затирание идёт через purge() либо cleanse().
 *    Закреплено AuditTest.PlaintextCleansing (накопители нулевые лишь с классом),
 *    AuditTest.SecretsViaPurge (голых wipe() в движке нет) и ContextTest.Wiping.
 *
 * 21. Прикладные данные с провода до потребителя без копий (круг 56, 30.09.2026). Запись
 *    ключей связи издания 1.3 вскрывается прямо в накопитель прикладных данных _plain
 *    (снятие защиты дописывает в конец): прикладные данные остаются на месте, содержимое
 *    иного вида переносится в _opened, а хвост _plain отзывается retract() - затирается
 *    по классу PLAINTEXT и отбрасывается; так же отзывается содержимое записи на всяком
 *    отказе и пропуске между вскрытием и приёмом. Потребителю данные выдаются обменом
 *    накопителей (read - swap), прежний накопитель потребителя остаётся движку под
 *    следующие записи и затирается по классу. Копия в 16 КиБ стоит 0,9 мкс на Xeon, и две
 *    копии стоили десятую часть записи: путь записи 18,8 → 17,1 мкс при 17,7…18,1 у
 *    OpenSSL (SSL_write и SSL_read через пару BIO). Пути упреждающих данных, издания 1.2 и
 *    дейтаграмм идут через _opened по-прежнему. Закреплено AuditTest.PlaintextCleansing
 *    (после read открытого текста в движке нет, прежний накопитель потребителя и _opened
 *    затёрты лишь с классом) и проверками записей ContextTest.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <sign/rsa.hpp>
#include <sign/ecdsa.hpp>
#include <sign/ed25519.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>
#include <asn1/asn1.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <agreement/x25519.hpp>
#include <agreement/x448.hpp>
#include <agreement/ffdhe.hpp>
#include <agreement/mlkem.hpp>
#include <field/field.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <x509/signature.hpp>
#include <digest/streebog.hpp>
#include <agreement/ecdhe.hpp>
#include <internal/engine/engine.hpp>
#include <sys/wipe.hpp>
#include <sys/log.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Заслоны понижения издания протокола
	 *
	 * @details Раздел 4.1.3 RFC 8446: сервер, знающий издание 1.3, но выбравший
	 *          издание пониже, кладёт эти восемь байтов в хвост своего случайного
	 *          значения - и клиент, знающий издание 1.3, обязан на них оборваться
	 *
	 */
	static const uint8_t DOWNGRADE[2][8] = {
		// Строка «DOWNGRD» с окончанием 01 и 00: понижение до изданий 1.2 и 1.1
		{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01},
		{0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00}
	};

	/**
	 * Предел числа просьб о подтверждении адреса HelloVerifyRequest, принимаемых клиентом за
	 * рукопожатие: сервер, сменивший секрет метки, вправе спросить заново, а зацикливание -
	 * оплошность собеседника (раздел 4.2.1 RFC 6347)
	 */
	static constexpr uint8_t QUERIES = 3;

	/**
	 * @brief Случайное значение приветствия сервера, назначенное просьбе о повторе
	 *
	 * @details Раздел 4.1.3 RFC 8446: хеш SHA-256 строки «HelloRetryRequest»
	 *
	 */
	static const uint8_t RETRY[32] = {
		// Хеш SHA-256 строки «HelloRetryRequest» по байтам записи
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};

	/**
	 * Схемы подписи, предлагаемые связью по умолчанию: лишь классические. Схем ГОСТ
	 * (S256A…S512C) в умолчании нет - их потребитель объявляет сам перечнем schemes(),
	 * как поддержку рядом с классикой либо как единственный вариант (намеренное
	 * решение 19)
	 */
	static const extension::scheme_t SCHEMES[] = {
		// Классические схемы по умолчанию: ECDSA, RSA-PSS, ED25519, RSA PKCS #1
		extension::scheme_t::ECDSA_SECP256R1_SHA256, extension::scheme_t::ECDSA_SECP384R1_SHA384,
		extension::scheme_t::ECDSA_SECP521R1_SHA512,
		extension::scheme_t::RSA_PSS_RSAE_SHA256, extension::scheme_t::RSA_PSS_RSAE_SHA384,
		extension::scheme_t::RSA_PSS_RSAE_SHA512, extension::scheme_t::ED25519,
		extension::scheme_t::RSA_PKCS1_SHA256, extension::scheme_t::RSA_PKCS1_SHA384,
		extension::scheme_t::RSA_PKCS1_SHA512
	};

	/**
	 * Издание протокола TLS 1.2 и издание TLS 1.3
	 */
	static constexpr uint16_t LEGACY = 0x0303;
	/**
	 * Издание TLS 1.1 в кодах TLS: изданию DTLS 1.0 (RFC 4347) отвечает именно оно
	 */
	static constexpr uint16_t ANCIENT = 0x0302;
	/**
	 * Издание TLS 1.3 в кодах TLS
	 */
	static constexpr uint16_t MODERN = 0x0304;

	/**
	 * Длина завершения рукопожатия издания TLS 1.2: раздел 7.4.9 RFC 5246
	 */
	static constexpr size_t VERIFIED = 12;

	/**
	 * Метки порождающей функции издания TLS 1.2: раздел 4 RFC 7627, разделы 6.3 и 7.4.9 RFC 5246
	 */
	static const char * EXTENDED = "extended master secret";
	// Метка главного секрета
	static const char * MASTER = "master secret";
	// Метка расширения ключа
	static const char * EXPANSION = "key expansion";
	// Метка завершения рукопожатия клиента
	static const char * CLIENT_FINISHED = "client finished";
	// Метка завершения рукопожатия сервера
	static const char * SERVER_FINISHED = "server finished";

	/**
	 * Тело расширения renegotiation_info у стороны, пересогласований не ведавшей:
	 * раздел 3.2 RFC 5746 - пустой перечень с однобайтовой длиной
	 */
	static const uint8_t RENEGOTIATION[] = {0x00};

	/**
	 * Тело расширения ec_point_formats: раздел 5.1.2 RFC 8422 - единственная запись
	 * uncompressed(0) с однобайтовой длиной перечня
	 */
	static const uint8_t FORMATS[] = {0x01, 0x00};

	/**
	 * Тело последнего расширения GREASE приветствия клиента и доли ключа GREASE: один
	 * нулевой байт, как у BoringSSL (раздел 3.1 RFC 8701 содержимого не предписывает)
	 */
	static const uint8_t GREASE_STUB[] = {0x00};

	/**
	 * Набор-сигнал TLS_EMPTY_RENEGOTIATION_INFO_SCSV: раздел 3.3 RFC 5746
	 */
	static constexpr uint16_t SCSV = 0x00FF;

	/**
	 * Виды сертификатов, запрашиваемых у клиента изданием TLS 1.2: раздел 7.4.4 RFC 5246 и
	 * раздел 5.5 RFC 8422 - ecdsa_sign(64) и rsa_sign(1)
	 */
	static const uint8_t TYPES[] = {0x40, 0x01};

	/**
	 * Опознаватели алгоритмов подписи RSASSA-PKCS1-v1_5 по хешу: RFC 8017
	 */
	static const char * PKCS1_SHA256 = "1.2.840.113549.1.1.11";
	// Опознаватель sha384WithRSAEncryption
	static const char * PKCS1_SHA384 = "1.2.840.113549.1.1.12";
	// Опознаватель sha512WithRSAEncryption
	static const char * PKCS1_SHA512 = "1.2.840.113549.1.1.13";

	/**
	 * @brief Функция переложения сообщения рукопожатия в обвязку DTLS
	 *
	 * @param message  сообщение рукопожатия вместе с обвязкой TLS
	 * @param sequence порядковый номер сообщения поверх дейтаграмм
	 * @param result   накопитель, в который помещается сообщение в обвязке DTLS
	 * @return         признак успешности переложения
	 *
	 * @details Раздел 4.2.6 RFC 6347: переписка ведётся сообщениями с номером, нулевым
	 *          смещением и длиной целого сообщения - как если бы оно шло одним куском
	 *
	 */
	static bool reframe(const view_t & message, const uint16_t sequence, vector <uint8_t> & result) noexcept {
		// Если сообщение короче обвязки TLS
		if((message.data == nullptr) || (message.size < handshake::HANDSHAKE_HEADER))
			// Выводим отказ переложения
			return false;
		// Обвязка сообщения одним куском
		datagram::fragment_t fragment;
		// Устанавливаем вид сообщения
		fragment.type = static_cast <handshake::type_t> (message.data[0]);
		// Устанавливаем длину целого сообщения
		fragment.size = (message.size - handshake::HANDSHAKE_HEADER);
		// Устанавливаем порядковый номер сообщения
		fragment.sequence = sequence;
		// Смещение куска нулевое
		fragment.offset = 0;
		// Кусок покрывает сообщение целиком
		fragment.length = fragment.size;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Занимаем место под обвязку DTLS и тело сообщения
			result.assign(datagram::DATAGRAM_FRAGMENT_HEADER + fragment.size, 0);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ переложения
			return false;
		}
		// Если обвязку записать не удалось
		if(datagram::build(fragment, result.data()) != datagram::error_t::NONE)
			// Выводим отказ переложения
			return false;
		// Переносим тело сообщения следом за обвязкой
		::memcpy(result.data() + datagram::DATAGRAM_FRAGMENT_HEADER, message.data + handshake::HANDSHAKE_HEADER, fragment.size);
		// Выводим успешность переложения
		return true;
	}
	/**
	 * @brief Функция проверки наличия наборов шифрования издания в перечне
	 *
	 * @param suites проверяемый перечень наборов шифрования
	 * @param legacy разыскиваются ли наборы издания TLS 1.2, а не 1.3
	 * @return       признак того, что хоть один набор издания в перечне есть
	 *
	 * @note Неведомые наборы (GREASE) изданию не принадлежат и не считаются
	 *
	 */
	static bool carries(const vector <protect::suite_t> & suites, const bool legacy) noexcept {
		/**
		 * Выполняем перебор наборов шифрования перечня
		 */
		for(size_t i = 0; i < suites.size(); i++){
			// Если набор ведом (хеш расписания задан: у наборов CBC вектора замены нет) и принадлежит разыскиваемому изданию
			if((protect::hash(suites[i]) != digest::hash_t::NONE) && (protect::legacy(suites[i]) == legacy))
				// Выводим признак наличия набора издания
				return true;
		}
		// Выводим признак отсутствия наборов издания
		return false;
	}
	/**
	 * @brief Функция проверки наличия набора шифрования в перечне
	 *
	 * @param suites проверяемый перечень наборов шифрования
	 * @param suite  разыскиваемый набор шифрования
	 * @return       признак того, что набор в перечне есть
	 *
	 */
	/**
	 * @brief Функция проверки годности набора шифрования изданию 1.1
	 *
	 * @param suite проверяемый набор
	 * @return      признак годности: набор издания 1.2 с CBC и HMAC-SHA1 (раздел 1.2 RFC 5246: AEAD и SHA-256 ввели изданием 1.2)
	 *
	 */
	static bool archaic(const protect::suite_t suite) noexcept {
		// Выводим признак годности
		return (protect::legacy(suite) && (protect::mac(suite) == digest::hash_t::SHA1));
	}
	/**
	 * @brief Функция проверки наличия наборов, годных изданию 1.1
	 *
	 * @param suites проверяемый перечень
	 * @return       признак наличия
	 *
	 */
	static bool archaical(const vector <protect::suite_t> & suites) noexcept {
		/**
		 * Выполняем перебор наборов
		 */
		for(size_t i = 0; i < suites.size(); i++){
			// Если набор годен изданию 1.1
			if(archaic(suites[i]))
				// Выводим признак наличия
				return true;
		}
		// Выводим признак отсутствия
		return false;
	}
	/**
	 * @brief Функция проверки вхождения набора шифрования в перечень
	 *
	 * @param suites проверяемый перечень
	 * @param suite  искомый набор шифрования
	 * @return       признак вхождения набора в перечень
	 *
	 */
	static bool listed(const vector <protect::suite_t> & suites, const protect::suite_t suite) noexcept {
		/**
		 * Выполняем перебор наборов шифрования перечня
		 */
		for(size_t i = 0; i < suites.size(); i++){
			// Если набор в перечне нашёлся
			if(suites[i] == suite)
				// Выводим признак наличия набора
				return true;
		}
		// Выводим признак отсутствия набора
		return false;
	}
	/**
	 * @brief Функция проверки принадлежности схемы подписи к RSASSA-PKCS1-v1_5
	 *
	 * @param scheme проверяемая схема подписи
	 * @return       признак схемы PKCS #1 v1.5, изданию TLS 1.3 запрещённой
	 *
	 */
	static bool pkcs1(const extension::scheme_t scheme) noexcept {
		// Выводим признак схемы подписи PKCS #1 v1.5
		return ((scheme == extension::scheme_t::RSA_PKCS1_SHA256) || (scheme == extension::scheme_t::RSA_PKCS1_SHA384) || (scheme == extension::scheme_t::RSA_PKCS1_SHA512));
	}
	/**
	 * @brief Функция проверки пригодности схемы подписи изданию TLS 1.2
	 *
	 * @param scheme проверяемая схема подписи
	 * @return       признак того, что схема подписи ведома и не принадлежит ветви ГОСТ
	 *
	 * @details Раздел 7.4.1.4.1 RFC 5246 и раздел 4.2.3 RFC 8446: изданию TLS 1.2 годны ECDSA,
	 *          RSASSA-PSS, RSASSA-PKCS1-v1_5 и Ed25519 (RFC 8422); схемы ГОСТ определены лишь
	 *          для TLS 1.3
	 *
	 */
	static bool legible(const extension::scheme_t scheme) noexcept {
		/**
		 * Выполняем определение схемы подписи
		 */
		switch(static_cast <uint16_t> (scheme)){
			// Схемы подписи, годные изданию TLS 1.2
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP256R1_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP384R1_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP521R1_SHA512):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA512):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA512):
			case static_cast <uint16_t> (extension::scheme_t::ED25519):
				// Выводим признак пригодности схемы подписи
				return true;
		}
		// Выводим признак непригодности схемы подписи
		return false;
	}
	/**
	 * @brief Функция получения опознавателя алгоритма подписи RSASSA-PKCS1-v1_5 по схеме
	 *
	 * @param scheme схема подписи PKCS #1 v1.5
	 * @return       опознаватель алгоритма подписи либо nullptr у чужой схемы
	 *
	 */
	static const char * identifier(const extension::scheme_t scheme) noexcept {
		// Если схема подписи - PKCS #1 v1.5 с хешем SHA-256
		if(scheme == extension::scheme_t::RSA_PKCS1_SHA256)
			// Выводим опознаватель алгоритма sha256WithRSAEncryption
			return PKCS1_SHA256;
		// Если схема подписи - PKCS #1 v1.5 с хешем SHA-384
		if(scheme == extension::scheme_t::RSA_PKCS1_SHA384)
			// Выводим опознаватель алгоритма sha384WithRSAEncryption
			return PKCS1_SHA384;
		// Если схема подписи - PKCS #1 v1.5 с хешем SHA-512
		if(scheme == extension::scheme_t::RSA_PKCS1_SHA512)
			// Выводим опознаватель алгоритма sha512WithRSAEncryption
			return PKCS1_SHA512;
		// Выводим отсутствие опознавателя у чужой схемы
		return nullptr;
	}

	/**
	 * Пределы длины опознавателя и ключа заранее разделённого ключа: раздел 5.3 RFC 4279
	 * велит принимать опознаватели до 128 байтов и ключи до 64 байтов
	 */
	static constexpr size_t IDENTITY = 128;
	// Предел длины ключа заранее разделённого ключа
	static constexpr size_t PRESHARED = 64;

	/**
	 * Длина общего значения обмена RSA: раздел 7.4.7.1 RFC 5246 - издание и 46 случайных байтов
	 */
	static constexpr size_t PREMASTER = 48;

	/**
	 * Наименьшая длина модуля RSA сертификата сервера при обмене шифрованием RSA в
	 * разрядах: ключ короче 2048 разрядов оставляет общее значение подбору, а
	 * упреждающей секретности у обмена RSA нет - клиент отвергает сертификат
	 */
	static constexpr size_t RSA_LEAST = 2048;

	/**
	 * Опознаватель расширения назначения ключа сертификата: раздел 4.2.1.3 RFC 5280
	 */
	static const char * USAGE = "2.5.29.15";

	/**
	 * @brief Функция составления общего значения обмена наборов PSK
	 *
	 * @param other  первая половина общего значения: общее значение кривой у ECDHE_PSK, нули длиною в ключ у PSK
	 * @param key    заранее разделённый ключ
	 * @param result накопитель, в который помещается общее значение
	 * @return       отказ составителя полей
	 *
	 * @details Раздел 2 RFC 4279 и раздел 3.2 RFC 5489: premaster = len(other) ‖ other ‖
	 *          len(psk) ‖ psk с двухбайтовыми длинами; составитель затирает свой накопитель сам
	 *
	 */
	static field::error_t premastering(const view_t & other, const view_t & key, sys::bytes_t & result) noexcept {
		// Объект составителя общего значения
		field::builder_t composer;
		// Занимаем место под длину первой половины
		field::error_t outcome = composer.open(2);
		// Если место занято
		if(outcome == field::error_t::NONE)
			// Записываем первую половину
			outcome = composer.bytes(other);
		// Если первая половина записана
		if(outcome == field::error_t::NONE)
			// Проставляем длину первой половины
			outcome = composer.close();
		// Если длина проставлена
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину ключа
			outcome = composer.open(2);
		// Если место занято
		if(outcome == field::error_t::NONE)
			// Записываем заранее разделённый ключ
			outcome = composer.bytes(key);
		// Если ключ записан
		if(outcome == field::error_t::NONE)
			// Проставляем длину ключа
			outcome = composer.close();
		// Если общее значение составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления
			return outcome;
		// Получаем составленное общее значение
		const view_t composed = composer.data();
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим составленное общее значение
			result.assign(composed.data, composed.data + composed.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return field::error_t::MEMORY;
		}
		// Выводим успешность составления
		return field::error_t::NONE;
	}
	/**
	 * @brief Функция проверки того, что набор шифрования ведёт обмен мимолётными ключами с сообщением обмена сервера
	 *
	 * @param suite проверяемый набор шифрования
	 * @return      признак того, что обмен набора идёт мимолётными ключами на кривой либо в конечном поле
	 *
	 */
	static bool ephemeral(const protect::suite_t suite) noexcept {
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(suite);
		// Выводим признак обмена мимолётными ключами
		return ((exchange == protect::exchange_t::ECDHE) || (exchange == protect::exchange_t::DHE) || (exchange == protect::exchange_t::ECDHE_PSK));
	}
	/**
	 * @brief Функция проверки того, что набор шифрования ведёт рукопожатие заранее разделённым ключом
	 *
	 * @param suite проверяемый набор шифрования
	 * @return      признак набора PSK либо ECDHE_PSK
	 *
	 */
	static bool preshared(const protect::suite_t suite) noexcept {
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(suite);
		// Выводим признак обмена заранее разделённым ключом
		return ((exchange == protect::exchange_t::PSK) || (exchange == protect::exchange_t::ECDHE_PSK));
	}

	/**
	 * Опознаватель ключа rsaEncryption по RFC 8017
	 */
	static const char * RSA_KEY = "1.2.840.113549.1.1.1";

	/**
	 * Опознаватель ключа id-RSASSA-PSS по RFC 4055: ключ, назначенный одной подписи RSASSA-PSS
	 */
	static const char * RSAPSS_KEY = "1.2.840.113549.1.1.10";

	/**
	 * Опознаватель ключа id-ecPublicKey по RFC 5480
	 */
	static const char * EC_KEY = "1.2.840.10045.2.1";

	/**
	 * Опознаватель ключа Ed25519 по RFC 8410
	 */
	static const char * ED_KEY = "1.3.101.112";

	/**
	 * Опознаватель ключа Ed448 по RFC 8410
	 */
	static const char * ED448_KEY = "1.3.101.113";

	/**
	 * Опознаватель ключа ML-DSA-44 по RFC 9881
	 */
	static const char * MLDSA44_KEY = "2.16.840.1.101.3.4.3.17";

	/**
	 * Опознаватель ключа ML-DSA-65 по RFC 9881
	 */
	static const char * MLDSA65_KEY = "2.16.840.1.101.3.4.3.18";

	/**
	 * Опознаватель ключа ML-DSA-87 по RFC 9881
	 */
	static const char * MLDSA87_KEY = "2.16.840.1.101.3.4.3.19";

	/**
	 * Опознаватель ключа SM2 по GB/T 32918 и RFC 8998
	 */
	static const char * SM2_KEY = "1.2.156.10197.1.301";

	/**
	 * Место расширения: приветствие сервера
	 */
	static constexpr uint8_t PLACE_HELLO = 0x01;
	/**
	 * Место расширения: просьба о повторе приветствия клиента
	 */
	static constexpr uint8_t PLACE_RETRY = 0x02;
	/**
	 * Место расширения: защищённые расширения сервера
	 */
	static constexpr uint8_t PLACE_GUARDED = 0x04;
	/**
	 * Место расширения: запрос подлинности клиента
	 */
	static constexpr uint8_t PLACE_REQUEST = 0x08;
	/**
	 * Место расширения: билет возобновления связи
	 */
	static constexpr uint8_t PLACE_TICKET = 0x10;

	/**
	 * @brief Вид расширения параметров переноса QUIC
	 *
	 * @details Раздел 8.2 RFC 9001: quic_transport_parameters(0x0039) идёт приветствием
	 *          клиента и защищёнными расширениями сервера, содержимое связью не толкуется
	 *
	 */
	static constexpr uint16_t TRANSPORT = 0x0039;
	/**
	 * Тело запроса состояния сертификата: раздел 8 RFC 6066 - вид ocsp (1), пустой
	 * перечень ответчиков и пустые расширения запроса
	 */
	static const uint8_t INQUIRY[] = {0x01, 0x00, 0x00, 0x00, 0x00};
	/**
	 * Расширение heartbeat по RFC 6520
	 */
	static constexpr uint16_t HEARTBEAT_EXTENSION = 0x000F;
	/**
	 * Режим heartbeat peer_allowed_to_send (раздел 2 RFC 6520)
	 */
	static const uint8_t HEARTBEAT_ALLOWED = 0x01;
	/**
	 * Наименьшая длина заполнения сообщения сердцебиения (раздел 4 RFC 6520)
	 */
	static constexpr size_t HEARTBEAT_PADDING = 16;
	/**
	 * Вид состояния сертификата ocsp: раздел 8 RFC 6066
	 */
	static constexpr uint32_t OCSP = 0x01;

	/**
	 * @brief Предел длины сообщения цепочки сертификатов по протоколу
	 *
	 * @details Раздел 4 RFC 8879: поле uncompressed_length занимает три байта, и длина
	 *          цепочки после распаковки не превышает 2^24-1
	 *
	 */
	static constexpr size_t CHAIN = 0xFFFFFF;
	/**
	 * @brief Предел длины цепочки сертификатов после распаковки по умолчанию
	 *
	 * @details Предел протокола 2^24-1 велик для памяти, отводимой по слову собеседника:
	 *          умолчанием стоят 64 КиБ, а потребитель ставит свой предел настройкой
	 *
	 */
	static constexpr size_t INFLATION = 65536;

	/**
	 * @brief Описание мест, в которых расширению идти дозволено
	 *
	 */
	typedef struct Placement {
		// Вид расширения приветствия
		uint16_t type;
		// Места, в которых расширению идти дозволено
		uint8_t places;
	} placement_t;

	/**
	 * Места расширений, признаваемых движком, среди сообщений сервера
	 *
	 * @details Раздел 4.2 RFC 8446 отводит всякому расширению свой перечень сообщений,
	 *          и расширение, признаваемое стороной, но пришедшее не в своём сообщении,
	 *          обрывает связь извещением «illegal_parameter». Здесь перечислены места
	 *          среди сообщений, которые разбирает клиент; приветствие клиента не
	 *          значится вовсе, ибо оттуда расширения и берут своё начало
	 *
	 */
	static const placement_t PLACEMENTS[] = {
		// Места расширений, признаваемых движком, среди сообщений сервера
		{static_cast <uint16_t> (extension::type_t::NAME),      PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::STATUS),    PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::TIMESTAMPS), PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::AUTHORITIES), PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::NEGOTIATION), 0},
		{static_cast <uint16_t> (extension::type_t::GROUPS),    PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::SCHEMES),   PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::COMPRESS),  PLACE_REQUEST},
		{static_cast <uint16_t> (extension::type_t::FRAGMENT),  PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::LIMIT),     PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::PROTOCOLS), PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::PROFILES),  (PLACE_HELLO | PLACE_GUARDED)},
		{static_cast <uint16_t> (extension::type_t::SETTINGS),  PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::SETTINGS_OLD), PLACE_GUARDED},
		{static_cast <uint16_t> (extension::type_t::SECRET),    PLACE_HELLO},
		{static_cast <uint16_t> (extension::type_t::EARLY),     (PLACE_GUARDED | PLACE_TICKET)},
		{static_cast <uint16_t> (extension::type_t::COOKIE),    PLACE_RETRY},
		{static_cast <uint16_t> (extension::type_t::VERSIONS),  (PLACE_HELLO | PLACE_RETRY)},
		{static_cast <uint16_t> (extension::type_t::MODES),     0},
		{static_cast <uint16_t> (extension::type_t::SHARE),     (PLACE_HELLO | PLACE_RETRY)},
		{TRANSPORT,                                             PLACE_GUARDED},
		{ech::ECH_EXTENSION,                                    (PLACE_RETRY | PLACE_GUARDED)}
	};

	/**
	 * @brief Функция получения мест, в которых расширению идти дозволено
	 *
	 * @param type   вид расширения, места которого запрашиваются
	 * @param result место, в которое помещается набор дозволенных мест
	 * @return       признак того, что вид расширения движку известен
	 *
	 */
	static bool placement(const uint16_t type, uint8_t & places) noexcept {
		/**
		 * Выполняем перебор описаний мест признаваемых расширений
		 */
		for(size_t i = 0; i < (sizeof(PLACEMENTS) / sizeof(placement_t)); i++){
			// Если описание мест разыскиваемого расширения найдено
			if(PLACEMENTS[i].type == type){
				// Запоминаем набор дозволенных мест расширения
				places = PLACEMENTS[i].places;
				// Выводим признак того, что вид расширения известен
				return true;
			}
		}
		// Выводим признак того, что вид расширения движку неизвестен
		return false;
	}
	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Функция получения места стороны связи в наборах связи
	 *
	 * @param side сторона связи, место которой запрашивается
	 * @return     место стороны связи в наборах связи
	 *
	 */
	static size_t index(const session::side_t side) noexcept {
		// Выводим место стороны связи в наборах связи
		return ((side == session::side_t::CLIENT) ? 0 : 1);
	}
	/**
	 * @brief Функция перевода отказа модуля полей в отказ связи
	 *
	 * @param error    отказ модуля полей
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const field::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == field::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == field::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля записи в отказ связи
	 *
	 * @param error    отказ модуля записи
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const record::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == record::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == record::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля защиты записей в отказ связи
	 *
	 * @param error    отказ модуля защиты записей
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const protect::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == protect::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == protect::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля сообщений рукопожатия в отказ связи
	 *
	 * @param error    отказ модуля сообщений рукопожатия
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const handshake::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == handshake::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == handshake::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля приветствий в отказ связи
	 *
	 * @param error    отказ модуля приветствий
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const hello::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == hello::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == hello::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля сообщений в отказ связи
	 *
	 * @param error    отказ модуля сообщений
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const message::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == message::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == message::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля расширений в отказ связи
	 *
	 * @param error    отказ модуля расширений
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const extension::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == extension::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == extension::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция перевода отказа модуля сертификатов в отказ связи
	 *
	 * @param error    отказ модуля сертификатов
	 * @param fallback отказ связи, которым отвечается всякий отказ модуля, кроме нехватки памяти
	 * @return         отказ связи, отвечающий отказу модуля
	 *
	 * @note Нехватка памяти переводится в нехватку памяти связи: выдавать её за отказ
	 *       разбора либо составления значило бы винить собеседника в своей беде
	 *
	 */
	static context::error_t translate(const x509::error_t error, const context::error_t fallback) noexcept {
		// Если отказа у модуля нет
		if(error == x509::error_t::NONE)
			// Выводим отсутствие отказа связи
			return context::error_t::NONE;
		// Выводим отказ связи, отвечающий отказу модуля
		return ((error == x509::error_t::MEMORY) ? context::error_t::MEMORY : fallback);
	}
	/**
	 * @brief Функция выбора описания извещения по отказу связи
	 *
	 * @param error    отказ, которым связь обрывается
	 * @param fallback описание извещения, отправляемого при всяком отказе, кроме нехватки памяти
	 * @return         описание извещения, отвечающее отказу связи
	 *
	 * @note Раздел 6.2 RFC 8446 велит на свои беды отвечать извещением о внутреннем
	 *       отказе: нехватка памяти собеседнику не вменяется
	 *
	 */
	static alert::description_t blame(const context::error_t error, const alert::description_t fallback) noexcept {
		// Выводим описание извещения, отвечающее отказу связи
		return ((error == context::error_t::MEMORY) ? alert::description_t::INTERNAL : fallback);
	}
	/**
	 * @brief Функция составления записи перечня расширений
	 *
	 * @param extensions составляемый перечень расширений
	 * @param result     накопитель, в который складывается запись перечня
	 * @return           отказ составления записи перечня
	 *
	 * @note Нехватка памяти отличается от прочих отказов составления: связь отвечает
	 *       на неё своим отказом памяти, а не отказом сообщения
	 *
	 */
	static context::error_t block(const vector <hello::extension_t> & extensions, vector <uint8_t> & result) noexcept {
		// Объект составителя записи перечня расширений
		field::builder_t builder;
		// Отказ составления записи перечня расширений
		context::error_t failure = translate(builder.open(2), context::error_t::MESSAGE);
		// Если место под длину перечня расширений занять не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления записи перечня
			return failure;
		/**
		 * Выполняем перебор составляемых расширений перечня
		 */
		for(size_t i = 0; i < extensions.size(); i++){
			// Отказ записи вида расширения
			failure = translate(builder.number(extensions[i].type, 2), context::error_t::MESSAGE);
			// Если вид расширения записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления записи перечня
				return failure;
			// Отказ занятия места под длину тела расширения
			failure = translate(builder.open(2), context::error_t::MESSAGE);
			// Если место под длину тела расширения занять не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления записи перечня
				return failure;
			// Отказ записи тела расширения
			failure = translate(builder.bytes(extensions[i].data), context::error_t::MESSAGE);
			// Если тело расширения записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления записи перечня
				return failure;
			// Отказ проставления длины тела расширения
			failure = translate(builder.close(), context::error_t::MESSAGE);
			// Если длину тела расширения проставить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления записи перечня
				return failure;
		}
		// Отказ проставления длины перечня расширений
		failure = translate(builder.close(), context::error_t::MESSAGE);
		// Если длину перечня расширений проставить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления записи перечня
			return failure;
		// Получаем составленную запись перечня расширений
		const view_t data = builder.data();
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем перенос составленной записи перечня в накопитель
			result.assign(data.data, data.data + data.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выводим успешность составления записи перечня расширений
		return context::error_t::NONE;
	}
	/**
	 * Окно расхождения объявленного возраста билета с наблюдаемым в миллисекундах
	 *
	 * @details Раздел 4.2.10 RFC 8446 велит сличать объявленный клиентом возраст билета
	 *          с наблюдаемым и отвергать упреждающие данные при расхождении: сеть даёт
	 *          задержку, оттого сличение и ведётся окном, а не точным равенством
	 *
	 */
	static constexpr int64_t WINDOW = 10000;
	/**
	 * @brief Предел срока жизни билета возобновления связи в секундах
	 *
	 * @note Раздел 4.6.1 RFC 8446 кладёт сроку билета семь суток
	 *
	 */
	static constexpr uint32_t LIFETIME = 604800;
	/**
	 * Предел давности первичного удостоверения собеседника в секундах: перевыдача билета
	 * его не продлевает (раздел 5.6 RFC 5077), старше - полное рукопожатие; семь суток,
	 * как у BoringSSL. Условие пересмотра: ручка потребителя
	 */
	static constexpr int64_t AUTHENTICATION = 604800;
	/**
	 * @brief Срок жизни выдаваемых билетов возобновления связи, принятый по умолчанию
	 *
	 * @note Два часа: срок, за который возобновление обычно и происходит, а
	 *       установщик срока даёт его переопределить
	 *
	 */
	static constexpr uint32_t TERM = 7200;
	/**
	 * @brief Предел тела сообщения рукопожатия после установления связи
	 *
	 * @note После установления связи идут лишь билеты возобновления и смены ключей;
	 *       билет с содержимым и расширениями по два байта длины не превосходит
	 *       131 072 байтов, а шестнадцать мегабайтов сообщения означали бы
	 *       накопление чужого мусора в памяти
	 *
	 */
	static constexpr size_t AFTERMATH = 131072;

	/**
	 * @brief Функция проверки того, что срок билета возобновления связи вышел
	 *
	 * @param ticket проверяемый билет возобновления связи
	 * @param moment миг, которым судится срок билета
	 * @return       признак того, что срок билета вышел
	 *
	 * @note Часов связь не читает: миг подаётся ей настройкой. Не заданный миг судить
	 *       сроки не позволяет вовсе, и билет тогда идёт в дело как есть
	 *
	 */
	static bool expired(const context::ticket_t & ticket, const int64_t moment) noexcept {
		// Если миг суждения либо миг выдачи билета не задан
		if((moment == 0) || (ticket.moment == 0))
			// Выводим признак того, что срок билета не вышел
			return false;
		// Выводим признак того, что срок билета вышел
		return ((moment < ticket.moment) || ((moment - ticket.moment) > static_cast <int64_t> (ticket.lifetime)));
	}
	/**
	 * @brief Функция суждения о давности первичного удостоверения собеседника
	 *
	 * @param authenticated миг первичного удостоверения в секундах, ноль - неизвестный
	 * @param moment        миг суждения в секундах, ноль - неизвестный
	 * @return              признак того, что удостоверение старше дозволенного
	 *
	 */
	static bool outdated(const int64_t authenticated, const int64_t moment) noexcept {
		// Если миг суждения либо миг удостоверения не задан
		if((moment == 0) || (authenticated == 0))
			// Выводим признак того, что удостоверение свежо
			return false;
		// Выводим признак того, что удостоверение старше дозволенного
		return ((moment < authenticated) || ((moment - authenticated) > AUTHENTICATION));
	}
	/**
	 * @brief Функция извлечения тела расширения из записи перечня расширений
	 *
	 * @param data   разбираемая запись перечня расширений
	 * @param type   разыскиваемый вид расширения
	 * @param result просмотр, в который помещается тело найденного расширения
	 * @return       признак того, что расширение в перечне объявлено
	 *
	 */
	static bool announced(const view_t & data, const uint16_t type, view_t & result) noexcept {
		// Объект разборщика записи перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую запись перечня расширений
		scanner.start(data);
		// Содержимое перечня расширений
		view_t body;
		// Если перечень расширений прочитать не удалось
		if(scanner.vector(body, 2) != field::error_t::NONE)
			// Выводим признак того, что расширение не объявлено
			return false;
		// Объект разборщика записей перечня расширений
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(body);
		/**
		 * Выполняем перебор объявленных расширений перечня
		 */
		while(reader.left() > 0){
			// Вид очередного расширения перечня
			uint32_t item = 0;
			// Если вид расширения прочитать не удалось
			if(reader.number(item, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Тело очередного расширения перечня
			view_t content;
			// Если тело расширения прочитать не удалось
			if(reader.vector(content, 2) != field::error_t::NONE)
				// Выводим признак того, что расширение не объявлено
				return false;
			// Если вид расширения совпал с разыскиваемым
			if(static_cast <uint16_t> (item) == type){
				// Устанавливаем тело найденного расширения
				result = content;
				// Выводим признак того, что расширение объявлено
				return true;
			}
		}
		// Выводим признак того, что расширение не объявлено
		return false;
	}
	/**
	 * @brief Функция разыскания расширения в записи перечня расширений
	 *
	 * @param data разбираемая запись перечня расширений
	 * @param type разыскиваемый вид расширения
	 * @return     признак того, что расширение в перечне объявлено
	 *
	 */
	static bool declared(const view_t & data, const uint16_t type) noexcept {
		// Тело разыскиваемого расширения перечня
		view_t content;
		// Выводим признак того, что расширение в перечне объявлено
		return announced(data, type, content);
	}
	/**
	 * @brief Функция перечисления видов расширений записи перечня расширений
	 *
	 * @param data   разбираемая запись перечня расширений
	 * @param result перечень, в который помещаются виды объявленных расширений
	 * @return       отказ разбора перечня расширений
	 *
	 * @note Тела расширений здесь не читаются: перечисляются лишь их виды
	 *
	 * @note Нехватка памяти отличается от прочих отказов разбора: связь отвечает на
	 *       неё своим отказом памяти, а не отказом сообщения
	 *
	 */
	static context::error_t enumerate(const view_t & data, vector <uint16_t> & result) noexcept {
		// Объект разборщика записи перечня расширений
		field::scanner_t scanner;
		// Устанавливаем разбираемую запись перечня расширений
		scanner.start(data);
		// Содержимое перечня расширений
		view_t body;
		// Если перечень расширений прочитать не удалось
		if(scanner.vector(body, 2) != field::error_t::NONE)
			// Выводим отказ разбора перечня расширений
			return context::error_t::MESSAGE;
		// Объект разборщика записей перечня расширений
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(body);
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			/**
			 * Выполняем перебор объявленных расширений перечня
			 */
			while(reader.left() > 0){
				// Вид очередного расширения перечня
				uint32_t item = 0;
				// Если вид расширения прочитать не удалось
				if(reader.number(item, 2) != field::error_t::NONE)
					// Выводим отказ разбора перечня расширений
					return context::error_t::MESSAGE;
				// Тело очередного расширения перечня
				view_t content;
				// Если тело расширения прочитать не удалось
				if(reader.vector(content, 2) != field::error_t::NONE)
					// Выводим отказ разбора перечня расширений
					return context::error_t::MESSAGE;
				// Добавляем вид расширения в перечень объявленных
				result.push_back(static_cast <uint16_t> (item));
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выводим успешность разбора перечня расширений
		return context::error_t::NONE;
	}
	/**
	 * @brief Функция проверки известности группы обмена ключами связи
	 *
	 * @param group проверяемая группа обмена ключами
	 * @return      признак того, что обмен по группе связь вести умеет
	 *
	 */
	static bool known(const extension::group_t group) noexcept {
		// Выводим признак того, что кривая группы связи ведома, группа есть гибрид с инкапсуляцией либо конечное поле RFC 7919
		return ((extension::curve(group) != nullptr) || extension::hybrid(group) || (extension::finite(group) > 0));
	}
	/**
	 * @brief Функция получения механизма инкапсуляции гибридной группы
	 *
	 * @param group гибридная группа обмена ключами
	 * @return      механизм ML-KEM гибрида
	 *
	 */
	static agreement::kem_t kemof(const extension::group_t group) noexcept {
		// Выводим механизм: 1024 у SecP384r1MLKEM1024, 768 у прочих
		return ((group == extension::group_t::SECP384R1MLKEM1024) ? agreement::kem_t::MLKEM1024 : agreement::kem_t::MLKEM768);
	}
	/**
	 * @brief Функция получения классической половины гибридной группы
	 *
	 * @param group гибридная группа обмена ключами
	 * @return      группа кривой: X25519, secp256r1 либо secp384r1
	 *
	 */
	static extension::group_t curveof(const extension::group_t group) noexcept {
		// Если гибрид с secp256r1
		if(group == extension::group_t::SECP256R1MLKEM768)
			// Выводим кривую
			return extension::group_t::SECP256R1;
		// Если гибрид с secp384r1
		if(group == extension::group_t::SECP384R1MLKEM1024)
			// Выводим кривую
			return extension::group_t::SECP384R1;
		// Если гибрид с curveSM2
		if(group == extension::group_t::CURVESM2MLKEM768)
			// Выводим кривую
			return extension::group_t::CURVESM2;
		// Иначе X25519
		return extension::group_t::X25519;
	}
	/**
	 * @brief Функция получения длины доли классической половины гибрида
	 *
	 * @param group гибридная группа обмена ключами
	 * @return      длина доли кривой: 32 у X25519, 65 и 97 у точек NIST в несжатом виде
	 *
	 */
	static size_t curvelength(const extension::group_t group) noexcept {
		// Выводим длину доли кривой
		return extension::length(curveof(group));
	}
	/**
	 * @brief Функция получения порядка половин гибрида
	 *
	 * @param group гибридная группа обмена ключами
	 * @return      признак того, что доля ML-KEM идёт впереди (X25519MLKEM768); у гибридов NIST впереди кривая
	 *
	 */
	static bool kemfirst(const extension::group_t group) noexcept {
		// Выводим признак порядка по RFC 10024
		return (group == extension::group_t::X25519MLKEM768);
	}
	/**
	 * @brief Функция проверки принадлежности группы обмена классической ветви
	 *
	 * @param group проверяемая группа обмена ключами
	 * @return      признак того, что доля ключа группы идёт записью RFC 8446
	 *
	 */
	static bool classic(const extension::group_t group) noexcept {
		/**
		 * Выполняем определение группы обмена ключами
		 */
		switch(static_cast <uint16_t> (group)){
			// Кривые записи RFC 8446: точки NIST несжатой записью, кривые Монтгомери первой координатой
			case static_cast <uint16_t> (extension::group_t::X25519):
			case static_cast <uint16_t> (extension::group_t::X448):
			case static_cast <uint16_t> (extension::group_t::SECP256R1):
			case static_cast <uint16_t> (extension::group_t::SECP384R1):
			case static_cast <uint16_t> (extension::group_t::SECP521R1):
			case static_cast <uint16_t> (extension::group_t::SECP256K1):
			case static_cast <uint16_t> (extension::group_t::CURVESM2):
				// Выводим признак классической группы обмена ключами
				return true;
		}
		// Группы конечного поля RFC 7919 идут записью раздела 4.2.8.1 RFC 8446
		return (extension::finite(group) > 0);
	}
	/**
	 * @brief Функция определения рода группы обмена ключами для умолчания долей ключа
	 *
	 * @param group группа обмена ключами
	 * @return      0 у кривых ГОСТ, 1 у гибридов с ML-KEM, 2 у классических кривых; -1 у прочих: группы конечного поля и неведомые долей по умолчанию не получают
	 *
	 */
	static int8_t family(const extension::group_t group) noexcept {
		// Если группа - кривая ГОСТ: коды 0x0022…0x0028 по RFC 9367
		if((static_cast <uint16_t> (group) >= static_cast <uint16_t> (extension::group_t::GC256A)) && (static_cast <uint16_t> (group) <= static_cast <uint16_t> (extension::group_t::GC512C)))
			// Выводим род кривых ГОСТ
			return 0;
		// Если группа - гибрид с ML-KEM
		if(extension::hybrid(group))
			// Выводим род гибридов
			return 1;
		// Если группа - группа конечного поля RFC 7919: доля по ней дорога, и своего рода она не имеет
		if(extension::finite(group) > 0)
			// Выводим отсутствие рода
			return -1;
		// Если группа - классическая кривая
		if(classic(group))
			// Выводим род классических кривых
			return 2;
		// Прочие группы своего рода не имеют
		return -1;
	}
	/**
	 * @brief Функция проверки принадлежности группы обмена кривым Монтгомери
	 *
	 * @param group проверяемая группа обмена ключами
	 * @return      признак того, что доля ключа группы есть первая координата точки по RFC 7748 (X25519, X448)
	 *
	 */
	static bool montgomery(const extension::group_t group) noexcept {
		// Выводим признак кривой Монтгомери
		return ((group == extension::group_t::X25519) || (group == extension::group_t::X448));
	}
	/**
	 * @brief Функция проверки допустимости группы обмена изданию протокола
	 *
	 * @param group  проверяемая группа обмена ключами
	 * @param legacy признак издания TLS 1.2
	 * @return       признак того, что группу изданием выбирать дозволено
	 *
	 * @details Реестр IANA групп TLS: secp256k1 изданием 1.3 не допускается (RFC 8446 знает лишь
	 *          secp256r1, secp384r1, secp521r1, x25519, x448 и группы RFC 7919); группы конечного
	 *          поля изданию 1.2 дают наборы DHE записью параметров раздела 7.4.3 RFC 5246,
	 *          изданию 1.3 - доли ключа раздела 4.2.8 RFC 8446
	 *
	 */
	static bool fitting(const extension::group_t group, const bool legacy) noexcept {
		// Если группа - secp256k1, она годна лишь изданию 1.2
		if(group == extension::group_t::SECP256K1)
			// Выводим допустимость по изданию
			return legacy;
		// Прочие группы годны обоим изданиям: кривые - точками, конечные поля - наборами DHE либо долями ключа
		return true;
	}
	/**
	 * @brief Функция розыска группы конечного поля RFC 7919 по модулю и генератору
	 *
	 * @param modulus   модуль группы от старшего байта
	 * @param generator генератор группы
	 * @return          группа конечного поля либо NONE у неведомого поля
	 *
	 */
	static extension::group_t finiteof(const view_t & modulus, const view_t & generator) noexcept {
		// Генератор всех групп RFC 7919 равен двум
		if((modulus.data == nullptr) || (modulus.size == 0) || (generator.size != 1) || (generator.data == nullptr) || (generator.data[0] != 0x02))
			// Выводим отсутствие группы
			return extension::group_t::NONE;
		/**
		 * Выполняем перебор длин модулей групп RFC 7919
		 */
		for(const size_t size : {256, 384, 512, 768, 1024}){
			// Модуль группы RFC 7919
			const view_t known = agreement::prime(size);
			// Если модуль совпал длиною и значением
			if((known.size == modulus.size) && (::memcmp(known.data, modulus.data, modulus.size) == 0))
				// Выводим группу по длине модуля
				return ((size == 256) ? extension::group_t::FFDHE2048 :
					((size == 384) ? extension::group_t::FFDHE3072 :
					((size == 512) ? extension::group_t::FFDHE4096 :
					((size == 768) ? extension::group_t::FFDHE6144 : extension::group_t::FFDHE8192))));
		}
		// Выводим отсутствие группы: поле неведомо связи
		return extension::group_t::NONE;
	}
	/**
	 * @brief Функция переноса области байтов в обратном порядке
	 *
	 * @param source переносимая область байтов
	 * @param result место, в которое помещается перенесённая область
	 * @param size   длина переносимой области байтов
	 *
	 */
	static void reverse(const uint8_t * source, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов переносимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Переносим очередной байт с конца области
			result[i] = source[size - i - 1];
	}
	/**
	 * @brief Функция извлечения опознавателя именованной кривой ключа EC
	 *
	 * @param key    ключ сертификата
	 * @param result место, в которое помещается опознаватель кривой
	 * @return       отказ извлечения опознавателя: KEY у негодных настроек, MEMORY у нехватки памяти
	 *
	 */
	static x509::error_t named(const x509::key_t & key, string & result) noexcept {
		// Если настройки ключа не переданы
		if((key.parameters.data == nullptr) || (key.parameters.size == 0))
			// Выводим отказ извлечения опознавателя
			return x509::error_t::KEY;
		// Объект чтения настроек ключа
		asn1::Reader reader(key.parameters);
		// Элемент настроек ключа
		asn1::element_t element;
		// Если опознаватель кривой в настройках не найден
		if(!reader.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ извлечения опознавателя
			return x509::error_t::KEY;
		// Разбираем опознаватель кривой
		const asn1::error_t outcome = asn1::oid(element, result);
		// Если памяти под опознаватель не хватило
		if(outcome == asn1::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return x509::error_t::MEMORY;
		// Выводим итог разбора опознавателя кривой
		return ((outcome == asn1::error_t::NONE) ? x509::error_t::NONE : x509::error_t::KEY);
	}
	/**
	 * @brief Функция проверки пригодности ключа сертификата подписи владения
	 *
	 * @param key      ключ сертификата
	 * @param suitable место, в которое помещается признак пригодности ключа
	 * @return         отказ нехватки памяти при разборе ключа, иначе NONE
	 *
	 */
	static context::error_t recognized(const x509::key_t & key, bool & suitable) noexcept {
		// Сбрасываем пригодность ключа
		suitable = false;
		// Опознаватель кривой ключа
		string identifier;
		// Разбираем ключ как ключ ГОСТ
		x509::error_t outcome = x509::identifier(key, identifier);
		// Если памяти под разбор не хватило
		if(outcome == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если ключ записан алгоритмом ГОСТ
		if(outcome == x509::error_t::NONE){
			// Отмечаем пригодность ключа
			suitable = true;
			// Выводим успешность разбора
			return context::error_t::NONE;
		}
		// Если ключ записан алгоритмом EC: кривая обязана быть именованной
		if(key.algorithm.compare(EC_KEY) == 0){
			// Извлекаем опознаватель именованной кривой
			outcome = named(key, identifier);
			// Если памяти под разбор не хватило
			if(outcome == x509::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Отмечаем пригодность ключа с именованной кривой
			suitable = (outcome == x509::error_t::NONE);
			// Выводим успешность разбора
			return context::error_t::NONE;
		}
		// Отмечаем пригодность ключа RSA либо Ed25519
		suitable = ((key.algorithm.compare(RSA_KEY) == 0) || (key.algorithm.compare(RSAPSS_KEY) == 0) || (key.algorithm.compare(ED_KEY) == 0) || (key.algorithm.compare(ED448_KEY) == 0) || (key.algorithm.compare(MLDSA44_KEY) == 0) || (key.algorithm.compare(MLDSA65_KEY) == 0) || (key.algorithm.compare(MLDSA87_KEY) == 0) || (key.algorithm.compare(SM2_KEY) == 0));
		// Выводим успешность разбора
		return context::error_t::NONE;
	}
	/**
	 * @brief Функция проверки соответствия схемы подписи ключу сертификата
	 *
	 * @param scheme проверяемая схема подписи
	 * @param key    ключ сертификата
	 * @param memory место, в которое помещается признак нехватки памяти при разборе
	 * @param loose  судится ли схема правилами издания TLS 1.2: кривая ECDSA любая
	 * @return       признак того, что схема подписи ключу отвечает
	 *
	 * @details Раздел 7.4.1.4.1 RFC 5246: в издании 1.2 схема ECDSA именует лишь хеш, а
	 *          кривая берётся из ключа сертификата - подпись ecdsa_sha256 ключом P-384
	 *          законна; раздел 4.2.3 RFC 8446 привязывает кривую к схеме
	 *
	 */
	static bool matching(const extension::scheme_t scheme, const x509::key_t & key, bool & memory, const bool loose) noexcept {
		// Сбрасываем признак нехватки памяти
		memory = false;
		/**
		 * Раздел 4.2.3 RFC 8446: схема подписи именует и алгоритм ключа, и хеш, и у
		 * ECDSA - кривую; подпись схемой, ключу не отвечающей, объявлена быть не вправе
		 */
		switch(static_cast <uint16_t> (scheme)){
			// Схемы подписи ГОСТ
			case static_cast <uint16_t> (extension::scheme_t::S256A):
			case static_cast <uint16_t> (extension::scheme_t::S256B):
			case static_cast <uint16_t> (extension::scheme_t::S256C):
			case static_cast <uint16_t> (extension::scheme_t::S256D):
			case static_cast <uint16_t> (extension::scheme_t::S512A):
			case static_cast <uint16_t> (extension::scheme_t::S512B):
			case static_cast <uint16_t> (extension::scheme_t::S512C): {
				// Опознаватель набора параметров кривой ключа
				string identifier;
				// Извлекаем опознаватель кривой ключа ГОСТ
				const x509::error_t outcome = x509::identifier(key, identifier);
				// Запоминаем нехватку памяти при разборе
				memory = (outcome == x509::error_t::MEMORY);
				// Если опознаватель кривой ключа ГОСТ извлечь не удалось
				if(outcome != x509::error_t::NONE)
					// Выводим несоответствие схемы ключу
					return false;
				// Получаем опознаватель кривой схемы подписи
				const char * declared = extension::curve(scheme);
				// Выводим итог сличения кривой схемы с кривой ключа
				return ((declared != nullptr) && (identifier.compare(declared) == 0));
			}
			// Схемы подписи ECDSA
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP256R1_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP384R1_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::ECDSA_SECP521R1_SHA512): {
				// Если ключ сертификата не ключ EC
				if(key.algorithm.compare(EC_KEY) != 0)
					// Выводим несоответствие схемы ключу
					return false;
				// Опознаватель именованной кривой ключа
				string identifier;
				// Извлекаем опознаватель именованной кривой
				const x509::error_t outcome = named(key, identifier);
				// Запоминаем нехватку памяти при разборе
				memory = (outcome == x509::error_t::MEMORY);
				// Если опознаватель кривой ключа извлечь не удалось
				if(outcome != x509::error_t::NONE)
					// Выводим несоответствие схемы ключу
					return false;
				// Изданию TLS 1.2 довольно именованной кривой: схема именует лишь хеш
				if(loose)
					// Выводим соответствие схемы ключу
					return true;
				// Получаем опознаватель кривой схемы подписи
				const char * declared = extension::curve(scheme);
				// Выводим итог сличения кривой схемы с кривой ключа
				return ((declared != nullptr) && (identifier.compare(declared) == 0));
			}
			// Схемы подписи RSASSA-PSS и RSASSA-PKCS1-v1_5 ключом rsaEncryption
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_RSAE_SHA512):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PKCS1_SHA512):
				// Выводим итог сличения алгоритма ключа с rsaEncryption
				return (key.algorithm.compare(RSA_KEY) == 0);
			// Схемы подписи RSASSA-PSS ключом id-RSASSA-PSS
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_PSS_SHA256):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_PSS_SHA384):
			case static_cast <uint16_t> (extension::scheme_t::RSA_PSS_PSS_SHA512):
				// Выводим итог сличения алгоритма ключа с id-RSASSA-PSS
				return (key.algorithm.compare(RSAPSS_KEY) == 0);
			// Схема подписи Ed25519
			case static_cast <uint16_t> (extension::scheme_t::ED25519):
				// Выводим итог сличения алгоритма ключа с Ed25519
				return (key.algorithm.compare(ED_KEY) == 0);
			// Схема подписи Ed448
			case static_cast <uint16_t> (extension::scheme_t::ED448):
				// Выводим итог сличения алгоритма ключа с Ed448
				return (key.algorithm.compare(ED448_KEY) == 0);
			// Схема подписи ML-DSA-44
			case static_cast <uint16_t> (extension::scheme_t::MLDSA44):
				// Выводим итог сличения алгоритма ключа с ML-DSA-44
				return (key.algorithm.compare(MLDSA44_KEY) == 0);
			// Схема подписи ML-DSA-65
			case static_cast <uint16_t> (extension::scheme_t::MLDSA65):
				// Выводим итог сличения алгоритма ключа с ML-DSA-65
				return (key.algorithm.compare(MLDSA65_KEY) == 0);
			// Схема подписи ML-DSA-87
			case static_cast <uint16_t> (extension::scheme_t::MLDSA87):
				// Выводим итог сличения алгоритма ключа с ML-DSA-87
				return (key.algorithm.compare(MLDSA87_KEY) == 0);
			// Схема подписи SM2
			case static_cast <uint16_t> (extension::scheme_t::SM2SIG_SM3): {
				// Если ключ сертификата не ключ EC: ключ SM2 идёт записью id-ecPublicKey с кривой curveSM2
				if(key.algorithm.compare(EC_KEY) != 0)
					// Выводим несоответствие схемы ключу
					return false;
				// Опознаватель именованной кривой ключа
				string identifier;
				// Извлекаем опознаватель именованной кривой
				const x509::error_t outcome = named(key, identifier);
				// Запоминаем нехватку памяти при разборе
				memory = (outcome == x509::error_t::MEMORY);
				// Если опознаватель кривой ключа извлечь не удалось
				if(outcome != x509::error_t::NONE)
					// Выводим несоответствие схемы ключу
					return false;
				// Выводим итог сличения кривой ключа с curveSM2
				return (identifier.compare(SM2_KEY) == 0);
			}
		}
		// Выводим несоответствие неведомой схемы всякому ключу
		return false;
	}
};

/**
 * @brief Метод обрыва связи отказом
 *
 * @param error       отказ, которым связь обрывается
 * @param description описание извещения, отправляемого собеседнику
 * @return            отказ, которым связь оборвана
 *
 */
context::error_t nts::internal::Engine::abort(const context::error_t error, const alert::description_t description) noexcept {
	// Составляем извещение об обрыве связи
	const alert::alert_t alert(alert::level_t::FATAL, description);
	// Место, в которое записывается извещение об обрыве связи
	uint8_t buffer[alert::ALERT_LENGTH];
	/**
	 * Раздел 4.8 RFC 9001: в переносе по уровням извещение записью не уходит, а несётся
	 * кодом закрытия связи QUIC тем, кто связь ведёт, - ему довольно описания извещения
	 */
	if((this->_transport != context::transport_t::LEVELS) && (alert::build(alert, buffer) == alert::error_t::NONE))
		// Выполняем складывание извещения в накопитель отправляемых байтов
		this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
	// Запоминаем извещение, которым связь оборвана
	this->_alert = alert;
	// Запоминаем отказ, которым связь оборвана
	this->_error = error;
	// Переводим связь в состояние обрыва
	this->_state = context::state_t::FAILED;
	// Оборванной связи залп повторять некому: часы переноса дейтаграммами останавливаются
	this->_flight.halt();
	// Выполняем затирание ключевого материала оборванной связи
	this->shred();
	// Сообщаем в сток журнала об обрыве связи: отказ кодом и извещение именем, без тайн
	sys::log::emitf(sys::log::level_t::CRITICAL, "A-NTS: %s: connection aborted, error %u, alert %s", (this->_server ? "server" : "client"), static_cast <unsigned> (error), alert::name(description));
	// Выводим отказ, которым связь оборвана
	return error;
}
/**
 * @brief Деструктор мимолётной пары: секрет и общий секрет затираются при всяком освобождении
 *
 */
nts::internal::Exchange::~Exchange() noexcept {
	// Если секретный ключ есть
	if(!this->secret.empty())
		// Затираем секретный ключ
		sys::wipe(this->secret.data(), this->secret.size());
	// Если общий секрет есть
	if(!this->shared.empty())
		// Затираем общий секрет
		sys::wipe(this->shared.data(), this->shared.size());
}
/**
 * @brief Метод затирания ключевого материала связи
 *
 */
void nts::internal::Engine::shred() noexcept {
	// Состояния HPKE зашифрованного приветствия: ключ AEAD и нонс ECH оборванной связи ни к чему
	this->_sealer.clear();
	// Выполняем сброс состояния HPKE получателя
	this->_opener.clear();
	// Выполняем сброс секретов связи
	this->_secrets.clear();
	// Выполняем сброс защиты отправляемых записей
	this->_output.clear();
	// Выполняем сброс защиты принимаемых записей
	this->_input.clear();
	// Выполняем сброс защиты упреждающих данных
	this->_early.clear();
	// Выполняем затирание ключевого материала пор поверх дейтаграмм
	this->_flight.shred();
	// Если укрытая память ключей заведена
	if(this->_keys != nullptr)
		// Выполняем затирание ключевого материала связи целиком: главный секрет, ключи завершения, ключи, векторы, имитовставки и направления
		this->_shelter.wipe();
	// Выполняем сброс признаков готовности значений направлений
	::memset(this->_ready, 0, sizeof(this->_ready));
	/**
	 * Выполняем перебор мимолётных пар ключей своей стороны
	 */
	for(size_t i = 0; i < this->_exchanges.size(); i++){
		// Если секретный мимолётный ключ пары выработан
		if(!this->_exchanges[i].secret.empty())
			// Выполняем затирание секретного мимолётного ключа
			this->purge(this->_exchanges[i].secret.data(), this->_exchanges[i].secret.size());
		// Если общий секрет инкапсуляции есть
		if(!this->_exchanges[i].shared.empty())
			// Выполняем затирание общего секрета инкапсуляции
			this->purge(this->_exchanges[i].shared.data(), this->_exchanges[i].shared.size());
	}
	// Выполняем сброс мимолётных пар ключей своей стороны
	this->_exchanges.clear();
	// Если привязка билета возобновления выработана
	if(!this->_binding.empty())
		// Выполняем затирание привязки билета возобновления
		this->purge(this->_binding.data(), this->_binding.size());
	// Выполняем сброс привязки билета возобновления
	this->_binding.clear();
	// Если обещанный билет несёт копию главного секрета
	if(!this->_promise.secret.empty())
		// Выполняем затирание копии главного секрета в обещанном билете
		this->purge(this->_promise.secret.data(), this->_promise.secret.size());
	// Выполняем сброс обещанного билета
	this->_promise = context::ticket_t();
	// Выполняем затирание секретов издания TLS 1.2
	this->scrub();
}
/**
 * @brief Метод затирания секретов издания TLS 1.2
 *
 */
void nts::internal::Engine::scrub() noexcept {
	// Если общее значение обмена ключами ещё не израсходовано
	if(!this->_premaster.empty())
		// Выполняем затирание общего значения обмена ключами
		this->purge(this->_premaster.data(), this->_premaster.size());
	// Выполняем сброс общего значения обмена ключами
	this->_premaster.clear();
	// Если заранее разделённый ключ связи выработан
	if(!this->_preshared.empty())
		// Выполняем затирание заранее разделённого ключа связи
		this->purge(this->_preshared.data(), this->_preshared.size());
	// Выполняем сброс заранее разделённого ключа связи
	this->_preshared.clear();
}
/**
 * @brief Метод затирания секрета на пути связи по классу SECRETS
 *
 * @param data затираемая область памяти
 * @param size размер затираемой области памяти в байтах
 *
 */
void nts::internal::Engine::purge(void * data, const size_t size) const noexcept {
	// Если класс SECRETS объявлен потребителем
	if(this->_scrubbing)
		// Выполняем затирание области памяти
		wipe(data, size);
}
/**
 * @brief Метод затирания накопителя открытого текста по классу PLAINTEXT
 *
 * @param data накопитель открытого текста; его длина остаётся прежней
 *
 */
void nts::internal::Engine::cleanse(vector <uint8_t> & data) const noexcept {
	// Выполняем затирание содержимого накопителя по классу PLAINTEXT
	this->cleanse(data.data(), data.size());
}
/**
 * @brief Метод затирания области открытого текста по классу PLAINTEXT
 *
 * @param data затираемая область открытого текста
 * @param size размер области в байтах
 *
 */
void nts::internal::Engine::cleanse(uint8_t * data, const size_t size) const noexcept {
	// Если класс PLAINTEXT объявлен потребителем и область не пуста
	if(this->_cleansing && (data != nullptr) && (size > 0))
		// Выполняем затирание области
		wipe(data, size);
}
/**
 * @brief Метод отзыва содержимого записи, вскрытой прямо в накопитель прикладных данных
 *
 * @param size длина накопителя до вскрытия записи: всё за нею затирается по классу PLAINTEXT и отбрасывается
 *
 */
void nts::internal::Engine::retract(const size_t size) noexcept {
	// Если за отметкой в накопителе есть содержимое вскрытой записи
	if(this->_plain.size() > size){
		// Выполняем затирание содержимого записи по классу PLAINTEXT
		this->cleanse(this->_plain.data() + size, this->_plain.size() - size);
		// Возвращаем накопитель к длине до вскрытия записи
		this->_plain.resize(size);
	}
}
/**
 * @brief Метод отказа собеседнику в пересогласовании издания TLS 1.2
 *
 * @return отказ отправки извещения об отказе пересогласования
 *
 */
context::error_t nts::internal::Engine::declining() noexcept {
	// Составляем извещение об отказе пересогласования уровня предупреждения
	const alert::alert_t refusal(alert::level_t::WARNING, alert::description_t::RENEGOTIATION);
	// Место, в которое записывается извещение об отказе пересогласования
	uint8_t buffer[alert::ALERT_LENGTH];
	// Если извещение об отказе пересогласования записать не удалось
	if(alert::build(refusal, buffer) != alert::error_t::NONE)
		// Выводим отказ составления извещения
		return context::error_t::MESSAGE;
	// Выводим итог складывания извещения в накопитель отправляемых байтов
	return this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
}
/**
 * @brief Метод складывания записи в накопитель отправляемых байтов
 *
 * @param type вид содержимого отправляемой записи
 * @param data содержимое отправляемой записи
 * @return     отказ складывания записи в накопитель
 *
 */
context::error_t nts::internal::Engine::emit(const record::type_t type, const view_t & data) noexcept {
	// Отказ связи, отвечающий отказу модуля
	context::error_t failure = context::error_t::NONE;
	// Получаем сторону связи, отправляющую запись
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Перенос по уровням записей не знает: сообщение рукопожатия уходит голым в
		 * накопитель уровня своей поры ключей, а прикладные данные и извещения этим
		 * путём не идут вовсе - данные шифрует QUIC, извещение уходит кодом закрытия
		 */
		if(this->_transport == context::transport_t::LEVELS){
			// Если складывается извещение
			if(type == record::type_t::ALERT)
				// Выводим успешность: извещение уходит кодом закрытия связи
				return context::error_t::NONE;
			// Если складываются прикладные данные
			if(type != record::type_t::HANDSHAKE)
				// Выводим отказ негодного состояния связи
				return context::error_t::STATE;
			// Получаем уровень защиты своей стороны
			const context::level_t level = this->layer(side);
			// Получаем накопитель сообщений уровня защиты
			vector <uint8_t> & storage = this->_levels[static_cast <uint8_t> (level) - 1];
			// Выполняем складывание сообщения в накопитель уровня
			storage.insert(storage.end(), data.data, data.data + data.size);
			// Выводим успешность складывания сообщения в накопитель
			return context::error_t::NONE;
		}
		/**
		 * Перенос дейтаграммами: сообщение рукопожатия ложится в залп и нарезается на
		 * записи раскладкой, а извещения и прикладные данные уходят своими записями
		 * сразу - им повторной передачи не положено
		 */
		if(this->_transport == context::transport_t::DATAGRAMS)
			// Выводим итог складывания записи в дейтаграммы
			return this->_flight.emit(type, data);
		/**
		 * Если содержимое длиннее предела, объявленного собеседником на приём (RFC 8449, RFC 6066),
		 * режем его на записи по пределу: каждая запись несёт не больше дозволенного
		 */
		if(data.size > this->_outgoing){
			/**
			 * Выполняем перебор содержимого кусками по пределу
			 */
			for(size_t offset = 0; offset < data.size; offset += this->_outgoing){
				// Длина куска: остаток либо предел
				const size_t size = (((data.size - offset) > this->_outgoing) ? this->_outgoing : (data.size - offset));
				// Отправляем кусок отдельной записью
				failure = this->emit(type, view_t(data.data + offset, size));
				// Если отправить кусок не удалось
				if(failure != context::error_t::NONE)
					// Выводим ошибку
					return failure;
			}
			// Сообщаем об успешной отправке частями
			return context::error_t::NONE;
		}
		/**
		 * Изданию TLS 1.2 защита включается сменой набора шифрования (раздел 7.1 RFC 5246):
		 * до своей смены записи идут открытыми, за нею - под ключами связи
		 */
		if(this->_legacy && this->_sealing){
			// Отказ наложения защиты на запись: запись ложится в накопитель отправки сразу, без промежуточной копии
			failure = translate(this->_output.seal(type, data, this->_wire, 0), context::error_t::PROTECTION);
			// Если наложить защиту на запись не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return failure;
		/**
		 * Записи упреждающих данных защищаются своими ключами: сервер о них ещё
		 * ничего не ответил, и ключей рукопожатия у клиента на этот миг нет вовсе
		 */
		} else if(!this->_server && this->_earlying){
			// Отказ наложения защиты на запись: запись ложится в накопитель отправки сразу, без промежуточной копии
			failure = translate(this->_early.seal(type, data, this->_wire, 0), context::error_t::PROTECTION);
			// Если наложить защиту упреждающих данных на запись не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return failure;
		// Если записи своей стороны защищены ключами связи
		} else if(!this->_legacy && (this->_machine.epoch(side) != flow::epoch_t::PLAIN)){
			// Отказ наложения защиты на запись: запись ложится в накопитель отправки сразу, без промежуточной копии
			failure = translate(this->_output.seal(type, data, this->_wire, 0), context::error_t::PROTECTION);
			// Если наложить защиту на запись не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ наложения защиты на запись
				return failure;
		// Если записи своей стороны идут без защиты
		} else {
			// Объект нарезчика отправляемых записей
			record::writer_t writer;
			// Отказ нарезки содержимого на записи
			failure = translate(writer.push(type, record::version_t::TLS12, data), context::error_t::RECORD);
			// Если содержимое на записи нарезать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ нарезки содержимого на записи
				return failure;
			// Получаем нарезанные записи содержимого
			const view_t records = writer.data();
			// Выполняем складывание нарезанных записей в накопитель
			this->_wire.insert(this->_wire.end(), records.data, records.data + records.size);
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность складывания записи в накопитель
	return context::error_t::NONE;
}
/**
 * @brief Метод получения уровня защиты, на котором идут сообщения стороны
 *
 * @param side сторона связи, уровень которой запрашивается
 * @return     уровень защиты сообщений стороны по поре её ключей
 *
 */
context::level_t nts::internal::Engine::layer(const session::side_t side) const noexcept {
	/**
	 * Раздел 4.1.4 RFC 9001 кладёт всякому сообщению рукопожатия свой уровень, и уровень
	 * этот совпадает с порой ключей стороны: приветствия идут открытыми на начальном
	 * уровне, выход сервера и ответ клиента - ключами рукопожатия, билеты - ключами
	 * прикладных данных
	 */
	switch(static_cast <uint8_t> (this->_machine.epoch(side))){
		// Если записи стороны идут без защиты
		case static_cast <uint8_t> (flow::epoch_t::PLAIN):
			// Выводим начальный уровень защиты
			return context::level_t::INITIAL;
		// Если записи стороны защищены ключами рукопожатия
		case static_cast <uint8_t> (flow::epoch_t::HANDSHAKE):
			// Выводим уровень рукопожатия
			return context::level_t::HANDSHAKE;
	}
	// Выводим уровень прикладных данных
	return context::level_t::APPLICATION;
}
/**
 * @brief Метод сохранения значений направлений уровня защиты для выдачи наружу
 *
 * @param level уровень защиты, значения которого сохраняются
 * @return      отказ сохранения значений направлений
 *
 */
context::error_t nts::internal::Engine::store(const context::level_t level) noexcept {
	/**
	 * Значения направлений снимаются с расписания сразу по выводу: переход к следующей
	 * ступени значения направлений переписывает, а потребителю под QUIC они нужны и после -
	 * ключи уровня рукопожатия он выводит из них уже тогда, когда связь ушла вперёд
	 */
	switch(static_cast <uint8_t> (level)){
		// Если сохраняется значение упреждающих данных
		case static_cast <uint8_t> (context::level_t::EARLY): {
			// Если значение упреждающих данных получить не удалось
			if(this->_secrets.early(this->_keys->traffic[0][0]) != session::error_t::NONE)
				// Выводим отказ вывода значения расписания ключей
				return context::error_t::SCHEDULE;
			/**
			 * Значение раннего экспорта выводится вместе с упреждающими данными
			 * меткою «e exp master» - раздел 7.2 RFC 8446
			 */
			// Место, в которое помещается значение раннего экспорта
			uint8_t exported[schedule::SCHEDULE_WIDEST];
			// Если значение раннего экспорта получить не удалось
			if(this->_secrets.earlyExporter(exported) != session::error_t::NONE)
				// Выводим отказ вывода значения расписания ключей
				return context::error_t::SCHEDULE;
			// Вызываем журнал секретов связи
			this->keylog("CLIENT_EARLY_TRAFFIC_SECRET", view_t(this->_keys->traffic[0][0], this->_secrets.size()));
			// Вызываем журнал секретов связи
			this->keylog("EARLY_EXPORTER_SECRET", view_t(exported, this->_secrets.size()));
			// Запоминаем длину значений направлений связи
			this->_width = this->_secrets.size();
			// Отмечаем готовность значения упреждающих данных клиента
			this->_ready[0] = 0x01;
		} break;
		// Если сохраняются значения рукопожатия либо прикладных данных
		case static_cast <uint8_t> (context::level_t::HANDSHAKE):
		case static_cast <uint8_t> (context::level_t::APPLICATION): {
			// Место уровня защиты среди сохранённых значений
			const size_t place = ((level == context::level_t::HANDSHAKE) ? 1 : 2);
			// Метки журнала секретов по уровням и сторонам
			static const char * LABELS[2][2] = {
				// Метки прикладного уровня и его сторон
				{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"},
				{"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}
			};
			/**
			 * Выполняем перебор сторон связи
			 */
			for(size_t i = 0; i < 2; i++){
				// Получаем очередную сторону связи
				const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
				// Если значение направления стороны получить не удалось
				if(this->_secrets.traffic(side, this->_keys->traffic[place][i]) != session::error_t::NONE)
					// Выводим отказ вывода значения расписания ключей
					return context::error_t::SCHEDULE;
				// Вызываем журнал секретов связи
				this->keylog(LABELS[place - 1][i], view_t(this->_keys->traffic[place][i], this->_secrets.size()));
			}
			// Если выводятся значения прикладных данных, журнал получает и значение экспорта
			if(level == context::level_t::APPLICATION){
				// Место, в которое помещается значение экспорта
				uint8_t exported[schedule::SCHEDULE_WIDEST];
				// Если значение экспорта получить не удалось
				if(this->_secrets.exporter(exported) != session::error_t::NONE)
					// Выводим отказ вывода значения расписания ключей
					return context::error_t::SCHEDULE;
				// Вызываем журнал секретов связи
				this->keylog("EXPORTER_SECRET", view_t(exported, this->_secrets.size()));
			}
			// Запоминаем длину значений направлений связи
			this->_width = this->_secrets.size();
			// Отмечаем готовность значений обеих сторон
			this->_ready[place] = 0x03;
		} break;
		// Если уровень значений не имеет
		default: return context::error_t::SCHEDULE;
	}
	// Выводим успешность сохранения значений направлений
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки сообщения рукопожатия собеседнику
 *
 * @param type вид отправляемого сообщения рукопожатия
 * @param body тело отправляемого сообщения рукопожатия
 * @return     отказ отправки сообщения рукопожатия
 *
 */
context::error_t nts::internal::Engine::send(const handshake::type_t type, const view_t & body) noexcept {
	// Получаем сторону связи, отправляющую сообщение
	const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Объект составителя отправляемых сообщений рукопожатия
	handshake::writer_t writer;
	// Отказ составления сообщения рукопожатия
	const context::error_t failure = translate(writer.push(type, body), context::error_t::MESSAGE);
	// Если сообщение рукопожатия составить не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ составления сообщения рукопожатия
		return failure;
	// Получаем составленное сообщение рукопожатия
	const view_t message = writer.data();
	/**
	 * Раздел 7.2 RFC 9849: по принятии ECH переписка ведётся внутренним приветствием, а
	 * на провод уходит внешнее - повторное приветствие после просьбы о повторе
	 * записывается в переписку внутренним
	 */
	const view_t recorded = ((!this->_server && (type == handshake::type_t::CLIENT) && (this->_ech == ech_t::ACCEPTED) && !this->_inner.empty()) ? view_t(this->_inner.data(), this->_inner.size()) : message);
	/**
	 * Запись складывается ключами той поры, которая идёт до объявления сообщения:
	 * приветствие сервера уходит открытым, а защита появляется лишь за ним
	 */
	// Порядковый номер сообщения поверх дейтаграмм: берётся до складывания, которое его продвигает
	const uint16_t number = this->_flight.outgoing();
	// Отказ складывания записи в накопитель
	const context::error_t error = this->emit(record::type_t::HANDSHAKE, message);
	// Если складывание записи в накопитель не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ складывания записи в накопитель
		return error;
	/**
	 * Изданию TLS 1.2 ход рукопожатия TLS 1.3 не подходит: порядок сообщений там иной, и
	 * ведёт его ступень связи; сообщения же копятся подряд ради подписи владения ключом
	 * (раздел 7.4.8 RFC 5246). Приветствие клиента копится и до согласования издания:
	 * издание выбирает сервер, а подпись владения ключом клиента изданием 1.2 покрывает
	 * и его приветствие; поверх дейтаграмм оно копится в обвязке DTLS (раздел 4.2.6 RFC 6347).
	 * Переписка ведётся одним путём с принятыми сообщениями - chronicle
	 */
	if(this->_legacy || (!this->_server && (type == handshake::type_t::CLIENT) && (this->_transport != context::transport_t::LEVELS))){
		// Приветствие клиента начинает переписку заново: прежней у издания 1.2 нет
		if(type == handshake::type_t::CLIENT)
			// Выполняем сброс переписки подряд
			this->_history.clear();
		// Если рукопожатие ещё не завершено
		if(this->_phase != phase_t::ESTABLISHED){
			// Отказ ведения переписки рукопожатия
			const context::error_t chronicled = this->chronicle(recorded, number);
			// Если сообщение в переписку рукопожатия добавить не удалось
			if(chronicled != context::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return chronicled;
		}
		// Если связь ведётся изданием TLS 1.2
		if(this->_legacy)
			// Выводим успешность отправки сообщения рукопожатия
			return context::error_t::NONE;
	// Если сообщение в переписку рукопожатия издания 1.3 добавить не удалось
	} else if(this->_transcript.update(recorded) != session::error_t::NONE)
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Если сообщение ходу рукопожатия объявить не удалось
	/**
	 * Раздел 4 RFC 8879: сжатая цепочка сертификатов идёт вместо обычной и занимает её
	 * место в ходе рукопожатия, оттого ходу она объявляется цепочкой сертификатов
	 */
	if(this->_machine.accept(((type == handshake::type_t::COMPRESSED) ? handshake::type_t::CERTIFICATE : type), side) != flow::error_t::NONE)
		// Выводим отказ объявления сообщения не в свой черёд
		return context::error_t::ORDER;
	// Выводим итог согласования ключевого материала защиты записей
	return this->refresh();
}
/**
 * @brief Метод согласования ключевого материала защиты записей
 *
 * @return отказ согласования ключевого материала
 *
 */
context::error_t nts::internal::Engine::refresh() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Ключевой материал прикладных данных выводится за завершением рукопожатия
		 * сервером, а пора ключей стороны переменяется самим этим завершением: до вывода
		 * ставить защите записей нечего
		 */
		if(this->_secrets.stage() != session::stage_t::APPLICATION)
			// Выводим успешность согласования ключевого материала
			return context::error_t::NONE;
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		/**
		 * Выполняем перебор сторон связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем очередную сторону связи
			const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
			// Получаем пору ключей записей стороны связи
			const flow::epoch_t epoch = this->_machine.epoch(side);
			// Если пора ключей стороны связи не переменилась
			if((epoch != flow::epoch_t::APPLICATION) || (this->_epoch[i] == epoch))
				// Переходим к следующей стороне связи
				continue;
			// Получаем объект защиты записей стороны связи
			protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
			/**
			 * Защита записей заводится лишь переносу записями: под QUIC записи шифрует тот,
			 * кто связь ведёт, значениями направлений, выданными наружу
			 */
			if((this->_transport != context::transport_t::LEVELS) && !protection.start(this->_suite, view_t(this->_keys->key[i], protect::key(this->_suite)), view_t(this->_keys->vector[i], protect::block(this->_suite))))
				// Выводим отказ установки ключевого материала
				return context::error_t::SCHEDULE;
			// Раздел 4.2.1 RFC 9147: прикладные ключи открывают третью пору направления
			if(this->_transport == context::transport_t::DATAGRAMS){
				// Отказ заведения поры ключей направления
				const context::error_t adopted = this->adopt(side, context::level_t::APPLICATION);
				// Если пору ключей завести не удалось
				if(adopted != context::error_t::NONE)
					// Выводим отказ заведения поры ключей
					return adopted;
			}
			// Запоминаем пору ключей, установленную защите записей
			this->_epoch[i] = epoch;
		}
		// Выводим успешность согласования ключевого материала
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод выбора хеша переписки и расписания по набору шифрования
 *
 * @return отказ выбора хеша
 *
 */
context::error_t nts::internal::Engine::hashing() noexcept {
	// Получаем хеш выбранного набора шифрования
	const digest::hash_t algorithm = protect::hash(this->_suite);
	// Если набор шифрования хеша не имеет
	if(algorithm == digest::hash_t::NONE)
		// Выводим отказ неизвестности набора шифрования
		return context::error_t::SUITE;
	/**
	 * Раздел 4.4.1 RFC 8446: переписка рукопожатия хешируется хешем набора шифрования,
	 * а выбранный набор за просьбой о повторе не меняется - оттого повторный выбор того
	 * же хеша переписке безразличен, а иного - отвергается ею как дефект состояния
	 */
	if(this->_transcript.select(algorithm) != session::error_t::NONE)
		// Выводим отказ выбора хеша переписки
		return context::error_t::SUITE;
	// Выводим успешность выбора хеша
	return context::error_t::NONE;
}
/**
 * @brief Метод выработки своей доли гибридной группы инкапсуляцией на долю клиента
 *
 * @param group группа обмена, гибрид с инкапсуляцией ключа
 * @param peer  доля клиента: ключ инкапсуляции и точка кривой
 * @return      отказ выработки доли
 *
 */
context::error_t nts::internal::Engine::encapsulating(const extension::group_t group, const view_t & peer) noexcept {
	// Если группа не гибрид
	if(!extension::hybrid(group))
		// Выходим с ошибкой группы
		return context::error_t::GROUP;
	// Механизм инкапсуляции, кривая и порядок половин гибрида
	const agreement::kem_t kem = kemof(group);
	// Кривая классической половины гибрида
	const extension::group_t half = curveof(group);
	// Длины шифртекста ML-KEM, общего значения и точки кривой
	const size_t opened = agreement::encapsulation(kem), cipher = agreement::ciphertext(kem), point = curvelength(group);
	// Место доли ML-KEM: впереди либо за точкой кривой
	const size_t kemat = (kemfirst(group) ? 0 : point);
	// Если доля клиента не той длины
	if((peer.data == nullptr) || (peer.size != (opened + point)))
		// Выходим с ошибкой обмена
		return context::error_t::EXCHANGE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Пара обмена сервера
		exchange_t item;
		// Устанавливаем группу
		item.group = group;
		// Кривая NIST классической половины и длина её секрета
		curve::curve_t curve;
		// Длина секрета кривой: 32 у X25519, размер кривой у NIST
		size_t scalar = agreement::X25519_SIZE;
		// Если половина - кривая NIST, берём её параметры
		if(half != extension::group_t::X25519){
			// Если параметры кривой не заведены: с незаведённой кривой пару не выработать
			if(!curve::parameters(extension::curve(half), curve))
				// Выводим отказ группы
				return context::error_t::GROUP;
			// Длина секрета - размер кривой
			scalar = curve.size();
		}
		// Секрет кривой, доля сервера (шифртекст и точка порядком гибрида) и общее значение ML-KEM
		item.secret.assign(scalar, 0);
		// Занимаем место под шифртекст ML-KEM и точку кривой
		item.opened.assign(cipher + point, 0);
		// Занимаем место под общее значение ML-KEM
		item.shared.assign(agreement::MLKEM_SHARED, 0);
		// Если инкапсуляцию на ключе клиента провести не удалось
		if(!agreement::encapsulate(kem, view_t(peer.data + kemat, opened), item.opened.data() + (kemfirst(group) ? 0 : point), item.shared.data())){
			// Затираем общее значение ML-KEM
			this->purge(item.shared.data(), item.shared.size());
			// Выводим отказ обмена
			return context::error_t::EXCHANGE;
		}
		// Если половина - X25519
		if(half == extension::group_t::X25519){
			// Если секрет и точку X25519 выработать не удалось
			if(!entropy::bytes(item.secret.data(), item.secret.size()) || !agreement::x25519(view_t(item.secret.data(), item.secret.size()), item.opened.data() + (kemfirst(group) ? cipher : 0))){
				// Затираем секрет кривой
				this->purge(item.secret.data(), item.secret.size());
				this->purge(item.shared.data(), item.shared.size());
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
		// Если половина - кривая NIST
		} else {
			// Место под точку младшим байтом вперёд
			uint8_t raw[math::NUMBER_SIZE * 2];
			// Если пару кривой породить не удалось
			if(!agreement::generate(curve, item.secret.data(), raw)){
				// Затираем секрет кривой
				this->purge(item.secret.data(), item.secret.size());
				this->purge(item.shared.data(), item.shared.size());
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
			// Кодируем точку в несжатом виде
			const size_t at = (kemfirst(group) ? cipher : 0);
			// Признак несжатого вида точки
			item.opened[at] = 0x04;
			// Переносим координаты точки младшим байтом вперёд
			reverse(raw, item.opened.data() + at + 1, scalar);
			reverse(raw + scalar, item.opened.data() + at + 1 + scalar, scalar);
			// Затираем коды точки
			this->purge(raw, sizeof(raw));
		}
		// Запоминаем пару и группу
		this->_exchanges.push_back(::move(item));
		// Запоминаем группу обмена
		this->_group = group;
		// Сообщаем об успешном запоминании пары
		return context::error_t::NONE;
	// Если памяти не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим ошибку памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод выработки общего значения обмена мимолётными ключами
 *
 * @param group  группа обмена, выбранная собеседником
 * @param key    открытый мимолётный ключ собеседника в записи протокола
 * @param result место, в которое помещается общее значение
 * @param length место, в которое помещается длина общего значения
 * @return       отказ выработки общего значения
 *
 */
context::error_t nts::internal::Engine::agree(const extension::group_t group, const view_t & key, uint8_t * result, size_t & length) noexcept {
	// Сбрасываем длину общего значения
	length = 0;
	// Мимолётная пара ключей своей стороны по выбранной группе
	const exchange_t * own = nullptr;
	/**
	 * Выполняем перебор мимолётных пар ключей своей стороны
	 */
	for(size_t i = 0; (i < this->_exchanges.size()) && (own == nullptr); i++){
		// Если пара ключей выработана по выбранной группе
		if(this->_exchanges[i].group == group)
			// Запоминаем найденную пару ключей
			own = &this->_exchanges[i];
	}
	// Если своей пары ключей по выбранной группе нет либо группа связи неведома
	if((own == nullptr) || own->secret.empty() || !known(group))
		// Выводим отказ обмена ключами по неведомой группе
		return context::error_t::GROUP;
	// Если группа обмена - гибрид X25519 и ML-KEM-768
	if(extension::hybrid(group)){
		// Механизм инкапсуляции, кривая и порядок половин гибрида
		const agreement::kem_t kem = kemof(group);
		// Кривая классической половины гибрида
		const extension::group_t half = curveof(group);
		// Длины доли ML-KEM, секрета декапсуляции и точки кривой
		const size_t opened = agreement::encapsulation(kem), secret = agreement::decapsulation(kem), cipher = agreement::ciphertext(kem), point = curvelength(group);
		// Сервер отвечал (общее значение ML-KEM уже есть) либо клиент распаковывает
		const bool responded = !own->shared.empty();
		// Длина доли ML-KEM у собеседника и её место, место доли кривой
		const size_t kemlength = (responded ? opened : cipher);
		// Место доли ML-KEM и доли кривой: порядок половин гибрида
		const size_t kemat = (kemfirst(group) ? 0 : point), curveat = (kemfirst(group) ? kemlength : 0);
		// Если доля собеседника не той длины
		if((key.data == nullptr) || (key.size != (kemlength + point)))
			// Выходим с ошибкой обмена
			return context::error_t::EXCHANGE;
		// Общее значение: у X25519MLKEM768 ML-KEM впереди, у гибридов NIST впереди кривая
		const size_t curveshared = ((half == extension::group_t::X25519) ? agreement::X25519_SIZE : (point - 1) / 2);
		// Место общего значения ML-KEM в выходном буфере
		uint8_t * kemout = (result + (kemfirst(group) ? 0 : curveshared));
		// Место общего значения кривой в выходном буфере
		uint8_t * curveout = (result + (kemfirst(group) ? agreement::MLKEM_SHARED : 0));
		// Если сервер отвечал, общее значение ML-KEM уже выработано
		if(responded)
			// Переносим готовое общее значение ML-KEM
			::memcpy(kemout, own->shared.data(), agreement::MLKEM_SHARED);
		// Если распаковать шифртекст не удалось
		else if(!agreement::decapsulate(kem, view_t(own->secret.data(), secret), view_t(key.data + kemat, cipher), kemout))
			// Выходим с ошибкой обмена
			return context::error_t::EXCHANGE;
		// Секрет кривой: у сервера весь секрет, у клиента - за ключом декапсуляции
		const uint8_t * scalar = (responded ? own->secret.data() : (own->secret.data() + secret));
		// Длина секрета кривой: без секрета декапсуляции у клиента
		const size_t scalarsize = (responded ? own->secret.size() : (own->secret.size() - secret));
		// Точка собеседника
		const uint8_t * peer = (key.data + curveat);
		// Если половина - X25519
		if(half == extension::group_t::X25519){
			// Если общее значение X25519 выработать не удалось
			if(!agreement::x25519(view_t(scalar, agreement::X25519_SIZE), view_t(peer, agreement::X25519_SIZE), curveout)){
				// Затираем выходной буфер
				this->purge(result, agreement::MLKEM_SHARED + agreement::X25519_SIZE);
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
		// Если половина - кривая NIST
		} else {
			// Кривая
			curve::curve_t curve;
			// Если параметры кривой не найдены либо точка не в несжатом виде
			if(!curve::parameters(extension::curve(half), curve) || (peer[0] != 0x04) || (curve.size() != curveshared)){
				// Затираем выходной буфер
				this->purge(result, agreement::MLKEM_SHARED + curveshared);
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
			// Точка младшим байтом вперёд
			uint8_t raw[math::NUMBER_SIZE * 2];
			// Переносим координату X младшим байтом вперёд
			reverse(peer + 1, raw, curveshared);
			reverse(peer + 1 + curveshared, raw + curveshared, curveshared);
			// Общее значение младшим байтом вперёд
			uint8_t little[math::NUMBER_SIZE];
			// Если общее значение кривой выработать не удалось
			if(!agreement::ecdhe(curve, view_t(scalar, scalarsize), view_t(raw, curveshared * 2), little)){
				// Затираем выходной буфер
				this->purge(raw, sizeof(raw));
				this->purge(result, agreement::MLKEM_SHARED + curveshared);
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
			// Переводим в старший байт вперёд, как велит RFC 8446 для кривых NIST
			reverse(little, curveout, curveshared);
			// Затираем общее значение кривой
			this->purge(little, sizeof(little));
			this->purge(raw, sizeof(raw));
		}
		// Длина общего значения
		length = (agreement::MLKEM_SHARED + curveshared);
		// Сообщаем об успешном заведении гибридной пары
		return context::error_t::NONE;
	}
	// Если доля собеседника негодной длины
	if((key.data == nullptr) || (key.size == 0) || (key.size != extension::length(group)))
		// Выводим отказ негодной длины открытого ключа собеседника
		return context::error_t::EXCHANGE;
	// Место, в которое помещается общее значение обмена
	uint8_t * shared = result;
	// Если группа обмена - кривая Монтгомери
	if(montgomery(group)){
		/**
		 * Раздел 7.4.2 RFC 8446: итог X25519 либо X448 из одних нулей связь обязана
		 * отвергнуть - примитив отвечает на него отказом сам
		 */
		if(group == extension::group_t::X25519){
			// Если общее значение X25519 выработать не удалось
			if(!agreement::x25519(view_t(own->secret.data(), own->secret.size()), key, shared))
				// Выводим отказ выработки общего значения обмена
				return context::error_t::EXCHANGE;
			// Запоминаем длину общего значения
			length = agreement::X25519_SIZE;
		// Если группа обмена - X448
		} else {
			// Если общее значение X448 выработать не удалось
			if(!agreement::x448(view_t(own->secret.data(), own->secret.size()), key, shared))
				// Выводим отказ выработки общего значения обмена
				return context::error_t::EXCHANGE;
			// Запоминаем длину общего значения
			length = agreement::X448_SIZE;
		}
	// Если группа обмена - конечное поле RFC 7919
	} else if(extension::finite(group) > 0){
		/**
		 * Раздел 7.4.1 RFC 8446: общее значение идёт длиной модуля с нулями спереди;
		 * ключ собеседника вне подгруппы простого порядка примитив отвергает сам
		 */
		if(!agreement::ffdhe(extension::finite(group), view_t(own->secret.data(), own->secret.size()), key, shared))
			// Выводим отказ выработки общего значения обмена
			return context::error_t::EXCHANGE;
		// Запоминаем длину общего значения
		length = extension::finite(group);
	// Если группа обмена - кривая
	} else {
		// Эллиптическая кривая обмена мимолётными ключами
		curve::curve_t curve;
		// Если кривую обмена мимолётными ключами завести не удалось
		if(!curve::parameters(extension::curve(group), curve))
			// Выводим отказ заведения кривой обмена ключами
			return context::error_t::GROUP;
		// Длина координаты точки кривой
		const size_t size = curve.size();
		// Место, в которое помещается открытый ключ собеседника в записи выработки
		uint8_t point[math::NUMBER_SIZE * 2];
		// Если группа обмена - кривая NIST
		if(classic(group)){
			/**
			 * Раздел 4.2.8.2 RFC 8446: доля ключа есть несжатая точка 0x04||X||Y в
			 * прямом порядке байтов, тогда как выработка ждёт координаты обратной
			 * записью; принадлежность точки кривой сверяет сама выработка
			 */
			if(key.data[0] != 0x04)
				// Выводим отказ негодной записи точки
				return context::error_t::EXCHANGE;
			// Переносим первую координату точки обратной записью
			reverse(key.data + 1, point, size);
			// Переносим вторую координату точки обратной записью
			reverse(key.data + 1 + size, point + size, size);
		// Если группа обмена - кривая ГОСТ
		} else
			// Переносим координаты точки как есть
			::memcpy(point, key.data, key.size);
		// Если общее значение обмена мимолётными ключами выработать не удалось
		if(!agreement::ecdhe(curve, view_t(own->secret.data(), own->secret.size()), view_t(point, size * 2), shared)){
			// Выполняем затирание записи точки
			this->purge(point, sizeof(point));
			// Выводим отказ выработки общего значения обмена
			return context::error_t::EXCHANGE;
		}
		// Выполняем затирание записи точки
		this->purge(point, sizeof(point));
		// Если группа обмена - кривая NIST
		if(classic(group)){
			// Место, в которое помещается общее значение прямой записью
			uint8_t straight[math::NUMBER_SIZE];
			/**
			 * Раздел 7.4.2 RFC 8446: общим значением служит координата X в прямом
			 * порядке байтов, а выработка отдаёт её обратной записью
			 */
			reverse(shared, straight, size);
			// Переносим общее значение прямой записью на место итога
			::memcpy(shared, straight, size);
			// Выполняем затирание общего значения прямой записи
			this->purge(straight, sizeof(straight));
		}
		// Запоминаем длину общего значения
		length = size;
	}
	// Выводим успешность выработки общего значения
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключей рукопожатия связи
 *
 * @param group группа обмена, выбранная собеседником
 * @param key   открытый мимолётный ключ собеседника в записи протокола
 * @return      отказ вывода ключей рукопожатия
 *
 */
context::error_t nts::internal::Engine::derive(const extension::group_t group, const view_t & key) noexcept {
	// Раздел 4.2.7 RFC 8446: доля ключа идёт лишь по группе, изданию 1.3 дозволенной
	if(!fitting(group, false))
		// Выводим отказ группы вне издания
		return context::error_t::GROUP;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Место под общее значение берётся по самому широкому: у гибрида это общее значение
		 * ML-KEM с координатой кривой, у конечного поля RFC 7919 - ключ длиной в модуль
		 * ffdhe8192; координата кривой шире числа арифметики быть не может
		 */
		uint8_t shared[agreement::MLKEM_SHARED + agreement::FFDHE_MOST];
		// Длина общего значения обмена мимолётными ключами
		size_t length = 0;
		// Отказ выработки общего значения обмена мимолётными ключами
		const context::error_t agreed = this->agree(group, key, shared, length);
		// Если общее значение выработать не удалось
		if(agreed != context::error_t::NONE){
			// Выполняем затирание общего значения обмена мимолётными ключами
			this->purge(shared, sizeof(shared));
			// Выводим отказ выработки общего значения
			return agreed;
		}
		// Получаем хеш набора шифрования связи
		const digest::hash_t algorithm = protect::hash(this->_suite);
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Признак успешности вывода ключей рукопожатия связи
		bool ok = (this->_transcript.digest(transcript) == session::error_t::NONE);
		/**
		 * Начальная ступень расписания ключей заводится лишь тогда, когда её ещё нет:
		 * при возобновлении связи билетом в неё уже вложен заранее разделённый ключ
		 */
		/**
		 * Слагаемое ok здесь истинно всегда: хеш переписки отказывает лишь у незаведённой
		 * переписки, а ключи рукопожатия выводятся не прежде приветствий. Слагаемое
		 * оставлено ради цепочки: заведение ступени после отказавшего хеша шло бы уже по
		 * мусору
		 */
		if(ok && (this->_secrets.stage() == session::stage_t::NONE))
			// Выполняем заведение начальной ступени расписания ключей хешем набора
			ok = (this->_secrets.start(algorithm, view_t(nullptr, 0)) == session::error_t::NONE);
		/**
		 * Раздел 4.2.11 RFC 8446: расписание, заведённое ключом билета, ведётся хешем
		 * набора билета, и набор связи обязан вести тот же хеш - иначе ступень
		 * рукопожатия выводилась бы из значения чужого хеша
		 */
		if(ok && (this->_secrets.algorithm() != algorithm))
			// Запоминаем отказ расхождения хешей расписания и набора
			ok = false;
		// Если начальная ступень расписания ключей заведена
		if(ok)
			// Выполняем вывод ступени рукопожатия расписания ключей
			ok = (this->_secrets.handshake(view_t(shared, length), view_t(transcript, this->_transcript.size())) == session::error_t::NONE);
		// Выполняем затирание общего значения обмена мимолётными ключами
		this->purge(shared, sizeof(shared));
		// Если ступень рукопожатия расписания ключей вывести не удалось
		if(!ok)
			// Выводим отказ вывода ключевого материала связи
			return context::error_t::SCHEDULE;
		// Отказ сохранения значений направлений рукопожатия для выдачи наружу
		const context::error_t kept = this->store(context::level_t::HANDSHAKE);
		// Если значения направлений рукопожатия сохранить не удалось
		if(kept != context::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return kept;
		/**
		 * Выполняем перебор сторон связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем очередную сторону связи
			const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
			/**
			 * Ключи завершения рукопожатия снимаются сразу: переход к ступени прикладных
			 * данных значения направлений связи переписывает
			 */
			if(this->_secrets.finished(side, this->_keys->completion[i]) != session::error_t::NONE)
				// Выводим отказ вывода ключей завершения рукопожатия
				return context::error_t::SCHEDULE;
			// Корневой ключ направления связи
			uint8_t material[protect::PROTECT_KEY];
			// Вектор замены направления связи
			uint8_t element[protect::PROTECT_VECTOR];
			// Если ключевой материал направления связи вывести не удалось
			if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
				// Выводим отказ вывода ключевого материала направления
				return context::error_t::SCHEDULE;
			// Получаем сторону связи, которую ведёт модуль
			const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
			// Получаем объект защиты записей стороны связи
			protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
			/**
			 * Защита записей заводится лишь переносу записями: под QUIC записи шифрует тот,
			 * кто связь ведёт, значениями направлений, выданными наружу
			 */
			const bool installed = ((this->_transport == context::transport_t::LEVELS) || protection.start(this->_suite, view_t(material, protect::key(this->_suite)), view_t(element, protect::block(this->_suite))));
			// Выполняем затирание вектора замены направления связи
			this->purge(element, sizeof(element));
			// Выполняем затирание корневого ключа направления связи
			this->purge(material, sizeof(material));
			// Если ключевой материал направления связи установить не удалось
			if(!installed)
				// Выводим отказ установки ключевого материала направления
				return context::error_t::SCHEDULE;
			// Раздел 4.2.1 RFC 9147: ключи рукопожатия открывают вторую пору направления
			if(this->_transport == context::transport_t::DATAGRAMS){
				// Отказ заведения поры ключей направления
				const context::error_t adopted = this->adopt(side, context::level_t::HANDSHAKE);
				// Если пору ключей завести не удалось
				if(adopted != context::error_t::NONE)
					// Выводим отказ заведения поры ключей
					return adopted;
			}
			// Запоминаем пору ключей, установленную защите записей
			this->_epoch[i] = flow::epoch_t::HANDSHAKE;
		}
		// Выводим успешность вывода ключей рукопожатия связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод вывода ключей прикладных данных связи
 *
 * @return отказ вывода ключей прикладных данных
 *
 */
context::error_t nts::internal::Engine::mature() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::SCHEDULE;
		// Если ступень прикладных данных расписания ключей вывести не удалось
		if(this->_secrets.application(view_t(transcript, this->_transcript.size())) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return context::error_t::SCHEDULE;
		// Отказ сохранения значений направлений прикладных данных для выдачи наружу
		const context::error_t kept = this->store(context::level_t::APPLICATION);
		// Если значения направлений прикладных данных сохранить не удалось
		if(kept != context::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return kept;
		/**
		 * Выполняем перебор сторон связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем очередную сторону связи
			const session::side_t side = ((i == 0) ? session::side_t::CLIENT : session::side_t::SERVER);
			// Если ключевой материал направления связи вывести не удалось
			if(this->_secrets.material(side, this->_suite, this->_keys->key[i], this->_keys->vector[i]) != session::error_t::NONE)
				// Выводим отказ вывода ключевого материала направления
				return context::error_t::SCHEDULE;
		}
		// Выводим успешность вывода ключей прикладных данных связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод заведения защиты записей упреждающих данных
 *
 * @return отказ заведения защиты записей упреждающих данных
 *
 */
context::error_t nts::internal::Engine::earliest() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Ключи упреждающих данных выводятся набором шифрования билета, а не набором
		 * этой связи: раздел 4.2.10 RFC 8446 велит брать тот, каким билет выдан, - иного
		 * согласования на этот миг ещё и не было
		 */
		if(protect::block(this->_ticket) == 0)
			// Выводим отказ неизвестности набора шифрования билета
			return context::error_t::SUITE;
		// Хеш набора шифрования билета
		const digest::hash_t algorithm = protect::hash(this->_ticket);
		// Длина хеша набора шифрования билета
		const size_t width = digest::length(algorithm);
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		/**
		 * Раздел 6.1 RFC 9849: под ECH упреждающие данные принадлежат внутреннему приветствию -
		 * их ключи выводятся из переписки с ClientHelloInner, а не с отправленным внешним;
		 * примет ли сервер ECH, ещё неизвестно, и при отказе данные пропадают вместе со связью
		 */
		if(!this->_server && (this->_ech == ech_t::OFFERED) && !this->_inner.empty()){
			// Переписка с внутренним приветствием
			session::transcript_t shadow;
			// Если переписку завести либо посчитать не удалось
			if((shadow.start(algorithm) != session::error_t::NONE) || (shadow.update(view_t(this->_inner.data(), this->_inner.size())) != session::error_t::NONE) || (shadow.digest(algorithm, view_t(nullptr, 0), transcript) != session::error_t::NONE))
				// Выходим с ошибкой расписания
				return context::error_t::SCHEDULE;
		// Если переписка обычная, хеш берётся с неё
		} else if(this->_transcript.digest(algorithm, view_t(nullptr, 0), transcript) != session::error_t::NONE)
			// Выходим с ошибкой расписания
			return context::error_t::SCHEDULE;
		// Если значение упреждающих данных вывести не удалось
		if(this->_secrets.early(view_t(transcript, width)) != session::error_t::NONE)
			// Выводим отказ вывода значения расписания ключей
			return context::error_t::SCHEDULE;
		// Отказ сохранения значения упреждающих данных для выдачи наружу
		const context::error_t kept = this->store(context::level_t::EARLY);
		// Если значение упреждающих данных сохранить не удалось
		if(kept != context::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return kept;
		/**
		 * Под QUIC упреждающие данные шифрует тот, кто связь ведёт: защита записей
		 * упреждения не заводится, а ход упреждения отмечается тотчас
		 */
		if(this->_transport == context::transport_t::LEVELS){
			// Запоминаем, что упреждающие данные идут прямо сейчас
			this->_earlying = true;
			// Выводим успешность заведения упреждающих данных
			return context::error_t::NONE;
		}
		// Значение упреждающих данных связи
		uint8_t traffic[schedule::SCHEDULE_WIDEST];
		// Если значение упреждающих данных получить не удалось
		if(this->_secrets.early(traffic) != session::error_t::NONE)
			// Выводим отказ вывода значения расписания ключей
			return context::error_t::SCHEDULE;
		// Место, в которое помещается корневой ключ упреждающих данных
		uint8_t material[protect::PROTECT_KEY];
		// Место, в которое помещается вектор замены упреждающих данных
		uint8_t element[protect::PROTECT_VECTOR];
		// Признак успешности вывода ключевого материала упреждающих данных
		bool ok = (session::material(view_t(traffic, width), this->_ticket, material, element) == session::error_t::NONE);
		// Если ключевой материал упреждающих данных выведен
		if(ok)
			// Выполняем установку ключевого материала упреждающих данных
			ok = this->_early.start(this->_ticket, view_t(material, protect::key(this->_ticket)), view_t(element, protect::block(this->_ticket)));
		// Выполняем затирание вектора замены упреждающих данных
		this->purge(element, sizeof(element));
		// Выполняем затирание корневого ключа упреждающих данных
		this->purge(material, sizeof(material));
		// Выполняем затирание значения упреждающих данных связи
		this->purge(traffic, sizeof(traffic));
		// Если ключевой материал упреждающих данных установить не удалось
		if(!ok)
			// Выводим отказ установки ключевого материала
			return context::error_t::SCHEDULE;
		// Запоминаем, что упреждающие данные идут прямо сейчас
		this->_earlying = true;
		// Выводим успешность заведения защиты записей упреждающих данных
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод выработки мимолётной пары ключей своей стороны
 *
 * @param group группа обмена, для которой вырабатывается пара ключей
 * @return      отказ выработки мимолётной пары ключей
 *
 */
context::error_t nts::internal::Engine::exchange(const extension::group_t group) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Вырабатываемая мимолётная пара ключей
		exchange_t item;
		// Запоминаем группу обмена пары ключей
		item.group = group;
		/**
		 * Раздел 3.1 RFC 8701: под группу, связи неведомую, доля ключа шлётся произвольной
		 * длины и содержимого - так потребитель вставляет своё значение GREASE снаружи, а
		 * выбрать такую группу собеседник не вправе
		 */
		if(!known(group)){
			// Занимаем место под произвольную долю ключа в один байт
			item.opened.assign(1, 0);
			// Если произвольную долю ключа выработать не удалось
			if(!entropy::bytes(item.opened.data(), item.opened.size()))
				// Выводим отказ выработки доли ключа
				return context::error_t::EXCHANGE;
			// Добавляем пару ключей к парам своей стороны
			this->_exchanges.push_back(::move(item));
			// Выводим успешность выработки доли ключа
			return context::error_t::NONE;
		}
		// Если группа обмена - гибрид X25519 и ML-KEM-768
		if(extension::hybrid(group)){
			// Механизм инкапсуляции, кривая и порядок половин гибрида
			const agreement::kem_t kem = kemof(group);
			// Кривая классической половины гибрида
			const extension::group_t half = curveof(group);
			// Длины доли ML-KEM, секрета декапсуляции и точки кривой
			const size_t opened = agreement::encapsulation(kem), secret = agreement::decapsulation(kem), point = curvelength(group);
			// Место доли ML-KEM и доли кривой: порядок половин гибрида
			const size_t kemat = (kemfirst(group) ? 0 : point), curveat = (kemfirst(group) ? opened : 0);
			// Кривая NIST классической половины
			curve::curve_t curve;
			// Длина секрета кривой: 32 у X25519, размер кривой у NIST
			size_t scalar = agreement::X25519_SIZE;
			// Если половина - кривая NIST, берём её параметры
			if((half != extension::group_t::X25519) && curve::parameters(extension::curve(half), curve))
				// Длина секрета - размер кривой
				scalar = curve.size();
			// Секрет: ключ декапсуляции и секрет кривой; доля: ключ инкапсуляции и точка порядком гибрида
			item.secret.assign(secret + scalar, 0);
			// Занимаем место под долю: ключ инкапсуляции и точка кривой
			item.opened.assign(opened + point, 0);
			// Если пару ML-KEM породить не удалось
			if(!agreement::generate(kem, item.opened.data() + kemat, item.secret.data())){
				// Затираем секрет пары
				this->purge(item.secret.data(), item.secret.size());
				// Выводим отказ обмена
				return context::error_t::EXCHANGE;
			}
			// Если половина - X25519
			if(half == extension::group_t::X25519){
				// Если секрет и точку X25519 выработать не удалось
				if(!entropy::bytes(item.secret.data() + secret, agreement::X25519_SIZE) || !agreement::x25519(view_t(item.secret.data() + secret, agreement::X25519_SIZE), item.opened.data() + curveat)){
					// Затираем секрет пары
					this->purge(item.secret.data(), item.secret.size());
					// Выводим отказ обмена
					return context::error_t::EXCHANGE;
				}
			// Если половина - кривая NIST: точка в несжатом виде 04 ‖ X ‖ Y старшим байтом вперёд
			} else {
				// Место под точку младшим байтом вперёд
				uint8_t raw[math::NUMBER_SIZE * 2];
				// Если пару кривой породить не удалось
				if((half != curveof(group)) || !agreement::generate(curve, item.secret.data() + secret, raw)){
					// Затираем секрет пары
					this->purge(item.secret.data(), item.secret.size());
					// Выводим отказ обмена
					return context::error_t::EXCHANGE;
				}
				// Кодируем точку
				item.opened[curveat] = 0x04;
				// Переносим координату X младшим байтом вперёд
				reverse(raw, item.opened.data() + curveat + 1, scalar);
				reverse(raw + scalar, item.opened.data() + curveat + 1 + scalar, scalar);
				// Затираем коды точки
				this->purge(raw, sizeof(raw));
			}
		} else if(montgomery(group)){
			// Длина ключей кривой Монтгомери
			const size_t size = ((group == extension::group_t::X25519) ? agreement::X25519_SIZE : agreement::X448_SIZE);
			// Занимаем место под секретный мимолётный ключ своей стороны
			item.secret.assign(size, 0);
			// Занимаем место под открытый мимолётный ключ своей стороны
			item.opened.assign(size, 0);
			// Если секретный мимолётный ключ выработать не удалось
			if(!entropy::bytes(item.secret.data(), item.secret.size())){
				// Затираем недовыработанный секрет
				this->purge(item.secret.data(), item.secret.size());
				// Выводим отказ выработки мимолётной пары ключей
				return context::error_t::EXCHANGE;
			}
			// Признак выработки открытого мимолётного ключа
			const bool produced = ((group == extension::group_t::X25519) ?
				agreement::x25519(view_t(item.secret.data(), item.secret.size()), item.opened.data()) :
				agreement::x448(view_t(item.secret.data(), item.secret.size()), item.opened.data())
			);
			// Если открытый мимолётный ключ выработать не удалось
			if(!produced){
				// Выполняем затирание секретного мимолётного ключа
				this->purge(item.secret.data(), item.secret.size());
				// Выводим отказ выработки мимолётной пары ключей
				return context::error_t::EXCHANGE;
			}
		// Если группа обмена - конечное поле RFC 7919
		} else if(extension::finite(group) > 0){
			// Длина модуля группы
			const size_t size = extension::finite(group);
			// Занимаем место под секретный показатель своей стороны
			item.secret.assign(agreement::exponent(size), 0);
			// Занимаем место под открытый ключ своей стороны длиной в модуль
			item.opened.assign(size, 0);
			// Если пару ключей группы выработать не удалось
			if(!agreement::pairffdhe(size, item.secret.data(), item.opened.data())){
				// Выполняем затирание секретного показателя
				this->purge(item.secret.data(), item.secret.size());
				// Выводим отказ выработки мимолётной пары ключей
				return context::error_t::EXCHANGE;
			}
		// Если группа обмена - кривая
		} else {
			// Эллиптическая кривая обмена мимолётными ключами
			curve::curve_t curve;
			// Если кривую обмена мимолётными ключами завести не удалось
			if(!curve::parameters(extension::curve(group), curve))
				// Выводим отказ заведения кривой обмена ключами
				return context::error_t::GROUP;
			// Длина координаты точки кривой
			const size_t size = curve.size();
			// Занимаем место под секретный мимолётный ключ своей стороны
			item.secret.assign(size, 0);
			// Место, в которое помещаются координаты открытого ключа обратной записью
			uint8_t point[math::NUMBER_SIZE * 2];
			// Если мимолётную пару ключей своей стороны выработать не удалось
			if(!agreement::generate(curve, item.secret.data(), point)){
				// Выполняем затирание секретного мимолётного ключа
				this->purge(item.secret.data(), item.secret.size());
				// Выводим отказ выработки мимолётной пары ключей
				return context::error_t::EXCHANGE;
			}
			// Если группа обмена - кривая NIST
			if(classic(group)){
				// Занимаем место под несжатую точку 0x04||X||Y
				item.opened.assign(1 + (size * 2), 0);
				// Записываем признак несжатой точки
				item.opened[0] = 0x04;
				// Переносим первую координату точки прямой записью
				reverse(point, item.opened.data() + 1, size);
				// Переносим вторую координату точки прямой записью
				reverse(point + size, item.opened.data() + 1 + size, size);
			// Если группа обмена - кривая ГОСТ
			} else
				// Переносим координаты точки обратной записью как есть
				item.opened.assign(point, point + (size * 2));
			// Выполняем затирание координат открытого ключа
			this->purge(point, sizeof(point));
		}
		// Добавляем пару ключей к парам своей стороны
		this->_exchanges.push_back(::move(item));
		// Запоминаем группу обмена мимолётными ключами связи
		this->_group = group;
		// Выводим успешность выработки мимолётной пары ключей
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод отправки приветствия клиента
 *
 * @return отказ отправки приветствия клиента
 *
 */
context::error_t nts::internal::Engine::greeting() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Составляемое приветствие клиента
		hello::client_t greeting;
		// Раздел 5.3 RFC 9147: поверх дейтаграмм приветствие несёт издание DTLS 1.2
		greeting.version = ((this->_transport == context::transport_t::DATAGRAMS) ? ((this->_highest >= LEGACY) ? datagram::DATAGRAM_LEGACY : this->eldest()) : 0x0303);
		// Переносим случайное значение своего приветствия
		::memcpy(greeting.random, this->_random, sizeof(this->_random));
		// Устанавливаем опознаватель связи, доставшийся от предыдущих изданий
		greeting.session = this->_session;
		// Устанавливаем перечень способов сжатия
		greeting.methods = {0x00};
		// Признак того, что приветствие несёт свои значения GREASE (RFC 8701): решает единая точка
		const bool greased = this->greased();
		/**
		 * Издание 1.2 предлагается переносом записями (TLS 1.2) и дейтаграммами (DTLS 1.2
		 * по RFC 6347); под QUIC (RFC 9001) связь ведёт одно лишь издание 1.3. Издание
		 * предлагается лишь тогда, когда у связи есть хоть один его набор: без наборов
		 * издания сторонам нечем сойтись, и предложение обернулось бы отказом
		 */
		const bool ancient = ((this->_transport != context::transport_t::LEVELS) && (this->_lowest <= LEGACY) && (this->_highest >= LEGACY) && carries(this->_suites, true));
		// Признак того, что издание TLS 1.3 предлагается
		const bool modern = ((this->_transport == context::transport_t::LEVELS) || ((this->_highest >= MODERN) && carries(this->_suites, false)));
		// Признак того, что издание DTLS 1.0 (RFC 4347) предлагается: лишь дейтаграммами и лишь при наборах CBC-SHA1
		const bool primeval = ((this->_transport == context::transport_t::DATAGRAMS) && (this->_lowest <= ANCIENT) && archaical(this->_suites));
		// Раздел 4.2.1 RFC 6347: метка из просьбы о подтверждении адреса повторяется приветствием дословно
		greeting.cookie = this->_token;
		// Запоминаем издание заголовка приветствия: оно идёт в общее значение обмена RSA (раздел 7.4.7.1 RFC 5246)
		this->_claimed = greeting.version;
		// Признак того, что заранее разделённый ключ клиенту задан: ключом либо вызовом по подсказке
		const bool keyed = (!this->_psk.key.empty() || (this->_psk.advise != nullptr));
		// Признак того, что среди предлагаемых наборов есть набор CBC
		bool chained = false;
		/**
		 * Выполняем перебор предлагаемых наборов шифрования
		 */
		for(size_t i = 0; i < this->_suites.size(); i++){
			// Признак принадлежности набора изданию TLS 1.2
			const bool old = protect::legacy(this->_suites[i]);
			/**
			 * Наборы издания, которое не предлагается, приветствием не идут: набор TLS 1.2
			 * без самого издания собеседнику не выбрать, а набор TLS 1.3 в приветствии
			 * одного лишь издания 1.2 означал бы то, чего связь не умеет
			 */
			if((old && !ancient && !(primeval && archaic(this->_suites[i]))) || (!old && !modern && (protect::hash(this->_suites[i]) != digest::hash_t::NONE)))
				// Переходим к следующему набору шифрования
				continue;
			// RFC 4279: наборы PSK предлагаются лишь при заданном ключе - иначе сервер выберет то, чего клиенту не исполнить
			if(old && preshared(this->_suites[i]) && !keyed)
				// Переходим к следующему набору шифрования
				continue;
			// Запоминаем наличие набора CBC в предложении
			chained = (chained || (protect::mac(this->_suites[i]) != digest::hash_t::NONE));
			// Добавляем очередной набор шифрования в приветствие
			greeting.suites.push_back(static_cast <uint16_t> (this->_suites[i]));
		}
		// Если приветствию не осталось ни одного набора шифрования
		if(greeting.suites.empty())
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		// Раздел 3.1 RFC 8701: набор GREASE идёт первым в перечне наборов, как у BoringSSL
		if(greased)
			// Вставляем набор GREASE в начало перечня наборов
			greeting.suites.insert(greeting.suites.begin(), this->greasing(grease_t::SUITE));
		// Накопители, в которых лежат тела расширений приветствия
		vector <uint8_t> versions, groups, schemes, shares, name, protocols, certtypes, profiles;
		// Перечень предлагаемых изданий протокола от старшего к младшему
		vector <uint16_t> editions;
		// Запоминаем, предлагается ли издание 1.3 приветствием
		this->_proposed = modern;
		// Раздел 3.1 RFC 8701: издание GREASE идёт первым в перечне изданий
		if(greased)
			// Добавляем издание GREASE в перечень
			editions.push_back(this->greasing(grease_t::VERSION));
		// Если издание TLS 1.3 предлагается
		if(modern)
			// Добавляем издание TLS 1.3 либо DTLS 1.3 в перечень
			editions.push_back(this->edition());
		// Если издание TLS 1.2 предлагается
		if(ancient)
			// Добавляем издание TLS 1.2 либо DTLS 1.2 в перечень
			editions.push_back(this->elder());
		// Если издание DTLS 1.0 предлагается: BoringSSL кладёт его в перечень изданий наравне с прочими
		if(primeval)
			// Добавляем издание DTLS 1.0 в перечень
			editions.push_back(this->eldest());
		// Отказ составления расширения приветствия
		failure = translate(extension::versions(editions, versions), context::error_t::MESSAGE);
		// Если перечень изданий протокола составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return failure;
		// Группы обмена, объявляемые приветствием
		vector <extension::group_t> curves;
		// Раздел 3.1 RFC 8701: группа GREASE идёт первой в перечне групп
		if(greased)
			// Добавляем группу GREASE в объявляемый перечень
			curves.push_back(static_cast <extension::group_t> (this->greasing(grease_t::GROUP)));
		// Добавляем группы потребителя в объявляемый перечень в его порядке
		curves.insert(curves.end(), this->_groups.begin(), this->_groups.end());
		// Отказ составления расширения приветствия
		failure = translate(extension::groups(curves, groups), context::error_t::MESSAGE);
		// Если перечень кривых обмена ключами составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return failure;
		// Схемы подписи, объявляемые приветствием
		vector <extension::scheme_t> declared;
		/**
		 * Выполняем перебор схем подписи, признаваемых связью
		 */
		for(size_t i = 0; i < this->_signatures.size(); i++){
			/**
			 * Схемы PKCS #1 v1.5 объявляются лишь при предложении издания TLS 1.2: в TLS 1.3
			 * они годны одним лишь подписям сертификатов, а связь такими не судит
			 */
			if(!ancient && pkcs1(this->_signatures[i]))
				// Переходим к следующей схеме подписи
				continue;
			// Добавляем схему подписи в объявляемый перечень
			declared.push_back(this->_signatures[i]);
		}
		// Отказ составления расширения приветствия
		failure = translate(extension::schemes(declared, schemes), context::error_t::MESSAGE);
		// Если перечень схем подписи составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return failure;
		// Открытые части ключей обмена своей стороны по группам долей
		vector <extension::share_t> list;
		/**
		 * Раздел 3.1 RFC 8701: доля GREASE идёт первой, тело её - один байт; после просьбы
		 * о повторе с долей ключа приветствие несёт долю по одной лишь запрошенной группе
		 * (раздел 4.2.8 RFC 8446), и доля GREASE снимается вместе с прежними, как у BoringSSL,
		 * - openssl отвергает всякую иную долю повторного приветствия; просьба без доли
		 * (одна метка) оставляет доли прежними, и доля GREASE остаётся с ними
		 */
		if(greased && !(this->_retried && this->_reshare))
			// Добавляем долю GREASE в перечень долей
			list.push_back(extension::share_t(static_cast <extension::group_t> (this->greasing(grease_t::GROUP)), view_t(GREASE_STUB, sizeof(GREASE_STUB))));
		/**
		 * Выполняем перебор мимолётных пар ключей своей стороны
		 */
		for(size_t i = 0; i < this->_exchanges.size(); i++)
			// Добавляем открытую часть очередной пары ключей в перечень долей
			list.push_back(extension::share_t(this->_exchanges[i].group, view_t(this->_exchanges[i].opened.data(), this->_exchanges[i].opened.size())));
		// Отказ составления расширения приветствия
		failure = translate(extension::shares(list, shares), context::error_t::MESSAGE);
		// Если перечень открытых частей ключей обмена составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return failure;
		// Раздел 3.1 RFC 8701: первое расширение GREASE идёт пустым впереди всех
		if(greased)
			// Добавляем первое расширение GREASE
			greeting.extensions.push_back(hello::extension_t(this->greasing(grease_t::FIRST), view_t(nullptr, 0)));
		/**
		 * Раздел 4.2.1 RFC 8446: расширение перечня изданий согласует издание 1.3; когда
		 * предлагается одно лишь издание 1.2, сведений оно не несёт - издание сервер берёт из
		 * заголовка приветствия, - и не кладётся, как у openssl (решение 15): LibreSSL 3.6.1
		 * в DTLS обрывает связь protocol_version на самом расширении. Перечень с DTLS 1.0
		 * сведения несёт - заголовок объявляет лишь 1.2 - и кладётся, как у BoringSSL
		 */
		if(modern || primeval)
			// Добавляем расширение перечня изданий протокола
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(versions.data(), versions.size())));
		// Добавляем расширение перечня кривых обмена ключами
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(groups.data(), groups.size())));
		// Добавляем расширение перечня схем подписи
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
		// Перечень видов сертификатов: RawPublicKey и X.509
		const extension::cert_t certkinds[] = {extension::cert_t::RAW, extension::cert_t::X509};
		// Если задан закреплённый сырой открытый ключ сервера
		if(!this->_pinned.empty()){
			// Составляем перечень видов сертификатов
			if(extension::certtypes(vector <extension::cert_t> (certkinds, certkinds + 2), certtypes) == extension::error_t::NONE)
				// Добавляем расширение вида сертификата сервера
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SERVER_CERT_TYPE), view_t(certtypes.data(), certtypes.size())));
		}
		/**
		 * Раздел 3 RFC 7250: готовность ответить сырым ключом объявляется расширением
		 * вида сертификата клиента при наличии своей подлинности, независимо от
		 * закрепления серверного ключа
		 */
		if(!this->_credential.chain.empty()){
			// Составляем перечень видов сертификатов
			if(extension::certtypes(vector <extension::cert_t> (certkinds, certkinds + 2), certtypes) == extension::error_t::NONE)
				// Добавляем расширение вида сертификата клиента
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::CLIENT_CERT_TYPE), view_t(certtypes.data(), certtypes.size())));
		}
		// Если профили защиты RTP связью предлагаются
		if(!this->_srtps.empty()){
			// Отказ составления расширения приветствия
			const context::error_t failure = translate(extension::profiles(this->_srtps, profiles), context::error_t::MESSAGE);
			// Если перечень профилей защиты RTP составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение перечня профилей защиты RTP
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROFILES), view_t(profiles.data(), profiles.size())));
		}
		// Доли ключа положены лишь изданию TLS 1.3: раздел 4.2.8 RFC 8446
		if(modern)
			// Добавляем расширение открытых частей ключей обмена
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(shares.data(), shares.size())));
		/**
		 * Издание TLS 1.2 объявляется тремя расширениями сразу: расширенный главный секрет
		 * (раздел 5.1 RFC 7627) - безусловно, ибо без него связь оборвётся; безопасное
		 * пересогласование (раздел 3.2 RFC 5746) - пустым, ибо связь пересогласований не
		 * ведёт; записи точек (раздел 5.1.2 RFC 8422) - одной несжатой. Изданию DTLS 1.0 всё
		 * это положено так же (RFC 7627, RFC 5746 и RFC 8422 действуют и у 1.1)
		 */
		if(ancient || primeval){
			// Добавляем расширение расширенного главного секрета
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
			// Добавляем расширение безопасного пересогласования
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::RENEGOTIATION), view_t(RENEGOTIATION, sizeof(RENEGOTIATION))));
			// Добавляем расширение записей точек кривой
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::FORMATS), view_t(FORMATS, sizeof(FORMATS))));
			// Раздел 2 RFC 7366: порядок «шифрование, затем имитовставка» предлагается пустым расширением при наборах CBC
			if(chained)
				// Добавляем расширение encrypt_then_mac
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::ETM), view_t(nullptr, 0)));
			/**
			 * Раздел 3.2 RFC 5077: билет сеанса предъявляется расширением session_ticket, а без
			 * билета расширение идёт пустым - так клиент объявляет готовность билет принять;
			 * билет с вышедшим сроком не предъявляется, связь идёт полным рукопожатием
			 */
			this->_presented = (protect::legacy(this->_resume.suite) && !this->_resume.identity.empty() && (this->_resume.secret.size() == sizeof(this->_keys->master)) && !expired(this->_resume, this->_moment) && !outdated(this->_resume.authenticated, this->_moment));
			// Добавляем расширение билета сеанса
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TICKET), (this->_presented ? view_t(this->_resume.identity.data(), this->_resume.identity.size()) : view_t(nullptr, 0))));
		}
		// Если имя узла у сервера запрашивается
		if(!this->_name.empty()){
			/**
			 * Имя берётся c_str(), а не data(): под libstdc++ старого ABI неконстантный
			 * data() разделённой строки копирует её внутри функции, объявленной noexcept
			 * стандартом, и нехватка памяти там обрывает процесс мимо перехвата (вскрыто
			 * ProfileTest.Starved на OpenWRT: имя пришло разделённой копией)
			 */
			failure = translate(extension::name(view_t(reinterpret_cast <const uint8_t *> (this->_name.c_str()), this->_name.size()), name), context::error_t::MESSAGE);
			// Если имя запрашиваемого узла составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение имени запрашиваемого узла
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(name.data(), name.size())));
		}
		// Если прикладные протоколы связью предлагаются
		if(!this->_protocols.empty()){
			// Отказ составления расширения приветствия
			failure = translate(extension::protocols(this->_protocols, protocols), context::error_t::MESSAGE);
			// Если перечень прикладных протоколов составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение перечня прикладных протоколов
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocols.data(), protocols.size())));
		}
		// Накопитель, в котором лежит тело расширения прикладных настроек ALPS
		vector <uint8_t> settings;
		/**
		 * Черновик draft-vvv-tls-alps: перечень протоколов с настройками идёт лишь при
		 * предложенном издании 1.3 и лишь вместе с перечнем прикладных протоколов
		 */
		if(!this->_settings.empty() && !this->_protocols.empty() && ((this->_transport == context::transport_t::LEVELS) || (this->_highest >= MODERN))){
			// Перечень протоколов, для которых настройки объявлены
			vector <string> names;
			/**
			 * Выполняем перебор объявленных прикладных настроек
			 */
			for(size_t i = 0; i < this->_settings.size(); i++)
				// Добавляем протокол в перечень
				names.push_back(this->_settings[i].protocol);
			// Отказ составления расширения приветствия
			failure = translate(extension::protocols(names, settings), context::error_t::MESSAGE);
			// Если перечень протоколов с настройками составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение прикладных настроек своей точкой кода
			greeting.extensions.push_back(hello::extension_t(this->_codepoint, view_t(settings.data(), settings.size())));
		}
		// Если метка возврата состояния сервера связью получена
		if(!this->_cookie.empty())
			// Повторяем метку возврата состояния сервера дословно
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(this->_cookie.data(), this->_cookie.size())));
		/**
		 * Раздел 8.2 RFC 9001: параметры переноса QUIC идут приветствием клиента всякий раз,
		 * когда рукопожатие переносится по уровням, и не идут вовсе, когда оно идёт записями
		 */
		if(this->_transport == context::transport_t::LEVELS)
			// Добавляем расширение параметров переноса QUIC как есть
			greeting.extensions.push_back(hello::extension_t(TRANSPORT, view_t(this->_parameters.data(), this->_parameters.size())));
		// Накопитель, в котором лежит тело расширения алгоритмов сжатия цепочки
		vector <uint8_t> algorithms;
		/**
		 * Раздел 3 RFC 8879: перечень алгоритмов сжатия цепочки объявляется лишь тогда,
		 * когда потребитель предоставил хоть один; без него приветствие не меняется вовсе
		 */
		if(!this->_codecs.empty()){
			// Перечень опознавателей алгоритмов сжатия в порядке предпочтения потребителя
			vector <uint16_t> list;
			/**
			 * Выполняем перебор алгоритмов сжатия, предоставленных потребителем
			 */
			for(size_t i = 0; i < this->_codecs.size(); i++)
				// Добавляем опознаватель очередного алгоритма в перечень
				list.push_back(this->_codecs[i].algorithm);
			// Отказ составления расширения приветствия
			failure = translate(extension::algorithms(list, algorithms), context::error_t::MESSAGE);
			// Если перечень алгоритмов сжатия составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение перечня алгоритмов сжатия цепочки сертификатов
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COMPRESS), view_t(algorithms.data(), algorithms.size())));
		}
		/**
		 * Раздел 4.4.2.1 RFC 8446: состояние сертификата сервера запрашивается
		 * расширением status_request приветствия; без запроса потребителя оно не идёт
		 */
		if(this->_inquiring)
			// Добавляем расширение запроса состояния сертификата
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::STATUS), view_t(INQUIRY, sizeof(INQUIRY))));
		// Раздел 3.3.1 RFC 6962: метки времени сертификата запрашиваются пустым расширением приветствия
		if(this->_stamping)
			// Добавляем расширение запроса меток времени сертификата
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TIMESTAMPS), view_t(nullptr, 0)));
		/**
		 * Черновик draft-agl-tls-nextprotoneg: выработка NPN предлагается пустым расширением лишь
		 * изданию 1.2 потоком - не дейтаграммам, не связи, зажатой на издании 1.3, и не под ECH (как у BoringSSL)
		 */
		if(this->_negotiating && (this->_transport == context::transport_t::RECORDS) && (this->_lowest < MODERN) && this->_configs.empty())
			// Добавляем расширение выработки NPN
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NEGOTIATION), view_t(nullptr, 0)));
		// Накопители, в которых лежат тела расширений возобновления связи
		vector <uint8_t> modes, secret;
		// Место, в которое помещается пустая привязка предъявляемого билета
		uint8_t empty[schedule::SCHEDULE_WIDEST];
		/**
		 * Билет с вышедшим сроком серверу не предъявляется вовсе: раздел 4.6.1 RFC 8446
		 * велит держать его не дольше объявленного срока, и связь идёт полным рукопожатием
		 */
		const bool resume = (!this->_resume.identity.empty() && !protect::legacy(this->_resume.suite) && !expired(this->_resume, this->_moment) && !outdated(this->_resume.authenticated, this->_moment));
		/**
		 * Раздел 4.2.11 RFC 8446: привязка и расписание билета ведутся хешем набора билета;
		 * билет без ведомого набора судится хешем переписки - у ветви ГОСТ он один на все
		 * наборы, и билет, сложенный потребителем без набора, остаётся годным
		 */
		const digest::hash_t algorithm = ((protect::hash(this->_resume.suite) != digest::hash_t::NONE) ? protect::hash(this->_resume.suite) : this->_transcript.algorithm());
		// Длина привязки предъявляемого билета: длина хеша набора билета
		const size_t width = (resume ? digest::length(algorithm) : 0);
		// Если билет возобновления связи предъявляется серверу
		if(resume)
			// Запоминаем набор шифрования предъявляемого билета
			this->_ticket = this->_resume.suite;
		// Если билет возобновления связи предъявляется серверу
		if(resume){
			// Способы обмена, при которых билет годен связи
			const vector <extension::regime_t> list = {extension::regime_t::SHARED};
			// Отказ составления расширения приветствия
			failure = translate(extension::modes(list, modes), context::error_t::MESSAGE);
			// Если перечень способов обмена составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение способов обмена заранее разделённым ключом
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(modes.data(), modes.size())));
			// Выполняем обнуление привязки предъявляемого билета
			::memset(empty, 0, sizeof(empty));
			// Если упреждающие данные связью предлагаются и дозволены билетом
			if(this->_advance && !this->_retried && (this->_resume.advance > 0) && (this->_transport != context::transport_t::DATAGRAMS) && this->inheritable(this->_resume)){
				/**
				 * Расширение упреждающих данных в приветствии пусто: раздел 4.2.10 RFC 8446
				 * велит объявлять им лишь само намерение, а предел объявлен билетом
				 */
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
				// Запоминаем, что упреждающие данные связью предложены
				this->_ventured = true;
			}
			/**
			 * Возраст билета объявляется скрытым: раздел 4.2.11 RFC 8446 велит складывать
			 * наблюдаемый возраст в миллисекундах с добавкой, назначенной сервером
			 */
			uint32_t age = this->_resume.age;
			// Если сроки билетов связи судить дозволено
			if((this->_moment != 0) && (this->_resume.moment != 0))
				// Складываем наблюдаемый возраст билета с добавкой сервера
				age = static_cast <uint32_t> ((static_cast <uint64_t> (this->_moment - this->_resume.moment) * 1000) + static_cast <uint64_t> (this->_resume.age));
			// Опознаватель предъявляемого билета возобновления связи
			const extension::identity_t identity(view_t(this->_resume.identity.data(), this->_resume.identity.size()), age);
			// Привязка предъявляемого билета возобновления связи
			const vector <view_t> binders = {view_t(empty, width)};
			// Отказ составления расширения приветствия
			failure = translate(extension::identities(vector <extension::identity_t> {identity}, binders, secret), context::error_t::MESSAGE);
			// Если предложение заранее разделённых ключей составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			/**
			 * Расширение заранее разделённых ключей идёт последним: раздел 4.2.11 RFC 8446
			 * велит ставить его в самый конец, ибо привязка покрывает всё, что идёт до неё
			 */
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(secret.data(), secret.size())));
		}
		/**
		 * Раздел 3.1 RFC 8701: второе расширение GREASE идёт последним среди расширений
		 * потребителя с телом в один нулевой байт, как у BoringSSL; заранее разделённый
		 * ключ остаётся за ним - раздел 4.2.11 RFC 8446 велит ему быть последним
		 */
		if(greased)
			// Вставляем второе расширение GREASE перед заранее разделённым ключом либо в конец
			greeting.extensions.insert(greeting.extensions.end() - (resume ? 1 : 0), hello::extension_t(this->greasing(grease_t::SECOND), view_t(GREASE_STUB, sizeof(GREASE_STUB))));
		// Хранилище тел расширений, сложенных по профилю отпечатка: живёт до составления приветствия
		vector <vector <uint8_t>> storage;
		// Если приветствие складывается по профилю отпечатка
		if(this->_profiled){
			// Отказ складывания приветствия по профилю
			failure = this->imitate(greeting, name, protocols, algorithms, modes, secret, resume, storage);
			// Если приветствие по профилю сложить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ складывания приветствия
				return failure;
		}
		// Если конфигурации ECH заданы и билет не предъявляется: внутреннее приветствие шифруется, внешнее собирается
		// Признак того, что приветствие ушло внутрь ECH: билет и его привязка лежат во внутреннем
		bool hidden = false;
		// Если конфигурации ECH заданы: внутреннее приветствие шифруется, внешнее собирается (билет - во внутреннем)
		if(!this->_configs.empty()){
			// Хранилище занимает место под публичное имя и расширение ECH: указатели на тела не должны переезжать
			storage.reserve(storage.size() + 2);
			// Отказ складывания зашифрованного приветствия
			failure = this->shrouding(greeting, resume, storage);
			// Если зашифрованное приветствие сложить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ складывания
				return failure;
			// Запоминаем, что приветствие ушло внутрь
			hidden = true;
		/**
		 * Раздел 6.2 RFC 9849: клиент без конфигураций ECH при включённом GREASE шлёт
		 * расширение ECH внешнего вида со случайным телом, как BoringSSL; профиль
		 * отпечатка расставляет своё значение GREASE ECH сам
		 */
		} else if(this->_configs.empty() && greased && !this->_profiled && !resume) {
			// Хранилище занимает место под расширение ECH
			storage.reserve(storage.size() + 1);
			// Значение GREASE ECH
			ech::hello_t stub;
			// Место случайного опознавателя
			uint8_t identifier[1];
			// Если опознаватель выработать не удалось
			if(!entropy::bytes(identifier, sizeof(identifier)))
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			// Опознаватель конфигурации случайный
			stub.id = identifier[0];
			// Набор: обязательный к исполнению по разделу 9 RFC 9849
			stub.suite = ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM);
			// Мимолётный ключ: инкапсулированный ключ обязан быть годной точкой X25519
			hpke::key_t ephemeral;
			// Если мимолётный ключ выработать не удалось
			if(ephemeral.generate(hpke::kem_t::X25519_HKDF_SHA256) != hpke::error_t::NONE)
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			// Переносим открытую часть мимолётного ключа
			stub.enc.assign(ephemeral.point().data, ephemeral.point().data + ephemeral.point().size);
			// Накопитель, в который складывается приветствие без ECH: по нему судится правдоподобная длина шифротекста
			vector <uint8_t> gauge;
			// Отказ составления приветствия
			failure = translate(hello::build(greeting, gauge, false), context::error_t::MESSAGE);
			// Если приветствие составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления
				return failure;
			// Шифротекст длиной закодированного приветствия, доведённой до кратной 32, с меткой шифра
			stub.payload.assign((((gauge.size() + 31) / 32) * 32) + hpke::overhead(stub.suite.aead), 0);
			// Если шифротекст выработать не удалось
			if(!entropy::bytes(stub.payload.data(), stub.payload.size()))
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			// Занимаем место под тело расширения
			storage.push_back(vector <uint8_t> ());
			// Если тело расширения составить не удалось
			if(ech::build(stub, storage.back()) != ech::error_t::NONE)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Добавляем расширение GREASE ECH перед вторым расширением GREASE: то остаётся последним, как у BoringSSL
			greeting.extensions.insert(greeting.extensions.end() - (greased ? 1 : 0), hello::extension_t(ech::ECH_EXTENSION, view_t(storage.back().data(), storage.back().size())));
			// Запоминаем, что отправлено лишь значение GREASE ECH
			this->_ech = ech_t::GREASED;
		}
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем сброс прежнего перечня предложенных расширений
			this->_offered.clear();
			/**
			 * Выполняем перебор расширений составленного приветствия клиента
			 */
			for(size_t i = 0; i < greeting.extensions.size(); i++){
				// Запоминаем вид очередного расширения, предложенного связью
				this->_offered.push_back(greeting.extensions[i].type);
				// Если приветствие предлагает heartbeat (RFC 6520, расширение 0x000F из профиля), записи вида 24 будут роняться молча
				if(greeting.extensions[i].type == HEARTBEAT_EXTENSION){
					// Отмечаем предложение
					this->_heartbeating = true;
					// Запоминаем свой режим: запросы собеседника принимаются лишь при peer_allowed_to_send (раздел 2 RFC 6520)
					this->_answering = ((greeting.extensions[i].data.size > 0) && (greeting.extensions[i].data.data[0] == 1));
				}
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Накопитель, в который складывается тело приветствия клиента
		vector <uint8_t> body;
		// Отказ составления приветствия клиента: поверх дейтаграмм с полем метки возврата состояния
		failure = translate(hello::build(greeting, body, (this->_transport == context::transport_t::DATAGRAMS)), context::error_t::MESSAGE);
		// Если тело приветствия клиента составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return failure;
		// Если билет возобновления связи серверу не предъявляется
		if(!resume || hidden){
			// Отправляем приветствие
			failure = this->send(handshake::type_t::CLIENT, view_t(body.data(), body.size()));
			/**
			 * Раздел 6.1 RFC 9849: упреждающие данные под ECH идут по билету внутреннего
			 * приветствия - если они дозволены и предложены, ключи выводятся сразу после отправки
			 */
			if((failure != context::error_t::NONE) || !hidden || !resume || !this->_advance || this->_retried || (this->_resume.advance == 0) || (this->_transport == context::transport_t::DATAGRAMS) || !this->inheritable(this->_resume))
				// Выводим итог отправки
				return failure;
			// Заводим ключи упреждения
			return this->earliest();
		}
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Отказ составления приветствия клиента
		failure = translate(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())), context::error_t::MESSAGE);
		// Если приветствие клиента составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия клиента
			return failure;
		// Получаем составленное приветствие клиента
		const view_t data = writer.data();
		// Накопитель, в котором приветствие клиента правится привязкой билета
		vector <uint8_t> message;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем перенос составленного приветствия в накопитель
			message.assign(data.data, data.data + data.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		/**
		 * Приветствие усекается перед перечнем привязок: два байта длины перечня, байт
		 * длины привязки и сама привязка себя же покрывать не вправе
		 */
		const size_t truncation = (message.size() - (width + 3));
		// Если начальную ступень расписания ключей завести не удалось хешем набора билета
		if(this->_secrets.start(algorithm, view_t(this->_resume.secret.data(), this->_resume.secret.size())) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return context::error_t::SCHEDULE;
		// Место, в которое помещается хеш усечённого приветствия клиента
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		/**
		 * Раздел 4.2.11.2 RFC 8446: привязка берётся хешем набора билета, тогда как набор
		 * связи сервер ещё не выбрал - переписка отдаёт хеш по заданному алгоритму
		 */
		if(this->_transcript.digest(algorithm, view_t(message.data(), truncation), transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Если привязку предъявляемого билета выработать не удалось
		if(this->_secrets.binder(view_t(transcript, width), message.data() + (message.size() - width)) != session::error_t::NONE)
			// Выводим отказ выработки привязки билета
			return context::error_t::SCHEDULE;
		// Номер записи приветствия: переписке издания 1.2 поверх дейтаграмм нужна обвязка DTLS
		const uint16_t number = this->_flight.outgoing();
		// Выполняем складывание приветствия клиента в накопитель отправляемых байтов
		const context::error_t error = this->emit(record::type_t::HANDSHAKE, view_t(message.data(), message.size()));
		// Если приветствие клиента отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки приветствия клиента
			return error;
		/**
		 * Переписка ведётся тем же путём, что и в send(): издание выбирает сервер, и если
		 * он ответит изданием 1.2, подпись владения ключом клиента (раздел 7.4.8 RFC 5246)
		 * покроет и это приветствие - оно обязано лежать в переписке издания 1.2, иначе
		 * сервер с запросом подлинности клиента ответил бы decrypt_error
		 */
		if(this->_transport != context::transport_t::LEVELS){
			// Приветствие клиента начинает переписку заново
			this->_history.clear();
			// Отказ ведения переписки
			const context::error_t chronicled = this->chronicle(view_t(message.data(), message.size()), number);
			// Если переписку вести не удалось
			if(chronicled != context::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return chronicled;
		// Если приветствие в переписку рукопожатия добавить не удалось
		} else if(this->_transcript.update(view_t(message.data(), message.size())) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Если приветствие клиента ходу рукопожатия объявить не удалось
		if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return context::error_t::ORDER;
		/**
		 * Раздел 4.1.2 RFC 8446: за просьбою о повторе упреждающие данные не идут, и
		 * повторное приветствие расширения упреждения не несёт. Ключи упреждения
		 * заводятся лишь тогда, когда упреждение и предложено, и билетом дозволено
		 */
		if(!this->_advance || this->_retried || (this->_resume.advance == 0) || (this->_transport == context::transport_t::DATAGRAMS) || !this->inheritable(this->_resume))
			// Выводим успешность отправки приветствия клиента
			return context::error_t::NONE;
		// Выводим итог заведения защиты записей упреждающих данных
		return this->earliest();
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод отправки приветствия сервера
 *
 * @param session опознаватель связи, повторяемый за приветствием клиента
 * @param retry   признак того, что отправляется просьба о повторе приветствия
 * @return        отказ отправки приветствия сервера
 *
 */
context::error_t nts::internal::Engine::answer(const vector <uint8_t> & session, const bool retry) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Составляемое приветствие сервера
		hello::server_t answer;
		// Раздел 5.3 RFC 9147: поверх дейтаграмм приветствие несёт издание DTLS 1.2
		answer.version = ((this->_transport == context::transport_t::DATAGRAMS) ? datagram::DATAGRAM_LEGACY : 0x0303);
		/**
		 * Просьба о повторе приветствия объявляется заранее назначенным случайным
		 * значением: раздел 4.1.3 RFC 8446
		 */
		if(retry)
			// Переносим случайное значение просьбы о повторе приветствия
			::memcpy(answer.random, RETRY, sizeof(RETRY));
		// Если отправляется само приветствие сервера
		else ::memcpy(answer.random, this->_random, sizeof(this->_random));
		// Устанавливаем опознаватель связи, повторяемый за приветствием клиента
		answer.session = session;
		// Устанавливаем выбранный набор шифрования
		answer.suite = static_cast <uint16_t> (this->_suite);
		// Устанавливаем выбранный способ сжатия
		answer.method = 0x00;
		// Накопители, в которых лежат тела расширений приветствия
		vector <uint8_t> version, share;
		// Отказ составления расширения приветствия
		failure = translate(extension::version(this->edition(), version), context::error_t::MESSAGE);
		// Если издание протокола составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления расширения приветствия
			return failure;
		// Накопитель, в котором лежит тело расширения метки возврата состояния
		vector <uint8_t> label;
		/**
		 * Раздел 4.1.4 RFC 8446: доля ключа просится лишь тогда, когда клиент её по выбранной
		 * группе не прислал; просьба о повторе ради одной метки возврата состояния (раздел
		 * 5.1 RFC 9147) долю не просит - иначе клиент оборвался бы на повторной просьбе
		 */
		if(retry && this->_reshare){
			// Отказ составления расширения приветствия
			failure = translate(extension::selected(this->_group, share), context::error_t::MESSAGE);
			// Если выбранную кривую обмена ключами составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
		// Если отправляется само приветствие сервера
		} else if(!retry) {
			// Если мимолётной пары ключей своей стороны нет
			if(this->_exchanges.empty())
				// Выводим отказ отсутствия ключа обмена
				return context::error_t::EXCHANGE;
			// Открытая часть ключа обмена своей стороны
			const extension::share_t item(this->_exchanges.back().group, view_t(this->_exchanges.back().opened.data(), this->_exchanges.back().opened.size()));
			// Отказ составления расширения приветствия
			failure = translate(extension::share(item, share), context::error_t::MESSAGE);
			// Если открытую часть ключа обмена составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
		}
		// Добавляем расширение издания протокола
		answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
		// Если открытая часть ключа обмена составлена
		if(!share.empty())
			// Добавляем расширение открытой части ключа обмена
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(share.data(), share.size())));
		/**
		 * Метка возврата состояния идёт лишь просьбой о повторе: раздел 4.2.2 RFC 8446
		 * велит сервером, состояния у себя не держащим, возвращать его этой меткой
		 */
		if(retry && !this->_cookie.empty()){
			// Отказ составления расширения приветствия
			failure = translate(extension::cookie(view_t(this->_cookie.data(), this->_cookie.size()), label), context::error_t::MESSAGE);
			// Если метку возврата состояния составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение метки возврата состояния сервера
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
		}
		// Раздел 7.2.1 RFC 9849: просьба о повторе принявшего ECH сервера несёт расширение ECH с подтверждением
		static const uint8_t CONFIRMATION[ech::ECH_CONFIRMATION] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
		// Накопитель, в котором лежит тело расширения выбранного ключа
		vector <uint8_t> selected;
		// Если связь возобновляется заранее разделённым ключом
		if(this->_shared && !retry){
			// Отказ составления расширения приветствия
			failure = translate(extension::chosen(this->_chosen, selected), context::error_t::MESSAGE);
			// Если выбранный заранее разделённый ключ составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return failure;
			// Добавляем расширение выбранного заранее разделённого ключа
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(selected.data(), selected.size())));
		}
		// Если сервер принял ECH и шлёт просьбу о повторе: расширение подтверждения идёт последним, место обнулено
		if(retry && this->_echaccepted)
			// Добавляем расширение подтверждения
			answer.extensions.push_back(hello::extension_t(ech::ECH_EXTENSION, view_t(CONFIRMATION, sizeof(CONFIRMATION))));
		// Накопитель, в который складывается тело приветствия сервера
		vector <uint8_t> body;
		// Отказ составления приветствия сервера
		failure = translate(hello::build(answer, body), context::error_t::MESSAGE);
		// Если тело приветствия сервера составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия сервера
			return failure;
		// Если сервер принял ECH: подтверждение вписывается в приветствие либо просьбу о повторе
		if(this->_echaccepted){
			// Отказ вписывания подтверждения
			failure = this->marking(body, retry);
			// Если подтверждение вписать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ вписывания
				return failure;
		}
		// Выводим итог отправки приветствия сервера
		return this->send(handshake::type_t::SERVER, view_t(body.data(), body.size()));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод отправки подтверждения подлинности своей стороны
 *
 * @return отказ отправки подтверждения подлинности
 *
 */
context::error_t nts::internal::Engine::authenticate() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Составляемое сообщение цепочки сертификатов
		message::certificate_t certificate;
		/**
		 * Раздел 4.4.2 RFC 8446: сервер шлёт опознаватель запроса пустым, а клиент
		 * повторяет им опознаватель принятого запроса подлинности дословно
		 */
		/**
		 * Слагаемое (!this->_binding.empty()) истинным своим сервером не задевается: запрос
		 * подлинности он шлёт с пустым опознавателем, как и велит раздел 4.3.2 RFC 8446 по
		 * ходу рукопожатия. Непустым его шлёт лишь собеседник - либо своя же сторона, когда
		 * подтверждение подлинности за рукопожатием будет заведено
		 */
		if(!this->_server && !this->_binding.empty())
			// Устанавливаем опознаватель принятого запроса подлинности
			certificate.context = view_t(this->_binding.data(), this->_binding.size());
		// Тела расширений состояния сертификатов, переживающие составление цепочки
		vector <vector <uint8_t>> statuses;
		/**
		 * Раздел 2 RFC 7250: при согласованном виде RawPublicKey сторона отвечает открытым
		 * ключом своего листа (записью SubjectPublicKeyInfo DER) вместо цепочки сертификатов;
		 * ответ о состоянии и метки времени цепочке записей не положены
		 */
		if(this->_owncert == extension::cert_t::RAW){
			// Объект разбора своего сертификата
			x509::certificate_t leaf;
			// Отказ разбора своего сертификата
			failure = translate(leaf.parse(view_t(this->_credential.chain[0].data(), this->_credential.chain[0].size())), context::error_t::CERTIFICATE);
			// Если свой сертификат разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора своего сертификата
				return failure;
			// Составляемая запись цепочки сертификатов
			message::entry_t entry;
			// Запись несёт открытый ключ своего листа целиком
			entry.data = leaf.key().element;
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
		/**
		 * Выполняем перебор сертификатов цепочки своей стороны
		 */
		} else for(size_t i = 0; i < this->_credential.chain.size(); i++){
			// Составляемая запись цепочки сертификатов
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			entry.data = view_t(this->_credential.chain[i].data(), this->_credential.chain[i].size());
			/**
			 * Раздел 4.4.2.1 RFC 8446: ответ о состоянии идёт расширением status_request
			 * записи цепочки лишь по запросу собеседника; раздел 8 RFC 6066 задаёт
			 * CertificateStatus: вид ocsp и запись ответа с трёхбайтовой длиной
			 */
			if(this->_inquired && (i < this->_staples.size()) && !this->_staples[i].empty() && (this->_staples[i].size() <= CHAIN)){
				// Объект составителя тела расширения состояния сертификата
				field::builder_t builder;
				// Отказ составления тела расширения состояния
				failure = translate(builder.number(OCSP, 1), context::error_t::MESSAGE);
				// Если вид состояния записать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления тела расширения состояния
					return failure;
				// Отказ открытия поля записи ответа
				failure = translate(builder.open(3), context::error_t::MESSAGE);
				// Если поле записи ответа открыть не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления тела расширения состояния
					return failure;
				// Отказ записи ответа о состоянии
				failure = translate(builder.bytes(view_t(this->_staples[i].data(), this->_staples[i].size())), context::error_t::MESSAGE);
				// Если ответ о состоянии записать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления тела расширения состояния
					return failure;
				// Отказ закрытия поля записи ответа
				failure = translate(builder.close(), context::error_t::MESSAGE);
				// Если поле записи ответа закрыть не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления тела расширения состояния
					return failure;
				// Получаем составленное тело расширения состояния
				const view_t data = builder.data();
				// Переносим тело расширения в накопитель, переживающий составление
				statuses.push_back(vector <uint8_t> (data.data, data.data + data.size));
			}
			/**
			 * Раздел 4.4.2.1 RFC 8446 и раздел 3.3 RFC 6962: перечень меток времени идёт
			 * расширением записи листа лишь по запросу собеседника; перечень - член связи,
			 * и просмотр внутрь него остаётся верным
			 */
			if((i == 0) && this->_stamped && !this->_stamps.empty())
				// Добавляем расширение меток времени сертификата
				entry.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TIMESTAMPS), view_t(this->_stamps.data(), this->_stamps.size())));
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
		}
		/**
		 * Выполняем привязку тел расширений состояния к записям цепочки: накопитель
		 * тел уже не растёт, и просмотры внутрь него остаются верными
		 */
		for(size_t i = 0, j = 0; (i < certificate.entries.size()) && (j < statuses.size()); i++){
			// Если у записи цепочки есть ответ о состоянии
			if(this->_inquired && (i < this->_staples.size()) && !this->_staples[i].empty() && (this->_staples[i].size() <= CHAIN)){
				// Добавляем расширение состояния сертификата в запись цепочки
				certificate.entries[i].extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::STATUS), view_t(statuses[j].data(), statuses[j].size())));
				// Переходим к следующему телу расширения
				j++;
			}
		}
		// Накопитель, в который складывается тело сообщения цепочки
		vector <uint8_t> body;
		// Отказ составления сообщения цепочки сертификатов
		failure = translate(message::build(certificate, body), context::error_t::MESSAGE);
		// Если тело сообщения цепочки сертификатов составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения цепочки сертификатов
			return failure;
		// Накопитель, в который складывается тело сжатой цепочки сертификатов
		vector <uint8_t> packed;
		// Алгоритм, которым сжата цепочка сертификатов, ноль без сжатия
		uint16_t algorithm = 0;
		// Отказ сжатия цепочки сертификатов
		failure = this->squeeze(body, packed, algorithm);
		// Если цепочку сертификатов сжать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ сжатия цепочки сертификатов
			return failure;
		/**
		 * Раздел 4 RFC 8879: при общем алгоритме цепочка уходит сообщением
		 * CompressedCertificate вместо Certificate, и в переписку она ложится сжатой как
		 * есть; без общего алгоритма либо при отказе сжатия уходит обычная цепочка
		 */
		const context::error_t error = ((algorithm != 0) ?
			this->send(handshake::type_t::COMPRESSED, view_t(packed.data(), packed.size())) :
			this->send(handshake::type_t::CERTIFICATE, view_t(body.data(), body.size())));
		// Если цепочку сертификатов отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки цепочки сертификатов
			return error;
		// Запоминаем алгоритм, которым сжата отправленная цепочка
		this->_squeezed = algorithm;
		/**
		 * Пустая цепочка сертификатов подписи владения ключом за собою не влечёт: раздел
		 * 4.4.2 RFC 8446 дозволяет её клиенту, у которого годного сертификата не нашлось
		 */
		if(this->_credential.chain.empty())
			// Выводим успешность отправки подтверждения подлинности
			return context::error_t::NONE;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Накопитель, в который складывается подписываемое содержимое
		vector <uint8_t> content;
		// Отказ составления подписываемого содержимого
		failure = translate(message::content(view_t(transcript, this->_transcript.size()), this->_server, content), context::error_t::MESSAGE);
		// Если подписываемое содержимое составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления подписываемого содержимого
			return failure;
		// Схема подписи владения своим ключом
		extension::scheme_t item = extension::scheme_t::NONE;
		// Накопитель, в который складывается подпись в записи протокола
		vector <uint8_t> signed_;
		// Отказ выработки подписи владения ключом
		failure = this->signing(view_t(content.data(), content.size()), item, signed_);
		// Если подпись владения ключом выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return failure;
		// Составляемое сообщение подписи владения ключом
		message::verify_t verify;
		// Устанавливаем схему подписи владения ключом
		verify.scheme = item;
		// Устанавливаем значение подписи владения ключом
		verify.signature = view_t(signed_.data(), signed_.size());
		// Выполняем сброс накопителя тела сообщения
		body.clear();
		// Отказ составления сообщения подписи владения ключом
		failure = translate(message::build(verify, body), context::error_t::MESSAGE);
		// Если тело сообщения подписи владения ключом составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения подписи владения ключом
			return failure;
		// Выводим итог отправки подписи владения ключом
		return this->send(handshake::type_t::VERIFY, view_t(body.data(), body.size()));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод отправки завершения рукопожатия своей стороной
 *
 * @return отказ отправки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::complete() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Длина хеша переписки рукопожатия
		const size_t width = this->_transcript.size();
		// Место, в которое помещается завершение рукопожатия своей стороной
		uint8_t completion[schedule::SCHEDULE_WIDEST];
		// Отказ выработки завершения рукопожатия
		const context::error_t failure = translate(message::finished(this->_transcript.algorithm(), view_t(this->_keys->completion[index(side)], width), view_t(transcript, width), completion), context::error_t::COMPLETION);
		// Если завершение рукопожатия выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки завершения рукопожатия
			return failure;
		// Выводим итог отправки завершения рукопожатия своей стороной
		return this->send(handshake::type_t::FINISHED, view_t(completion, width));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятого запроса подлинности клиента
 *
 * @param body тело принятого сообщения запроса подлинности
 * @return     отказ разбора запроса подлинности
 *
 */
context::error_t nts::internal::Engine::requesting(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Объект разборщика тела запроса подлинности клиента
		field::scanner_t scanner;
		// Устанавливаем разбираемое тело запроса подлинности клиента
		scanner.start(body);
		// Опознаватель запроса подлинности клиента
		view_t binding;
		// Если опознаватель запроса подлинности прочитать не удалось
		if(scanner.vector(binding, 1) != field::error_t::NONE)
			// Выводим отказ разбора запроса подлинности клиента
			return context::error_t::MESSAGE;
		// Перечень расширений запроса подлинности клиента
		view_t extensions;
		// Если перечень расширений запроса прочитать не удалось
		if(scanner.vector(extensions, 2) != field::error_t::NONE)
			// Выводим отказ разбора запроса подлинности клиента
			return context::error_t::MESSAGE;
		// Если за телом запроса подлинности идут лишние байты
		if(scanner.left() > 0)
			// Выводим отказ разбора запроса подлинности клиента
			return context::error_t::MESSAGE;
		// Объект разборщика записей перечня расширений запроса
		field::scanner_t reader;
		// Устанавливаем разбираемое содержимое перечня расширений
		reader.start(extensions);
		// Тело расширения схем подписи, признаваемых сервером
		view_t offer(nullptr, 0);
		// Тело расширения алгоритмов сжатия цепочки, признаваемых сервером
		view_t squeezing(nullptr, 0);
		// Тело расширения запроса состояния сертификата клиента
		view_t asking(nullptr, 0);
		// Тело расширения перечня доверенных удостоверяющих центров
		view_t naming(nullptr, 0);
		// Тело расширения вида сертификата клиента, признаваемого сервером
		view_t certtype(nullptr, 0);
		/**
		 * Выполняем перебор расширений, объявленных запросом подлинности
		 */
		while(reader.left() > 0){
			// Вид очередного расширения запроса подлинности
			uint32_t type = 0;
			// Если вид расширения прочитать не удалось
			if(reader.number(type, 2) != field::error_t::NONE)
				// Выводим отказ разбора запроса подлинности клиента
				return context::error_t::MESSAGE;
			// Тело очередного расширения запроса подлинности
			view_t content;
			// Если тело расширения прочитать не удалось
			if(reader.vector(content, 2) != field::error_t::NONE)
				// Выводим отказ разбора запроса подлинности клиента
				return context::error_t::MESSAGE;
			// Места, в которых объявленному расширению идти дозволено
			uint8_t places = 0;
			/**
			 * Раздел 4.2 RFC 8446 кладёт запросу подлинности свой перечень расширений, и
			 * признаваемое расширение вне его обрывает связь извещением
			 * «illegal_parameter»: из тех, что движок признаёт, запросу положены одни
			 * лишь схемы подписи
			 */
			if(placement(static_cast <uint16_t> (type), places) && ((places & PLACE_REQUEST) == 0))
				// Выводим отказ объявления расширения не в своём сообщении
				return context::error_t::EXTENSION;
			// Если объявлено расширение схем подписи
			if(type == static_cast <uint32_t> (extension::type_t::SCHEMES))
				// Запоминаем тело расширения схем подписи
				offer = content;
			// Если объявлено расширение алгоритмов сжатия цепочки сертификатов
			else if(type == static_cast <uint32_t> (extension::type_t::COMPRESS))
				// Запоминаем тело расширения алгоритмов сжатия
				squeezing = content;
			// Если объявлено расширение запроса состояния сертификата
			else if(type == static_cast <uint32_t> (extension::type_t::STATUS))
				// Запоминаем тело расширения запроса состояния
				asking = content;
			// Если объявлен перечень доверенных удостоверяющих центров
			else if(type == static_cast <uint32_t> (extension::type_t::AUTHORITIES))
				// Запоминаем тело перечня
				naming = content;
			// Если объявлен вид сертификата клиента
			else if(type == static_cast <uint32_t> (extension::type_t::CLIENT_CERT_TYPE))
				// Запоминаем тело вида сертификата клиента
				certtype = content;
		}
		// Выполняем сброс перечня доверенных центров собеседника
		this->_authorities.clear();
		// Раздел 4.2.4 RFC 8446: перечень имён разбирается по виду и хранится как записан - выбор сертификата по нему за потребителем
		if(naming.data != nullptr){
			// Отказ разбора перечня
			const context::error_t named = translate(extension::authorities(naming, this->_authorities), context::error_t::MESSAGE);
			// Если перечень разобрать не удалось
			if(named != context::error_t::NONE)
				// Выводим отказ разбора запроса подлинности
				return named;
		}
		// Выполняем сброс признака запроса состояния прежним запросом подлинности
		this->_inquired = false;
		/**
		 * Раздел 4.4.2.1 RFC 8446: сервер просит у клиента ответ OCSP ПУСТЫМ расширением
		 * status_request в CertificateRequest (так шлёт GnuTLS); OpenSSL кладёт туда полную
		 * структуру CertificateStatusRequest, как в приветствии, - принимаем обе формы
		 */
		if((asking.data != nullptr) && (asking.size == 0))
			// Пустое расширение - просьба об ответе OCSP
			this->_inquired = true;
		// Если расширение с телом, разбираем структуру запроса состояния
		else if(asking.data != nullptr){
			// Разбираем запрос состояния
			const context::error_t status = this->inquiry(asking);
			// Если запрос состояния сертификата разобрать не удалось
			if(status != context::error_t::NONE)
				// Выводим отказ разбора запроса подлинности клиента
				return status;
		}
		/**
		 * Раздел 4.2.1 RFC 7250: сервер, выбравший вид сертификата клиента, объявляет
		 * его одним элементом запроса подлинности
		 */
		if(certtype.data != nullptr){
			// Перечень видов сертификатов, объявленных сервером
			vector <extension::cert_t> kinds;
			// Отказ разбора расширения вида сертификата клиента
			const context::error_t refused = translate(extension::certtypes(certtype, kinds), context::error_t::MESSAGE);
			// Если виды сертификатов, объявленные сервером, разобрать не удалось
			if(refused != context::error_t::NONE)
				// Выводим отказ разбора запроса подлинности клиента
				return refused;
			// Если сервер объявил не один вид сертификата
			if(kinds.size() != 1)
				// Выводим отказ негодного расширения
				return context::error_t::MESSAGE;
			// Если сервер выбрал RawPublicKey
			if(kinds[0] == extension::cert_t::RAW)
				// Запоминаем согласованный вид своего сертификата
				this->_owncert = extension::cert_t::RAW;
		}
		/**
		 * Раздел 4.3.2 RFC 8446 велит запросу подлинности нести схемы подписи всегда:
		 * без них клиенту нечем узнать, какую подпись сервер сличить сумеет
		 */
		if(offer.data == nullptr)
			// Выводим отказ отсутствия схем подписи в запросе подлинности
			return context::error_t::SCHEME;
		// Отказ разбора запроса подлинности клиента
		context::error_t failure = translate(extension::schemes(offer, this->_schemes), context::error_t::MESSAGE);
		// Если схемы подписи, признаваемые сервером, разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора запроса подлинности клиента
			return failure;
		// Выполняем сброс алгоритмов сжатия, объявленных собеседником
		this->_compressible.clear();
		/**
		 * Раздел 3 RFC 8879: перечень алгоритмов в запросе подлинности говорит, какую
		 * сжатую цепочку сервер примет от клиента; перечень запоминается в порядке
		 * сервера, и клиент выбирает по нему первый общий со своими
		 */
		if(squeezing.data != nullptr){
			// Отказ разбора перечня алгоритмов сжатия
			failure = translate(extension::algorithms(squeezing, this->_compressible), context::error_t::MESSAGE);
			// Если алгоритмы сжатия, признаваемые сервером, разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора запроса подлинности клиента
				return failure;
		}
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			/**
			 * Раздел 4.4.2 RFC 8446 велит клиенту повторить опознаватель принятого запроса
			 * своей цепочкой сертификатов дословно: им сервер и опознаёт, какому запросу
			 * цепочка отвечает
			 */
			this->_binding.assign(binding.data, binding.data + binding.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выводим успешность разбора запроса подлинности клиента
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятой цепочки сертификатов собеседника
 *
 * @param body тело принятого сообщения цепочки сертификатов
 * @return     отказ разбора цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::chain(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разбираемое сообщение цепочки сертификатов
		message::certificate_t certificate;
		// Отказ разбора сообщения цепочки сертификатов
		const context::error_t failure = translate(message::parse(body, certificate), context::error_t::MESSAGE);
		// Если сообщение цепочки сертификатов разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора сообщения цепочки сертификатов
			return failure;
		/**
		 * Раздел 4.4.2 RFC 8446 велит серверу оставлять опознаватель запроса пустым, а
		 * клиенту - повторять им опознаватель принятого запроса подлинности. Модуль шлёт
		 * запрос подлинности с пустым опознавателем всегда, оттого пустым обязан быть и
		 * повтор: опознаватель, набитый содержимым, отвечает не тому запросу
		 */
		if(certificate.context.size > 0)
			// Выводим отказ непустого опознавателя запроса подлинности
			return context::error_t::MESSAGE;
		/**
		 * Раздел 4.4.2 RFC 8446 велит серверу присылать цепочку непустой: пустая цепочка
		 * означает отказ от подлинности, а он серверу не дозволен вовсе
		 */
		if(!this->_server && certificate.entries.empty())
			// Выводим отказ отсутствия сертификатов в цепочке сервера
			return context::error_t::CERTIFICATE;
		/**
		 * Выполняем перебор записей принятой цепочки сертификатов
		 */
		for(size_t i = 0; i < certificate.entries.size(); i++){
			/**
			 * Выполняем перебор расширений очередной записи цепочки
			 */
			for(size_t j = 0; j < certificate.entries[i].extensions.size(); j++){
				// Признак того, что расширение записи цепочки связью предлагалось
				bool suitable = false;
				/**
				 * Выполняем перебор расширений, предложенных связью приветствием
				 */
				for(size_t k = 0; (k < this->_offered.size()) && !suitable; k++)
					// Запоминаем, предлагалось ли расширение записи цепочки связью
					suitable = (certificate.entries[i].extensions[j].type == this->_offered[k]);
				/**
				 * Раздел 4.4.2.1 RFC 8446: ответ о состоянии сертификата клиента
				 * положен записи цепочки по запросу подлинности сервера, а не по
				 * приветствию; сервер судит его своим запросом
				 */
				if(!suitable && this->_server)
					// Запоминаем, запрашивалось ли состояние сертификата связью
					suitable = ((certificate.entries[i].extensions[j].type == static_cast <uint16_t> (extension::type_t::STATUS)) && this->_inquiring);
				/**
				 * Раздел 4.4.2 RFC 8446 велит расширениям записи цепочки отвечать
				 * предложенным: клиент судит их по своему приветствию, а сервер - по
				 * запросу подлинности, в котором расширений, годных записи цепочки, нет
				 * вовсе. Оттого у сервера перечень предложенных пуст, и всякое расширение
				 * записи он отвергает
				 */
				if(!suitable)
					// Выводим отказ объявления непрошенного расширения записи цепочки
					return context::error_t::EXTENSION;
			}
		}
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем сброс прежней цепочки сертификатов собеседника
			this->_peer.clear();
			/**
			 * Выполняем перебор записей принятой цепочки сертификатов
			 */
			for(size_t i = 0; i < certificate.entries.size(); i++){
				// Получаем тело сертификата очередной записи цепочки
				const view_t & data = certificate.entries[i].data;
				// Добавляем сертификат в цепочку собеседника
				this->_peer.push_back(vector <uint8_t> (data.data, data.data + data.size));
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выполняем сброс прежнего ответа о состоянии сертификата собеседника
		this->_status.clear();
		// Выполняем сброс прежнего состояния сертификата собеседника
		this->_certified = ocsp::status_t::NONE;
		// Если задан закреплённый сырой открытый ключ
		if(!this->_pinned.empty()){
			// Если согласован сырой открытый ключ
			if(this->_certtype == extension::cert_t::RAW){
				// Если цепочка пуста либо ключ не совпал с закреплённым
				if(this->_peer.empty() || (this->_peer[0].size() != this->_pinned.size()) || (::memcmp(this->_peer[0].data(), this->_pinned.data(), this->_pinned.size()) != 0))
					// Выводим отказ несовпадения сырого ключа с закреплённым
					return context::error_t::CERTIFICATE;
			// Иначе извлекаем SPKI из X.509 листа и сверяем с закреплённым
			} else if(!this->_peer.empty()){
				// Разбираем лист цепочки
				x509::certificate_t leaf;
				// Если лист разобрался и его SPKI не совпал с закреплённым
				if((leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())) == x509::error_t::NONE) && ((leaf.key().element.size != this->_pinned.size()) || (::memcmp(leaf.key().element.data, this->_pinned.data(), this->_pinned.size()) != 0)))
					// Выводим отказ несовпадения ключа сертификата с закреплённым
					return context::error_t::CERTIFICATE;
			}
		}
		// Расширение состояния сертификата собеседника
		const hello::extension_t * extension = nullptr;
		// Выполняем сброс прежних ответов о состоянии сертификатов цепочки
		this->_statuses.clear();
		// Занимаем место под ответы по числу записей цепочки
		this->_statuses.resize(certificate.entries.size());
		/**
		 * Раздел 4.4.2.1 RFC 8446: ответ о состоянии относится к сертификату своей записи;
		 * связь берёт ответ о сертификате самого собеседника - из первой записи либо из
		 * записи, несущей тот же сертификат ещё раз: s_server кладёт ответ на повтор листа
		 * из своей цепочки, а не на первую запись
		 */
		for(size_t i = 0; (i < certificate.entries.size()) && (extension == nullptr); i++){
			// Запись цепочки
			const view_t & data = certificate.entries[i].data;
			// Запись первого сертификата цепочки
			const view_t & first = certificate.entries[0].data;
			// Если запись несёт не сертификат собеседника
			if((i > 0) && ((data.size != first.size) || (::memcmp(data.data, first.data, data.size) != 0)))
				// Переходим к следующей записи
				continue;
			// Разыскиваем расширение состояния сертификата записи цепочки
			extension = hello::extension(certificate.entries[i].extensions, static_cast <uint16_t> (extension::type_t::STATUS));
		}
		// Если ответ о состоянии сертификата собеседника прислан
		if(extension != nullptr){
			// Отказ разбора ответа о состоянии сертификата
			const context::error_t error = this->stapled(extension->data);
			// Если ответ о состоянии сертификата разобрать либо проверить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ разбора ответа о состоянии
				return error;
		}
		/**
		 * Раздел 4.4.2.1 RFC 8446: ответы о состоянии иных записей цепочки собираются
		 * по местам для потребителя; проверка их - дело потребителя, связь лишь хранит
		 */
		for(size_t i = 1; i < certificate.entries.size(); i++){
			// Разыскиваем расширение состояния сертификата записи цепочки
			const hello::extension_t * status = hello::extension(certificate.entries[i].extensions, static_cast <uint16_t> (extension::type_t::STATUS));
			// Если ответ о состоянии записи прислан
			if(status != nullptr){
				// Объект разборщика тела расширения состояния
				field::scanner_t scanner;
				// Устанавливаем разбираемое тело расширения состояния
				scanner.start(status->data);
				// Вид присланного состояния сертификата
				uint32_t type = 0;
				// Если вид состояния прочитать не удалось
				if(scanner.number(type, 1) != field::error_t::NONE)
					// Переходим к следующей записи
					continue;
				// Запись ответа о состоянии
				view_t response;
				// Если запись ответа прочитать не удалось
				if(scanner.vector(response, 3) != field::error_t::NONE)
					// Переходим к следующей записи
					continue;
				// Если вид состояния не ocsp либо запись пуста
				if((type != OCSP) || (response.size == 0))
					// Переходим к следующей записи
					continue;
				// Переносим запись ответа в накопитель по месту записи
				this->_statuses[i].assign(response.data, response.data + response.size);
			}
		}
		// Выполняем сброс перечня меток времени сертификата собеседника
		this->_timestamps.clear();
		/**
		 * Раздел 4.4.2.1 RFC 8446 и раздел 3.3 RFC 6962: перечень меток времени берётся с
		 * листа - первой записи цепочки; в иных записях он терпится и не хранится (как у
		 * BoringSSL). Перечень проверяется по виду и хранится как записан: ни журналы, ни
		 * подписи связь не толкует
		 */
		if(!certificate.entries.empty()){
			// Разыскиваем расширение меток времени в записи листа
			extension = hello::extension(certificate.entries[0].extensions, static_cast <uint16_t> (extension::type_t::TIMESTAMPS));
			// Если перечень меток времени сервером выдан
			if(extension != nullptr){
				// Записи перечня, разобранные ради проверки вида
				vector <vector <uint8_t>> entries;
				// Отказ разбора перечня меток времени: негодная запись - свой отказ, нехватка памяти - своя
				const context::error_t failure = translate(extension::timestamps(extension->data, entries), context::error_t::TIMESTAMPS);
				// Если перечень разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора перечня меток времени
					return ((failure == context::error_t::MEMORY) ? failure : context::error_t::TIMESTAMPS);
				// Запоминаем перечень меток времени как записан
				this->_timestamps.assign(extension->data.data, extension->data.data + extension->data.size);
			}
		}
		// Выводим успешность разбора цепочки сертификатов собеседника
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод распаковки принятой сжатой цепочки сертификатов собеседника
 *
 * @param body   тело принятого сообщения сжатой цепочки сертификатов
 * @param result накопитель, в который помещается тело цепочки после распаковки
 * @return       отказ распаковки цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::unpack(const view_t & body, vector <uint8_t> & result) noexcept {
	// Объект разборщика тела сжатой цепочки сертификатов
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело сжатой цепочки сертификатов
	scanner.start(body);
	// Опознаватель алгоритма, которым сжата цепочка
	uint32_t algorithm = 0;
	// Если опознаватель алгоритма прочитать не удалось
	if(scanner.number(algorithm, 2) != field::error_t::NONE)
		// Выводим отказ разбора сжатой цепочки сертификатов
		return context::error_t::MESSAGE;
	// Объявленная длина цепочки после распаковки
	uint32_t length = 0;
	// Если длину цепочки после распаковки прочитать не удалось
	if(scanner.number(length, 3) != field::error_t::NONE)
		// Выводим отказ разбора сжатой цепочки сертификатов
		return context::error_t::MESSAGE;
	// Сжатое тело цепочки сертификатов
	view_t packed;
	// Если сжатое тело цепочки прочитать не удалось
	if(scanner.vector(packed, 3) != field::error_t::NONE)
		// Выводим отказ разбора сжатой цепочки сертификатов
		return context::error_t::MESSAGE;
	// Если за телом сжатой цепочки идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ разбора сжатой цепочки сертификатов
		return context::error_t::MESSAGE;
	// Алгоритм сжатия потребителя, отвечающий объявленному опознавателю
	const context::codec_t * codec = nullptr;
	/**
	 * Выполняем перебор алгоритмов сжатия, предоставленных потребителем
	 */
	for(size_t i = 0; (i < this->_codecs.size()) && (codec == nullptr); i++){
		// Если опознаватель очередного алгоритма сошёлся с объявленным
		if(this->_codecs[i].algorithm == static_cast <uint16_t> (algorithm))
			// Запоминаем алгоритм сжатия потребителя
			codec = &this->_codecs[i];
	}
	/**
	 * Раздел 4 RFC 8879: цепочка, сжатая алгоритмом, который сторона не объявляла,
	 * обрывает связь извещением «illegal_parameter»
	 */
	if(codec == nullptr)
		// Выводим отказ сжатия алгоритмом, связью не объявлявшимся
		return context::error_t::COMPRESSION;
	/**
	 * Раздел 4 RFC 8879: пустая цепочка после распаковки цепочкой не является, а длина
	 * сверх предела отвергается до распаковки - память под цепочку по слову собеседника
	 * отводится лишь в пределах, поставленных потребителем
	 */
	if((length == 0) || (packed.size == 0) || (static_cast <size_t> (length) > this->_inflation))
		// Выводим отказ непригодности сжатой цепочки сертификатов
		return context::error_t::CERTIFICATE;
	// Признак успешности распаковки у потребителя
	bool inflated = false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Выполняем сброс накопителя цепочки после распаковки
		result.clear();
		// Выполняем распаковку цепочки вызовом потребителя
		inflated = codec->decompress(packed, static_cast <size_t> (length), result, codec->context);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(...) {
		// Выводим отказ непригодности сжатой цепочки сертификатов
		return context::error_t::CERTIFICATE;
	}
	/**
	 * Раздел 4 RFC 8879: отказ распаковки и расхождение длины после распаковки с
	 * объявленной обрывают связь извещением «bad_certificate»
	 */
	if(!inflated || (result.size() != static_cast <size_t> (length)))
		// Выводим отказ непригодности сжатой цепочки сертификатов
		return context::error_t::CERTIFICATE;
	// Запоминаем алгоритм, которым была сжата принятая цепочка
	this->_inflated = static_cast <uint16_t> (algorithm);
	// Выводим успешность распаковки цепочки сертификатов
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого запроса состояния сертификата
 *
 * @param data тело расширения запроса состояния сертификата
 * @return     отказ разбора запроса состояния
 *
 */
context::error_t nts::internal::Engine::inquiry(const view_t & data) noexcept {
	// Объект разборщика тела запроса состояния
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело запроса состояния
	scanner.start(data);
	// Вид запрошенного состояния сертификата
	uint32_t type = 0;
	// Если вид состояния прочитать не удалось
	if(scanner.number(type, 1) != field::error_t::NONE)
		// Выводим отказ разбора запроса состояния
		return context::error_t::MESSAGE;
	// Перечень ответчиков, признаваемых собеседником
	view_t responders;
	// Если перечень ответчиков прочитать не удалось
	if(scanner.vector(responders, 2) != field::error_t::NONE)
		// Выводим отказ разбора запроса состояния
		return context::error_t::MESSAGE;
	// Расширения запроса состояния
	view_t extensions;
	// Если расширения запроса прочитать не удалось
	if(scanner.vector(extensions, 2) != field::error_t::NONE)
		// Выводим отказ разбора запроса состояния
		return context::error_t::MESSAGE;
	// Если за телом запроса состояния идут лишние байты
	if(scanner.left() > 0)
		// Выводим отказ разбора запроса состояния
		return context::error_t::MESSAGE;
	/**
	 * Раздел 8 RFC 6066: перечень ответчиков и расширения запроса связь не толкует -
	 * ответ задаёт потребитель заранее, а вид состояния, отличный от ocsp, оставляет
	 * запрос без ответа, что разделом 4.4.2.1 RFC 8446 серверу дозволено
	 */
	this->_inquired = (type == OCSP);
	// Выводим успешность разбора запроса состояния
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора принятого ответа о состоянии сертификата собеседника
 *
 * @param data тело расширения записи цепочки с ответом о состоянии
 * @return     отказ разбора либо проверки ответа о состоянии
 *
 */
context::error_t nts::internal::Engine::stapled(const view_t & data) noexcept {
	// Объект разборщика тела расширения состояния
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело расширения состояния
	scanner.start(data);
	// Вид присланного состояния сертификата
	uint32_t type = 0;
	// Если вид состояния прочитать не удалось
	if(scanner.number(type, 1) != field::error_t::NONE)
		// Выводим отказ разбора ответа о состоянии
		return context::error_t::STATUS;
	// Запись ответа о состоянии
	view_t response;
	// Если запись ответа прочитать не удалось
	if(scanner.vector(response, 3) != field::error_t::NONE)
		// Выводим отказ разбора ответа о состоянии
		return context::error_t::STATUS;
	/**
	 * Раздел 8 RFC 6066: вид состояния обязан быть ocsp, запись ответа - непустой, а
	 * лишние байты за телом не дозволены
	 */
	if((type != OCSP) || (response.size == 0) || (scanner.left() > 0))
		// Выводим отказ разбора ответа о состоянии
		return context::error_t::STATUS;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим запись ответа в накопитель
		this->_status.assign(response.data, response.data + response.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	/**
	 * Без проверки ответ лишь хранится для потребителя: суждение о нём он выносит
	 * сам; цепочка без сертификата собеседника проверять не даёт
	 */
	if(!this->_verifying || this->_peer.empty())
		// Выводим успешность разбора ответа о состоянии
		return context::error_t::NONE;
	// Объект разбора ответа о состоянии
	ocsp::response_t parsed;
	// Отказ разбора ответа о состоянии
	ocsp::error_t failure = parsed.parse(view_t(this->_status.data(), this->_status.size()));
	// Если памяти под разбор не хватило
	if(failure == ocsp::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Если ответ о состоянии разобрать не удалось
	if(failure != ocsp::error_t::NONE)
		// Выводим отказ разбора ответа о состоянии
		return context::error_t::STATUS;
	// Запись сертификата издателя собеседника
	view_t issuer(nullptr, 0);
	// Объект разбора сертификата собеседника
	x509::certificate_t leaf;
	// Отказ разбора сертификата собеседника
	const x509::error_t error = leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size()));
	// Если памяти под разбор не хватило
	if(error == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Если сертификат собеседника разобрать не удалось
	if(error != x509::error_t::NONE)
		// Выводим отказ проверки ответа о состоянии
		return context::error_t::STATUS;
	// Имя издателя сертификата собеседника
	const view_t & name = leaf.issuers().element;
	// Имя владельца сертификата собеседника
	const view_t & subject = leaf.subjects().element;
	/**
	 * Выполняем перебор звеньев цепочки собеседника в поисках издателя: раздел 4.4.2
	 * RFC 8446 велит слать издателя следом за сертификатом, но иные стороны шлют лист и
	 * дважды - издатель разыскивается по имени, а не по месту
	 */
	for(size_t i = 1; (i < this->_peer.size()) && (issuer.data == nullptr); i++){
		// Объект разбора звена цепочки
		x509::certificate_t link;
		// Отказ разбора звена цепочки
		const x509::error_t parsed = link.parse(view_t(this->_peer[i].data(), this->_peer[i].size()));
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если звено цепочки разобрать не удалось
		if(parsed != x509::error_t::NONE)
			// Переходим к следующему звену
			continue;
		// Имя владельца звена цепочки
		const view_t & owner = link.subjects().element;
		// Если имя владельца звена сошлось с именем издателя
		if((owner.size == name.size) && (::memcmp(owner.data, name.data, name.size) == 0))
			// Берём издателем звено цепочки
			issuer = view_t(this->_peer[i].data(), this->_peer[i].size());
	}
	// Если издателя в цепочке нет, а сертификат собеседника издан им самим
	if((issuer.data == nullptr) && (name.size == subject.size) && (::memcmp(name.data, subject.data, name.size) == 0))
		// Берём издателем сам сертификат собеседника
		issuer = view_t(this->_peer[0].data(), this->_peer[0].size());
	/**
	 * Выполняем перебор запаса доверенных сертификатов в поисках издателя
	 */
	for(size_t i = 0; (i < this->_anchors.size()) && (issuer.data == nullptr); i++){
		// Объект разбора доверенного сертификата
		x509::certificate_t anchor;
		// Отказ разбора доверенного сертификата
		const x509::error_t parsed = anchor.parse(this->_anchors.get(i));
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если доверенный сертификат разобрать не удалось
		if(parsed != x509::error_t::NONE)
			// Переходим к следующему сертификату
			continue;
		// Имя владельца доверенного сертификата
		const view_t & owner = anchor.subjects().element;
		// Если имя владельца доверенного сертификата сошлось с именем издателя
		if((owner.size == name.size) && (::memcmp(owner.data, name.data, name.size) == 0))
			// Берём издателем доверенный сертификат
			issuer = this->_anchors.get(i);
	}
	/**
	 * Без издателя ответ проверить нечем: ни хеши опознавателя, ни подпись ответчика
	 * не сличить, и ответ при включённой проверке считается негодным
	 */
	if(issuer.data == nullptr)
		// Выводим отказ проверки ответа о состоянии
		return context::error_t::STATUS;
	// Состояние сертификата собеседника
	ocsp::status_t status = ocsp::status_t::NONE;
	// Выполняем проверку ответа против сертификата собеседника и его издателя
	failure = ocsp::verify(parsed, view_t(this->_peer[0].data(), this->_peer[0].size()), issuer, this->_moment, this->_leeway, view_t(nullptr, 0), status);
	// Если памяти под проверку не хватило
	if(failure == ocsp::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Если ответ о состоянии проверку не прошёл
	if(failure != ocsp::error_t::NONE)
		// Выводим отказ проверки ответа о состоянии
		return context::error_t::STATUS;
	// Запоминаем состояние сертификата собеседника
	this->_certified = status;
	/**
	 * Раздел 4.4.2.1 RFC 8446: отозванный сертификат обрывает связь; неведомый
	 * ответчику сертификат отказом не считается - решение о нём за потребителем
	 */
	if(status == ocsp::status_t::REVOKED)
		// Выводим отказ отозванного сертификата
		return context::error_t::STATUS;
	// Выводим успешность проверки ответа о состоянии
	return context::error_t::NONE;
}
/**
 * @brief Метод сжатия отправляемой цепочки сертификатов своей стороны
 *
 * @param body      тело сообщения цепочки сертификатов
 * @param result    накопитель, в который помещается тело сжатого сообщения
 * @param algorithm место, в которое помещается выбранный алгоритм, ноль без сжатия
 * @return          отказ сжатия цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::squeeze(const vector <uint8_t> & body, vector <uint8_t> & result, uint16_t & algorithm) noexcept {
	// Сжатия нет, пока общий алгоритм не найден
	algorithm = 0;
	/**
	 * Раздел 4 RFC 8879: цепочка, в трёхбайтовую длину не входящая, сжатой уйти не
	 * может; без алгоритмов у себя либо у собеседника сжимать нечем
	 */
	if(this->_codecs.empty() || this->_compressible.empty() || body.empty() || (body.size() > CHAIN))
		// Выводим успешность: цепочка уходит несжатой
		return context::error_t::NONE;
	// Алгоритм сжатия потребителя, общий с собеседником
	const context::codec_t * codec = nullptr;
	/**
	 * Раздел 3 RFC 8879: выбирается первый общий алгоритм по порядку объявившей стороны -
	 * сервер идёт по перечню клиента, клиент по перечню запроса подлинности; неведомые
	 * значения собеседника пропускаются молча
	 */
	for(size_t i = 0; (i < this->_compressible.size()) && (codec == nullptr); i++){
		/**
		 * Выполняем перебор алгоритмов сжатия, предоставленных потребителем
		 */
		for(size_t j = 0; (j < this->_codecs.size()) && (codec == nullptr); j++){
			// Если опознаватель алгоритма потребителя сошёлся с объявленным собеседником
			if(this->_codecs[j].algorithm == this->_compressible[i])
				// Запоминаем общий алгоритм сжатия
				codec = &this->_codecs[j];
		}
	}
	// Если общего алгоритма сжатия не нашлось
	if(codec == nullptr)
		// Выводим успешность: цепочка уходит несжатой
		return context::error_t::NONE;
	// Накопитель, в который складывается сжатое тело цепочки
	vector <uint8_t> packed;
	// Признак успешности сжатия у потребителя
	bool squeezed = false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Выполняем сжатие цепочки вызовом потребителя
		squeezed = codec->compress(view_t(body.data(), body.size()), packed, codec->context);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(...) {
		// Запоминаем отказ сжатия у потребителя
		squeezed = false;
	}
	/**
	 * Раздел 4 RFC 8879: сторона вправе не сжимать; отказ сжатия у потребителя и сжатое
	 * тело, в трёхбайтовую длину не входящее, шлют цепочку несжатой
	 */
	if(!squeezed || packed.empty() || (packed.size() > CHAIN))
		// Выводим успешность: цепочка уходит несжатой
		return context::error_t::NONE;
	// Объект составителя тела сжатой цепочки сертификатов
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = field::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Записываем опознаватель алгоритма сжатия
		if((failure = builder.number(static_cast <uint32_t> (codec->algorithm), 2)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure, context::error_t::MESSAGE);
		// Записываем длину цепочки до сжатия
		if((failure = builder.number(static_cast <uint32_t> (body.size()), 3)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure, context::error_t::MESSAGE);
		// Открываем поле сжатого тела цепочки
		if((failure = builder.open(3)) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure, context::error_t::MESSAGE);
		// Записываем сжатое тело цепочки
		if((failure = builder.bytes(view_t(packed.data(), packed.size()))) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure, context::error_t::MESSAGE);
		// Если поле сжатого тела закрыть не удалось
		if((failure = builder.close()) != field::error_t::NONE)
			// Выводим отказ, которым ответил составитель полей
			return translate(failure, context::error_t::MESSAGE);
		// Получаем составленное тело сжатой цепочки
		const view_t data = builder.data();
		// Переносим тело сжатой цепочки в накопитель
		result.assign(data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Запоминаем выбранный алгоритм сжатия
	algorithm = codec->algorithm;
	// Выводим успешность сжатия цепочки сертификатов
	return context::error_t::NONE;
}
/**
 * @brief Метод выработки подписи содержимого своим ключом
 *
 * @param content   подписываемое содержимое
 * @param scheme    место, в которое помещается выбранная схема подписи
 * @param signature накопитель, в который помещается подпись в записи протокола
 * @return          отказ выработки подписи
 *
 */
context::error_t nts::internal::Engine::signing(const view_t & content, extension::scheme_t & scheme, vector <uint8_t> & signature) noexcept {
	/**
	 * Выполняем перехват ошибок работы с памятью: тело выработки подписи занимает
	 * память на всяком шаге, и всякий такой шаг вправе ответить нехваткой памяти
	 */
	// Раздел 7.4.3 RFC 4346: изданием 1.1 подпись идёт без схемы - RSA над MD5 ‖ SHA-1, ECDSA над SHA-1
	if(this->_ancient){
		// Схемы у издания 1.1 нет
		scheme = extension::scheme_t::NONE;
		// Выводим итог выработки подписи изданием 1.1
		return this->engraving(content, signature);
	}
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если своей подлинности у связи нет
		if(this->_credential.chain.empty())
			// Выводим отказ отсутствия своего сертификата
			return context::error_t::CERTIFICATE;
		// Объект разбора своего сертификата
		x509::certificate_t leaf;
		// Отказ разбора своего сертификата
		failure = translate(leaf.parse(view_t(this->_credential.chain[0].data(), this->_credential.chain[0].size())), context::error_t::CERTIFICATE);
		// Если свой сертификат разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора своего сертификата
			return failure;
		// Схема подписи владения своим ключом
		extension::scheme_t item = extension::scheme_t::NONE;
		// Накопитель, в который складывается подпись в записи протокола
		vector <uint8_t> signed_;
		/**
		 * Выполняем перебор схем подписи, признаваемых связью, в порядке предпочтения
		 */
		for(size_t i = 0; (i < this->_signatures.size()) && (item == extension::scheme_t::NONE); i++){
			/**
			 * Раздел 4.2.3 RFC 8446 запрещает схемы PKCS #1 v1.5 подписи владения ключом в
			 * издании TLS 1.3, а схемы ГОСТ определены лишь для него: изданию TLS 1.2 годны
			 * лишь классические схемы
			 */
			if(this->_legacy ? !legible(this->_signatures[i]) : pkcs1(this->_signatures[i]))
				// Переходим к следующей схеме подписи
				continue;
			// Признак нехватки памяти при разборе ключа
			bool memory = false;
			// Признак соответствия схемы своему ключу
			const bool suitable = matching(this->_signatures[i], leaf.key(), memory, this->_legacy);
			// Если памяти под разбор ключа не хватило
			if(memory)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Если схема подписи своему ключу не отвечает
			if(!suitable)
				// Переходим к следующей схеме подписи
				continue;
			/**
			 * Выполняем перебор схем подписи, признаваемых собеседником
			 */
			for(size_t j = 0; (j < this->_schemes.size()) && (item == extension::scheme_t::NONE); j++){
				// Если схема подписи признаётся собеседником
				if(this->_signatures[i] == this->_schemes[j])
					// Запоминаем выбранную схему подписи
					item = this->_signatures[i];
			}
		}
		/**
		 * Раздел 4.4.3 RFC 8446 велит подписывать владение ключом лишь той схемой, какую
		 * собеседник объявил признаваемой: подписи схемой, ему неведомой, он не сличит, и
		 * оборвётся рукопожатие тогда у него - позже и невнятнее, чем здесь
		 */
		if(item == extension::scheme_t::NONE)
			// Выводим отказ непризнания схемы подписи собеседником
			return context::error_t::SCHEME;
		// Если схема подписи - схема ГОСТ
		if(extension::hash(item) == digest::hash_t::STREEBOG256 || extension::hash(item) == digest::hash_t::STREEBOG512){
			// Подготовленный секретный ключ своей стороны
			const keys::signer_t * signer = nullptr;
			// Отказ подготовки секретного ключа своей стороны
			failure = this->signer(signer);
			// Если секретный ключ своей стороны подготовить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ подготовки секретного ключа
				return failure;
			// Если подготовленный ключ - не ключ ГОСТ
			if(signer->kind() != keys::kind_t::GOST)
				// Выводим отказ установки секретного ключа
				return context::error_t::SIGNATURE;
			// Модуль электронной подписи подготовленного ключа
			const sign::gost_t & gost = signer->gost();
			// Длина числа кривой подготовленного ключа
			const size_t size = signer->curve().size();
			// Место, в которое помещается хеш подписываемого содержимого
			uint8_t digest[64];
			// Определяем длину хеша подписываемого содержимого
			const digest::type_t type = ((size == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
			// Если хеш подписываемого содержимого выработать не удалось
			if(!digest::streebog(type, content, digest, size, digest::order_t::VECTOR))
				// Выводим отказ выработки хеша подписываемого содержимого
				return context::error_t::SIGNATURE;
			// Место, в которое помещается выработанная подпись владения ключом
			uint8_t signature[math::NUMBER_SIZE * 2];
			// Если подпись владения ключом выработать не удалось
			if(!gost.make(view_t(digest, size), signature))
				// Выводим отказ выработки подписи владения ключом
				return context::error_t::SIGNATURE;
			// Место, в которое помещается подпись в записи протокола
			uint8_t reversed[math::NUMBER_SIZE * 2];
			/**
			 * Раздел 5.3 описания наборов шифрования: обе половины подписи записываются в
			 * протокол младшим байтом вперёд, тогда как выработка даёт их обратной записью
			 */
			// Отказ разворота записи подписи
			failure = translate(message::reverse(view_t(signature, gost.size()), reversed), context::error_t::SIGNATURE);
			// Если разворот записи подписи отказал
			if(failure != context::error_t::NONE)
				// Выводим отказ разворота записи подписи
				return failure;
			// Переносим подпись в записи протокола в накопитель
			signed_.assign(reversed, reversed + gost.size());
		// Если схема подписи - классическая
		} else {
			// Подготовленный секретный ключ своей стороны
			const keys::signer_t * signer = nullptr;
			// Отказ подготовки секретного ключа своей стороны
			failure = this->signer(signer);
			// Если секретный ключ своей стороны подготовить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ подготовки секретного ключа
				return failure;
			// Хеш подписываемого содержимого по схеме подписи
			const digest::hash_t algorithm = extension::hash(item);
			// Если схема подписи - SM2
			if(item == extension::scheme_t::SM2SIG_SM3){
				// Если подготовленный ключ - не ключ SM2
				if(signer->kind() != keys::kind_t::SM2)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи SM2 подготовленного ключа
				const sign::sm2_t & sm2 = signer->sm2();
				// Опознаватель подписи владения ключом по RFC 8998
				static const char * ID = "TLSv1.3+GM+Cipher+Suite";
				// Если опознаватель подписи владения ключом установить не удалось
				if(!sm2.reidentify(view_t(reinterpret_cast <const uint8_t *> (ID), 22)))
					// Выводим отказ установки опознавателя
					return context::error_t::SIGNATURE;
				// Место, в которое помещается подпись в записи выработки
				uint8_t raw[64];
				// Случайное число выработки подписи
				uint8_t random[32];
				// Признак успешности выработки подписи
				bool made = false;
				/**
				 * GB/T 32918.2: неудачный выбор случайного числа (нулевое r, нулевое s
				 * либо r + k = n) велит выбрать новое число и повторить выработку
				 */
				for(size_t attempt = 0; !made && (attempt < 128); attempt++){
					// Если случайное число выработать не удалось
					if(!entropy::bytes(random, sizeof(random)))
						// Выводим отказ выработки случайного числа
						return context::error_t::SIGNATURE;
					// Выполняем выработку подписи владения ключом
					made = sm2.make(content, view_t(random, sizeof(random)), raw);
				}
				// Выполняем затирание случайного числа выработки подписи
				this->purge(random, sizeof(random));
				// Если подпись выработать не удалось
				if(!made)
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
				// Выделяем место под запись подписи по её пределу: ведущий нуль у обоих чисел
				signed_.assign(72, 0);
				// Длина записи подписи
				size_t written = signed_.size();
				// Если подпись в запись DER перевести не удалось
				if(!sign::encode(view_t(raw, sizeof(raw)), signed_.data(), written))
					// Выводим отказ записи подписи владения ключом
					return context::error_t::SIGNATURE;
				// Усекаем запись до её длины: усечение памяти не выделяет
				signed_.resize(written);
			// Если схема подписи - ECDSA
			} else if((item == extension::scheme_t::ECDSA_SECP256R1_SHA256) || (item == extension::scheme_t::ECDSA_SECP384R1_SHA384) || (item == extension::scheme_t::ECDSA_SECP521R1_SHA512)){
				// Если подготовленный ключ - не ключ на кривой Вейерштрасса
				if(signer->kind() != keys::kind_t::EC)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи ECDSA подготовленного ключа
				const sign::ecdsa_t & ecdsa = signer->ecdsa();
				// Место, в которое помещается хеш подписываемого содержимого
				uint8_t digest[64];
				// Если хеш подписываемого содержимого выработать не удалось
				if(!digest::hash(algorithm, content, digest, sizeof(digest)))
					// Выводим отказ выработки хеша подписываемого содержимого
					return context::error_t::SIGNATURE;
				// Место, в которое помещается подпись в записи выработки
				uint8_t raw[math::NUMBER_SIZE * 2];
				/**
				 * Раздел 4.2.3 RFC 8446: подпись ECDSA вырабатывается с детерминированным
				 * случайным значением по RFC 6979 и записывается в протокол структурой DER
				 */
				if(!ecdsa.make(algorithm, view_t(digest, digest::length(algorithm)), raw))
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
				// Выделяем место под запись подписи по её пределу: нехватка памяти всплывает исключением наружу как MEMORY, а сама запись идёт в готовое место без выделений
				signed_.assign(ecdsa.limit(), 0);
				// Длина записи подписи
				size_t written = signed_.size();
				// Если подпись в запись DER перевести не удалось
				if(!sign::encode(view_t(raw, ecdsa.size()), signed_.data(), written))
					// Выводим отказ записи подписи владения ключом
					return context::error_t::SIGNATURE;
				// Усекаем запись до её длины: усечение памяти не выделяет
				signed_.resize(written);
			// Если схема подписи - RSASSA-PSS
			} else if(algorithm != digest::hash_t::NONE){
				// Если подготовленный ключ - не ключ RSA
				if(signer->kind() != keys::kind_t::RSA)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи RSA подготовленного ключа
				const sign::rsa_t & rsa = signer->rsa();
				// Место, в которое помещается хеш подписываемого содержимого
				uint8_t digest[64];
				// Если хеш подписываемого содержимого выработать не удалось
				if(!digest::hash(algorithm, content, digest, sizeof(digest)))
					// Выводим отказ выработки хеша подписываемого содержимого
					return context::error_t::SIGNATURE;
				// Занимаем место под подпись длиною в модуль ключа
				signed_.assign(rsa.size(), 0);
				/**
				 * Раздел 4.2.3 RFC 8446: подпись RSASSA-PSS с функцией порождения маски MGF1
				 * на том же хеше и солью длиною в хеш; схема PKCS #1 v1.5 в TLS 1.3 запрещена,
				 * а изданию TLS 1.2 дозволена ради чужих сторон (раздел 7.4.1.4.1 RFC 5246)
				 */
				if(!rsa.make((pkcs1(item) ? sign::scheme_t::PKCS1 : sign::scheme_t::PSS), algorithm, view_t(digest, digest::length(algorithm)), signed_.data(), digest::length(algorithm)))
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
			// Если схема подписи - ML-DSA
			} else if((item == extension::scheme_t::MLDSA44) || (item == extension::scheme_t::MLDSA65) || (item == extension::scheme_t::MLDSA87)){
				// Если подготовленный ключ - не ключ ML-DSA
				if(signer->kind() != keys::kind_t::MLDSA)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи ML-DSA подготовленного ключа
				const sign::mldsa_t & mldsa = signer->mldsa();
				// Если набор ключа не отвечает схеме
				if(((item == extension::scheme_t::MLDSA44) && (mldsa.set() != sign::mldsa_t::set_t::DSA44)) || ((item == extension::scheme_t::MLDSA65) && (mldsa.set() != sign::mldsa_t::set_t::DSA65)) || ((item == extension::scheme_t::MLDSA87) && (mldsa.set() != sign::mldsa_t::set_t::DSA87)))
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Занимаем место под подпись набора ключа
				signed_.assign(mldsa.size(), 0);
				/**
				 * draft-ietf-tls-mldsa-06: чистый ML-DSA без предхеширования, контекст
				 * пустой - подписывается само содержимое владения ключом
				 */
				if(!mldsa.make(content, view_t(nullptr, 0), signed_.data()))
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
			// Если схема подписи - Ed448
			} else if(item == extension::scheme_t::ED448){
				// Если подготовленный ключ - не ключ Ed448
				if(signer->kind() != keys::kind_t::ED448)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи Ed448 подготовленного ключа
				const sign::ed448_t & ed448 = signer->ed448();
				// Занимаем место под подпись Ed448
				signed_.assign(sign::ed448_t::SIGNATURE_SIZE, 0);
				// Если подпись владения ключом выработать не удалось
				if(!ed448.make(content, signed_.data()))
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
			// Если схема подписи - Ed25519
			} else {
				// Если подготовленный ключ - не ключ Ed25519
				if(signer->kind() != keys::kind_t::ED25519)
					// Выводим отказ установки секретного ключа
					return context::error_t::SIGNATURE;
				// Модуль подписи Ed25519 подготовленного ключа
				const sign::ed25519_t & ed25519 = signer->ed25519();
				// Занимаем место под подпись Ed25519
				signed_.assign(sign::ed25519_t::SIGNATURE_SIZE, 0);
				// Если подпись владения ключом выработать не удалось
				if(!ed25519.make(content, signed_.data()))
					// Выводим отказ выработки подписи владения ключом
					return context::error_t::SIGNATURE;
			}
		}
		// Устанавливаем выбранную схему подписи
		scheme = item;
		// Переносим подпись в записи протокола
		signature = ::move(signed_);
		// Выводим успешность выработки подписи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Функция проверки подписи содержимого ключом сертификата собеседника
 *
 * @param scheme    объявленная собеседником схема подписи
 * @param content   подписанное содержимое
 * @param signature подпись в записи протокола
 * @return          отказ проверки подписи
 *
 */
/**
 * @brief Функция разбора записи сведений об открытом ключе собеседника
 *
 * @param der    запись SubjectPublicKeyInfo DER
 * @param result место, в которое помещаются сведения об открытом ключе
 * @return       признак успешности разбора
 *
 * @details Раздел 2 RFC 7250: при согласованном виде RawPublicKey запись цепочки
 *          сертификатов несёт сами сведения об открытом ключе, и подпись владения
 *          им проверяется по ним, без сертификата
 *
 */
static bool publicKey(const view_t & der, nts::x509::key_t & result) noexcept {
	// Разборщик записи сведений об открытом ключе
	asn1::reader_t outer(der);
	// Объект разобранного поля записи сведений
	asn1::element_t item;
	// Если запись сведений не читается либо имеет простой вид метки
	if(!outer.next(asn1::tag_t::SEQUENCE, item) || !item.constructed)
		// Выводим отказ разбора
		return false;
	// Запоминаем запись сведений целиком
	result.element = item.element;
	// Разборщик содержимого записи сведений
	asn1::reader_t info(item.content);
	// Если опознаватель алгоритма ключа не читается либо имеет простой вид метки
	if(!info.next(asn1::tag_t::SEQUENCE, item) || !item.constructed)
		// Выводим отказ разбора
		return false;
	// Разборщик содержимого записи опознавателя алгоритма
	asn1::reader_t algorithm(item.content);
	// Если опознаватель алгоритма не читается
	if(!algorithm.next(asn1::tag_t::OBJECT, item))
		// Выводим отказ разбора
		return false;
	// Если опознаватель алгоритма извлечь не удалось
	if(asn1::oid(item, result.algorithm) != asn1::error_t::NONE)
		// Выводим отказ разбора
		return false;
	// Если после опознавателя алгоритма остались поля
	if(!algorithm.empty()){
		// Если настройки алгоритма не читаются
		if(!algorithm.next(item))
			// Выводим отказ разбора
			return false;
		// Запоминаем запись настроек алгоритма
		result.parameters = item.element;
		// Если после настроек алгоритма остались лишние поля
		if(!algorithm.empty())
			// Выводим отказ разбора
			return false;
	}
	// Если открытый ключ не читается
	if(!info.next(asn1::tag_t::BIT_STRING, item))
		// Выводим отказ разбора
		return false;
	// Если открытый ключ извлечь не удалось
	if(asn1::bits(item, result.key, result.unused) != asn1::error_t::NONE)
		// Выводим отказ разбора
		return false;
	// Если после открытого ключа остались лишние поля
	if(!info.empty())
		// Выводим отказ разбора
		return false;
	// Выводим успешность разбора
	return true;
}

context::error_t nts::internal::Engine::checking(const extension::scheme_t scheme, const view_t & content, const view_t & signature) noexcept {
	/**
	 * Выполняем перехват ошибок работы с памятью: тело проверки подписи занимает память
	 * на всяком шаге, и всякий такой шаг вправе ответить нехваткой памяти
	 */
	// Раздел 7.4.3 RFC 4346: изданием 1.1 подпись судится без схемы
	if(this->_ancient)
		// Выводим итог проверки подписи изданием 1.1
		return this->engraved(content, signature);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если цепочка сертификатов собеседника пуста
		if(this->_peer.empty())
			// Выводим отказ отсутствия сертификата собеседника
			return context::error_t::CERTIFICATE;
		// Сведения об открытом ключе собеседника
		x509::key_t key;
		// Объект разбора сертификата собеседника
		x509::certificate_t leaf;
		// Если согласован сырой открытый ключ
		if(this->_certtype == extension::cert_t::RAW){
			// Если сведения об открытом ключе собеседника не разобрались
			if(!publicKey(view_t(this->_peer[0].data(), this->_peer[0].size()), key))
				// Выводим отказ разбора сырого ключа собеседника
				return context::error_t::CERTIFICATE;
		// Иначе ключ берётся из листа цепочки сертификатов
		} else {
			// Отказ разбора сертификата собеседника
			failure = translate(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())), context::error_t::CERTIFICATE);
			// Если сертификат собеседника разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора сертификата собеседника
				return failure;
			// Запоминаем сведения об открытом ключе листа
			key = leaf.key();
		}
		/**
		 * Раздел 4.4.2.2 RFC 8446: сертификат с ключом непригодного алгоритма отвергается
		 * прежде всякой сверки подписи
		 */
		// Признак пригодности ключа сертификата
		bool suitable = false;
		// Разбираем ключ сертификата собеседника
		failure = recognized(key, suitable);
		// Если памяти под разбор ключа не хватило
		if(failure != context::error_t::NONE)
			// Выводим отказ нехватки памяти
			return failure;
		// Если ключ записан алгоритмом, связи неведомым
		if(!suitable)
			// Выводим отказ непригодности ключа сертификата
			return context::error_t::CERTIFICATE;
		// Признак того, что объявленная схема подписи связью предложена
		bool offered = false;
		/**
		 * Выполняем перебор схем подписи, признаваемых связью
		 */
		for(size_t i = 0; (i < this->_signatures.size()) && !offered; i++)
			// Запоминаем совпадение объявленной схемы с признаваемой связью
			offered = (scheme == this->_signatures[i]);
		/**
		 * Раздел 4.2.3 RFC 8446: схемы PKCS #1 v1.5 подписи владения ключом в издании
		 * TLS 1.3 запрещены, даже если объявлены ради подписей сертификатов; изданию
		 * TLS 1.2 они дозволены, а схемы ГОСТ - нет
		 */
		if(this->_legacy ? !legible(scheme) : pkcs1(scheme))
			// Запоминаем непригодность схемы подписи изданию
			offered = false;
		/**
		 * Раздел 4.4.3 RFC 8446: схема подписи обязана быть из предложенных связью, и
		 * отвечать ключу сертификата. Подпись по кривой, которой в сертификате нет,
		 * проверялась бы не тем ключом, которым объявлена, а схема вне предложения -
		 * в том числе всякая схема PKCS #1 v1.5, в TLS 1.3 запрещённая, - отвергается
		 * тем же заслоном
		 */
		// Признак нехватки памяти при разборе ключа
		bool memory = false;
		// Признак соответствия схемы ключу сертификата
		const bool matched = (offered && matching(scheme, key, memory, this->_legacy));
		// Если памяти под разбор ключа не хватило
		if(memory)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если схема подписи связью не предложена либо ключу не отвечает
		if(!matched)
			// Выводим отказ несоответствия схемы подписи ключу сертификата
			return context::error_t::SCHEME;
		// Хеш схемы подписи
		const digest::hash_t algorithm = extension::hash(scheme);
		// Если схема подписи - схема ГОСТ
		if((algorithm == digest::hash_t::STREEBOG256) || (algorithm == digest::hash_t::STREEBOG512)){
			// Место, в которое помещается подпись в записи выработки
			uint8_t reversed[math::NUMBER_SIZE * 2];
			/**
			 * Длина подписи приходит с той стороны связи: раздел 4.4.3 RFC 8446 кладёт полю
			 * подписи два байта длины, то есть до 65535 байтов, тогда как место под подпись
			 * отведено на стеке размером в два числа. Разворот записи переносит подпись
			 * ЦЕЛИКОМ, и сверка длины обязана идти прежде него - иначе подпись, объявленная
			 * непомерной, вынесла бы разворот за отведённое место.
			 *
			 * Сверка эта стережёт лишь память; точная же длина, ключу собеседника отвечающая,
			 * сверяется дальше самой проверкой подписи
			 */
			if(signature.size > sizeof(reversed))
				// Выводим отказ непомерной длины подписи владения ключом
				return context::error_t::SIGNATURE;
			// Отказ разворота записи подписи
			failure = translate(message::reverse(signature, reversed), context::error_t::SIGNATURE);
			// Если запись подписи развернуть не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разворота записи подписи
				return failure;
			// Отказ проверки подписи владения ключом собеседника
			failure = translate(x509::check(key, content, view_t(reversed, signature.size)), context::error_t::SIGNATURE);
		/**
		 * Подпись PKCS #1 v1.5 издания TLS 1.2 сверяется тем же путём, что и подпись
		 * сертификата: по опознавателю алгоритма sha*WithRSAEncryption с кодировкой
		 * DigestInfo внутри
		 */
		} else if(pkcs1(scheme)) {
			// Опознаватель алгоритма подписи по схеме
			const string algorithm(identifier(scheme));
			// Отказ проверки подписи PKCS #1 v1.5
			failure = translate(x509::verify(content, signature, algorithm, key), context::error_t::SIGNATURE);
		/**
		 * Классическая подпись идёт в протокол своей записью: DER у ECDSA, число длиною в
		 * модуль у RSASSA-PSS с солью длиною в хеш, шестьдесят четыре байта у Ed25519
		 */
		} else failure = translate(x509::check(key, algorithm, content, signature), context::error_t::SIGNATURE);
		// Если подпись владения ключом не сошлась либо памяти не хватило
		if(failure != context::error_t::NONE)
			// Выводим отказ проверки подписи владения ключом
			return failure;
		// Выводим успешность проверки подписи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки принятой подписи владения ключом
 *
 * @param body тело принятого сообщения подписи владения ключом
 * @return     отказ проверки подписи владения ключом
 *
 */
context::error_t nts::internal::Engine::possession(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если цепочка сертификатов собеседника пуста
		if(this->_peer.empty())
			// Выводим отказ отсутствия сертификата собеседника
			return context::error_t::CERTIFICATE;
		// Разбираемое сообщение подписи владения ключом
		message::verify_t verify;
		// Отказ разбора сообщения подписи владения ключом
		failure = translate(message::parse(body, verify), context::error_t::MESSAGE);
		// Если сообщение подписи владения ключом разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора сообщения подписи владения ключом
			return failure;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Накопитель, в который складывается подписанное содержимое
		vector <uint8_t> content;
		// Отказ составления подписанного содержимого
		failure = translate(message::content(view_t(transcript, this->_transcript.size()), !this->_server, content), context::error_t::MESSAGE);
		// Если подписанное содержимое составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления подписанного содержимого
			return failure;
		// Выводим итог проверки подписи владения ключом собеседника
		return this->checking(verify.scheme, view_t(content.data(), content.size()), verify.signature);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки принятого завершения рукопожатия
 *
 * @param body тело принятого сообщения завершения рукопожатия
 * @return     отказ проверки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::confirm(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Длина хеша переписки рукопожатия
		const size_t width = this->_transcript.size();
		// Место, в которое помещается ожидаемое завершение рукопожатия
		uint8_t completion[schedule::SCHEDULE_WIDEST];
		// Отказ выработки завершения рукопожатия
		const context::error_t failure = translate(message::finished(this->_transcript.algorithm(), view_t(this->_keys->completion[index(side)], width), view_t(transcript, width), completion), context::error_t::COMPLETION);
		// Если ожидаемое завершение рукопожатия выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки завершения рукопожатия
			return failure;
		/**
		 * Сличение ведётся за постоянное время: по времени сличения восстанавливается
		 * ожидаемое завершение, а с ним и подделка рукопожатия
		 */
		if(!message::compare(body, view_t(completion, width)))
			// Выводим отказ схождения завершения рукопожатия
			return context::error_t::COMPLETION;
		// Выводим успешность проверки завершения рукопожатия
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора предложения заранее разделённых ключей клиента
 *
 * @param extensions перечень расширений принятого приветствия клиента
 * @param proposed   перечень наборов шифрования, предложенных клиентом
 * @param message    принятое приветствие клиента вместе с обвязкой
 * @return           отказ разбора предложения заранее разделённых ключей
 *
 */
context::error_t nts::internal::Engine::offered(const vector <hello::extension_t> & extensions, const vector <uint16_t> & proposed, const view_t & message) noexcept {
	/**
	 * Раздел 4.1.2 RFC 8446: второе приветствие за просьбой о повторе вправе снять либо
	 * сменить pre_shared_key - состояние билета, выставленное первым приветствием,
	 * сбрасывается всякий раз, иначе сервер возобновлял бы связь билетом, которого во
	 * втором предложении нет, а ступень секретов оставалась бы заведённой его ключом
	 */
	this->_shared = false;
	// Выполняем сброс места выбранного ключа в предложении
	this->_chosen = 0;
	// Выполняем сброс предела упреждающих данных билета
	this->_granted = 0;
	// Выполняем сброс признака отвергнутого возрастом упреждения
	this->_misaged = false;
	// Выполняем сброс набора шифрования билета
	this->_ticket = protect::suite_t::NONE;
	// Выполняем сброс прикладного протокола выдавшей билет связи
	this->_previous.clear();
	// Выполняем сброс своих прикладных настроек выдавшей билет связи
	this->_bequest.clear();
	// Выполняем сброс настроек собеседника выдавшей билет связи
	this->_heritage.clear();
	// Выполняем сброс значений расписания ключей
	this->_secrets.clear();
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Разыскиваем расширение заранее разделённых ключей клиента
		const hello::extension_t * offer = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::SECRET));
		// Если заранее разделённых ключей клиент не предлагает
		if(offer == nullptr)
			// Выводим успешность разбора предложения заранее разделённых ключей
			return context::error_t::NONE;
		// Разыскиваем расширение способов обмена заранее разделённым ключом
		const hello::extension_t * item = hello::extension(extensions, static_cast <uint16_t> (extension::type_t::MODES));
		// Раздел 4.2.9 RFC 8446: pre_shared_key без psk_key_exchange_modes - обрыв, и без запаса билетов тоже
		if(item == nullptr)
			// Выводим отказ отсутствия обязательного расширения
			return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
		// Если признавать заранее разделённые ключи нечем
		if(this->_store.empty())
			// Выводим успешность разбора предложения заранее разделённых ключей
			return context::error_t::NONE;
		// Способы обмена, объявленные клиентом
		vector <extension::regime_t> modes;
		// Отказ разбора расширения приветствия
		failure = translate(extension::modes(item->data, modes), context::error_t::MESSAGE);
		// Если способы обмена разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		// Признак того, что обмен ключом кривой вместе с билетом клиентом объявлен
		bool suitable = false;
		/**
		 * Выполняем перебор способов обмена, объявленных клиентом
		 */
		for(size_t i = 0; (i < modes.size()) && !suitable; i++)
			// Запоминаем объявление обмена ключом кривой вместе с билетом
			suitable = (modes[i] == extension::regime_t::SHARED);
		/**
		 * Обмен одним лишь билетом связью не ведётся: без ключа кривой хищение билета
		 * выдаёт всё, что этим билетом когда-либо защищено
		 */
		if(!suitable)
			// Выводим успешность разбора предложения заранее разделённых ключей
			return context::error_t::NONE;
		// Перечень опознавателей заранее разделённых ключей клиента
		vector <extension::identity_t> identities;
		// Перечень привязок заранее разделённых ключей клиента
		vector <view_t> binders;
		// Длина усечения приветствия от начала тела расширения
		size_t truncation = 0;
		// Отказ разбора расширения приветствия
		failure = translate(extension::identities(offer->data, identities, binders, truncation), context::error_t::MESSAGE);
		// Если предложение заранее разделённых ключей разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		// Место найденного билета в перечне признаваемых
		size_t found = this->_store.size();
		// Место предъявленного ключа в предложении клиента
		size_t chosen = 0;
		/**
		 * Выполняем перебор опознавателей ключей, предложенных клиентом
		 */
		for(size_t i = 0; (i < identities.size()) && (found == this->_store.size()); i++){
			/**
			 * Выполняем перебор билетов, признаваемых сервером
			 */
			for(size_t j = 0; j < this->_store.size(); j++){
				// Если длина опознавателя с длиной признаваемого билета не совпала
				if(identities[i].identity.size != this->_store[j].identity.size())
					// Переходим к следующему признаваемому билету
					continue;
				// Если опознаватель с признаваемым билетом не совпал
				if(::memcmp(identities[i].identity.data, this->_store[j].identity.data(), identities[i].identity.size) != 0)
					// Переходим к следующему признаваемому билету
					continue;
				/**
				 * Билет с вышедшим сроком в дело не идёт: раздел 4.6.1 RFC 8446 велит
				 * серверу и клиенту держать его не дольше объявленного срока, и связь
				 * с таким билетом идёт полным рукопожатием
				 */
				if(expired(this->_store[j], this->_moment))
					// Переходим к следующему признаваемому билету
					continue;
				// Раздел 5.6 RFC 5077: удостоверение старше дозволенного - билет в дело не идёт
				if(outdated(this->_store[j].authenticated, this->_moment))
					// Переходим к следующему признаваемому билету
					continue;
				// Если опознаватель совпал с признаваемым билетом
				{
					// Запоминаем место найденного билета в перечне признаваемых
					found = j;
					// Запоминаем миг первичного удостоверения из билета
					this->_authenticated = this->_store[j].authenticated;
					// Запоминаем место предъявленного ключа в предложении клиента
					chosen = i;
					// Прекращаем перебор признаваемых билетов
					break;
				}
			}
		}
		// Если ни один из предложенных ключей сервером не признан
		if(found == this->_store.size())
			// Выводим успешность разбора предложения: связь идёт полным рукопожатием
			return context::error_t::NONE;
		/**
		 * Хеш набора шифрования признанного билета: билет без ведомого набора судится
		 * хешем набора связи - у ветви ГОСТ он один на все наборы
		 */
		const digest::hash_t algorithm = ((protect::hash(this->_store[found].suite) != digest::hash_t::NONE) ? protect::hash(this->_store[found].suite) : protect::hash(this->_suite));
		/**
		 * Раздел 4.2.11 RFC 8446: ключ билета пригоден лишь набору с тем же хешем, что
		 * и у набора билета. Набор связи выбран прежде по предпочтению сервера, и при
		 * расхождении хешей набор выбирается заново среди предложенных клиентом уже с
		 * хешем билета; за просьбой о повторе набор менять нельзя, и билет пропускается
		 */
		if(protect::hash(this->_suite) != algorithm){
			// Если повтор приветствия клиента уже был
			if(this->_retried)
				// Выводим успешность разбора предложения: связь идёт полным рукопожатием
				return context::error_t::NONE;
			// Набор шифрования, выбираемый заново под хеш билета
			protect::suite_t suite = protect::suite_t::NONE;
			/**
			 * Выполняем перебор наборов шифрования, предлагаемых связью
			 */
			for(size_t i = 0; (i < this->_suites.size()) && (suite == protect::suite_t::NONE); i++){
				// Если набор годен лишь изданию 1.2: рукопожатию 1.3 с билетом он не подходит, как и при первичном выборе
				if(protect::legacy(this->_suites[i]))
					// Переходим к следующему набору шифрования
					continue;
				// Если хеш набора с хешем билета не сходится
				if(protect::hash(this->_suites[i]) != algorithm)
					// Переходим к следующему набору шифрования
					continue;
				/**
				 * Выполняем перебор наборов шифрования, предлагаемых клиентом
				 */
				for(size_t j = 0; (j < proposed.size()) && (suite == protect::suite_t::NONE); j++){
					// Если набор шифрования предложен обеими сторонами
					if(proposed[j] == static_cast <uint16_t> (this->_suites[i]))
						// Запоминаем набор шифрования под хеш билета
						suite = this->_suites[i];
				}
			}
			// Если набора под хеш билета у сторон не нашлось
			if(suite == protect::suite_t::NONE)
				// Выводим успешность разбора предложения: связь идёт полным рукопожатием
				return context::error_t::NONE;
			// Запоминаем выбранный заново набор шифрования связи
			this->_suite = suite;
		}
		// Запоминаем предел упреждающих данных, объявленный признанным билетом
		this->_granted = this->_store[found].advance;
		/**
		 * Объявленный возраст билета сличается с наблюдаемым: раздел 4.2.10 RFC 8446 велит
		 * отвергать упреждающие данные при расхождении, а самому возобновлению связи
		 * расхождение это не мешает - для него довольно совпадения привязки
		 */
		if((this->_moment != 0) && (this->_store[found].moment != 0)){
			// Получаем объявленный клиентом возраст билета в миллисекундах
			const int64_t declared = static_cast <int64_t> (static_cast <uint32_t> (identities[chosen].age - this->_store[found].age));
			// Получаем наблюдаемый сервером возраст билета в миллисекундах
			const int64_t observed = ((this->_moment - this->_store[found].moment) * 1000);
			// Если объявленный возраст с наблюдаемым разошёлся шире окна
			if(((declared - observed) > WINDOW) || ((observed - declared) > WINDOW))
				// Запоминаем, что упреждение этой связи отвергнуто расхождением возраста
				this->_misaged = true;
		}
		// Если начальную ступень расписания ключей завести не удалось хешем набора билета
		if(this->_secrets.start(algorithm, view_t(this->_store[found].secret.data(), this->_store[found].secret.size())) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
		/**
		 * Длина усечения отсчитывается от начала сообщения: тело расширения лежит внутри
		 * него, и место его начала к длине усечения и прибавляется
		 */
		const size_t offset = (static_cast <size_t> (offer->data.data - message.data) + truncation);
		/**
		 * Заслон этот оборонительный: длина усечения берётся смещением внутри тела
		 * расширения, а тело лежит просмотром внутри самого приветствия - сумма их за
		 * приветствие выйти не может, и через связь заслон недостижим. Стоит он на
		 * случай, если тело расширения перестанет быть просмотром внутрь приветствия
		 */
		if(offset > message.size)
			// Выводим отказ разбора расширения приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Место, в которое помещается хеш усечённого приветствия клиента
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш усечённого приветствия получить не удалось хешем набора билета
		if(this->_transcript.digest(algorithm, view_t(message.data, offset), transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Место, в которое помещается ожидаемая привязка билета
		uint8_t expected[schedule::SCHEDULE_WIDEST];
		// Если ожидаемую привязку билета выработать не удалось
		if(this->_secrets.binder(view_t(transcript, digest::length(algorithm)), expected) != session::error_t::NONE)
			// Выводим отказ выработки привязки билета
			return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
		/**
		 * Привязка сличается за постоянное время: по времени сличения восстанавливается
		 * ожидаемая привязка, а с нею и подделка владения билетом
		 */
		if(!message::compare(binders[chosen], view_t(expected, digest::length(algorithm)))){
			// Выполняем сброс значений расписания ключей связи
			this->_secrets.clear();
			// Выводим отказ схождения привязки предъявленного билета
			return this->abort(context::error_t::SIGNATURE, alert::description_t::DECRYPT);
		}
		// Запоминаем набор шифрования признанного билета
		this->_ticket = this->_store[found].suite;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Запоминаем прикладной протокол связи, выдавшей признанный билет
			this->_previous = this->_store[found].protocol;
			// Запоминаем признак согласования прикладных настроек выдавшей билет связи
			this->_bequeathed = this->_store[found].settled;
			// Запоминаем свои прикладные настройки выдавшей билет связи
			this->_bequest = this->_store[found].settings;
			// Запоминаем прикладные настройки собеседника выдавшей билет связи
			this->_heritage = this->_store[found].obtained;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
		// Запоминаем место выбранного ключа в предложении клиента
		this->_chosen = static_cast <uint16_t> (chosen);
		// Запоминаем возобновление связи заранее разделённым ключом
		this->_shared = true;
		// Выводим успешность разбора предложения заранее разделённых ключей
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора принятого приветствия клиента
 *
 * @param body    тело принятого приветствия клиента
 * @param message принятое приветствие клиента вместе с обвязкой
 * @return        отказ разбора приветствия клиента
 *
 */
context::error_t nts::internal::Engine::incoming(const view_t & body, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Разбираемое приветствие клиента
		hello::client_t greeting;
		// Отказ разбора приветствия клиента: поверх дейтаграмм с полем метки возврата состояния
		failure = translate(hello::parse(body, greeting, (this->_transport == context::transport_t::DATAGRAMS)), context::error_t::MESSAGE);
		// Если приветствие клиента разобрать не удалось: до подтверждения адреса - молчаливый отброс
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора приветствия клиента
			return this->dismissing(failure, blame(failure, alert::description_t::DECODE));
		// Запоминаем принятое приветствие вместе с обвязкой: с него потребитель снимает отпечаток (внешнее, как на проводе)
		if(!this->_unshrouding)
			// Запоминаем приветствие
			this->_salutation.assign(message.data, message.data + message.size);
		// Если сервер служит ECH и разбирается внешнее приветствие
		if(!this->_unshrouding && !this->_serving.empty()){
			// Признак принятия ECH
			bool accepted = false;
			// Тело восстановленного внутреннего приветствия
			vector <uint8_t> inner;
			// Отказ раскрытия зашифрованного приветствия
			failure = this->unshrouding(greeting, body, accepted, inner);
			// Если зашифрованное приветствие сложено не по правилам
			if(failure != context::error_t::NONE)
				// Выводим отказ раскрытия
				return this->abort(failure, blame(failure, alert::description_t::PARAMETER));
			// Если ECH принят: рукопожатие идёт по внутреннему приветствию
			if(accepted){
				// Объект составителя сообщения рукопожатия
				handshake::writer_t writer;
				// Отказ составления внутреннего приветствия с обвязкой
				failure = translate(writer.push(handshake::type_t::CLIENT, view_t(inner.data(), inner.size())), context::error_t::MESSAGE);
				// Если внутреннее приветствие составить не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления
					return this->abort(failure, alert::description_t::INTERNAL);
				// Отмечаем разбор внутреннего приветствия
				this->_unshrouding = true;
				// Сообщение внутреннего приветствия с обвязкой
				const view_t whole = writer.data();
				// Разбираем внутреннее приветствие как принятое: тело - срез того же сообщения, по нему считаются смещения привязок билета
				const context::error_t outcome = this->incoming(view_t(whole.data + handshake::HANDSHAKE_HEADER, whole.size - handshake::HANDSHAKE_HEADER), whole);
				// Снимаем отметку разбора
				this->_unshrouding = false;
				// Выводим итог разбора внутреннего приветствия
				return outcome;
			}
			/**
			 * ECH предложен и отклонён: клиент мог слать упреждающие данные под внутреннее
			 * приветствие, которое здесь не прочесть, - их записи пропускаются как отвергнутые
			 * (раздел 4.2.10 RFC 8446), пока не придёт завершение клиента. Лишь при отвергнутом
			 * ECH и early_data во внешнем приветствии (раздел 7.1 RFC 9849): у клиента без ECH,
			 * с GREASE либо без упреждения негодная запись рвёт связь bad_record_mac (раздел 5.2)
			 */
			if(this->_echrejected && (hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::EARLY)) != nullptr))
				// Устанавливаем объём пропускаемых записей упреждения
				this->_skipped = (static_cast <size_t> ((this->_granted > this->_limit) ? this->_granted : this->_limit) * 2 + 4096);
		}
		// Признак того, что среди способов сжатия объявлен нулевой
		bool uncompressed = false;
		/**
		 * Выполняем перебор способов сжатия, объявленных клиентом
		 */
		for(size_t i = 0; (i < greeting.methods.size()) && !uncompressed; i++)
			// Запоминаем объявление нулевого способа сжатия
			uncompressed = (greeting.methods[i] == 0x00);
		/**
		 * Раздел 6.2.2 RFC 5246: сжатие записей связью не ведётся ни в одном издании, и без
		 * нулевого способа среди объявленных сторонам не сойтись; издание 1.3 сверх того
		 * требует нулевой способ единственным (раздел 4.1.2 RFC 8446), и сверка эта идёт
		 * ниже, по согласовании издания
		 */
		if(!uncompressed)
			// Выводим отказ негодного перечня способов сжатия
			return this->dismissing(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		/**
		 * Заранее разделённые ключи идут последним расширением приветствия: раздел 4.2.11
		 * RFC 8446 велит класть их именно туда, ибо привязка их считается по переписке,
		 * усечённой ровно до начала этого расширения
		 */
		/**
		 * Слагаемое (!greeting.extensions.empty()) истинно всегда: приветствие без единого
		 * расширения не объявляет и перечня изданий протокола, а без него оно отвергается
		 * много раньше. Слагаемое оставлено ради самостоятельности выражения: розыск по
		 * пустому перечню и обращение к его последнему расширению стоят рядом
		 */
		if(!greeting.extensions.empty() && (hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SECRET)) != nullptr) && (greeting.extensions.back().type != static_cast <uint16_t> (extension::type_t::SECRET)))
			// Выводим отказ места расширения заранее разделённых ключей
			return this->dismissing(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Разыскиваем расширение метки возврата состояния сервера
		const hello::extension_t * returned = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
		// Если метка возврата состояния приветствием повторена
		if(returned != nullptr){
			/**
			 * Метку сервер судит сам: раздел 4.2.2 RFC 8446 не кладёт на её содержимое
			 * никаких правил, ибо складывал её тот же сервер, что её и читает
			 */
			// Тело принятой метки возврата состояния сервера
			view_t label;
			// Отказ разбора расширения приветствия
			failure = translate(extension::cookie(returned->data, label), context::error_t::MESSAGE);
			// Если метку возврата состояния разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->dismissing(failure, blame(failure, alert::description_t::DECODE));
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Переносим принятую метку возврата состояния сервера
				this->_label.assign(label.data, label.data + label.size);
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
		}
		/**
		 * Раздел 5.1 RFC 9147: повторное приветствие поверх дейтаграмм обязано нести метку,
		 * сложенную сервером для этого собеседника; приветствие без неё либо с чужою
		 * отбрасывается молча - извещение неподтверждённому адресу слать нельзя
		 */
		if((this->_transport == context::transport_t::DATAGRAMS) && this->_retried && ((returned == nullptr) || !this->_flight.verify(view_t(this->_label.data(), this->_label.size())))){
			// Выполняем сброс отвергнутой метки
			this->_label.clear();
			// Считаем отброшенное приветствие
			this->_flight.discard(datagram::reason_t::COOKIE);
			// Отброшенное приветствие своего номера не занимает: настоящее придёт тем же номером
			this->_flight.retract();
			// Выводим успешность: приветствие отброшено
			return context::error_t::NONE;
		}
		// Раздел 5.1 RFC 9147: метка сошлась - адрес собеседника подтверждён
		if((this->_transport == context::transport_t::DATAGRAMS) && this->_retried){
			// Запоминаем подтверждение адреса
			this->_confirmed = true;
			// Отмечаем подтверждённость адреса переносу: запись приветствия ложится в окно
			this->_flight.verified(true);
		}
		// Разыскиваем расширение перечня изданий протокола
		const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		/**
		 * Издание 1.2 ведётся переносом записями (TLS 1.2) и дейтаграммами (DTLS 1.2 по
		 * RFC 6347); под QUIC (RFC 9001) связь знает одно лишь издание 1.3
		 */
		const bool ancient = ((this->_transport != context::transport_t::LEVELS) && (this->_lowest <= LEGACY) && (this->_highest >= LEGACY) && carries(this->_suites, true));
		// Признак того, что издание TLS 1.3 связью дозволено: без наборов издания оно не выбирается
		const bool modern = ((this->_transport == context::transport_t::LEVELS) || ((this->_highest >= MODERN) && carries(this->_suites, false)));
		/**
		 * Раздел 4.1 RFC 6347: издания DTLS считаются в обратную сторону - заголовок
		 * приветствия объявляет издание не ниже 1.2, когда несёт 0xFEFD либо младше, но
		 * непременно издание DTLS (старший байт 0xFE): 0xFEFF (DTLS 1.0), 0x0303 и всякое
		 * чужое издание заголовка ниже 1.2 не опускают, а обрывают связь protocol_version
		 */
		// Признак того, что издание DTLS 1.0 связью дозволено: лишь дейтаграммами и лишь при наборах CBC-SHA1
		const bool primeval = ((this->_transport == context::transport_t::DATAGRAMS) && (this->_lowest <= ANCIENT) && archaical(this->_suites));
		// Признак того, что заголовок приветствия несёт издание DTLS 1.0 (RFC 4347)
		const bool oldest = ((this->_transport == context::transport_t::DATAGRAMS) && (greeting.version == this->eldest()));
		// Признак того, что издание заголовка дозволено связи
		const bool declared = ((this->_transport == context::transport_t::DATAGRAMS) ? (((greeting.version >> 8) == 0xFE) && ((greeting.version <= datagram::DATAGRAM_LEGACY) || (primeval && oldest))) : (greeting.version >= LEGACY));
		// Поверх дейтаграмм заголовок приветствия судится всегда, и с перечнем изданий тоже (раздел 5.3 RFC 9147)
		if((this->_transport == context::transport_t::DATAGRAMS) && !declared)
			// Выводим отказ несовпадения издания протокола
			return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		// Издание протокола, выбранное сервером
		uint16_t chosen = 0;
		// Издание TLS 1.3 приветствием без перечня изданий не предлагается
		this->_proposed = false;
		/**
		 * Приложение D.2 RFC 8446: при отсутствующем перечне изданий сервер обязан вести
		 * переговоры по наименьшему из объявленного приветствием и TLS 1.2, а не
		 * поддерживая ни того ни другого - обрывать связь извещением protocol_version.
		 *
		 * Извещение missing_extension сюда НЕ относится, сколь бы ни было оно похоже:
		 * раздел 9.2 держит его для приветствия, ведущего переговоры по ЭТОМУ стандарту, а
		 * таковым он числит лишь приветствие, несущее перечень изданий с 0x0304 в теле.
		 * Приветствие без перечня переговоров по этому стандарту не ведёт вовсе, и требовать
		 * с него обязательных расширений не с чего
		 */
		if(extension == nullptr){
			// Если издание 1.2 дозволено связи и объявлено заголовком приветствия
			if(ancient && declared && !oldest)
				// Выбираем издание TLS 1.2 либо DTLS 1.2
				chosen = this->elder();
			// Если заголовок несёт издание DTLS 1.0 и оно дозволено связи
			else if(primeval && oldest)
				// Выбираем издание DTLS 1.0
				chosen = this->eldest();
			// Если общего издания протокола у сторон нет
			else return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		// Если перечень изданий протокола приветствием объявлен
		} else {
			// Перечень изданий протокола, предлагаемых клиентом
			vector <uint16_t> versions;
			// Отказ разбора расширения приветствия
			failure = translate(extension::versions(extension->data, versions), context::error_t::MESSAGE);
			// Если перечень изданий протокола разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->dismissing(failure, blame(failure, alert::description_t::DECODE));
			/**
			 * Раздел 4.2.1 RFC 8446: сервер выбирает высшее из изданий, предложенных клиентом
			 * и дозволенных себе; порядок перечня клиента предпочтением не считается
			 */
			// Признак того, что клиент предложил издание DTLS 1.0
			bool primal = false;
			/**
			 * Выполняем перебор изданий, предложенных клиентом
			 */
			for(size_t i = 0; i < versions.size(); i++){
				// Запоминаем предложение клиентом издания DTLS 1.0
				primal = (primal || (versions[i] == this->eldest()));
				// Запоминаем предложение клиентом издания 1.3
				this->_proposed = (this->_proposed || (versions[i] == this->edition()));
				// Если клиент предложил издание TLS 1.3 либо DTLS 1.3 и оно дозволено связи
				if(modern && (versions[i] == this->edition()))
					// Выбираем издание 1.3
					chosen = this->edition();
				// Если клиент предложил издание TLS 1.2 либо DTLS 1.2, оно дозволено связи, а издание 1.3 ещё не выбрано
				else if(ancient && (versions[i] == this->elder()) && (chosen == 0))
					// Выбираем издание TLS 1.2 либо DTLS 1.2
					chosen = this->elder();
			}
			// Если ни 1.3, ни 1.2 не выбраны, а издание DTLS 1.0 предложено и дозволено
			if((chosen == 0) && primeval && primal)
				// Выбираем издание DTLS 1.0: раздел 4.2.1 RFC 8446 велит брать высшее из общих, и оно последнее
				chosen = this->eldest();
			// Если общего издания протокола у сторон не нашлось
			if(chosen == 0)
				// Выводим отказ несовпадения издания протокола
				return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		}
		/**
		 * Раздел 4.1.4 RFC 8446: просьба о повторе - сообщение издания 1.3, и второе
		 * приветствие обязано вести переговоры тем же изданием; приветствие, предлагающее
		 * после просьбы лишь 1.2 (либо вовсе без перечня изданий), - illegal_parameter.
		 * Иначе сервер уходил бы в рукопожатие 1.2 поверх состояния, настроенного под 1.3
		 */
		if(this->_retried && (chosen != this->edition()))
			// Выводим отказ смены издания после просьбы о повторе
			return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
		// Запоминаем, ведётся ли связь изданием DTLS 1.0
		this->_ancient = (chosen == this->eldest());
		// Если сторонами выбрано издание TLS 1.2, DTLS 1.2 либо DTLS 1.0
		if((chosen == this->elder()) || (chosen == this->eldest())){
			// Если связь ведётся поверх дейтаграмм
			if(this->_transport == context::transport_t::DATAGRAMS){
				/**
				 * Раздел 4.2.1 RFC 6347: первое приветствие без метки отвечается просьбой о
				 * подтверждении адреса, и сервер состояния по нему не тратит
				 */
				if(greeting.cookie.empty())
					// Выводим итог отправки просьбы о подтверждении адреса
					return this->querying(greeting);
				// Приветствие без метки: по нему метка складывалась и по нему же сверяется
				hello::client_t bare = greeting;
				// Снимаем метку с приветствия
				bare.cookie.clear();
				// Накопитель приветствия без метки
				vector <uint8_t> rebuilt;
				// Отказ составления приветствия без метки
				failure = translate(hello::build(bare, rebuilt, true), context::error_t::MESSAGE);
				// Если приветствие без метки составить не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления приветствия
					return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
				/**
				 * Раздел 4.2.1 RFC 6347: приветствие с чужой либо порченой меткой отбрасывается
				 * молча - извещение неподтверждённому адресу слать нельзя (намеренное решение,
				 * то же, что у DTLS 1.3)
				 */
				if(!this->_flight.verify(view_t(greeting.cookie.data(), greeting.cookie.size()), view_t(rebuilt.data(), rebuilt.size()))){
					// Считаем отброшенное приветствие
					this->_flight.discard(datagram::reason_t::COOKIE);
					// Выводим успешность: приветствие отброшено
					return context::error_t::NONE;
				}
				// Метка принята: сервер держит состояние, приветствие своё идёт номером один
				this->_flight.stateless(false);
				// Раздел 4.2.1 RFC 6347: адрес собеседника подтверждён меткой
				this->_confirmed = true;
				// Отмечаем подтверждённость адреса переносу: запись приветствия ложится в окно
				this->_flight.verified(true);
			}
			// Выводим итог ответа на приветствие клиента изданием TLS 1.2
			return this->welcome(greeting, message);
		}
		// Раздел 5.3 RFC 9147: у DTLS 1.3 поле метки приветствия обязано быть пустым
		if((this->_transport == context::transport_t::DATAGRAMS) && !greeting.cookie.empty())
			// Выводим отказ негодного поля метки приветствия
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		/**
		 * Способ сжатия у издания 1.3 остался один и тот же - никакого: раздел 4.1.2
		 * RFC 8446 велит оборвать связь, если клиент объявил иное
		 */
		if((greeting.methods.size() != 1) || (greeting.methods[0] != 0x00))
			// Выводим отказ негодного перечня способов сжатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Запоминаем согласованное издание протокола кодом TLS: единая шкала изданий на любом переносе
		this->_version = ((chosen == this->edition()) ? MODERN : LEGACY);
		// Признак того, что общий набор шифрования у сторон нашёлся
		bool suitable = false;
		/**
		 * Раздел 4.1.4 RFC 8446: набор шифрования приветствия сервера обязан совпадать с
		 * набором просьбы о повторе - на втором приветствии набор не перевыбирается, а
		 * лишь сверяется с предложением клиента; иначе перевыбор по порядку сервера
		 * расходился бы с хешем переписки и с самой просьбой
		 */
		if(this->_retried){
			/**
			 * Выполняем перебор наборов шифрования, предлагаемых клиентом
			 */
			for(size_t j = 0; (j < greeting.suites.size()) && !suitable; j++)
				// Если набор просьбы предложен и вторым приветствием
				suitable = (greeting.suites[j] == static_cast <uint16_t> (this->_suite));
			// Если набор просьбы снят вторым приветствием
			if(!suitable)
				// Выводим отказ негодных параметров
				return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		}
		/**
		 * Выполняем перебор наборов шифрования порядком стороны, чьё предпочтение ведёт
		 * выбор: раздел 4.1.1 RFC 8446 велит выбирать серверу, а порядок задаёт ручка
		 * preference - свой (умолчание) либо порядок клиента (намеренное решение 19)
		 */
		for(size_t i = 0; (i < (this->_own ? this->_suites.size() : greeting.suites.size())) && !suitable; i++){
			/**
			 * Выполняем перебор наборов шифрования встречной стороны
			 */
			for(size_t j = 0; (j < (this->_own ? greeting.suites.size() : this->_suites.size())) && !suitable; j++){
				// Свой набор шифрования по порядку перебора
				const protect::suite_t mine = (this->_own ? this->_suites[i] : this->_suites[j]);
				// Набор шифрования клиента по порядку перебора
				const uint16_t theirs = (this->_own ? greeting.suites[j] : greeting.suites[i]);
				// Наборы издания TLS 1.2 изданию 1.3 не годны: у них иная защита записей
				if(protect::legacy(mine))
					// Переходим к следующему набору шифрования
					continue;
				// Если набор шифрования предложен обеими сторонами
				if(theirs == static_cast <uint16_t> (mine)){
					// Запоминаем выбранный набор шифрования связи
					this->_suite = mine;
					// Запоминаем, что общий набор шифрования нашёлся
					suitable = true;
				}
			}
		}
		// Если общего набора шифрования у сторон не нашлось
		if(!suitable)
			// Выводим отказ отсутствия общего набора шифрования
			return this->abort(context::error_t::SUITE, alert::description_t::HANDSHAKE);
		/**
		 * Раздел 4.1.2 RFC 8446: второе приветствие за просьбой о повторе судится своим
		 * содержимым - всё, что сервер вывел из первого (имя узла, протокол приложения,
		 * настройки ALPS, схемы подписи, сердцебиение), сбрасывается и выводится заново;
		 * иначе сервер отвечал бы расширениями, которых второе приветствие не предлагало
		 */
		if(this->_retried){
			// Выполняем сброс имени узла, запрошенного первым приветствием
			this->_name.clear();
			// Выполняем сброс протокола приложения, выбранного по первому приветствию
			this->_protocol.clear();
			// Выполняем сброс признака согласования настроек ALPS
			this->_settled = false;
			// Выполняем сброс настроек ALPS, принятых по первому приветствию
			this->_applied.clear();
			// Выполняем сброс схем подписи первого приветствия
			this->_schemes.clear();
			// Выполняем сброс признаков сердцебиения первого приветствия
			this->_heartbeating = false;
			// Выполняем сброс дозволения запросов сердцебиения первого приветствия
			this->_permitted = false;
			// Выполняем сброс пределов длины записей первого приветствия (RFC 8449 §4, RFC 6066 §4)
			this->_outgoing = record::RECORD_PLAINTEXT;
			// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
			this->_flight.limit(this->_outgoing);
			// Выполняем сброс своего предела приёма
			this->_incoming = record::RECORD_PLAINTEXT;
			// Выполняем сброс признака действующего расширения предела
			this->_sizing = 0;
			// Выполняем сброс присланного первым приветствием record_size_limit
			this->_bounding = 0;
			// Выполняем сброс присланного первым приветствием max_fragment_length
			this->_fragmenting = 0;
		}
		// Разыскиваем расширение имени запрашиваемого узла
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::NAME));
		// Если имя запрашиваемого узла приветствием объявлено
		if(extension != nullptr){
			// Имя узла, запрошенное клиентом у сервера
			view_t host;
			// Отказ разбора расширения приветствия
			failure = translate(extension::name(extension->data, host), context::error_t::MESSAGE);
			// Если имя запрашиваемого узла разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				/**
				 * Имя узла сервером лишь принимается: раздел 3 RFC 6066 велит выбирать по нему
				 * подлинность своей стороны, а выбор этот принадлежит потребителю, который
				 * подлинность и устанавливает
				 */
				this->_name.assign(reinterpret_cast <const char *> (host.data), host.size);
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
		}
		// Разбираем предложенные клиентом пределы длины записи (RFC 8449, раздел 4 RFC 6066)
		failure = this->sizing(greeting);
		// Если пределы не приняты
		if(failure != context::error_t::NONE)
			// Выводим ошибку
			return failure;
		// Если клиент предложил heartbeat (RFC 6520), его записи вида 24 будут роняться молча
		{
			// Расширение heartbeat приветствия клиента
			const hello::extension_t * beat = hello::extension(greeting.extensions, HEARTBEAT_EXTENSION);
			// Раздел 2 RFC 6520: режим - один октет со значением 1 либо 2, иное обрывает связь illegal_parameter
			if((beat != nullptr) && ((beat->data.size != 1) || ((beat->data.data[0] != 1) && (beat->data.data[0] != 2))))
				// Выводим отказ негодных параметров
				return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			// Запоминаем предложение
			this->_heartbeating = (beat != nullptr);
			// Раздел 2 RFC 6520: запросы клиенту шлются лишь при peer_allowed_to_send (1)
			this->_permitted = ((beat != nullptr) && (beat->data.data[0] == 1));
		}
		// Если прикладные протоколы сервером признаются
		if(!this->_protocols.empty()){
			// Разыскиваем расширение перечня прикладных протоколов
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
			// Если прикладные протоколы приветствием объявлены
			if(extension != nullptr){
				// Перечень прикладных протоколов, предложенных клиентом
				vector <string> offer;
				// Отказ разбора расширения приветствия
				failure = translate(extension::protocols(extension->data, offer), context::error_t::MESSAGE);
				// Если перечень прикладных протоколов разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					/**
					 * Выбор идёт порядком сервера, а не клиента: раздел 3.2 RFC 7301 велит
					 * выбирать протокол серверу, и порядок его перечня - это и есть его
					 * предпочтение
					 */
					for(size_t i = 0; (i < this->_protocols.size()) && this->_protocol.empty(); i++){
						/**
						 * Выполняем перебор прикладных протоколов, предложенных клиентом
						 */
						for(size_t j = 0; (j < offer.size()) && this->_protocol.empty(); j++){
							// Если прикладной протокол предложен обеими сторонами
							if(offer[j].compare(this->_protocols[i]) == 0)
								// Запоминаем выбранный сторонами прикладной протокол
								this->_protocol = this->_protocols[i];
						}
					}
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
				// Если общего прикладного протокола у сторон не нашлось
				if(this->_protocol.empty())
					// Выводим отказ отсутствия общего прикладного протокола
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
			}
		}
		// Если профили защиты RTP сервером признаются
		if(!this->_srtps.empty()){
			// Разыскиваем расширение перечня профилей защиты RTP
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROFILES));
			// Если профили защиты RTP приветствием объявлены
			if(extension != nullptr){
				// Перечень профилей защиты RTP, предложенных клиентом
				vector <uint16_t> offer;
				// Отказ разбора расширения приветствия
				failure = translate(extension::profiles(extension->data, offer), context::error_t::MESSAGE);
				// Если перечень профилей защиты RTP разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор профилей защиты RTP сервера: выбор идёт его порядком,
				 * как у прикладных протоколов (раздел 3.2 RFC 7301)
				 */
				for(size_t i = 0; (i < this->_srtps.size()) && (this->_srtp == 0); i++){
					/**
					 * Выполняем перебор профилей защиты RTP, предложенных клиентом
					 */
					for(size_t j = 0; (j < offer.size()) && (this->_srtp == 0); j++){
						// Если профиль защиты RTP предложен обеими сторонами
						if(offer[j] == this->_srtps[i])
							// Запоминаем выбранный сторонами профиль защиты RTP
							this->_srtp = this->_srtps[i];
					}
				}
				// Если общего профиля защиты RTP у сторон не нашлось
				if(this->_srtp == 0)
					// Выводим отказ отсутствия общего профиля защиты RTP
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
			}
		}
		// Свои прикладные настройки выбранного протокола
		view_t applied;
		/**
		 * Черновик draft-vvv-tls-alps: настройки согласуются лишь изданием 1.3, лишь для
		 * выбранного протокола и лишь когда клиент объявил его в перечне своей точки кода;
		 * разошедшиеся точки кода сторон оставляют связь без настроек молча
		 */
		if((this->_version == MODERN) && !this->_protocol.empty() && this->pick(this->_protocol, applied)){
			// Разыскиваем расширение прикладных настроек своей точкой кода
			extension = hello::extension(greeting.extensions, this->_codepoint);
			// Если перечень протоколов с настройками клиентом объявлен
			if(extension != nullptr){
				// Перечень протоколов с настройками, предложенных клиентом
				vector <string> declared;
				// Отказ разбора расширения приветствия
				failure = translate(extension::protocols(extension->data, declared), context::error_t::MESSAGE);
				// Если перечень протоколов с настройками разобрать не удалось (пустой перечень разборщик отвергает сам)
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор протоколов с настройками, предложенных клиентом
				 */
				for(size_t i = 0; (i < declared.size()) && !this->_settled; i++)
					// Запоминаем, объявлен ли выбранный протокол клиентом с настройками
					this->_settled = (declared[i].compare(this->_protocol) == 0);
				// Если прикладные настройки согласованы
				if(this->_settled){
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем свои настройки выбранного протокола
						this->_applied.assign(applied.data, applied.data + applied.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
				}
			}
		}
		/**
		 * Раздел 8.1 RFC 9001: под QUIC прикладной протокол обязателен, и связь без него
		 * обрывается извещением no_application_protocol - клиент, протокола не предложивший,
		 * задевается тем же заслоном
		 */
		if((this->_transport == context::transport_t::LEVELS) && this->_protocol.empty())
			// Выводим отказ отсутствия общего прикладного протокола
			return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
		// Разыскиваем расширение параметров переноса QUIC
		extension = hello::extension(greeting.extensions, TRANSPORT);
		/**
		 * Раздел 8.2 RFC 9001: под QUIC параметры переноса обязательны, и приветствие без них
		 * обрывается извещением missing_extension; переносу записями они не положены вовсе, и
		 * приветствие с ними обрывается извещением unsupported_extension
		 */
		if(this->_transport == context::transport_t::LEVELS){
			// Если параметры переноса приветствием не объявлены
			if(extension == nullptr)
				// Выводим отказ отсутствия обязательного расширения
				return this->abort(context::error_t::PARAMETERS, alert::description_t::MISSING);
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Переносим параметры переноса собеседника как есть
				this->_received.assign(extension->data.data, extension->data.data + extension->data.size);
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const std::bad_alloc &) {
				// Выводим отказ нехватки памяти
				return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
			}
			// Запоминаем, что параметры переноса собеседника приняты
			this->_acquired = true;
		// Если параметры переноса объявлены приветствием переносу записями
		} else if(extension != nullptr)
			// Выводим отказ объявления расширения, связи не положенного
			return this->abort(context::error_t::PARAMETERS, alert::description_t::EXTENSION);
		// Выполняем сброс алгоритмов сжатия, объявленных прежним приветствием
		this->_compressible.clear();
		// Разыскиваем расширение алгоритмов сжатия цепочки сертификатов клиента
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::COMPRESS));
		// Если алгоритмы сжатия цепочки приветствием клиента объявлены
		if(extension != nullptr){
			/**
			 * Раздел 3 RFC 8879: перечень клиента запоминается в его порядке: по нему сервер
			 * выбирает первый общий алгоритм, а неведомые значения пропускает молча
			 */
			failure = translate(extension::algorithms(extension->data, this->_compressible), context::error_t::MESSAGE);
			// Если алгоритмы сжатия, объявленные клиентом, разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
		}
		// Выполняем сброс признака запроса состояния прежним приветствием
		this->_inquired = false;
		// Выполняем сброс признака запроса меток времени сертификата
		this->_stamped = false;
		// Разыскиваем расширение запроса меток времени сертификата
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::TIMESTAMPS));
		// Если метки времени сертификата клиентом запрошены
		if(extension != nullptr){
			// Раздел 3.3.1 RFC 6962: тело запроса пусто, а непустое выдаёт негодное приветствие
			if(extension->data.size > 0)
				// Выводим отказ негодного расширения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			// Запоминаем, что метки времени сертификата запрошены
			this->_stamped = true;
		}
		// Разыскиваем расширение запроса состояния сертификата
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::STATUS));
		// Если состояние сертификата приветствием клиента запрошено
		if(extension != nullptr){
			// Отказ разбора запроса состояния сертификата
			failure = this->inquiry(extension->data);
			// Если запрос состояния сертификата разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
		}
		// Разыскиваем расширение схем подписи, признаваемых клиентом
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SCHEMES));
		// Если схемы подписи приветствием клиента объявлены
		if(extension != nullptr){
			// Отказ разбора расширения приветствия
			failure = translate(extension::schemes(extension->data, this->_schemes), context::error_t::MESSAGE);
			// Если схемы подписи, признаваемые клиентом, разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
		}
		/**
		 * Раздел 3 RFC 7250: вид сертификата сервера выбирается по предложению клиента и
		 * объявляется защищёнными расширениями - лишь изданию TLS 1.3; у сервера с цепочкой
		 * открытый ключ листа всегда готов к ответу сырым ключом
		 */
		if(this->_proposed && !this->_credential.chain.empty()){
			// Разыскиваем расширение вида сертификата сервера
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SERVER_CERT_TYPE));
			// Если вид сертификата сервера объявлен
			if(extension != nullptr){
				// Перечень видов сертификатов
				vector <extension::cert_t> types;
				// Отказ разбора расширения
				failure = translate(extension::certtypes(extension->data, types), context::error_t::MESSAGE);
				// Если виды сертификатов разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				// Если сервер выбрал RawPublicKey
				if(!types.empty() && (types[0] == extension::cert_t::RAW))
					// Запоминаем согласованный вид своего сертификата
					this->_owncert = extension::cert_t::RAW;
			}
		}
		/**
		 * Раздел 3 RFC 7250: готовность клиента принять ответ сырым ключом объявляется
		 * расширением вида сертификата клиента - сервер запоминает её, чтобы просить
		 * клиентский ключ сырым запросом подлинности
		 */
		if(this->_proposed){
			// Разыскиваем расширение вида сертификата клиента
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::CLIENT_CERT_TYPE));
			// Если вид сертификата клиента объявлен
			if(extension != nullptr){
				// Перечень видов сертификатов
				vector <extension::cert_t> types;
				// Отказ разбора расширения
				failure = translate(extension::certtypes(extension->data, types), context::error_t::MESSAGE);
				// Если виды сертификатов разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				// Запоминаем, готов ли клиент принять ответ сырым ключом
				this->_clientraw = (!types.empty() && (types[0] == extension::cert_t::RAW));
			}
		}
		// Выполняем разбор предложения заранее разделённых ключей клиента
		const context::error_t offered = this->offered(greeting.extensions, greeting.suites, message);
		// Если предложение заранее разделённых ключей разобрать не удалось
		if(offered != context::error_t::NONE)
			// Выводим отказ разбора предложения заранее разделённых ключей
			return offered;
		/**
		 * Хеш переписки выбирается набором шифрования лишь теперь: разбор предложения
		 * билетов вправе сменить набор под хеш билета, а привязку он берёт хешем билета
		 * у переписки, ещё не закреплённой
		 */
		const context::error_t hashed = this->hashing();
		// Если хеш переписки выбрать не удалось
		if(hashed != context::error_t::NONE)
			// Выводим отказ выбора хеша переписки
			return this->abort(hashed, alert::description_t::INTERNAL);
		/**
		 * Раздел 9.2 RFC 8446 велит клиенту объявлять схемы подписи всякий раз, когда
		 * сервер подтверждает подлинность сертификатом: без них сервер подписать владение
		 * ключом не вправе ничем. Возобновление заранее разделённым ключом сертификата не
		 * требует, и там расширение это не нужно вовсе
		 */
		/**
		 * Слагаемое (!this->_shared) ложным своим клиентом не задевается: схемы подписи он
		 * объявляет всякий раз, и приветствие без них приходит лишь от собеседника.
		 * Задеть его способен собеседник, возобновляющий связь билетом и схем не
		 * объявляющий, - такому приветствие проходит законно
		 */
		if(this->_schemes.empty() && !this->_shared)
			// Выводим отказ отсутствия схем подписи в приветствии клиента
			return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
		/**
		 * Приветствие ложится в переписку лишь теперь: привязка билета берётся от
		 * переписки без него, и добавь его раньше - привязка не сошлась бы
		 */
		if(this->_transcript.update(message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если приветствие клиента ходу рукопожатия объявить не удалось
		if(this->_machine.accept(handshake::type_t::CLIENT, session::side_t::CLIENT) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если связь не возобновлена заранее разделённым ключом либо билетом: подлинность подтверждается сертификатом
		if(!this->_shared){
			// Отказ выбора подлинности сервера по имени узла приветствия
			failure = this->choosing();
			// Если выбор подлинности обрывал рукопожатие
			if(failure != context::error_t::NONE)
				// Выводим отказ выбора подлинности
				return failure;
		}
		// Если упреждающие данные клиентом предложены
		if(hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::EARLY)) != nullptr){
			/**
			 * Упреждающие данные принимаются лишь при возобновлении связи билетом: ключи
			 * их выводятся из заранее разделённого ключа, которого при полном рукопожатии
			 * попросту нет
			 *
			 * Раздел 4.2.10 RFC 8446 кладёт приёму ещё два условия: признанным обязан быть
			 * первый из предложенных клиентом ключей, а набор шифрования связи - совпасть с
			 * тем, каким выдан билет. Клиент шлёт упреждающие данные до ответа сервера и
			 * шифрует их набором билета, ибо иного на тот миг не знает; выбери сервер иной
			 * набор и прими данные - он читал бы их набором, о котором клиент не уславливался.
			 * Третьим условием идёт прикладной протокол: упреждающие данные сложены по тому
			 * протоколу, каким шла выдавшая билет связь, и разойдись он с протоколом новой -
			 * сервер разобрал бы их не тем разборщиком
			 *
			 * Условие о первом ключе своим клиентом не задевается вовсе: он предлагает
			 * один-единственный билет, и место выбранного ключа у него всегда нулевое.
			 * Задеть это условие способен лишь собеседник, предлагающий несколько билетов
			 * разом, оттого закреплённой проверки на него и нет
			 */
			if(this->_advance && !this->_retried && !this->_misaged && (this->_granted > 0) && this->_shared && (this->_chosen == 0) && (this->_suite == this->_ticket) && (this->_protocol == this->_previous) && (this->_settled == this->_bequeathed) && (this->_applied == this->_bequest)){
				/**
				 * Ключи упреждающих данных выводятся от переписки с одним лишь приветствием
				 * клиента: ответа сервера в ней на этот миг ещё нет, и завестись им надо
				 * прежде вывода ключей рукопожатия
				 */
				const context::error_t outcome = this->earliest();
				// Если защиту записей упреждающих данных завести не удалось
				if(outcome != context::error_t::NONE)
					// Выводим отказ заведения защиты записей
					return this->abort(outcome, alert::description_t::INTERNAL);
				// Запоминаем приём упреждающих данных клиента
				this->_accepted = true;
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Черновик draft-vvv-tls-alps: настройки клиента при принятом упреждении наследуются от билета
					this->_obtained = this->_heritage;
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
			/**
			 * Отвергнутые упреждающие данные прочесть нечем, и записи их пропускаются:
			 * число пропусков ограничено, иначе им открылся бы бесконечный поток
			 */
			/**
			 * Раздел 4.2.10 RFC 8446 ограничивает пропуск объёмом упреждения в байтах, а
			 * не числом записей: клиент вправе нарезать его сколь угодно мелко. Запас
			 * покрывает обвязку записей
			 */
			} else this->_skipped = (static_cast <size_t> ((this->_granted > this->_limit) ? this->_granted : this->_limit) * 2 + 4096);
		}
		// Разыскиваем расширение открытых частей ключей обмена
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Перечень открытых частей ключей обмена, объявленных клиентом
		vector <extension::share_t> shares;
		// Если открытые части ключей обмена приветствием объявлены
		if(extension != nullptr){
			// Отказ разбора расширения приветствия
			failure = translate(extension::shares(extension->data, shares), context::error_t::MESSAGE);
			// Если перечень открытых частей ключей обмена разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
			// Разыскиваем расширение перечня кривых обмена ключами
			const hello::extension_t * declared = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
			// Раздел 9.2 RFC 8446: приветствие с key_share обязано нести supported_groups - без него missing_extension
			if(declared == nullptr)
				// Выводим отказ отсутствия обязательного расширения
				return this->abort(context::error_t::GROUP, alert::description_t::MISSING);
			// Если перечень кривых обмена ключами приветствием объявлен
			if(declared != nullptr){
				// Перечень кривых обмена ключами, поддерживаемых клиентом
				vector <extension::group_t> supported;
				// Отказ разбора расширения приветствия
				failure = translate(extension::groups(declared->data, supported), context::error_t::MESSAGE);
				// Если перечень кривых обмена ключами разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор открытых частей ключей обмена клиента
				 */
				for(size_t i = 0; i < shares.size(); i++){
					// Признак того, что кривая ключа объявлена клиентом поддержанной
					bool known = false;
					/**
					 * Выполняем перебор кривых обмена ключами, поддерживаемых клиентом
					 */
					for(size_t j = 0; (j < supported.size()) && !known; j++)
						// Запоминаем совпадение кривой ключа с поддержанной клиентом
						known = (shares[i].group == supported[j]);
					/**
					 * Ключ по кривой, которой клиент не объявил поддержанной, в дело не
					 * идёт: раздел 4.2.8 RFC 8446 велит оборвать связь, ибо приветствие
					 * само себе противоречит
					 */
					if(!known)
						// Выводим отказ кривой ключа вне объявленной поддержки
						return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
				}
			}
		}
		// Открытая часть ключа обмена, выбранная сервером
		const extension::share_t * selected = nullptr;
		/**
		 * Выполняем перебор порядком стороны, чьё предпочтение ведёт выбор: своим перечнем
		 * кривых (умолчание) либо долями клиента в его порядке - ручка preference
		 * (намеренное решение 19)
		 */
		for(size_t i = 0; (i < (this->_own ? this->_groups.size() : shares.size())) && (selected == nullptr); i++){
			/**
			 * Выполняем перебор встречной стороны
			 */
			for(size_t j = 0; (j < (this->_own ? shares.size() : this->_groups.size())) && (selected == nullptr); j++){
				// Своя кривая обмена ключами по порядку перебора
				const extension::group_t mine = (this->_own ? this->_groups[i] : this->_groups[j]);
				// Доля ключа клиента по порядку перебора
				const extension::share_t & theirs = (this->_own ? shares[j] : shares[i]);
				// Если группа обмена связи неведома либо изданию 1.3 не дозволена: своё значение GREASE выбирать нельзя
				if(!known(mine) || !fitting(mine, false))
					// Переходим к следующей кривой обмена ключами
					continue;
				// Если открытая часть ключа обмена отвечает предлагаемой кривой
				if(theirs.group == mine)
					// Запоминаем выбранную открытую часть ключа обмена
					selected = &theirs;
			}
		}
		/**
		 * Раздел 4.2.8 RFC 8446: за просьбой о повторе клиент обязан прислать долю ключа
		 * ровно по той группе, о которой его просили, и никакой иной
		 */
		if((selected != nullptr) && this->_retried && (selected->group != this->_group))
			// Выводим отказ доли ключа не по запрошенной группе
			return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
		/**
		 * Раздел 5.1 RFC 9147: первое приветствие поверх дейтаграмм отвечается просьбой о
		 * повторе с меткой возврата состояния всегда - адрес собеседника до повтора не
		 * подтверждён, а доля ключа, если она пришла годной, заново не просится
		 */
		const bool challenging = ((this->_transport == context::transport_t::DATAGRAMS) && !this->_retried);
		// Если открытой части ключа обмена по общей кривой у клиента не нашлось либо метка ещё не выдана
		if((selected == nullptr) || challenging){
			// Если повтор приветствия клиента уже был
			if(this->_retried)
				// Выводим отказ отсутствия общей кривой обмена ключами
				return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
			// Просьба о повторе просит долю ключа лишь тогда, когда годной доли нет
			this->_reshare = (selected == nullptr);
			/**
			 * Раздел 4.2.10 RFC 8446: за просьбою о повторе упреждающие данные не
			 * принимаются - уже ушедшие от клиента записи пропускаются в пределах
			 * объявленного билетом объёма, а ключи упреждения не нужны
			 */
			this->_earlying = false;
			// Сбрасываем признак приёма упреждающих данных
			this->_accepted = false;
			// Устанавливаем объём пропускаемых записей упреждения с запасом на обвязку: лишь если упреждение предлагалось (раздел 4.2.10 RFC 8446) либо ECH предложен и отвергнут (внутреннее приветствие не прочесть), иначе открытые записи за просьбой - unexpected_message
			this->_skipped = (((hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::EARLY)) != nullptr) || this->_echrejected) ? (static_cast <size_t> ((this->_granted > this->_limit) ? this->_granted : this->_limit) * 2 + 4096) : 0);
			// Перечень кривых обмена ключами, поддерживаемых клиентом
			vector <extension::group_t> groups;
			// Если годная доля ключа пришла: группа берётся у неё
			if(selected != nullptr){
				// Запоминаем группу доли ключа клиента
				this->_group = selected->group;
				// Добавляем группу доли в перечень, чтобы перебор ниже её нашёл
				groups.push_back(selected->group);
			// Если доли ключа по общей кривой нет
			} else {
				// Разыскиваем расширение перечня кривых обмена ключами
				extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
				// Если перечень кривых обмена ключами приветствием не объявлен
				if(extension == nullptr)
					// Выводим отказ отсутствия кривой обмена ключами
					return this->abort(context::error_t::GROUP, alert::description_t::MISSING);
				// Отказ разбора расширения приветствия
				failure = translate(extension::groups(extension->data, groups), context::error_t::MESSAGE);
				// Если перечень кривых обмена ключами разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
			}
			// Признак того, что общая кривая обмена ключами у сторон нашлась
			suitable = false;
			/**
			 * Выполняем перебор порядком стороны, чьё предпочтение ведёт выбор: своим
			 * перечнем кривых (умолчание) либо перечнем клиента - ручка preference
			 */
			for(size_t i = 0; (i < (this->_own ? this->_groups.size() : groups.size())) && !suitable; i++){
				/**
				 * Выполняем перебор кривых встречной стороны
				 */
				for(size_t j = 0; (j < (this->_own ? groups.size() : this->_groups.size())) && !suitable; j++){
					// Своя кривая обмена ключами по порядку перебора
					const extension::group_t mine = (this->_own ? this->_groups[i] : this->_groups[j]);
					// Кривая клиента по порядку перебора
					const extension::group_t theirs = (this->_own ? groups[j] : groups[i]);
					// Если группа обмена связи неведома либо изданию 1.3 не дозволена: своё значение GREASE выбирать нельзя
					if(!known(mine) || !fitting(mine, false))
						// Переходим к следующей кривой обмена ключами
						continue;
					// Если кривая обмена ключами поддержана обеими сторонами
					if(theirs == mine){
						// Запоминаем выбранную кривую обмена ключами
						this->_group = mine;
						// Запоминаем, что общая кривая обмена ключами нашлась
						suitable = true;
					}
				}
			}
			// Если общей кривой обмена ключами у сторон не нашлось
			if(!suitable)
				// Выводим отказ отсутствия общей кривой обмена ключами
				return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
			// Если приветствие поверх дейтаграмм отвечается меткой возврата состояния
			if(challenging){
				// Отказ составления метки возврата состояния
				const context::error_t stamped = this->_flight.stamp(message, this->_cookie);
				// Если метку возврата состояния составить не удалось
				if(stamped != context::error_t::NONE)
					// Выводим отказ составления метки
					return this->abort(stamped, alert::description_t::INTERNAL);
				// Запоминаем, что залп составлен просьбою о повторе
				this->_flight.challenge();
			}
			/**
			 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
			 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
			 */
			if(this->_transcript.replace() != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
			// Выполняем отправку просьбы о повторе приветствия клиента
			const context::error_t error = this->answer(greeting.session, true);
			// Если просьбу о повторе приветствия отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки просьбы о повторе приветствия
				return this->abort(error, alert::description_t::INTERNAL);
			/**
			 * Повторность просьбы сличена выше собственным признаком связи, и второй раз
			 * сюда управление не приходит: через связь заслон недостижим. Лежит он за
			 * отправкой самой просьбы нарочно - объявление ходу идёт в паре с заменою
			 * переписки, а не с составлением сообщения
			 */
			if(this->_machine.retry() != flow::error_t::NONE)
				// Выводим отказ объявления просьбы не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Запоминаем, что повтор приветствия клиента уже был
			this->_retried = true;
			// Выводим успешность разбора приветствия клиента
			return context::error_t::NONE;
		}
		/**
		 * Слагаемое (selected->key.data == nullptr) ложно всегда: разбор доли обмена место
		 * ей отводит непременно, а пустую долю выдаёт нулевая длина, за которую отвечает
		 * вторая половина. Слагаемое оставлено ради самостоятельности заслона
		 */
		// Если открытая часть ключа обмена клиента непригодна
		if((selected->key.data == nullptr) || (selected->key.size == 0))
			// Выводим отказ непригодности открытой части ключа обмена
			return this->abort(context::error_t::EXCHANGE, alert::description_t::PARAMETER);
		// Открытая часть ключа обмена клиента, из которой выводятся ключи связи
		const vector <uint8_t> key(selected->key.data, selected->key.data + selected->key.size);
		// Группа обмена ключами, выбранная сервером
		const extension::group_t group = selected->group;
		// Выполняем сброс мимолётных пар ключей своей стороны
		this->_exchanges.clear();
		// Выполняем выработку своей доли: у гибридной группы инкапсуляцией на долю клиента, иначе своей парой ключей
		context::error_t error = (extension::hybrid(group) ? this->encapsulating(group, view_t(key.data(), key.size())) : this->exchange(group));
		// Если мимолётную пару ключей выработать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ выработки мимолётной пары ключей
			return this->abort(error, blame(error, alert::description_t::HANDSHAKE));
		// Выполняем выработку случайного значения своего приветствия
		if(!entropy::bytes(this->_random, sizeof(this->_random)))
			// Выводим отказ выработки случайного значения приветствия
			return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
		// Выполняем отправку приветствия сервера
		error = this->answer(greeting.session, false);
		// Если приветствие сервера отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки приветствия сервера
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод ключей рукопожатия связи
		error = this->derive(group, view_t(key.data(), key.size()));
		// Если ключи рукопожатия связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода ключей рукопожатия связи
			return this->abort(error, blame(error, alert::description_t::HANDSHAKE));
		// Перечень расширений, объявляемых сервером под защитой
		vector <hello::extension_t> items;
		// Накопитель, в котором лежит тело расширения прикладного протокола
		vector <uint8_t> protocol;
		// Накопитель, в котором лежит тело расширения профиля защиты RTP
		vector <uint8_t> protection;
		// Накопитель, в котором лежит тело расширения вида сертификата сервера
		vector <uint8_t> certificate;
		// Если упреждающие данные клиента приняты
		if(this->_accepted)
			// Объявляем клиенту приём упреждающих данных
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
		/**
		 * Имя узла подтверждается пустым расширением: раздел 3 RFC 6066 велит серверу лишь
		 * объявить, что имя принято, а самого имени в ответ не возвращать
		 */
		// Если предел длины записи договорён, отвечаем клиенту своим расширением
		if(this->_sizing != 0){
			// Добавляем ответное расширение предела
			items.push_back(hello::extension_t(static_cast <uint16_t> ((this->_sizing == 1) ? extension::type_t::LIMIT : extension::type_t::FRAGMENT), view_t(this->_sized, ((this->_sizing == 1) ? 2 : 1))));
			// С ответом договорённая длина max_fragment_length связывает и приём (раздел 4 RFC 6066)
			if(this->_sizing == 2)
				// Ограничиваем приём договорённой длиной
				this->_incoming = this->_outgoing;
		}
		// Если имя запрашиваемого узла заведено
		if(!this->_name.empty())
			// Объявляем клиенту приём имени запрашиваемого узла
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
		// Если прикладной протокол сторонами выбран
		if(!this->_protocol.empty()){
			// Отказ составления сообщения защищённых расширений
			failure = translate(extension::protocol(this->_protocol, protocol), context::error_t::MESSAGE);
			// Если выбранный прикладной протокол составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления сообщения защищённых расширений
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Объявляем клиенту выбранный прикладной протокол
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocol.data(), protocol.size())));
		}
		// Если профиль защиты RTP сторонами выбран
		if(this->_srtp != 0){
			// Отказ составления сообщения защищённых расширений
			failure = translate(extension::profiles(vector <uint16_t> (1, this->_srtp), protection), context::error_t::MESSAGE);
			// Если выбранный профиль защиты RTP составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления сообщения защищённых расширений
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Объявляем клиенту выбранный профиль защиты RTP
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROFILES), view_t(protection.data(), protection.size())));
		}
		// Если вид сертификата сервера согласован сырым открытым ключом
		if(this->_owncert == extension::cert_t::RAW){
			// Отказ составления тела расширения вида сертификата сервера
			failure = translate(extension::certtypes(vector <extension::cert_t> (1, extension::cert_t::RAW), certificate), context::error_t::MESSAGE);
			// Если тело расширения вида сертификата сервера составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления сообщения защищённых расширений
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Объявляем клиенту выбранный вид сертификата сервера
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SERVER_CERT_TYPE), view_t(certificate.data(), certificate.size())));
		}
		/**
		 * Черновик draft-vvv-tls-alps: свои настройки идут под защитой, а при принятом
		 * упреждении опускаются - они унаследованы билетом
		 */
		if(this->_settled && !this->_accepted)
			// Объявляем клиенту свои прикладные настройки
			items.push_back(hello::extension_t(this->_codepoint, view_t(this->_applied.data(), this->_applied.size())));
		/**
		 * Раздел 8.2 RFC 9001: параметры переноса сервера идут защищёнными расширениями
		 * всякий раз, когда рукопожатие переносится по уровням
		 */
		if(this->_transport == context::transport_t::LEVELS)
			// Объявляем клиенту свои параметры переноса QUIC как есть
			items.push_back(hello::extension_t(TRANSPORT, view_t(this->_parameters.data(), this->_parameters.size())));
		// Раздел 7.1 RFC 9849: сервер, отвергший ECH, шлёт свои конфигурации как retry_configs
		if(this->_echrejected && !this->_echlist.empty())
			// Добавляем расширение запасных конфигураций
			items.push_back(hello::extension_t(ech::ECH_EXTENSION, view_t(this->_echlist.data(), this->_echlist.size())));
		// Накопитель, в который складывается тело защищённых расширений
		vector <uint8_t> extensions;
		// Отказ составления тела сообщения защищённых расширений
		failure = block(items, extensions);
		// Если тело сообщения защищённых расширений составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения защищённых расширений
			return this->abort(failure, alert::description_t::INTERNAL);
		// Выполняем отправку защищённых расширений сервера
		error = this->send(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()));
		// Если защищённые расширения отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки защищённых расширений
			return this->abort(error, alert::description_t::INTERNAL);
		/**
		 * Раздел 4.3.2 RFC 8446: на заранее разделённом ключе запрос подлинности
		 * клиента не посылается
		 */
		if(this->_request && !this->_shared){
			// Объект составителя тела запроса подлинности клиента
			field::builder_t builder;
			// Отказ записи пустой привязки запроса
			failure = translate(builder.number(0, 1), context::error_t::MESSAGE);
			// Если пустую привязку запроса записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления запроса подлинности клиента
				return this->abort(failure, alert::description_t::INTERNAL);
			// Накопитель, в который складывается тело расширения схем подписи
			vector <uint8_t> schemes;
			// Схемы подписи, объявляемые запросом подлинности
			vector <extension::scheme_t> declared;
			/**
			 * Выполняем перебор схем подписи, признаваемых связью
			 */
			for(size_t i = 0; i < this->_signatures.size(); i++){
				// Схемы PKCS #1 v1.5 подписи владения ключом в издании TLS 1.3 запрещены
				if(pkcs1(this->_signatures[i]))
					// Переходим к следующей схеме подписи
					continue;
				// Добавляем схему подписи в объявляемый перечень
				declared.push_back(this->_signatures[i]);
			}
			// Отказ составления запроса подлинности клиента
			failure = translate(extension::schemes(declared, schemes), context::error_t::MESSAGE);
			// Если перечень схем подписи составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления запроса подлинности клиента
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Перечень расширений запроса подлинности клиента
			vector <hello::extension_t> list;
			// Накопитель, в котором лежит тело расширения вида сертификата клиента
			vector <uint8_t> certificate;
			// Раздел 3.2 RFC 8701: расширение GREASE запроса подлинности идёт пустым впереди всех, как у BoringSSL
			if(this->greased())
				// Добавляем расширение GREASE запроса подлинности
				list.push_back(hello::extension_t(this->greasing(grease_t::FIRST), view_t(nullptr, 0)));
			// Добавляем расширение перечня схем подписи
			list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(schemes.data(), schemes.size())));
			/**
			 * Раздел 4.2.1 RFC 7250: сервер, которому клиент объявил готовность принять
			 * ответ сырым ключом и у которого ключ клиента закреплён, просит клиентский
			 * сертификат сырым ключом
			 */
			if(this->_clientraw && !this->_pinned.empty()){
				// Отказ составления тела расширения вида сертификата клиента
				failure = translate(extension::certtypes(vector <extension::cert_t> (1, extension::cert_t::RAW), certificate), context::error_t::MESSAGE);
				// Если тело расширения вида сертификата клиента составить не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления запроса подлинности клиента
					return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
				// Добавляем расширение вида сертификата клиента
				list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::CLIENT_CERT_TYPE), view_t(certificate.data(), certificate.size())));
				// Запоминаем согласованный вид сертификата собеседника: клиент ответит сырым ключом
				this->_certtype = extension::cert_t::RAW;
			}
			// Накопитель, в который складывается тело расширения алгоритмов сжатия
			vector <uint8_t> algorithms;
			/**
			 * Раздел 3 RFC 8879: запросом подлинности сервер объявляет, какую сжатую цепочку
			 * он примет от клиента; без алгоритмов у потребителя запрос не меняется вовсе
			 */
			if(!this->_codecs.empty()){
				// Перечень опознавателей алгоритмов сжатия в порядке предпочтения потребителя
				vector <uint16_t> identifiers;
				/**
				 * Выполняем перебор алгоритмов сжатия, предоставленных потребителем
				 */
				for(size_t i = 0; i < this->_codecs.size(); i++)
					// Добавляем опознаватель очередного алгоритма в перечень
					identifiers.push_back(this->_codecs[i].algorithm);
				// Отказ составления расширения запроса подлинности
				failure = translate(extension::algorithms(identifiers, algorithms), context::error_t::MESSAGE);
				// Если перечень алгоритмов сжатия составить не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления запроса подлинности клиента
					return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
				// Добавляем расширение перечня алгоритмов сжатия цепочки сертификатов
				list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COMPRESS), view_t(algorithms.data(), algorithms.size())));
			}
			/**
			 * Раздел 4.4.2.1 RFC 8446: состояние сертификата клиента запрашивается
			 * расширением status_request запроса подлинности
			 */
			/**
			 * Раздел 4.4.2.1 RFC 8446: ответ OCSP у клиента просится ПУСТЫМ расширением
			 * status_request в CertificateRequest (так шлёт GnuTLS; OpenSSL и BoringSSL у клиента
			 * его не просят вовсе); структура CertificateStatusRequest принадлежит приветствию
			 */
			if(this->_inquiring)
				// Добавляем пустую просьбу об ответе OCSP
				list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::STATUS), view_t(nullptr, 0)));
			// Накопитель, в котором лежит тело расширения доверенных удостоверяющих центров
			vector <uint8_t> names;
			// Раздел 4.2.4 RFC 8446: перечень доверенных центров идёт запросом подлинности лишь по настройке потребителя
			if(!this->_trusted.empty()){
				// Отказ составления перечня
				failure = translate(extension::authorities(this->_trusted, names), context::error_t::MESSAGE);
				// Если перечень составить не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ составления запроса подлинности
					return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
				// Добавляем расширение перечня доверенных центров
				list.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::AUTHORITIES), view_t(names.data(), names.size())));
			}
			// Накопитель, в который складывается запись перечня расширений
			vector <uint8_t> record;
			// Отказ составления записи перечня расширений
			failure = block(list, record);
			// Если запись перечня расширений составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления запроса подлинности клиента
				return this->abort(failure, alert::description_t::INTERNAL);
			// Отказ добавления записи перечня расширений в тело запроса
			failure = translate(builder.bytes(view_t(record.data(), record.size())), context::error_t::MESSAGE);
			// Если запись перечня расширений в тело запроса добавить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления запроса подлинности клиента
				return this->abort(failure, alert::description_t::INTERNAL);
			// Получаем составленное тело запроса подлинности клиента
			const view_t request = builder.data();
			// Выполняем отправку запроса подлинности клиента
			error = this->send(handshake::type_t::REQUEST, request);
			// Если запрос подлинности клиента отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки запроса подлинности клиента
				return this->abort(error, alert::description_t::INTERNAL);
		}
		/**
		 * Подлинность сервера предъявляется лишь вне возобновления связи: раздел 2.2
		 * RFC 8446 велит при возобновлении опираться на заранее разделённый ключ, которым
		 * стороны уже опознали друг друга прошлой связью
		 */
		if(!this->_shared){
			// Выполняем отправку подтверждения подлинности сервера
			error = this->authenticate();
			// Если подтверждение подлинности сервера отправить не удалось
			if(error != context::error_t::NONE)
				/**
				 * Раздел 4.4.3 RFC 8446: отсутствие схемы подписи, признаваемой обеими
				 * сторонами, есть несхождение сторон, а не внутренний отказ
				 */
				return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL)));
		}
		// Выполняем отправку завершения рукопожатия сервером
		error = this->complete();
		// Если завершение рукопожатия сервером отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки завершения рукопожатия
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем вывод ключей прикладных данных связи
		error = this->mature();
		// Если ключи прикладных данных вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода ключей прикладных данных
			return this->abort(error, alert::description_t::INTERNAL);
		// Выполняем согласование ключевого материала защиты записей
		error = this->refresh();
		// Если ключевой материал защиты записей согласовать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ согласования ключевого материала
			return this->abort(error, alert::description_t::INTERNAL);
		// Выводим успешность разбора приветствия клиента
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора принятого приветствия сервера
 *
 * @param body    тело принятого приветствия сервера
 * @param message принятое приветствие сервера вместе с обвязкой
 * @return        отказ разбора приветствия сервера
 *
 */
context::error_t nts::internal::Engine::outgoing(const view_t & body, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Разбираемое приветствие сервера
		hello::server_t answer;
		// Отказ разбора приветствия сервера
		failure = translate(hello::parse(body, answer), context::error_t::MESSAGE);
		// Если приветствие сервера разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора приветствия сервера
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		/**
		 * Приветствие сервера без расширения издания означает выбор издания, объявленного
		 * заголовком приветствия, - то есть TLS 1.2 либо более раннего: приложение D.1
		 * RFC 8446. Просьба о повторе без расширения издания изданием 1.2 не бывает, и её
		 * отвергает сверка ниже
		 */
		if(!hello::retry(answer) && (hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS)) == nullptr)){
			// Раздел 6.1 RFC 9849: под предложенным ECH издание ниже 1.3 недопустимо - защита в глубину от связи по публичному имени без признака
			if((this->_ech == ech_t::OFFERED) || (this->_ech == ech_t::ACCEPTED))
				// Выводим отказ несовпадения издания протокола
				return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
			// Выводим итог разбора приветствия сервера издания TLS 1.2
			return this->greeted(answer, message);
		}
		/**
		 * Опознаватель связи сервер обязан вернуть тем же, каким его прислал клиент:
		 * раздел 4.1.3 RFC 8446 велит оборвать связь, если он вернулся иным. Поверх
		 * дейтаграмм сверки нет: раздел 5 RFC 9147 велит серверу DTLS 1.3 опознаватель
		 * клиента НЕ повторять, и приветствие сервера несёт его пустым
		 */
		/**
		 * Слагаемое (!answer.session.empty()) ложным не задевается: свой клиент шлёт
		 * опознаватель связи длиною ровно в HELLO_SESSION, и приветствие, прошедшее
		 * сверку длин, несёт его непустым. Слагаемое оставлено оттого, что сличение
		 * пустого места через memcmp опирается на непереданный указатель
		 */
		if((this->_transport != context::transport_t::DATAGRAMS) && ((answer.session.size() != this->_session.size()) || (!answer.session.empty() && (::memcmp(answer.session.data(), this->_session.data(), answer.session.size()) != 0))))
			// Выводим отказ несовпадения опознавателя связи
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		/**
		 * Способ сжатия достался изданию 1.3 от предыдущих и назначения в нём не имеет:
		 * раздел 4.1.3 RFC 8446 велит серверу слать нуль, а всякое иное значение выдаёт
		 * собеседника, ведущего иное издание протокола под видом нынешнего
		 */
		if(answer.method != 0x00)
			// Выводим отказ негодного способа сжатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Признак того, что выбранный сервером набор шифрования связью предложен
		bool suitable = false;
		/**
		 * Выполняем перебор наборов шифрования, предлагаемых связью
		 */
		for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++)
			// Запоминаем совпадение выбранного набора шифрования с предложенным
			suitable = (answer.suite == static_cast <uint16_t> (this->_suites[i]));
		// Если сервер выбрал набор профиля отпечатка, связи неведомый: профиль исполнить нельзя
		if(!suitable && this->_profiled && this->carried(answer.suite))
			// Выводим отказ исполнения профиля
			return this->abort(context::error_t::PROFILE, alert::description_t::PARAMETER);
		// Если сервер выбрал набор шифрования, связью не предложенный
		if(!suitable)
			// Выводим отказ несовпадения набора шифрования
			return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		/**
		 * Набор издания TLS 1.2 изданию 1.3 не годен: раздел 4.1.3 RFC 8446 велит выбирать
		 * из предложенных, а предложен он был лишь изданию 1.2
		 */
		if(protect::legacy(static_cast <protect::suite_t> (answer.suite)))
			// Выводим отказ несовпадения набора шифрования
			return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		/**
		 * За просьбой о повторе сервер обязан выбрать тот же набор шифрования, каким
		 * объявил самоё просьбу: раздел 4.1.4 RFC 8446 менять его между просьбой и
		 * приветствием запрещает. Заслон этот не украшение: переписка рукопожатия
		 * хешируется набором, и сменой его сервер развёл бы стороны по разным хешам
		 */
		if(this->_retried && (answer.suite != static_cast <uint16_t> (this->_suite)))
			// Выводим отказ смены набора шифрования за просьбой о повторе
			return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		// Запоминаем выбранный сервером набор шифрования
		this->_suite = static_cast <protect::suite_t> (answer.suite);
		// Выполняем выбор хеша переписки по набору шифрования
		const context::error_t hashed = this->hashing();
		// Если хеш переписки выбрать не удалось
		if(hashed != context::error_t::NONE)
			// Выводим отказ выбора хеша переписки
			return this->abort(hashed, alert::description_t::PARAMETER);
		// Если зашифрованное приветствие предложено либо принято просьбой о повторе: судим о принятии
		if((this->_ech == ech_t::OFFERED) || ((this->_ech == ech_t::ACCEPTED) && this->_retried)){
			// Отказ суждения о принятии ECH
			failure = this->confirming(answer, message);
			// Если о принятии судить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ суждения
				return this->abort(failure, blame(failure, alert::description_t::PARAMETER));
		}
		// Если приветствие сервера просьбой о повторе не является
		if(!hello::retry(answer)){
			/**
			 * Выполняем перебор заслонов понижения издания протокола
			 */
			for(size_t i = 0; i < (sizeof(DOWNGRADE) / sizeof(DOWNGRADE[0])); i++){
				/**
				 * Заслон лежит в хвосте случайного значения сервера: раздел 4.1.3 RFC 8446
				 * велит клиенту, знающему издание 1.3, оборваться на нём, а не понижать
				 * издание вслед за сервером
				 */
				if(::memcmp(answer.random + (sizeof(answer.random) - sizeof(DOWNGRADE[i])), DOWNGRADE[i], sizeof(DOWNGRADE[i])) == 0)
					// Выводим отказ понижения издания протокола
					return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
			}
		}
		// Определяем место, которым идут разбираемые расширения
		const uint8_t place = (hello::retry(answer) ? PLACE_RETRY : PLACE_HELLO);
		/**
		 * Выполняем перебор расширений, объявленных приветствием сервера
		 */
		for(size_t i = 0; i < answer.extensions.size(); i++){
			// Места, в которых объявленному расширению идти дозволено
			uint8_t places = 0;
			/**
			 * Раздел 4.1.3 RFC 8446 кладёт приветствию сервера всего три расширения, а
			 * просьбе о повторе - три своих: всё прочее принадлежит защищённым расширениям
			 * и открытым приветствием идти не вправе.
			 *
			 * Извещения тут ДВА, и раздел 4.2 RFC 8446 их разводит: расширение, стороне
			 * ИЗВЕСТНОЕ, но пришедшее не в своём сообщении, обрывает связь извещением
			 * «illegal_parameter», а расширение, о котором сторона не просила вовсе, -
			 * извещением «unsupported_extension»
			 */
			if(placement(answer.extensions[i].type, places)){
				// Если известному расширению это место не отведено
				if((places & place) == 0)
					// Выводим отказ объявления расширения не в своём сообщении
					return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			// Выводим отказ объявления расширения, связью не предлагавшегося
			} else return this->abort(context::error_t::MESSAGE, alert::description_t::EXTENSION);
		}
		/**
		 * @brief Функция поиска расширения приветствия по его виду
		 *
		 * @param extensions перечень расширений приветствия
		 * @param type       разыскиваемый вид расширения
		 * @return           найденное расширение либо nullptr
		 *
		 */
		// Разыскиваем расширение издания протокола
		const hello::extension_t * item = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		/**
		 * Приветствие сервера без расширения издания означает выбор издания, объявленного
		 * заголовком приветствия, - то есть TLS 1.2 либо более раннего. Приложение D.1 RFC
		 * 8446 велит клиенту обрывать связь по неподдерживаемому изданию извещением
		 * protocol_version, а не missing_extension: последнее раздел 9.2 держит для
		 * СЕРВЕРА, принявшего негодное приветствие клиента
		 */
		if(item == nullptr)
			// Выводим отказ несовпадения издания протокола
			return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		// Издание протокола, выбранное сервером
		uint16_t version = 0;
		// Отказ разбора расширения приветствия
		failure = translate(extension::version(item->data, version), context::error_t::MESSAGE);
		// Если издание протокола разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		/**
		 * Раздел 4.2.1 RFC 8446 велит обрывать связь извещением illegal_parameter, если
		 * расширение издания несёт издание, клиентом не предложенное либо предшествующее
		 * TLS 1.3. Связь предлагает единственное издание, оттого оба случая и сходятся в
		 * одну сверку. Извещение здесь ИНОЕ, нежели при вовсе отсутствующем расширении:
		 * там сервер издания не объявлял и остался при заголовке, а тут объявил негодное
		 */
		if(version != this->edition())
			// Выводим отказ негодного издания протокола
			return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
		/**
		 * Издание 1.3 предлагалось лишь в пределах, поставленных потребителю: сервер, его
		 * выбравший при предложении одного 1.2, отвечает не тому приветствию
		 */
		if((this->_transport == context::transport_t::RECORDS) && (this->_highest < MODERN))
			// Выводим отказ негодного издания протокола
			return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
		// Запоминаем согласованное издание протокола кодом TLS: единая шкала изданий на любом переносе
		this->_version = MODERN;
		// Разыскиваем расширение открытой части ключа обмена
		const hello::extension_t * extension = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		/**
		 * Раздел 4.1.4 RFC 8446: просьба о повторе вправе не просить доли ключа, если
		 * меняет иное - поверх дейтаграмм она несёт метку возврата состояния (раздел 5.1
		 * RFC 9147); самому приветствию сервера доля обязательна
		 */
		if((extension == nullptr) && (!hello::retry(answer) || ((this->_transport != context::transport_t::DATAGRAMS) && (hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::COOKIE)) == nullptr))))
			// Выводим отказ отсутствия открытой части ключа обмена: просьба без доли обязана нести хотя бы метку (разделы 4.1.4, 4.2.2 RFC 8446); поверх дейтаграмм метку судит свой заслон
			return this->abort(context::error_t::EXCHANGE, alert::description_t::MISSING);
		/**
		 * Просьба о повторе приветствия идёт тем же сообщением, что и приветствие сервера,
		 * и отличается лишь заранее назначенным случайным значением
		 */
		if(hello::retry(answer)){
			// Кривая обмена ключами, выбранная сервером
			extension::group_t group = extension::group_t::NONE;
			// Если доля ключа просьбой запрошена
			if(extension != nullptr){
				// Отказ разбора расширения приветствия
				failure = translate(extension::selected(extension->data, group), context::error_t::MESSAGE);
				// Если выбранную сервером кривую обмена ключами разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Просить повтора сервер вправе лишь на кривой, которую клиент предложил и
				 * ключа по которой ещё не прислал: раздел 4.1.4 RFC 8446 запрещает и просьбу
				 * о кривой вне предложения, и просьбу о той, ключ по которой уже отправлен
				 */
				/**
				 * Выполняем перебор мимолётных пар ключей своей стороны
				 */
				for(size_t i = 0; i < this->_exchanges.size(); i++){
					// Если доля ключа по запрошенной группе уже отправлена
					if(this->_exchanges[i].group == group)
						// Выводим отказ просьбы о кривой, ключ по которой уже отправлен
						return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
				}
				// Если запрошенная группа связи неведома
				if(!known(group))
					// Выводим отказ просьбы о группе, обмен по которой вести нечем
					return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
				// Признак того, что выбранная сервером кривая связью предложена
				bool offered = false;
				/**
				 * Выполняем перебор кривых обмена ключами, предлагаемых связью
				 */
				for(size_t i = 0; (i < this->_groups.size()) && !offered; i++)
					// Запоминаем совпадение выбранной кривой с предложенной
					offered = (group == this->_groups[i]);
				// Если сервер попросил повтора на кривой, связью не предложенной
				if(!offered)
					// Выводим отказ просьбы о кривой вне предложения связи
					return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
			}
			// Разыскиваем расширение метки возврата состояния сервера
			const hello::extension_t * label = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::COOKIE));
			// Раздел 5.1 RFC 9147: просьба о повторе поверх дейтаграмм без метки бесполезна
			if((label == nullptr) && (this->_transport == context::transport_t::DATAGRAMS))
				// Выводим отказ отсутствия метки возврата состояния
				return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
			// Если метка возврата состояния сервера просьбой объявлена
			if(label != nullptr){
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					/**
					 * Раздел 4.2.2 RFC 8446 велит клиенту повторить метку в новом
					 * приветствии дословно: ею сервер возвращает себе состояние, которого
					 * он у себя не держал, и без неё повторное приветствие бесполезно
					 */
					this->_cookie.assign(label->data.data, label->data.data + label->data.size);
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
			}
			/**
			 * Переписка рукопожатия заменяется хешем приветствия клиента: раздел 4.4.1
			 * RFC 8446 велит поступать так всякий раз при просьбе о повторе приветствия
			 */
			if(this->_transcript.replace() != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
			// Если просьбу о повторе в переписку рукопожатия добавить не удалось
			if(this->_transcript.update(message) != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
			// Если просьбу о повторе ходу рукопожатия объявить не удалось
			if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
				// Выводим отказ объявления сообщения не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Если просьба о повторе приветствия ходом рукопожатия отвергнута
			if(this->_machine.retry() != flow::error_t::NONE)
				// Выводим отказ объявления просьбы не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Отказ выработки мимолётной пары ключей
			context::error_t error = context::error_t::NONE;
			// Запоминаем, просит ли просьба о повторе долю ключа: по ней судится доля GREASE повторного приветствия
			this->_reshare = (extension != nullptr);
			// Если доля ключа просьбой запрошена
			if(extension != nullptr){
				/**
				 * Раздел 4.2.8 RFC 8446: повторное приветствие несёт долю ключа лишь по
				 * запрошенной группе, прежние доли снимаются
				 */
				/**
				 * Выполняем затирание секретов снимаемых долей: секреты всех предложенных
				 * групп иначе оставались бы в освобождённой памяти
				 */
				for(size_t i = 0; i < this->_exchanges.size(); i++){
					// Затираем секрет доли
					this->purge(this->_exchanges[i].secret.data(), this->_exchanges[i].secret.size());
					// Затираем общее значение доли
					this->purge(this->_exchanges[i].shared.data(), this->_exchanges[i].shared.size());
				}
				// Выполняем сброс мимолётных пар ключей своей стороны
				this->_exchanges.clear();
				// Выполняем выработку мимолётной пары ключей на выбранной кривой
				error = this->exchange(group);
				// Если мимолётную пару ключей выработать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ выработки мимолётной пары ключей
					return this->abort(error, blame(error, alert::description_t::HANDSHAKE));
			}
			// Запоминаем, что повтор приветствия клиента уже был
			this->_retried = true;
			/**
			 * Раздел 4.1.2 RFC 8446: упреждающие данные после просьбы о повторе не
			 * дозволены - ход упреждения прекращается, и повторное приветствие уходит
			 * открытой записью
			 */
			this->_earlying = false;
			// Сбрасываем признак приёма упреждающих данных
			this->_accepted = false;
			// Выполняем отправку повторного приветствия клиента
			error = this->greeting();
			// Если повторное приветствие клиента отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки приветствия клиента
				return this->abort(error, alert::description_t::INTERNAL);
			// Выводим успешность разбора просьбы о повторе приветствия
			return context::error_t::NONE;
		}
		// Разыскиваем расширение выбранного заранее разделённого ключа
		const hello::extension_t * selected = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SECRET));
		// Если сервер выбрал заранее разделённый ключ клиента
		if(selected != nullptr){
			// Место выбранного сервером ключа в предложении клиента
			uint16_t chosen = 0;
			// Отказ разбора расширения приветствия
			failure = translate(extension::chosen(selected->data, chosen), context::error_t::MESSAGE);
			// Если выбранный сервером ключ разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
			/**
			 * Клиент предлагает единственный ключ, и всякое иное его место есть выбор
			 * того, чего клиент не предлагал вовсе. Той же сверкой удовлетворено и
			 * требование раздела 4.2.11 RFC 8446 о нулевом месте при объявленных сервером
			 * упреждающих данных: нулю здесь равно всякое принимаемое место.
			 *
			 * Сверки хеша набора шифрования с хешем ключа тут нет, и вот почему: все
			 * четыре набора, связью признаваемые, ведут расписание ключей на «Стрибоге»
			 * длиной 256 разрядов, и требование раздела 4.2.11 удовлетворено само собою.
			 * Появись набор с иным хешем - сверку эту заводить обязательно
			 */
			// Признак того, что заранее разделённый ключ приветствием предлагался
			bool proposed = false;
			/**
			 * Выполняем поиск предложения ключа среди расширений своего приветствия
			 */
			for(size_t i = 0; !proposed && (i < this->_offered.size()); i++)
				// Сличаем вид предложенного расширения
				proposed = (this->_offered[i] == static_cast <uint16_t> (extension::type_t::SECRET));
			/**
			 * Раздел 4.2.11 RFC 8446: выбранный сервером ключ обязан лежать в пределах
			 * предложенного, и билет, приветствием не предъявленный (например, с вышедшим
			 * сроком), выбран быть не может
			 */
			if((chosen != 0) || !proposed)
				// Выводим отказ несовпадения заранее разделённого ключа
				return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			/**
			 * Раздел 4.2.11 RFC 8446: сервер, признавший ключ билета, обязан выбрать набор
			 * с тем же хешем, что и у набора билета, - иначе расписание, заведённое ключом
			 * билета, разошлось бы с перепиской по хешу
			 */
			if((protect::hash(this->_ticket) != digest::hash_t::NONE) && (protect::hash(this->_suite) != protect::hash(this->_ticket)))
				// Выводим отказ несовпадения хеша набора с хешем билета
				return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
			// Запоминаем возобновление связи заранее разделённым ключом
			this->_shared = true;
		/**
		 * Сервер вправе билет и не признать: тогда связь идёт полным рукопожатием, а
		 * начальная ступень расписания заводится заново - уже без ключа билета
		 */
		} else if(this->_secrets.stage() != session::stage_t::NONE)
			// Выполняем сброс значений расписания ключей связи
			this->_secrets.clear();
		// Открытая часть ключа обмена сервера
		extension::share_t share;
		// Отказ разбора расширения приветствия
		failure = translate(extension::share(extension->data, share), context::error_t::MESSAGE);
		// Если открытую часть ключа обмена сервера разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		// Признак того, что доля ключа по выбранной сервером группе связью отправлена
		bool sent = false;
		/**
		 * Выполняем перебор мимолётных пар ключей своей стороны
		 */
		for(size_t i = 0; (i < this->_exchanges.size()) && !sent; i++)
			// Запоминаем совпадение выбранной группы с группой отправленной доли
			sent = ((this->_exchanges[i].group == share.group) && known(share.group));
		// Если сервер выбрал кривую обмена ключами, о которой его не просили
		if(!sent)
			// Выводим отказ несовпадения кривой обмена ключами
			return this->abort(context::error_t::GROUP, alert::description_t::PARAMETER);
		// Запоминаем группу обмена ключами связи
		this->_group = share.group;
		// Открытая часть ключа обмена сервера, из которой выводятся ключи связи
		const vector <uint8_t> key(share.key.data, share.key.data + share.key.size);
		// Если приветствие сервера в переписку рукопожатия добавить не удалось
		if(this->_transcript.update(message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если приветствие сервера ходу рукопожатия объявить не удалось
		if(this->_machine.accept(handshake::type_t::SERVER, session::side_t::SERVER) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Выполняем вывод ключей рукопожатия связи
		const context::error_t error = this->derive(share.group, view_t(key.data(), key.size()));
		// Если ключи рукопожатия связи вывести не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ вывода ключей рукопожатия связи
			return this->abort(error, blame(error, alert::description_t::HANDSHAKE));
		// Выводим успешность разбора приветствия сервера
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод смены ключевого материала направления связи
 *
 * @param side сторона, чьё направление связи сменяется
 * @return     отказ смены ключевого материала направления
 *
 */
context::error_t nts::internal::Engine::rotate(const session::side_t side) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если значение направления связи сменить не удалось
		if(this->_secrets.renew(side) != session::error_t::NONE)
			// Выводим отказ смены значения направления связи
			return context::error_t::SCHEDULE;
		// Отказ сохранения сменённых значений направлений для выдачи наружу
		const context::error_t kept = this->store(context::level_t::APPLICATION);
		// Если сменённые значения направлений сохранить не удалось
		if(kept != context::error_t::NONE)
			// Выводим отказ вывода ключевого материала связи
			return kept;
		// Место, в которое помещается корневой ключ направления связи
		uint8_t material[protect::PROTECT_KEY];
		// Место, в которое помещается вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
			// Выводим отказ вывода ключевого материала направления
			return context::error_t::SCHEDULE;
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		// Получаем объект защиты записей стороны связи
		protect::protection_t & protection = ((side == own) ? this->_output : this->_input);
		/**
		 * Установка ключевого материала обнуляет и счётчик записей направления: раздел
		 * 5.3 RFC 8446 велит считать записи заново от смены ключей
		 */
		const bool installed = protection.start(this->_suite, view_t(material, protect::key(this->_suite)), view_t(element, protect::block(this->_suite)));
		// Выполняем затирание вектора замены направления связи
		this->purge(element, sizeof(element));
		// Выполняем затирание корневого ключа направления связи
		this->purge(material, sizeof(material));
		// Если ключевой материал установить не удалось
		if(!installed)
			// Выводим отказ установки ключевого материала
			return context::error_t::SCHEDULE;
		// Раздел 4.2.1 RFC 9147: всякая смена ключей открывает следующую пору направления
		if(this->_transport == context::transport_t::DATAGRAMS)
			// Выводим итог заведения поры ключей направления
			return this->adopt(side, context::level_t::APPLICATION);
		// Выводим успешность установки ключевого материала направления связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятой смены ключевого материала
 *
 * @param body тело принятого сообщения смены ключевого материала
 * @return     отказ разбора смены ключевого материала
 *
 */
context::error_t nts::internal::Engine::renew(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если связь ещё не установлена либо оборвана: закрывшему свою передачу приём открыт
		if((this->_state != context::state_t::ESTABLISHED) && (this->_state != context::state_t::CLOSED))
			// Выводим отказ прихода смены ключей не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Разбираемый вид смены ключевого материала
		message::update_t update = message::update_t::NOTIFY;
		// Если сообщение смены ключевого материала разобрать не удалось
		// Итог разбора сообщения смены ключевого материала
		const message::error_t parsed = message::parse(body, update);
		/**
		 * Раздел 6 RFC 8446: негодная запись сообщения объявляется decode_error, а
		 * неизвестное значение просьбы (раздел 4.6.3) - illegal_parameter
		 */
		if(parsed != message::error_t::NONE){
			// Отказ разбора сообщения смены ключевого материала
			const context::error_t failure = translate(parsed, context::error_t::MESSAGE);
			// Выводим отказ разбора сообщения смены ключевого материала
			return this->abort(failure, blame(failure, ((parsed == message::error_t::EMPTY) ? alert::description_t::PARAMETER : alert::description_t::DECODE)));
		}
		/**
		 * Ход рукопожатия за установленной связью смену ключевого материала принимает от
		 * всякой стороны, а состояние связи сличено выше: через связь заслон этот
		 * недостижим и стоит обороною на случай расхождения состояния с ходом
		 */
		if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Выполняем смену ключевого материала направления собеседника
		const context::error_t error = this->rotate(side);
		// Если ключевой материал направления собеседника сменить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ смены ключевого материала направления
			return this->abort(error, alert::description_t::INTERNAL);
		// Сбрасываем признак испрошенной у собеседника смены ключей: ключи сменены
		this->_asked = false;
		/**
		 * Раздел 4.6.3 RFC 8446: ответная смена уходит прежде следующей записи
		 * прикладных данных, и на пачку просьб отвечает одна смена - иначе собеседник
		 * усиливал бы каждую свою просьбу целой выработкой ключей
		 */
		if(update == message::update_t::REQUEST)
			// Запоминаем, что ответная смена ключей задолжена
			this->_owed = true;
		// Выводим успешность разбора смены ключевого материала
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод вывода значения возобновления связи
 *
 * @return отказ вывода значения возобновления связи
 *
 */
context::error_t nts::internal::Engine::keeping() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки рукопожатия получить не удалось
		if(this->_transcript.digest(transcript) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::SCHEDULE;
		// Если значение возобновления связи вывести не удалось
		if(this->_secrets.resumption(view_t(transcript, this->_transcript.size())) != session::error_t::NONE)
			// Выводим отказ вывода значения расписания ключей
			return context::error_t::SCHEDULE;
		// Выводим успешность вывода значения возобновления связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятого билета возобновления связи
 *
 * @param body тело принятого сообщения билета
 * @return     отказ разбора билета возобновления связи
 *
 */
context::error_t nts::internal::Engine::accept(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если связь ещё не установлена либо оборвана: закрывшему свою передачу приём открыт
		if((this->_state != context::state_t::ESTABLISHED) && (this->_state != context::state_t::CLOSED))
			// Выводим отказ прихода билета не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Разбираемый билет возобновления связи
		message::ticket_t ticket;
		// Отказ разбора билета возобновления связи
		failure = translate(message::parse(body, ticket), context::error_t::MESSAGE);
		// Если билет возобновления связи разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора билета возобновления связи
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		/**
		 * Сторона задана здесь постоянной, и ход рукопожатия за установленной связью
		 * сличает её сам с собою: через связь заслон недостижим. Постоянная эта верна -
		 * билет от сервера, и приход его серверу отвергается разбором раньше
		 */
		if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 4.6.1 RFC 8446 кладёт сроку билета предел в семь суток и запрещает
		 * держать билет дольше: билет с большим сроком означает сервер, зовущий связь
		 * возобновляться ключом, которому давно вышел срок
		 */
		if(ticket.lifetime > LIFETIME)
			// Выводим отказ выхода срока билета за дозволенный предел
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Раздел 4.6.1 RFC 8446: нулевой срок велит билет отбросить тотчас
		if(ticket.lifetime == 0)
			// Выводим успешность разбора билета: хранить его незачем
			return context::error_t::NONE;
		// Принятый билет возобновления связи
		context::ticket_t item;
		// Устанавливаем набор шифрования связи, выдавшей билет
		item.suite = this->_suite;
		// Устанавливаем миг выдачи принятого билета
		item.moment = this->_moment;
		// Миг первичного удостоверения: у возобновлённой связи - из предъявленного билета, иначе - этот
		item.authenticated = ((this->_shared && (this->_resume.authenticated != 0)) ? this->_resume.authenticated : this->_moment);
		// Устанавливаем срок жизни принятого билета
		item.lifetime = ticket.lifetime;
		/**
		 * Выполняем перебор расширений принятого билета
		 */
		for(size_t i = 0; i < ticket.extensions.size(); i++){
			// Места, в которых объявленному расширению идти дозволено
			uint8_t places = 0;
			/**
			 * Раздел 4.2 RFC 8446 кладёт билету возобновления связи одно-единственное
			 * расширение - предел упреждающих данных, - и признаваемое расширение вне его
			 * обрывает связь извещением «illegal_parameter»
			 */
			if(placement(ticket.extensions[i].type, places) && ((places & PLACE_TICKET) == 0))
				// Выводим отказ объявления расширения не в своём сообщении
				return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			// Если расширение билета предела упреждающих данных не объявляет
			if(ticket.extensions[i].type != static_cast <uint16_t> (extension::type_t::EARLY))
				// Переходим к следующему расширению билета
				continue;
			// Отказ разбора билета возобновления связи
			failure = translate(extension::early(ticket.extensions[i].data, item.advance), context::error_t::MESSAGE);
			// Если предел упреждающих данных разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора билета возобновления связи
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
		}
		// Устанавливаем добавку к возрасту принятого билета
		item.age = ticket.age;
		// Место, в которое помещается ключ принятого билета
		uint8_t secret[schedule::SCHEDULE_WIDEST];
		// Если ключ принятого билета вывести не удалось
		if(this->_secrets.ticket(ticket.nonce, secret) != session::error_t::NONE)
			// Выводим отказ вывода ключа билета возобновления связи
			return this->abort(context::error_t::SCHEDULE, alert::description_t::INTERNAL);
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Запоминаем прикладной протокол связи, принявшей билет
			item.protocol = this->_protocol;
			// Устанавливаем признак согласования прикладных настроек связи
			item.settled = this->_settled;
			// Устанавливаем свои прикладные настройки связи
			item.settings = this->_applied;
			// Устанавливаем прикладные настройки собеседника
			item.obtained = this->_obtained;
			/**
			 * Раздел 8.2 RFC 9001: упреждающие данные будущей связи идут по параметрам
			 * переноса сервера этой связи - билет уносит их с собою
			 */
			if(this->_transport == context::transport_t::LEVELS)
				// Запоминаем параметры переноса сервера, выдавшего билет
				item.parameters = this->_received;
			// Переносим тело принятого билета возобновления связи
			item.identity.assign(ticket.data.data, ticket.data.data + ticket.data.size);
			// Переносим ключ принятого билета возобновления связи длиною в хеш набора
			item.secret.assign(secret, secret + this->_secrets.size());
			/**
			 * Сервер вправе слать билеты без счёта, а память клиента не безгранична:
			 * хранятся последние шестнадцать, старейший вытесняется с затиранием ключа
			 */
			if(this->_tickets.size() >= 16){
				// Выполняем затирание ключа вытесняемого билета
				this->purge(this->_tickets.front().secret.data(), this->_tickets.front().secret.size());
				// Выполняем вытеснение старейшего билета
				this->_tickets.erase(this->_tickets.begin());
			}
			// Добавляем принятый билет в перечень билетов связи
			this->_tickets.push_back(::move(item));
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выполняем затирание ключа принятого билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ нехватки памяти: сообщение уже снято со сборщика, связь обрывается
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
		// Выполняем затирание ключа принятого билета
		this->purge(secret, sizeof(secret));
		// Выводим успешность разбора билета возобновления связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора принятого извещения
 *
 * @param data принятое извещение
 * @return     отказ разбора принятого извещения
 *
 */
context::error_t nts::internal::Engine::notice(const view_t & data) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разбираемое извещение собеседника
		alert::alert_t alert;
		// Если извещение собеседника разобрать не удалось
		if(alert::parse(data, alert) != alert::error_t::NONE)
			// Выводим отказ разбора извещения собеседника
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		/**
		 * Решение о разрыве связи принимается по описанию извещения: раздел 6.2 RFC 8446
		 * объявляет уровень извещения в издании TLS 1.3 не имеющим значения. У изданий до
		 * 1.3 (раздел 7.2.2 RFC 5246) связь рвёт лишь смертельный уровень либо описание,
		 * объявленное смертельным всегда; предупреждение (no_renegotiation, unrecognized_name
		 * по разделу 3 RFC 6066) связь не рвёт и извещением обрыва не запоминается; до
		 * согласования издания (_version ещё нулевое) уровень судится так же - предупреждение
		 * сервера 1.2 приходит прежде его приветствия; по согласованному 1.3 всякое извещение
		 * рвёт связь независимо от уровня
		 */
		if((this->_legacy || (this->_version == 0)) && (alert.level != alert::level_t::FATAL) && !alert::grave(alert.description) && (alert.description != alert::description_t::CLOSE) && (alert.description != alert::description_t::CANCELED))
			// Выводим успешность: предупреждение принято к сведению
			return context::error_t::NONE;
		// Запоминаем извещение, принятое от собеседника
		this->_alert = alert;
		// Если извещение рвёт связь
		if(alert::fatal(alert)){
			// Запоминаем отказ, которым связь оборвана
			this->_error = context::error_t::ALERT;
			// Переводим связь в состояние обрыва
			this->_state = context::state_t::FAILED;
			// Выполняем затирание ключевого материала оборванной связи
			this->shred();
			// Выводим отказ обрыва связи собеседником
			return context::error_t::ALERT;
		}
		// Если собеседник завершил передачу данных
		if(alert.description == alert::description_t::CLOSE){
			// Запоминаем, что собеседник передачу завершил
			this->_drained = true;
			/**
			 * Раздел 6.1 RFC 8446 велит принявшему извещение о закрытии ответить своим
			 * таким же и передачу прекратить; отвечает связь сама, чтобы закрытие не
			 * зависело от того, вспомнит ли о нём тот, кто связь ведёт
			 */
			if(!this->_closed){
				// Составляем ответное извещение о завершении передачи данных
				const alert::alert_t answer(alert::level_t::WARNING, alert::description_t::CLOSE);
				// Место, в которое записывается ответное извещение
				uint8_t buffer[alert::ALERT_LENGTH];
				// Если ответное извещение записать удалось
				if(alert::build(answer, buffer) == alert::error_t::NONE)
					// Выполняем складывание ответного извещения в накопитель отправляемых байтов
					this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
				// Запоминаем, что своя передача завершена
				this->_closed = true;
			}
			// Переводим связь в состояние закрытия
			this->_state = context::state_t::CLOSED;
		}
		// Выводим успешность разбора извещения собеседника
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора принятого сообщения рукопожатия
 *
 * @param type    вид принятого сообщения рукопожатия
 * @param body    тело принятого сообщения рукопожатия
 * @param message принятое сообщение рукопожатия вместе с обвязкой
 * @return        отказ разбора сообщения рукопожатия
 *
 */
context::error_t nts::internal::Engine::handle(const handshake::type_t type, const view_t & body, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Если связь ведётся изданием TLS 1.2: порядок сообщений там иной
		if(this->_legacy)
			// Выводим итог разбора сообщения рукопожатия издания TLS 1.2
			return this->legacy(type, body, message);
		// Раздел 4.2.1 RFC 6347: просьба о подтверждении адреса приходит клиенту до согласования издания
		if(type == handshake::type_t::VERIFY_REQUEST)
			// Выводим итог разбора просьбы о подтверждении адреса
			return this->queried(body);
		// Если принята просьба о пересогласовании HelloRequest издания TLS 1.2
		if(type == handshake::type_t::HELLO_REQUEST){
			/**
			 * Раздел 7.4.1.1 RFC 5246: по ходу рукопожатия клиент просьбу пропускает; до
			 * приветствия сервера издание ещё не согласовано, и просьба законна лишь клиенту,
			 * издание 1.2 дозволяющему, лишь переносом записями и лишь с пустым телом. Изданию
			 * 1.3 вид ноль неведом (раздел 4 RFC 8446), и всюду прочее - unexpected_message
			 */
			if(this->_server || (this->_transport != context::transport_t::RECORDS) || (this->_lowest > LEGACY) || (this->_version != 0))
				// Выводим отказ сообщения не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Раздел 7.4.1.1 RFC 5246: тело просьбы пусто
			if(body.size > 0)
				// Выводим отказ лишних байтов за телом сообщения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			// Выводим успешность: просьба пропущена и в переписку не легла
			return context::error_t::NONE;
		}
		/**
		 * За установленной связью законны лишь смена ключей и билеты: прочее
		 * отвергается до разбора тела, чтобы чужая цепочка не подменила принятую.
		 * Закрытая связь сюда доходит лишь закрывшей свою передачу: принятое за
		 * извещением собеседника о закрытии пропускается раньше разбора
		 */
		if(((this->_state == context::state_t::ESTABLISHED) || (this->_state == context::state_t::CLOSED)) && (type != handshake::type_t::UPDATE) && (type != handshake::type_t::TICKET))
			// Выводим отказ сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 4.5 RFC 8446: сервер, принявший упреждающие данные, ждёт их конца
		 * прежде всякого иного сообщения рукопожатия - иначе завершение клиента
		 * пришло бы ключами упреждения. Под QUIC конца упреждающих данных нет (раздел
		 * 8.3 RFC 9001): их поток закрывается самим переносом, и заслон этот там не стоит
		 */
		if(this->_server && this->_earlying && (type != handshake::type_t::EARLY) && (this->_transport == context::transport_t::RECORDS))
			// Выводим отказ сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 6 RFC 9001 запрещает под QUIC смену ключей сообщением KeyUpdate, а раздел
		 * 8.3 - конец упреждающих данных: то и другое там означает собеседника, ведущего
		 * связь по TLS поверх потока, и обрывает её извещением unexpected_message
		 */
		if((this->_transport == context::transport_t::LEVELS) && ((type == handshake::type_t::UPDATE) || (type == handshake::type_t::EARLY)))
			// Выводим отказ сообщения, переносу по уровням не положенного
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Раздел 5.6 RFC 9147: конца упреждающих данных у DTLS 1.3 нет вовсе
		if((this->_transport == context::transport_t::DATAGRAMS) && (type == handshake::type_t::EARLY))
			// Выводим отказ сообщения, переносу дейтаграммами не положенного
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если принят билет возобновления связи
		if(type == handshake::type_t::TICKET)
			// Выводим итог разбора билета возобновления связи
			return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->accept(body));
		// Если принята смена ключевого материала собеседника
		if(type == handshake::type_t::UPDATE)
			// Выводим итог разбора смены ключевого материала
			return this->renew(body);
		// Если принято приветствие стороны связи
		if(type == handshake::type_t::CLIENT)
			// Выводим итог разбора приветствия клиента
			return (this->_server ? this->incoming(body, message) : this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED));
		// Если принято приветствие сервера
		if(type == handshake::type_t::SERVER)
			// Выводим итог разбора приветствия сервера
			return (this->_server ? this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED) : this->outgoing(body, message));
		// Отказ разбора принятого сообщения рукопожатия
		context::error_t error = context::error_t::NONE;
		/**
		 * Черновик draft-vvv-tls-alps: по согласованным настройкам за завершением сервера
		 * первым идёт сообщение защищённых расширений клиента, и иное сообщение прежде него
		 * выдаёт клиента, настроек не пославшего
		 */
		if(this->_server && this->_settled && !this->_accepted && !this->_stated && (type != handshake::type_t::EXTENSIONS))
			// Выводим отказ сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Выполняем определение вида принятого сообщения рукопожатия
		 */
		switch(static_cast <uint8_t> (type)){
			// Если приняты защищённые расширения стороны
			case static_cast <uint8_t> (handshake::type_t::EXTENSIONS): {
				// Если связь ведётся стороной сервера
				if(this->_server){
					/**
					 * Черновик draft-vvv-tls-alps: защищённые расширения клиента идут лишь по
					 * согласованным настройкам, лишь при отвергнутом упреждении и лишь однажды
					 */
					if(!this->_settled || this->_accepted || this->_stated)
						// Выводим отказ сообщения не в свой черёд
						return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
					// Перечень видов расширений, объявленных клиентом
					vector <uint16_t> kinds;
					// Отказ разбора перечня защищённых расширений клиента
					failure = enumerate(body, kinds);
					// Если перечень защищённых расширений клиента разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора защищённых расширений клиента
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Тело прикладных настроек клиента
					view_t stated;
					// Если настроек своей точкой кода клиент не объявил
					if(!announced(body, this->_codepoint, stated))
						// Выводим отказ отсутствия обязательного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::MISSING);
					// Иных расширений сообщению клиента не положено
					if(kinds.size() != 1)
						// Выводим отказ объявления непрошенного расширения
						return this->abort(context::error_t::EXTENSION, alert::description_t::EXTENSION);
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем настройки клиента
						this->_obtained.assign(stated.data, stated.data + stated.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
					// Запоминаем, что защищённые расширения клиента прошли по связи
					this->_stated = true;
					// Выходим из разбора
					break;
				}
				// Перечень видов расширений, объявленных сервером
				vector <uint16_t> types;
				// Отказ разбора перечня защищённых расширений сервера
				failure = enumerate(body, types);
				// Если перечень защищённых расширений сервера разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора защищённых расширений сервера
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор расширений, объявленных сервером
				 */
				for(size_t i = 0; i < types.size(); i++){
					// Места, в которых объявленному расширению идти дозволено
					uint8_t places = 0;
					/**
					 * Раздел 4.2 RFC 8446 отводит защищённым расширениям свой перечень
					 * видов, и признаваемое расширение вне его обрывает связь извещением
					 * «illegal_parameter». Заслон этот НЕ покрывается сверкой с
					 * предложенным ниже: открытая часть ключа обмена, издание протокола,
					 * заранее разделённый ключ, способы обмена им, метка возврата состояния
					 * и схемы подписи связью предлагаются все, а защищённым расширениям не
					 * положено ни одно из них
					 */
					if(placement(types[i], places) && ((places & PLACE_GUARDED) == 0))
						// Выводим отказ объявления расширения не в своём сообщении
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Признак того, что объявленное сервером расширение связью предлагалось
					bool suitable = false;
					/**
					 * Выполняем перебор расширений, предложенных связью приветствием
					 */
					for(size_t j = 0; (j < this->_offered.size()) && !suitable; j++)
						// Запоминаем, предлагалось ли объявленное сервером расширение связью
						suitable = (types[i] == this->_offered[j]);
					/**
					 * Раздел 4.2 RFC 8446 велит клиенту оборваться на расширении, которого
					 * он не просил, извещением «unsupported_extension»: ответ на
					 * непрошенное означает, что сервер отвечает не тому приветствию
					 */
					if(!suitable)
						// Выводим отказ объявления непрошенного расширения
						return this->abort(context::error_t::EXTENSION, alert::description_t::EXTENSION);
				}
				// Тела расширений предела длины записи, присланных сервером
				view_t bound, fragment;
				// Если сервер подтвердил предел record_size_limit (RFC 8449)
				if(announced(body, static_cast <uint16_t> (extension::type_t::LIMIT), bound)){
					// Если тело расширения не двухбайтовое
					if(bound.size != 2)
						// Выходим с ошибкой разбора
						return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
					// Применяем присланный предел к отправке
					const context::error_t bounded = this->bounding(static_cast <uint16_t> ((static_cast <uint16_t> (bound.data[0]) << 8) | bound.data[1]), false);
					// Если предел не принят
					if(bounded != context::error_t::NONE)
						// Выводим ошибку
						return bounded;
				}
				// Если сервер подтвердил длину max_fragment_length (раздел 4 RFC 6066)
				if(announced(body, static_cast <uint16_t> (extension::type_t::FRAGMENT), fragment)){
					// Если тело расширения не однобайтовое
					if(fragment.size != 1)
						// Выходим с ошибкой разбора
						return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
					// Применяем присланный код длины к обеим сторонам
					const context::error_t fragmented = this->fragmenting(fragment.data[0], false);
					// Если код не принят
					if(fragmented != context::error_t::NONE)
						// Выводим ошибку
						return fragmented;
				}
				// Запасные конфигурации ECH сервера
				view_t retrying;
				// Тело расширения вида сертификата сервера, присланного сервером
				view_t certtype;
				// Раздел 4.2.1 RFC 7250: сервер, выбравший вид сертификата, объявляет его одним элементом
				if(announced(body, static_cast <uint16_t> (extension::type_t::SERVER_CERT_TYPE), certtype)){
					// Перечень видов сертификатов, объявленных сервером
					vector <extension::cert_t> kinds;
					// Отказ разбора расширения вида сертификата сервера
					failure = translate(extension::certtypes(certtype, kinds), context::error_t::MESSAGE);
					// Если виды сертификатов, объявленные сервером, разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора защищённых расширений сервера
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Если сервер объявил не один вид сертификата
					if(kinds.size() != 1)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Если сервер выбрал RawPublicKey
					if(kinds[0] == extension::cert_t::RAW)
						// Запоминаем согласованный вид сертификата сервера
						this->_certtype = extension::cert_t::RAW;
				}
				// Раздел 7.1 RFC 9849: сервер, отвергший ECH, шлёт retry_configs защищённым расширением
				if(announced(body, ech::ECH_EXTENSION, retrying)){
					// Принявший ECH сервер расширения не шлёт: раздел 7.1
					if(this->_ech == ech_t::ACCEPTED)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем запасные конфигурации как записаны
						this->_retries.assign(retrying.data, retrying.data + retrying.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
				}
				// Тело расширения параметров переноса QUIC сервера
				view_t transport;
				// Признак того, что параметры переноса сервером объявлены
				const bool carried = announced(body, TRANSPORT, transport);
				/**
				 * Раздел 8.2 RFC 9001: под QUIC параметры переноса сервера обязательны, и
				 * защищённые расширения без них обрывают связь извещением missing_extension.
				 * Переносу записями расширение это не предлагалось, и приход его отвергнут
				 * выше как непрошенное
				 */
				if((this->_transport == context::transport_t::LEVELS) && !carried)
					// Выводим отказ отсутствия обязательного расширения
					return this->abort(context::error_t::PARAMETERS, alert::description_t::MISSING);
				// Если параметры переноса сервером объявлены
				if(carried){
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Переносим параметры переноса собеседника как есть
						this->_received.assign(transport.data, transport.data + transport.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
					// Запоминаем, что параметры переноса собеседника приняты
					this->_acquired = true;
				}
				/**
				 * Приём упреждающих данных сервер объявляет расширением: раздел 4.2.10
				 * RFC 8446 велит объявлять его именно здесь, а не приветствием
				 */
				/**
				 * Раздел 4.2.11 RFC 8446: приём упреждающих данных возможен лишь при
				 * выбранном сервером заранее разделённом ключе, иначе - illegal_parameter
				 */
				if(!this->_shared && declared(body, static_cast <uint16_t> (extension::type_t::EARLY)))
					// Выводим отказ приёма упреждения без заранее разделённого ключа
					return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
				// Запоминаем, приняты ли упреждающие данные сервером
				this->_accepted = (this->_shared && this->_earlying && declared(body, static_cast <uint16_t> (extension::type_t::EARLY)));
				// Запоминаем, что решение сервера об упреждающих данных получено
				this->_judged = true;
				// Если упреждающие данные приняты, прикладные настройки наследуются от билета
				if(this->_accepted){
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Наследуем свои настройки от билета
						this->_applied = this->_resume.settings;
						// Наследуем настройки сервера от билета
						this->_obtained = this->_resume.obtained;
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
					// Наследуем признак согласования от билета
					this->_settled = this->_resume.settled;
				}
				/**
				 * Отвергнутые упреждающие данные пропали: связь возвращается к ключам
				 * рукопожатия, а посланное ими сервер не прочтёт вовсе
				 */
				if(!this->_accepted)
					// Прекращаем ход упреждающих данных связи
					this->_earlying = false;
				// Тело расширения выбранного сервером прикладного протокола
				view_t chosen;
				// Если прикладной протокол сервером объявлен
				if(announced(body, static_cast <uint16_t> (extension::type_t::PROTOCOLS), chosen)){
					// Название прикладного протокола, выбранного сервером
					string selected;
					// Отказ разбора защищённых расширений сервера
					failure = translate(extension::protocol(chosen, selected), context::error_t::MESSAGE);
					// Если выбранный сервером прикладной протокол разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора защищённых расширений сервера
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Признак того, что выбранный протокол связью предлагался
					bool suitable = false;
					/**
					 * Выполняем перебор прикладных протоколов, предложенных связью
					 */
					for(size_t i = 0; (i < this->_protocols.size()) && !suitable; i++)
						// Запоминаем, предлагался ли выбранный сервером протокол связью
						suitable = (selected.compare(this->_protocols[i]) == 0);
					/**
					 * Раздел 3.2 RFC 7301: сервер выбирает лишь из того, что ему предложено,
					 * и протокол вне предложения принимать нельзя - им связь пошла бы
					 * протоколом, которого сторона не понимает
					 */
					if(!suitable)
						// Выводим отказ отсутствия общего прикладного протокола
						return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем выбранный сторонами прикладной протокол
						this->_protocol = ::move(selected);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
				}
				// Тело расширения выбранного сервером профиля защиты RTP
				view_t picked;
				// Если профиль защиты RTP сервером объявлен
				if(announced(body, static_cast <uint16_t> (extension::type_t::PROFILES), picked)){
					// Перечень профилей защиты RTP, выбранный сервером
					vector <uint16_t> offer;
					// Отказ разбора защищённых расширений сервера
					failure = translate(extension::profiles(picked, offer), context::error_t::MESSAGE);
					// Если выбранный сервером профиль защиты RTP разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора защищённых расширений сервера
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Раздел 4.1.1 RFC 5764: сервер выбирает ровно один профиль из предложенных
					if(offer.size() != 1)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Признак того, что выбранный профиль связью предлагался
					bool suitable = false;
					/**
					 * Выполняем перебор профилей защиты RTP, предложенных связью
					 */
					for(size_t i = 0; (i < this->_srtps.size()) && !suitable; i++)
						// Запоминаем, предлагался ли выбранный сервером профиль связью
						suitable = (offer[0] == this->_srtps[i]);
					// Профиль вне предложения принимать нельзя, как и протокол вне предложения (раздел 3.2 RFC 7301)
					if(!suitable)
						// Выводим отказ отсутствия общего профиля защиты RTP
						return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
					// Запоминаем выбранный сторонами профиль защиты RTP
					this->_srtp = offer[0];
				}
				/**
				 * Раздел 8.1 RFC 9001: под QUIC прикладной протокол обязателен, и сервер, его
				 * не выбравший, обрывает связь извещением no_application_protocol
				 */
				if((this->_transport == context::transport_t::LEVELS) && this->_protocol.empty())
					// Выводим отказ отсутствия общего прикладного протокола
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
				// Тело расширения прикладных настроек сервера
				view_t offered;
				// Если прикладные настройки сервером объявлены
				if(announced(body, this->_codepoint, offered)){
					// Свои настройки выбранного протокола
					view_t applied;
					/**
					 * Черновик draft-vvv-tls-alps: настройки идут лишь при выбранном протоколе, лишь
					 * для протокола с объявленными настройками и лишь при отвергнутом упреждении -
					 * при принятом они унаследованы билетом, и расширение сервер обязан опустить
					 */
					if(this->_protocol.empty() || !this->pick(this->_protocol, applied) || this->_accepted)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем свои настройки выбранного протокола
						this->_applied.assign(applied.data, applied.data + applied.size);
						// Запоминаем настройки сервера
						this->_obtained.assign(offered.data, offered.data + offered.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
					// Запоминаем, что прикладные настройки согласованы
					this->_settled = true;
				}
			} break;
			// Если принят конец упреждающих данных клиента
			case static_cast <uint8_t> (handshake::type_t::EARLY): {
				// Если связь ведётся стороной клиента
				if(!this->_server)
					// Выводим отказ прихода сообщения не от той стороны
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				/**
				 * Раздел 4.5 RFC 8446: конец упреждающих данных закрывает поток, идущий
				 * ключами упреждения, и слать его клиенту дозволено лишь тогда, когда
				 * сервер упреждающие данные принял. Не принял - потока нет, закрывать
				 * нечего, а сообщение это идёт уже ключами рукопожатия и означает
				 * собеседника, ведущего свой счёт ходу связи
				 */
				if(!this->_earlying)
					// Выводим отказ прихода конца упреждающих данных не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				/**
				 * Раздел 4.5 RFC 8446 кладёт концу упреждающих данных пустое тело: всё,
				 * что за ним идёт, объявляется извещением «decode_error»
				 */
				if(body.size > 0)
					// Выводим отказ лишних байтов за телом сообщения
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				// Прекращаем приём упреждающих данных клиента
				this->_earlying = false;
			} break;
			// Если принят запрос подлинности клиента
			case static_cast <uint8_t> (handshake::type_t::REQUEST): {
				/**
				 * Раздел 4.3.2 RFC 8446: сервер, подтверждающий себя заранее разделённым
				 * ключом, запрос подлинности клиента слать не вправе
				 */
				if(this->_shared)
					// Выводим отказ запроса подлинности на заранее разделённом ключе
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор запроса подлинности клиента
				error = this->requesting(body);
				// Если запрос подлинности клиента разобрать не удалось
				if(error != context::error_t::NONE)
					/**
					 * Раздел 4.3.2 RFC 8446: отсутствие схем подписи объявляется извещением
					 * «missing_extension», расширение не в своём сообщении -
					 * «illegal_parameter», а негодная запись запроса - «decode_error»
					 */
					return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::MISSING :
						((error == context::error_t::EXTENSION) ? alert::description_t::PARAMETER : alert::description_t::DECODE))));
				// Запоминаем, что подлинность клиента запрошена сервером
				this->_requested = true;
			} break;
			// Если принята сжатая цепочка сертификатов собеседника
			case static_cast <uint8_t> (handshake::type_t::COMPRESSED): {
				/**
				 * Разделы 2 и 4.2.11 RFC 8446: связь, подтверждённая заранее разделённым
				 * ключом, сертификатов не несёт - цепочка на ней есть сообщение не в свой черёд
				 */
				if(this->_shared)
					// Выводим отказ цепочки на заранее разделённом ключе
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				/**
				 * Раздел 4 RFC 8879: сжатую цепочку сторона принимает лишь после того, как
				 * сама объявила алгоритмы; сжатая цепочка без объявления есть сообщение не
				 * в свой черёд и обрывает связь извещением «unexpected_message»
				 */
				if(this->_codecs.empty())
					// Выводим отказ сжатой цепочки без объявления алгоритмов
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Накопитель, в который помещается цепочка сертификатов после распаковки
				vector <uint8_t> plain;
				// Выполняем распаковку сжатой цепочки сертификатов
				error = this->unpack(body, plain);
				// Если сжатую цепочку сертификатов распаковать не удалось
				if(error != context::error_t::NONE)
					/**
					 * Раздел 4 RFC 8879: алгоритм вне объявленных объявляется извещением
					 * «illegal_parameter», а несошедшаяся длина, отказ распаковки и выход за
					 * предел - извещением «bad_certificate»
					 */
					return this->abort(error, blame(error, ((error == context::error_t::COMPRESSION) ? alert::description_t::PARAMETER :
						((error == context::error_t::MESSAGE) ? alert::description_t::DECODE : alert::description_t::BADCERT))));
				/**
				 * Цепочка после распаковки разбирается тем же путём, что и несжатая: сжатие
				 * покрывает лишь перенос сообщения, а подлинность судится по содержимому
				 */
				error = this->chain(view_t(plain.data(), plain.size()));
				// Если цепочку сертификатов собеседника разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора цепочки теми же извещениями, что и у несжатой
					/**
					 * Раздел 4.4.2.1 RFC 8446 и раздел 8 RFC 6066: негодный ответ о состоянии
					 * либо отозванный сертификат - «bad_certificate_status_response»
					 */
					return this->abort(error, blame(error, ((error == context::error_t::EXTENSION) ? alert::description_t::EXTENSION :
						((error == context::error_t::STATUS) ? alert::description_t::STATUS :
						(((error == context::error_t::CERTIFICATE) || (error == context::error_t::TIMESTAMPS)) ? alert::description_t::DECODE : alert::description_t::BADCERT)))));
			} break;
			// Если принята цепочка сертификатов собеседника
			case static_cast <uint8_t> (handshake::type_t::CERTIFICATE): {
				/**
				 * Разделы 2 и 4.2.11 RFC 8446: связь, подтверждённая заранее разделённым
				 * ключом, сертификатов не несёт - цепочка на ней есть сообщение не в свой черёд
				 */
				if(this->_shared)
					// Выводим отказ цепочки на заранее разделённом ключе
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор цепочки сертификатов собеседника
				error = this->chain(body);
				// Если цепочку сертификатов собеседника разобрать не удалось
				if(error != context::error_t::NONE)
					/**
					 * Раздел 4.2 RFC 8446: непрошенное расширение объявляется извещением
					 * «unsupported_extension», негодная цепочка - «bad_certificate», а
					 * пустая цепочка сервера по разделу 4.4.2.4 - «decode_error»
					 */
					/**
					 * Раздел 4.4.2.1 RFC 8446 и раздел 8 RFC 6066: негодный ответ о состоянии
					 * либо отозванный сертификат - «bad_certificate_status_response»
					 */
					return this->abort(error, blame(error, ((error == context::error_t::EXTENSION) ? alert::description_t::EXTENSION :
						((error == context::error_t::STATUS) ? alert::description_t::STATUS :
						(((error == context::error_t::CERTIFICATE) || (error == context::error_t::TIMESTAMPS)) ? alert::description_t::DECODE : alert::description_t::BADCERT)))));
			} break;
			// Если принята подпись владения ключом собеседника
			case static_cast <uint8_t> (handshake::type_t::VERIFY): {
				/**
				 * Подпись владения ключом сличается с перепиской до этого сообщения:
				 * себя самоё подпись не покрывает
				 */
				error = this->possession(body);
				// Если подпись владения ключом не сошлась
				if(error != context::error_t::NONE)
					/**
					 * Раздел 4.4.3 RFC 8446: несошедшаяся подпись объявляется извещением
					 * «decrypt_error», а непригодная схема подписи - «illegal_parameter»
					 */
					return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::PARAMETER : alert::description_t::DECRYPT)));
			} break;
			// Если принято завершение рукопожатия собеседником
			case static_cast <uint8_t> (handshake::type_t::FINISHED): {
				/**
				 * Завершение рукопожатия сличается с перепиской до этого сообщения:
				 * себя самоё завершение не покрывает
				 */
				/**
				 * Раздел 4.4.2 RFC 8446: во всяком рукопожатии, кроме связи на заранее
				 * разделённом ключе, сервер обязан предъявить сертификат, и завершение без
				 * него - сообщение не в свой черёд. Ключ завершения выводится из обмена,
				 * который посредник знает как сторона обмена, оттого сходимость завершения
				 * подлинности сервера не заменяет
				 */
				if(!this->_server && !this->_shared && this->_peer.empty())
					// Выводим отказ завершения без подлинности сервера
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				/**
				 * Раздел 4.4.3 RFC 8446: за непустым сертификатом клиента обязана идти
				 * подпись владения ключом; завершение без неё оставило бы цепочку
				 * недоказанной
				 */
				if(this->_server && !this->_peer.empty() && !this->_machine.certified())
					// Выводим отказ завершения без подписи владения
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Проверяем завершение рукопожатия собеседника
				error = this->confirm(body);
				// Если завершение рукопожатия собеседника не сошлось
				if(error != context::error_t::NONE)
					// Выводим отказ схождения завершения рукопожатия
					return this->abort(error, blame(error, alert::description_t::DECRYPT));
			} break;
			// Если принято сообщение, связью не поддержанное
			default: return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		}
		// Если сообщение в переписку рукопожатия добавить не удалось
		if(this->_transcript.update(message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		// Если сообщение ходу рукопожатия объявить не удалось
		/**
		 * Раздел 4 RFC 8879: сжатая цепочка сертификатов идёт вместо обычной и занимает её
		 * место в ходе рукопожатия, оттого ходу она объявляется цепочкой сертификатов
		 */
		if(this->_machine.accept(((type == handshake::type_t::COMPRESSED) ? handshake::type_t::CERTIFICATE : type), side) != flow::error_t::NONE)
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если принято не завершение рукопожатия собеседником
		if(type != handshake::type_t::FINISHED)
			// Выводим успешность разбора сообщения рукопожатия
			return context::error_t::NONE;
		// Если связь ведётся стороной клиента
		if(!this->_server){
			// Выполняем вывод ключей прикладных данных связи
			error = this->mature();
			// Если ключи прикладных данных вывести не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ вывода ключей прикладных данных
				return this->abort(error, alert::description_t::INTERNAL);
			// Выполняем согласование ключевого материала защиты записей
			error = this->refresh();
			// Если ключевой материал защиты записей согласовать не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ согласования ключевого материала
				return this->abort(error, alert::description_t::INTERNAL);
			// Если упреждающие данные связи приняты сервером
			if(this->_earlying){
				/**
				 * Конец упреждающих данных уходит их же ключами: раздел 4.5 RFC 8446 велит
				 * закрывать поток теми ключами, какими он и шёл. Под QUIC сообщение это не
				 * посылается (раздел 8.3 RFC 9001): поток упреждения закрывает сам перенос
				 */
				if(this->_transport == context::transport_t::RECORDS){
					// Выполняем отправку конца упреждающих данных
					error = this->send(handshake::type_t::EARLY, view_t(nullptr, 0));
					// Если конец упреждающих данных отправить не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ отправки конца упреждающих данных
						return this->abort(error, alert::description_t::INTERNAL);
				}
				// Прекращаем ход упреждающих данных связи
				this->_earlying = false;
			}
			// Если прикладные настройки согласованы и упреждение не принято
			if(this->_settled && !this->_accepted){
				// Выполняем отправку защищённых расширений клиента
				error = this->stating();
				// Если защищённые расширения клиента отправить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ отправки защищённых расширений клиента
					return this->abort(error, alert::description_t::INTERNAL);
			}
			// Если подлинность клиента запрошена сервером
			if(this->_requested){
				// Выполняем отправку подтверждения подлинности клиента
				error = this->authenticate();
				// Если подтверждение подлинности клиента отправить не удалось
				if(error != context::error_t::NONE)
					/**
					 * Раздел 4.4.3 RFC 8446: отсутствие схемы подписи, признаваемой обеими
					 * сторонами, есть несхождение сторон, а не внутренний отказ
					 */
					return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL)));
			}
			// Выполняем отправку завершения рукопожатия клиентом
			error = this->complete();
			// Если завершение рукопожатия клиентом отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки завершения рукопожатия
				return this->abort(error, alert::description_t::INTERNAL);
			// Выполняем вывод значения возобновления связи
			error = this->keeping();
			// Если значение возобновления связи вывести не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ вывода значения возобновления связи
				return this->abort(error, alert::description_t::INTERNAL);
		// Если связь ведётся стороной сервера
		} else {
			/**
			 * Под QUIC конец упреждающих данных не приходит, и поток упреждения закрывает
			 * завершение клиента: за ним клиент ведёт связь ключами прикладных данных
			 */
			if(this->_transport == context::transport_t::LEVELS)
				// Прекращаем приём упреждающих данных клиента
				this->_earlying = false;
			// Выполняем согласование ключевого материала защиты записей
			error = this->refresh();
			// Если ключевой материал защиты записей согласовать не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ согласования ключевого материала
				return this->abort(error, alert::description_t::INTERNAL);
			// Выполняем вывод значения возобновления связи
			error = this->keeping();
			// Если значение возобновления связи вывести не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ вывода значения возобновления связи
				return this->abort(error, alert::description_t::INTERNAL);
		}
		// Если рукопожатие связи завершено обеими сторонами
		if(this->_machine.established()){
			// Переводим связь в состояние установленной связи
			this->_state = context::state_t::ESTABLISHED;
			// Понижаем сборщику сообщений предел до положенного установленной связи
			this->_messages.limit(AFTERMATH);
			/**
			 * Раздел 6.1.7 RFC 9849: сервер ECH отверг - рукопожатие сложено по публичному имени,
			 * и связь обрывается извещением ech_required прежде всяких прикладных данных;
			 * запасные конфигурации сервера остаются потребителю
			 */
			if(!this->_server && (this->_ech == ech_t::REJECTED))
				// Выводим отказ отвергнутого ECH
				return this->abort(context::error_t::ECH, alert::description_t::ECH_REQUIRED);
		}
		// Выводим успешность разбора сообщения рукопожатия
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод получения состояния связи
 *
 * @return состояние связи
 *
 */
context::state_t nts::internal::Engine::state() const noexcept {
	// Выводим состояние связи
	return this->_state;
}
/**
 * @brief Метод получения отказа, которым связь оборвана
 *
 * @return отказ, которым связь оборвана
 *
 */
context::error_t nts::internal::Engine::error() const noexcept {
	// Выводим отказ, которым связь оборвана
	return this->_error;
}
/**
 * @brief Метод получения извещения, которым связь оборвана
 *
 * @return извещение, которым связь оборвана
 *
 */
const alert::alert_t & nts::internal::Engine::alert() const noexcept {
	// Выводим извещение, которым связь оборвана
	return this->_alert;
}
/**
 * @brief Метод получения набора шифрования связи
 *
 * @return согласованный сторонами набор шифрования
 *
 */
protect::suite_t nts::internal::Engine::suite() const noexcept {
	// Выводим согласованный сторонами набор шифрования
	return this->_suite;
}
/**
 * @brief Метод получения группы обмена ключами связи
 *
 * @return группа, по которой сложилось общее значение
 *
 */
extension::group_t nts::internal::Engine::group() const noexcept {
	// Пока рукопожатие не завершено, группа ещё не согласована: у клиента поле держит группу последней доли
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::HANDSHAKE))
		// Выводим отсутствие согласованной группы
		return extension::group_t::NONE;
	// Выводим группу обмена ключами связи
	return this->_group;
}
/**
 * @brief Метод получения цепочки сертификатов собеседника
 *
 * @return цепочка сертификатов, предъявленная собеседником
 *
 */
const vector <vector <uint8_t>> & nts::internal::Engine::peer() const noexcept {
	// Выводим цепочку сертификатов, предъявленную собеседником
	return this->_peer;
}
/**
 * @brief Метод получения имени узла связи
 *
 * @return имя узла, запрошенное клиентом у сервера
 *
 */
const string & nts::internal::Engine::name() const noexcept {
	// Выводим имя узла, запрошенное клиентом у сервера
	return this->_name;
}
/**
 * @brief Метод получения прикладного протокола связи
 *
 * @return прикладной протокол, выбранный сторонами связи
 *
 */
const string & nts::internal::Engine::protocol() const noexcept {
	// Выводим прикладной протокол, выбранный сторонами связи
	return this->_protocol;
}
/**
 * @brief Метод установки профилей защиты RTP, предлагаемых связью
 *
 * @param profiles предлагаемые профили защиты RTP
 *
 */
void nts::internal::Engine::profiles(const vector <uint16_t> & profiles) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим перечень предлагаемых профилей защиты RTP
		this->_srtps = profiles;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем перечень предлагаемых профилей защиты RTP
		this->_srtps.clear();
	}
}
/**
 * @brief Метод получения профиля защиты RTP, выбранного сторонами связи
 *
 * @return выбранный профиль защиты RTP; 0, если профиль не выбран
 *
 */
uint16_t nts::internal::Engine::profile() const noexcept {
	// Выводим профиль защиты RTP, выбранный сторонами связи
	return this->_srtp;
}
/**
 * @brief Метод установки запроса состояния сертификата собеседника
 *
 * @param inquire запрашивается ли состояние сертификата собеседника
 *
 */
void nts::internal::Engine::inquire(const bool inquire) noexcept {
	// Запоминаем, запрашивается ли состояние сертификата собеседника
	this->_inquiring = inquire;
}
/**
 * @brief Метод установки ответа о состоянии своего сертификата
 *
 * @param response запись ответа OCSP, пустая снимает ответ
 * @param index    место сертификата в своей цепочке
 *
 */
void nts::internal::Engine::staple(const vector <uint8_t> & response, const size_t index) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Место сертификата не может быть дальше дозволенной длины цепочки: ответ вне её
		 * никогда не выдаётся, а перечень под него занимал бы память по чужому числу
		 */
		if(index >= trust::TRUST_DEPTH)
			// Выходим из метода: ответу места нет
			return;
		// Если места под ответ в перечне ещё нет
		if(index >= this->_staples.size())
			// Расширяем перечень ответов до нужного места
			this->_staples.resize(index + 1);
		// Устанавливаем ответ о состоянии сертификата
		this->_staples[index] = response;
		/**
		 * Выполняем усечение перечня по последнему непустому ответу
		 */
		while(!this->_staples.empty() && this->_staples.back().empty())
			// Снимаем пустой ответ с конца перечня
			this->_staples.pop_back();
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Запоминаем нехватку памяти до заведения связи
		this->_starved = true;
	}
}
/**
 * @brief Метод установки запроса меток времени сертификата собеседника
 *
 * @param request запрашиваются ли метки времени сертификата собеседника
 *
 */
void nts::internal::Engine::timestamps(const bool request) noexcept {
	// Устанавливаем признак запроса меток времени
	this->_stamping = request;
}
/**
 * @brief Метод установки перечня меток времени своего сертификата для выдачи по запросу
 *
 * @param list перечень меток времени как записан (SignedCertificateTimestampList)
 *
 */
void nts::internal::Engine::timestamps(const vector <uint8_t> & list) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем перечень меток времени
		this->_stamps = list;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс перечня
		this->_stamps.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод получения перечня меток времени сертификата собеседника
 *
 * @return перечень меток времени как записан, пустой без ответа
 *
 */
const vector <uint8_t> & nts::internal::Engine::timestamps() const noexcept {
	// Выводим перечень меток времени
	return this->_timestamps;
}
/**
 * @brief Метод установки перечня доверенных удостоверяющих центров для запроса подлинности
 *
 * @param names имена как записаны (DER X.501 Name)
 *
 */
void nts::internal::Engine::authorities(const vector <vector <uint8_t>> & names) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем перечень доверенных центров
		this->_trusted = names;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс перечня
		this->_trusted.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод получения перечня доверенных удостоверяющих центров из запроса подлинности
 *
 * @return имена как записаны, пусто без запроса либо без перечня
 *
 */
const vector <vector <uint8_t>> & nts::internal::Engine::authorities() const noexcept {
	// Выводим перечень доверенных центров
	return this->_authorities;
}
/**
 * @brief Метод установки выработки следующего протокола NPN
 *
 * @param negotiation предлагается ли (объявляется ли) выработка NPN
 *
 */
void nts::internal::Engine::negotiation(const bool negotiation) noexcept {
	// Устанавливаем признак выработки NPN
	this->_negotiating = negotiation;
}
/**
 * @brief Метод проверки выработки протокола связи через NPN
 *
 * @return признак того, что протокол связи взят выработкой NPN
 *
 */
bool nts::internal::Engine::negotiated() const noexcept {
	// Выводим признак выработки NPN
	return this->_negotiated;
}
/**
 * @brief Метод отправки сообщения NextProtocol выработки NPN клиентом издания TLS 1.2
 *
 * @return отказ отправки сообщения
 *
 */
context::error_t nts::internal::Engine::announcing() noexcept {
	// Если связь ведётся сервером либо выработка не состоялась
	if(this->_server || !this->_negotiated)
		// Выводим успешность: слать нечего
		return context::error_t::NONE;
	// Объект составителя тела сообщения
	field::builder_t builder;
	// Отказ составления
	field::error_t outcome = builder.open(1);
	// Если имя открыто
	if(outcome == field::error_t::NONE)
		// Записываем выбранный протокол
		outcome = builder.bytes(view_t(reinterpret_cast <const uint8_t *> (this->_protocol.data()), this->_protocol.size()));
	// Если имя записано
	if(outcome == field::error_t::NONE)
		// Закрываем имя
		outcome = builder.close();
	// Черновик draft-agl-tls-nextprotoneg: заполнение нулями до кратной 32 длины тела
	const size_t padding = (32 - ((this->_protocol.size() + 2) % 32));
	// Нули заполнения
	static const uint8_t ZEROS[32] = {0};
	// Если заполнение открыть удалось
	if((outcome == field::error_t::NONE) && ((outcome = builder.open(1)) == field::error_t::NONE))
		// Записываем нули заполнения
		outcome = builder.bytes(view_t(ZEROS, padding));
	// Если заполнение записано
	if(outcome == field::error_t::NONE)
		// Закрываем запись заполнения нулями
		outcome = builder.close();
	// Если сообщение составить не удалось
	if(outcome != field::error_t::NONE)
		// Выводим отказ составления сообщения
		return translate(outcome, context::error_t::MESSAGE);
	// Запоминаем, что сообщение NextProtocol прошло
	this->_announced = true;
	// Выводим итог отправки сообщения
	return this->send(handshake::type_t::NEXT_PROTOCOL, builder.data());
}
/**
 * @brief Метод принятия предела record_size_limit, присланного собеседником (раздел 4 RFC 8449)
 *
 * @param value  присланный предел длины принимаемой собеседником записи
 * @param legacy признак издания 1.2: предел без октета вида содержимого
 * @return       результат работы: NONE при успехе либо ошибка с отправленным извещением
 *
 */
context::error_t nts::internal::Engine::bounding(const uint16_t value, const bool legacy) noexcept {
	/**
	 * Раздел 4 RFC 8449: предел меньше 64 недопустим - illegal_parameter; предел выше
	 * дозволенного протоколом не ошибка, но записи длиннее протокольного предела не шлются;
	 * в TLS 1.3 предел считается вместе с октетом вида содержимого, потому полезная часть на
	 * единицу короче. Раздел 5: сервер, поддерживающий record_size_limit, не отвечает
	 * max_fragment_length, оба ответа разом - illegal_parameter
	 */
	if((value < 64) || (this->_sizing == 2))
		// Выходим с ошибкой недопустимого значения
		return this->abort(context::error_t::PARAMETERS, alert::description_t::PARAMETER);
	// Полезная длина записи под присланный предел: без октета вида у TLS 1.3
	const size_t outgoing = (static_cast <size_t> (value) - (legacy ? 0 : 1));
	// Применяем предел к отправке, не выходя за предел протокола
	this->_outgoing = ((outgoing > record::RECORD_PLAINTEXT) ? record::RECORD_PLAINTEXT : outgoing);
	// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
	this->_flight.limit(this->_outgoing);
	// Если свой предел был предложен, собеседник его подтвердил и обязан ему следовать: стережём приём
	if(this->_bounded >= 64){
		// Полезная длина принимаемой записи под свой предел
		const size_t incoming = (static_cast <size_t> (this->_bounded) - (legacy ? 0 : 1));
		// Применяем свой предел к приёму, не выходя за предел протокола
		this->_incoming = ((incoming > record::RECORD_PLAINTEXT) ? record::RECORD_PLAINTEXT : incoming);
	}
	// Отмечаем действующее расширение
	this->_sizing = 1;
	// Сообщаем об успешном применении предела
	return context::error_t::NONE;
}
/**
 * @brief Метод принятия кода max_fragment_length, присланного сервером (раздел 4 RFC 6066)
 *
 * @param code   присланный код длины: 1…4 для 2^9…2^12 байтов
 * @param legacy признак издания 1.2: длина без октета вида содержимого
 * @return       результат работы: NONE при успехе либо ошибка с отправленным извещением
 *
 */
context::error_t nts::internal::Engine::fragmenting(const uint8_t code, const bool legacy) noexcept {
	/**
	 * Раздел 4 RFC 6066: сервер обязан вернуть ровно предложенный код, иной код либо код вне
	 * 1…4 - illegal_parameter; договорённая длина связывает обе стороны. Раздел 5 RFC 8449:
	 * рядом с record_size_limit этому ответу не место
	 */
	if((code < 1) || (code > 4) || (code != this->_fragmented) || (this->_sizing == 1))
		// Выходим с ошибкой недопустимого значения
		return this->abort(context::error_t::PARAMETERS, alert::description_t::PARAMETER);
	// Договорённая длина: 2^(8 + код), у TLS 1.3 без октета вида содержимого
	const size_t length = ((static_cast <size_t> (1) << (8 + code)) - (legacy ? 0 : 1));
	// Применяем длину к обеим сторонам
	this->_outgoing = length;
	// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
	this->_flight.limit(this->_outgoing);
	// Применяем длину и к приёму записей
	this->_incoming = length;
	// Отмечаем действующее расширение
	this->_sizing = 2;
	// Сообщаем об успешном применении длины
	return context::error_t::NONE;
}
/**
 * @brief Метод разбора сервером пределов длины записи, предложенных приветствием клиента (RFC 8449, RFC 6066)
 *
 * @param greeting приветствие клиента
 * @return         результат работы: NONE при успехе либо ошибка с отправленным извещением
 *
 */
context::error_t nts::internal::Engine::sizing(const hello::client_t & greeting) noexcept {
	// Пределы над дейтаграммами не договариваются: там длину записи диктует MTU полёта
	if(this->_transport == context::transport_t::DATAGRAMS)
		// Сообщаем, что разбор не требуется
		return context::error_t::NONE;
	// Расширение предела record_size_limit клиента
	const hello::extension_t * bound = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::LIMIT));
	// Расширение длины max_fragment_length клиента
	const hello::extension_t * fragment = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::FRAGMENT));
	// Если клиент предложил предел record_size_limit
	if(bound != nullptr){
		// Если тело расширения не двухбайтовое
		if(bound->data.size != 2)
			// Выходим с ошибкой разбора
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Присланный предел
		const uint16_t value = static_cast <uint16_t> ((static_cast <uint16_t> (bound->data.data[0]) << 8) | bound->data.data[1]);
		// Раздел 4 RFC 8449: предел меньше 64 недопустим
		if(value < 64)
			// Выходим с ошибкой недопустимого значения
			return this->abort(context::error_t::PARAMETERS, alert::description_t::PARAMETER);
		// Полезная длина отправляемой записи под предел клиента: без октета вида у TLS 1.3
		const size_t outgoing = (static_cast <size_t> (value) - (this->_legacy ? 0 : 1));
		// Применяем предел клиента к отправке, не выходя за предел протокола
		this->_outgoing = ((outgoing > record::RECORD_PLAINTEXT) ? record::RECORD_PLAINTEXT : outgoing);
		// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
		this->_flight.limit(this->_outgoing);
		// Запоминаем предложенное значение
		this->_bounding = value;
		// Свой предел на приём: наибольший дозволенный протоколом, у TLS 1.3 с октетом вида
		const uint16_t own = static_cast <uint16_t> (record::RECORD_PLAINTEXT + (this->_legacy ? 0 : 1));
		// Составляем тело ответного расширения
		this->_sized[0] = static_cast <uint8_t> (own >> 8);
		// Младший байт предела на приём
		this->_sized[1] = static_cast <uint8_t> (own & 0xFF);
		/**
		 * Раздел 5 RFC 8449: сервер, поддерживающий record_size_limit, отвечает лишь им,
		 * а max_fragment_length рядом с ним пропускает без ответа
		 */
		this->_sizing = 1;
	// Если клиент предложил лишь длину max_fragment_length
	} else if(fragment != nullptr) {
		// Если тело расширения не однобайтовое
		if(fragment->data.size != 1)
			// Выходим с ошибкой разбора
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Присланный код длины
		const uint8_t code = fragment->data.data[0];
		// Раздел 4 RFC 6066: код вне 1…4 недопустим
		if((code < 1) || (code > 4))
			// Выходим с ошибкой недопустимого значения
			return this->abort(context::error_t::PARAMETERS, alert::description_t::PARAMETER);
		// Договорённая длина: 2^(8 + код), у TLS 1.3 без октета вида содержимого
		const size_t length = ((static_cast <size_t> (1) << (8 + code)) - (this->_legacy ? 0 : 1));
		/**
		 * Отправку связываем сразу, приём - лишь с отправкой ответа: до него договора нет,
		 * и второе приветствие клиента после HelloRetryRequest длиной не ограничено
		 */
		this->_outgoing = length;
		// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
		this->_flight.limit(this->_outgoing);
		// Запоминаем предложенный код
		this->_fragmenting = code;
		// Составляем тело ответного расширения: тот же код
		this->_sized[0] = code;
		// Младший байт кода - ноль
		this->_sized[1] = 0;
		// Отмечаем действующее расширение
		this->_sizing = 2;
	}
	// Сообщаем об успешном разборе пределов
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки запроса сердцебиения (RFC 6520)
 *
 * @param payload нагрузка запроса
 * @return        отказ отправки
 *
 */
context::error_t nts::internal::Engine::heartbeat(const view_t & payload) noexcept {
	// Раздел 4 RFC 6520: запросы идут лишь по установленной связи и по одному до ответа
	if((this->_state != context::state_t::ESTABLISHED) || this->_beating)
		// Выводим отказ состояния
		return context::error_t::STATE;
	// Раздел 2 RFC 6520: без расширения heartbeat и дозволения собеседника запросы не шлются; изданию 1.3 сердцебиения нет
	if(!this->_heartbeating || !this->_permitted || !this->_legacy)
		// Выводим отказ настроек
		return context::error_t::SETTINGS;
	// Нагрузка вместе с заголовком и заполнением обязана уместиться в запись, а поверх дейтаграмм - и в дейтаграмму
	if((payload.size > 0xFFFF) || ((3 + payload.size + HEARTBEAT_PADDING) > this->heartroom()))
		// Выводим отказ предела
		return context::error_t::LIMIT;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сообщение сердцебиения: вид, длина нагрузки, нагрузка, заполнение
		vector <uint8_t> message(3 + payload.size + HEARTBEAT_PADDING, 0);
		// Вид heartbeat_request
		message[0] = 0x01;
		// Длина нагрузки старшим байтом вперёд
		message[1] = static_cast <uint8_t> (payload.size >> 8);
		// Младший байт длины нагрузки
		message[2] = static_cast <uint8_t> (payload.size & 0xFF);
		// Если нагрузка есть
		if(payload.size > 0)
			// Переносим нагрузку
			::memcpy(message.data() + 3, payload.data, payload.size);
		// Заполнение: случайные байты (раздел 4 RFC 6520)
		if(!entropy::bytes(message.data() + 3 + payload.size, HEARTBEAT_PADDING))
			// Выводим отрицательный результат - заполнение не выработано
			return context::error_t::SETTINGS;
		// Запоминаем нагрузку в пути
		this->_pulse.assign(message.begin() + 3, message.begin() + 3 + payload.size);
		// Отказ складывания записи
		const context::error_t error = this->emit(record::type_t::HEARTBEAT, view_t(message.data(), message.size()));
		// Если запись сложена
		if(error == context::error_t::NONE)
			// Запоминаем запрос в пути
			this->_beating = true;
		// Выводим итог
		return error;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод получения числа принятых ответов на свои запросы сердцебиения
 *
 * @return число ответов
 *
 */
size_t nts::internal::Engine::pulses() const noexcept {
	// Выводим число ответов
	return this->_pulses;
}
/**
 * @brief Метод получения места под сообщение сердцебиения
 *
 * @return место в байтах: предел записи собеседника, а поверх дейтаграмм - и место в дейтаграмме за вычетом обвязки записи
 *
 */
size_t nts::internal::Engine::heartroom() noexcept {
	// Место в записи по пределу собеседника
	size_t room = this->_outgoing;
	// Если связь идёт поверх дейтаграмм
	if(this->_transport == context::transport_t::DATAGRAMS){
		// Место в дейтаграмме за вычетом обвязки записи текущей поры
		const size_t space = this->_flight.room();
		// Берём меньшее
		room = ((space < room) ? space : room);
	}
	// Выводим место
	return room;
}
/**
 * @brief Метод разбора принятой записи сердцебиения (RFC 6520)
 *
 * @param content открытое содержимое записи вида 24
 * @return        отказ разбора
 *
 */
context::error_t nts::internal::Engine::pulse(const view_t & content) noexcept {
	// Если heartbeat не предлагался, запись неожиданна
	if(!this->_heartbeating)
		// Выходим с ошибкой
		return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
	/**
	 * Раздел 4 RFC 6520: сердцебиение вне установленной связи не ходит, а сообщение
	 * короче заголовка либо с длиной нагрузки, выходящей за запись с наименьшим
	 * заполнением, роняется молча; изданию 1.3 сердцебиения нет вовсе
	 */
	if((this->_state != context::state_t::ESTABLISHED) || !this->_legacy || (content.size < 3))
		// Выводим успешность: запись уронена
		return context::error_t::NONE;
	// Длина нагрузки
	const size_t length = ((static_cast <size_t> (content.data[1]) << 8) | content.data[2]);
	// Если нагрузка с заполнением не умещается в сообщение
	if((3 + length + HEARTBEAT_PADDING) > content.size)
		// Выводим успешность: запись уронена
		return context::error_t::NONE;
	// Раздел 4 RFC 6520: ответ той же длины обязан уместиться в одну запись собеседника (и в дейтаграмму), иначе запрос роняется молча
	if((3 + length + HEARTBEAT_PADDING) > this->heartroom())
		// Выводим успешность: запись уронена
		return context::error_t::NONE;
	/**
	 * Выполняем определение вида сообщения
	 */
	switch(content.data[0]){
		// Если принят запрос: ответ несёт ту же нагрузку и своё заполнение
		case 0x01: {
			// Раздел 2 RFC 6520: объявивший peer_not_allowed_to_send роняет запрос молча
			if(!this->_answering)
				// Выводим успешность: запись уронена
				return context::error_t::NONE;
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Ответ сердцебиения
				vector <uint8_t> message(3 + length + HEARTBEAT_PADDING, 0);
				// Вид heartbeat_response
				message[0] = 0x02;
				// Длина нагрузки
				message[1] = content.data[1];
				// Младший байт длины нагрузки слово в слово
				message[2] = content.data[2];
				// Если нагрузка есть
				if(length > 0)
					// Переносим нагрузку слово в слово
					::memcpy(message.data() + 3, content.data + 3, length);
				// Заполнение: случайные байты
				if(!entropy::bytes(message.data() + 3 + length, HEARTBEAT_PADDING))
					// Выводим успешность: ответ не сложен, запись уронена
					return context::error_t::NONE;
				// Складываем ответ
				return this->emit(record::type_t::HEARTBEAT, view_t(message.data(), message.size()));
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			}
		}
		// Если принят ответ: сличается с нагрузкой запроса в пути, иное роняется молча
		case 0x02: {
			// Если запрос в пути и нагрузка совпала
			if(this->_beating && (length == this->_pulse.size()) && ((length == 0) || (::memcmp(content.data + 3, this->_pulse.data(), length) == 0))){
				// Запрос отвечен
				this->_beating = false;
				// Считаем ответ
				this->_pulses++;
				// Забываем нагрузку
				this->_pulse.clear();
			}
		} break;
	}
	// Сообщаем об успешном разборе записи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения предела длины открытого содержимого отправляемой записи
 *
 * @return предел в байтах: объявленный собеседником либо предел протокола
 *
 */
size_t nts::internal::Engine::ceiling() const noexcept {
	// Выводим предел отправки
	return this->_outgoing;
}
/**
 * @brief Метод получения предела длины открытого содержимого принимаемой записи
 *
 * @return предел в байтах: свой объявленный и подтверждённый либо предел протокола
 *
 */
size_t nts::internal::Engine::threshold() const noexcept {
	// Выводим предел приёма
	return this->_incoming;
}
/**
 * @brief Метод получения ответа о состоянии сертификата собеседника
 *
 * @return запись принятого ответа OCSP либо пустой накопитель
 *
 */
const vector <uint8_t> & nts::internal::Engine::status() const noexcept {
	// Выводим принятый ответ о состоянии
	return this->_status;
}
/**
 * @brief Метод получения ответов о состоянии сертификатов цепочки собеседника
 *
 * @return записи принятых ответов OCSP по местам в цепочке либо пустой накопитель
 *
 */
const vector <vector <uint8_t>> & nts::internal::Engine::statuses() const noexcept {
	// Выводим принятые ответы о состоянии по местам
	return this->_statuses;
}
/**
 * @brief Метод вывода экспортируемого ключевого материала связи
 *
 * @param label   метка назначения экспортируемого материала
 * @param context привязка экспортируемого материала к потребителю
 * @param result  место, в которое помещается экспортируемый материал
 * @param size    требуемая длина экспортируемого материала в байтах
 * @param early   признак раннего вывода из значения раннего экспорта
 * @return        отказ вывода экспортируемого материала
 *
 */
context::error_t nts::internal::Engine::exporting(const view_t & label, const view_t & context, uint8_t * result, const size_t size, const bool early) const noexcept {
	// Если связь не установлена, а ранний вывод не заказан, либо метка назначения не передана
	if((!early && (this->_state != context::state_t::ESTABLISHED)) || (label.data == nullptr) || (label.size == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ вызова не в том состоянии связи
		return context::error_t::STATE;
	// Если заказан ранний вывод: он возможен лишь изданием 1.3 по заведённым ранним секретам,
	// и расписание само судит о готовности - издание ответом сервера на этот миг может быть ещё не согласовано
	if(early)
		// Выводим итог раннего вывода экспортируемого материала расписанием ключей
		return ((this->_secrets.exporting(label, context, result, size, true) == session::error_t::NONE) ? context::error_t::NONE : context::error_t::SCHEDULE);
	// Если связь ведётся изданием 1.3
	if(this->_version == MODERN)
		// Выводим итог вывода экспортируемого материала расписанием ключей
		return ((this->_secrets.exporting(label, context, result, size) == session::error_t::NONE) ? context::error_t::NONE : context::error_t::SCHEDULE);
	// Если ключевого материала связи нет
	if(this->_keys == nullptr)
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	/**
	 * Раздел 4 RFC 5705: материал изданий 1.0-1.2 выводится псевдослучайной
	 * последовательностью из главного секрета, затравкой из случайных значений
	 * приветствий обеих сторон и, при заданной привязке, хеша привязки
	 */
	uint8_t seed[64 + schedule::SCHEDULE_WIDEST];
	// Записываем случайное значение клиента
	::memcpy(seed, (this->_server ? this->_foreign : this->_random), 32);
	// Записываем случайное значение сервера
	::memcpy(seed + 32, (this->_server ? this->_random : this->_foreign), 32);
	// Длина собранной затравки
	size_t width = 64;
	// Если привязка потребителя задана
	if((context.data != nullptr) && (context.size > 0)){
		// Хеш, которым берётся хеш привязки: изданием 1.1 - SHA-1, изданием 1.2 - хеш набора
		const digest::hash_t algorithm = (this->_ancient ? digest::hash_t::SHA1 : protect::hash(this->_suite));
		// Длина хеша привязки
		const size_t length = digest::length(algorithm);
		// Если хеш привязки выработать не удалось
		if((length == 0) || (length > schedule::SCHEDULE_WIDEST) || !digest::hash(algorithm, context, seed + 64, length)){
			// Выводим отказ вывода экспортируемого материала
			return context::error_t::SCHEDULE;
		}
		// Дописываем длину хеша привязки к затравке
		width += length;
	}
	// Выводим итог выработки экспортируемого материала из главного секрета
	return (this->sequencing(view_t(this->_keys->master, sizeof(this->_keys->master)), label, view_t(seed, width), result, size) ? context::error_t::NONE : context::error_t::SCHEDULE);
}
/**
 * @brief Метод установки проверки принятого ответа о состоянии
 *
 * @param verify проверяется ли принятый ответ
 * @param leeway дозволенный люфт сроков ответа в секундах
 * @param store  запас доверенных сертификатов для розыска издателя
 *
 */
void nts::internal::Engine::verification(const bool verify, const int64_t leeway, const trust::store_t & store) noexcept {
	// Запоминаем, проверяется ли принятый ответ
	this->_verifying = verify;
	// Запоминаем дозволенный люфт сроков ответа
	this->_leeway = ((leeway < 0) ? -leeway : leeway);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим запас доверенных сертификатов
		this->_anchors = store;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Запоминаем нехватку памяти до заведения связи
		this->_starved = true;
	}
}
/**
 * @brief Метод получения состояния сертификата собеседника
 *
 * @return состояние по проверенному ответу либо NONE
 *
 */
nts::ocsp::status_t nts::internal::Engine::certified() const noexcept {
	// Выводим состояние сертификата собеседника
	return this->_certified;
}
/**
 * @brief Метод установки предлагаемых наборов шифрования
 *
 * @param suites устанавливаемые наборы шифрования
 *
 */
void nts::internal::Engine::suites(const vector <protect::suite_t> & suites) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если предлагаемые наборы шифрования переданы
		if(!suites.empty()){
			// Запоминаем предлагаемые наборы шифрования
			this->_suites = suites;
			// Запоминаем настройку: заведение связи поверх дейтаграмм отсеивает наборы из копии, а не из настройки
			this->_catalog = suites;
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс предлагаемые наборы шифрования
		this->_suites.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки предлагаемых кривых обмена ключами
 *
 * @param groups устанавливаемые кривые обмена ключами
 *
 */
void nts::internal::Engine::groups(const vector <extension::group_t> & groups) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если предлагаемые кривые обмена ключами переданы
		if(!groups.empty())
			// Запоминаем предлагаемые кривые обмена ключами
			this->_groups = groups;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс предлагаемые кривые обмена ключами
		this->_groups.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки групп обмена, по которым приветствием шлются доли ключа
 *
 * @param shares устанавливаемые группы долей ключа
 *
 */
void nts::internal::Engine::shares(const vector <extension::group_t> & shares) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Устанавливаем перечень групп долей ключа: пустой перечень возвращает умолчание
		this->_shares = shares;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс групп долей ключа
		this->_shares.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки признаваемых схем подписи
 *
 * @param schemes устанавливаемые схемы подписи
 *
 */
void nts::internal::Engine::schemes(const vector <extension::scheme_t> & schemes) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если перечень схем подписи не пуст
		if(!schemes.empty())
			// Устанавливаем перечень признаваемых схем подписи
			this->_signatures = schemes;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс схем подписи связи
		this->_signatures.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод получения предлагаемых наборов шифрования
 *
 * @return перечень наборов шифрования, назначенный потребителем либо умолчание
 *
 */
const vector <nts::protect::suite_t> & nts::internal::Engine::suites() const noexcept {
	// Выводим настройку наборов: рабочий перечень заведение связи поверх дейтаграмм отсеивает, а настройка неизменна
	return this->_catalog;
}
/**
 * @brief Метод получения предлагаемых кривых обмена ключами
 *
 * @return перечень кривых обмена ключами, назначенный потребителем либо умолчание
 *
 */
const vector <nts::extension::group_t> & nts::internal::Engine::groups() const noexcept {
	// Выводим перечень предлагаемых кривых обмена ключами
	return this->_groups;
}
/**
 * @brief Метод получения групп обмена, по которым приветствием шлются доли ключа
 *
 * @return перечень групп долей ключа, назначенный потребителем; пустой при умолчании
 *
 */
const vector <nts::extension::group_t> & nts::internal::Engine::shares() const noexcept {
	// Выводим перечень групп долей ключа
	return this->_shares;
}
/**
 * @brief Метод получения признаваемых схем подписи
 *
 * @return перечень схем подписи, назначенный потребителем либо умолчание
 *
 */
const vector <nts::extension::scheme_t> & nts::internal::Engine::schemes() const noexcept {
	// Выводим перечень признаваемых схем подписи
	return this->_signatures;
}
/**
 * @brief Метод установки алгоритмов сжатия цепочки сертификатов
 *
 * @param codecs    устанавливаемые алгоритмы в порядке предпочтения
 * @param inflation предел длины цепочки после распаковки, ноль оставляет умолчание
 *
 */
void nts::internal::Engine::codecs(const vector <context::codec_t> & codecs, const size_t inflation) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Устанавливаем перечень алгоритмов сжатия: пустой перечень выключает сжатие
		this->_codecs = codecs;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс алгоритмов сжатия
		this->_codecs.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
	/**
	 * Раздел 4 RFC 8879 кладёт длине после распаковки предел 2^24-1, но столько памяти
	 * под цепочку по слову собеседника отводить незачем: предел ставится потребителем,
	 * а ноль оставляет умолчание
	 */
	this->_inflation = ((inflation > 0) ? ((inflation < CHAIN) ? inflation : CHAIN) : INFLATION);
}
/**
 * @brief Метод получения алгоритма сжатия цепочки сертификатов направления
 *
 * @param direction направление связи относительно своей стороны
 * @return          опознаватель алгоритма по RFC 8879, ноль у несжатой цепочки
 *
 */
uint16_t nts::internal::Engine::compression(const context::direction_t direction) const noexcept {
	// Выводим алгоритм сжатия цепочки направления: чтение - принятой, запись - отправленной
	return ((direction == context::direction_t::READ) ? this->_inflated : this->_squeezed);
}
/**
 * @brief Метод установки подлинности своей стороны связи
 *
 * @param credential устанавливаемая подлинность своей стороны
 *
 */
void nts::internal::Engine::credential(const context::credential_t & credential) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если прежняя подлинность несёт секретный ключ
		if(!this->_credential.secret.empty())
			// Выполняем затирание прежнего секретного ключа
			this->purge(this->_credential.secret.data(), this->_credential.secret.size());
		// Запоминаем подлинность своей стороны связи
		this->_credential = credential;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс подлинность своей стороны связи
		this->_credential = context::credential_t();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}

/**
 * @brief Метод выбора подлинности сервера по имени узла из принятого приветствия
 *
 * @return отказ выбора подлинности по имени узла
 *
 */
context::error_t nts::internal::Engine::choosing() noexcept {
	// Если выбор подлинности по имени потребителем не задан
	if(this->_select.respond == nullptr)
		// Выводим успешность выбора: подлинность остаётся настроенной
		return context::error_t::NONE;
	// Подлинность, выданная потребителем по имени узла
	context::credential_t candidate;
	// Итог выбора потребителя по предъявленному имени узла
	const context::select_t::outcome_t outcome = this->_select.respond(this->_name, candidate, this->_select.context);
	// Если потребитель отказался вести имя узла
	if(outcome == context::select_t::outcome_t::REFUSE)
		// Раздел 3 RFC 6066: нежелание сервера вести имя отвечается извещением unrecognized_name
		return this->abort(context::error_t::NAME, alert::description_t::NAME);
	// Если потребитель оставил настроенную подлинность
	if(outcome != context::select_t::outcome_t::GIVEN)
		// Выводим успешность выбора: подлинность остаётся настроенной
		return context::error_t::NONE;
	// Если выданная подлинность не несёт цепочки своего сертификата
	if(candidate.chain.empty()){
		// Выполняем затирание выданного секретного ключа
		this->purge(candidate.secret.data(), candidate.secret.size());
		// Выводим отказ негодной выданной подлинности
		return this->abort(context::error_t::CERTIFICATE, alert::description_t::INTERNAL);
	}
	// Отказ подготовки выданной подлинности
	const context::error_t failure = candidate.prepare();
	// Если выданную подлинность подготовить не удалось: ключ не читается либо сертификату не отвечает
	if(failure != context::error_t::NONE){
		// Выполняем затирание выданного секретного ключа
		this->purge(candidate.secret.data(), candidate.secret.size());
		// Выводим отказ негодной выданной подлинности
		return this->abort(failure, alert::description_t::INTERNAL);
	}
	// Устанавливаем выданную подлинность своей стороны связи: прежний ключ затирается установкой
	this->credential(candidate);
	// Выполняем затирание выданного секретного ключа
	this->purge(candidate.secret.data(), candidate.secret.size());
	// Снимаем прошивки состояния, привязанные к прежней цепочке своего сертификата
	this->_staples.clear();
	// Снимаем метки времени, привязанные к прежней цепочке своего сертификата
	this->_stamps.clear();
	// Выводим успешность выбора подлинности
	return context::error_t::NONE;
}
/**
 * @brief Метод получения подготовленного секретного ключа своей подлинности
 *
 * @param result место, в которое помещается указатель на подготовленный ключ
 * @return       отказ подготовки ключа
 *
 */
context::error_t nts::internal::Engine::signer(const keys::Signer *& result) noexcept {
	// Сбрасываем указатель на подготовленный ключ
	result = nullptr;
	/**
	 * Ключ, подготовленный потребителем в подлинности, берётся общим, если его отпечаток
	 * отвечает байтам ключа и сертификата; иначе связь готовит ключ сама в своей копии
	 * подлинности и держит его до конца своей жизни
	 */
	if(!this->_credential.ready()){
		// Отказ подготовки ключа связью
		const context::error_t failure = this->_credential.prepare();
		// Если ключ подготовить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ подготовки ключа
			return failure;
	}
	// Запоминаем указатель на подготовленный ключ
	result = this->_credential.signer.get();
	// Сообщаем об успешной выдаче ключа
	return context::error_t::NONE;
}
/**
 * @brief Метод установки имени узла, запрашиваемого у сервера
 *
 * @param name устанавливаемое имя узла
 *
 */
void nts::internal::Engine::name(const string & name) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем имя узла, запрашиваемое у сервера
		this->_name = name;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс имя узла, запрашиваемое у сервера
		this->_name.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки предлагаемых прикладных протоколов
 *
 * @param protocols устанавливаемые прикладные протоколы
 *
 */
void nts::internal::Engine::protocols(const vector <string> & protocols) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем предлагаемые прикладные протоколы связи
		this->_protocols = protocols;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс предлагаемые прикладные протоколы связи
		this->_protocols.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод объявления прикладных настроек ALPS для прикладного протокола
 *
 * @param protocol прикладной протокол, для которого объявляются настройки
 * @param value    прикладные настройки как есть
 *
 */
void nts::internal::Engine::settings(const string & protocol, const vector <uint8_t> & value) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Выполняем перебор объявленных прикладных настроек
		 */
		for(size_t i = 0; i < this->_settings.size(); i++){
			// Если настройки для протокола уже объявлены
			if(this->_settings[i].protocol.compare(protocol) == 0){
				// Заменяем настройки протокола
				this->_settings[i].value = value;
				// Выходим из метода
				return;
			}
		}
		// Настройки протокола
		setting_t item;
		// Устанавливаем протокол настроек
		item.protocol = protocol;
		// Устанавливаем настройки протокола
		item.value = value;
		// Объявляем настройки протокола
		this->_settings.push_back(item);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс объявленных настроек
		this->_settings.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки точки кода расширения прикладных настроек ALPS
 *
 * @param type вид расширения: SETTINGS либо SETTINGS_OLD
 *
 */
void nts::internal::Engine::codepoint(const uint16_t type) noexcept {
	// Если вид расширения есть одна из точек кода ALPS
	if((type == static_cast <uint16_t> (extension::type_t::SETTINGS)) || (type == static_cast <uint16_t> (extension::type_t::SETTINGS_OLD)))
		// Устанавливаем точку кода
		this->_codepoint = type;
}
/**
 * @brief Метод проверки согласования прикладных настроек ALPS
 *
 * @return признак того, что прикладные настройки сторонами согласованы
 *
 */
bool nts::internal::Engine::settled() const noexcept {
	// Выводим признак согласования прикладных настроек
	return this->_settled;
}
/**
 * @brief Метод получения прикладных настроек собеседника
 *
 * @return прикладные настройки собеседника как есть
 *
 */
const vector <uint8_t> & nts::internal::Engine::settings() const noexcept {
	// Выводим прикладные настройки собеседника
	return this->_obtained;
}
/**
 * @brief Метод получения точки кода расширения прикладных настроек ALPS
 *
 * @return вид расширения, которым ведётся связь
 *
 */
uint16_t nts::internal::Engine::codepoint() const noexcept {
	// Выводим точку кода
	return this->_codepoint;
}
/**
 * @brief Метод поиска своих прикладных настроек по протоколу
 *
 * @param protocol прикладной протокол, настройки которого ищутся
 * @param result   место, в которое помещаются найденные настройки
 * @return         признак того, что настройки для протокола объявлены
 *
 */
bool nts::internal::Engine::pick(const string & protocol, view_t & result) const noexcept {
	/**
	 * Выполняем перебор объявленных прикладных настроек
	 */
	for(size_t i = 0; i < this->_settings.size(); i++){
		// Если настройки для протокола объявлены
		if(this->_settings[i].protocol.compare(protocol) == 0){
			// Выводим настройки протокола
			result = view_t(this->_settings[i].value.data(), this->_settings[i].value.size());
			// Выводим признак находки
			return true;
		}
	}
	// Выводим признак отсутствия настроек
	return false;
}
/**
 * @brief Метод сличения состояния прикладных настроек связи с билетом
 *
 * @param ticket билет, с которым сличается состояние
 * @return       признак того, что состояние равно билетному
 *
 */
bool nts::internal::Engine::inheritable(const context::ticket_t & ticket) const noexcept {
	// Свои настройки протокола билета
	view_t applied;
	// Признак того, что настройки для протокола билета объявлены
	const bool found = this->pick(ticket.protocol, applied);
	/**
	 * Черновик draft-vvv-tls-alps: упреждение идёт лишь при том же состоянии настроек,
	 * что и у выдавшей билет связи - и признак согласования, и сами настройки
	 */
	if(found != ticket.settled)
		// Выводим признак расхождения
		return false;
	// Если настройки не объявлены ни теперь, ни билетом
	if(!found)
		// Выводим признак равенства
		return true;
	// Выводим признак равенства настроек
	return ((applied.size == ticket.settings.size()) && ((applied.size == 0) || (::memcmp(applied.data, ticket.settings.data(), applied.size) == 0)));
}
/**
 * @brief Метод отправки защищённых расширений клиента с прикладными настройками
 *
 * @return отказ отправки защищённых расширений клиента
 *
 */
context::error_t nts::internal::Engine::stating() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Перечень расширений, объявляемых клиентом под защитой
		vector <hello::extension_t> items;
		// Черновик draft-vvv-tls-alps: сообщение несёт одно расширение - свои настройки своей точкой кода
		items.push_back(hello::extension_t(this->_codepoint, view_t(this->_applied.data(), this->_applied.size())));
		// Накопитель, в который складывается тело сообщения
		vector <uint8_t> extensions;
		// Отказ составления тела сообщения
		const context::error_t failure = block(items, extensions);
		// Если тело сообщения составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления тела сообщения
			return failure;
		// Запоминаем, что защищённые расширения клиента прошли по связи
		this->_stated = true;
		// Выводим итог отправки сообщения
		return this->send(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод установки метки возврата состояния сервера
 *
 * @param cookie устанавливаемая метка возврата состояния
 *
 */
void nts::internal::Engine::cookie(const vector <uint8_t> & cookie) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем метку возврата состояния, выдаваемую просьбой о повторе
		this->_cookie = cookie;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс метку возврата состояния
		this->_cookie.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод получения метки возврата состояния сервера
 *
 * @return метка возврата состояния, принятая от собеседника
 *
 */
const vector <uint8_t> & nts::internal::Engine::cookie() const noexcept {
	/**
	 * Сервер получает метку повтором приветствия клиента, а клиент - самой просьбой
	 * о повторе: сторонам возвращается то, что каждая из них приняла
	 */
	return (this->_server ? this->_label : this->_cookie);
}
/**
 * @brief Метод установки мига, которым судятся сроки билетов
 *
 * @param moment устанавливаемый миг в секундах
 *
 */
void nts::internal::Engine::moment(const int64_t moment) noexcept {
	// Запоминаем миг, которым связь судит сроки билетов
	this->_moment = moment;
}
/**
 * @brief Метод установки срока жизни выдаваемых билетов
 *
 * @param lifetime устанавливаемый срок в секундах
 *
 */
void nts::internal::Engine::lifetime(const uint32_t lifetime) noexcept {
	/**
	 * Раздел 4.6.1 RFC 8446 кладёт сроку билета семь суток, а нулевой срок велит
	 * билет выбрасывать тотчас - такой билет выдавать незачем, и нуль возвращает
	 * срок, принятый по умолчанию
	 */
	this->_lifetime = ((lifetime == 0) ? TERM : ((lifetime > LIFETIME) ? LIFETIME : lifetime));
}
/**
 * @brief Метод установки билета возобновления связи клиентом
 *
 * @param ticket предъявляемый билет возобновления связи
 *
 */
void nts::internal::Engine::resume(const context::ticket_t & ticket) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем билет, предъявляемый на возобновление связи
		this->_resume = ticket;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс билет возобновления связи
		this->_resume = context::ticket_t();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки билетов, признаваемых сервером
 *
 * @param tickets признаваемые билеты возобновления связи
 *
 */
void nts::internal::Engine::resume(const vector <context::ticket_t> & tickets) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем билеты, признаваемые на возобновление связи
		this->_store = tickets;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс признаваемые билеты возобновления связи
		this->_store.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод проверки возобновления связи заранее разделённым ключом
 *
 * @return признак того, что связь возобновлена билетом
 *
 */
bool nts::internal::Engine::shared() const noexcept {
	// Выводим признак возобновления связи билетом
	return this->_shared;
}
/**
 * @brief Метод установки предложения упреждающих данных
 *
 * @param advance устанавливаемое предложение упреждающих данных
 *
 */
void nts::internal::Engine::advance(const bool advance, const uint32_t limit) noexcept {
	// Запоминаем предложение упреждающих данных связи
	this->_advance = advance;
	// Запоминаем предел упреждающих данных связи
	this->_limit = limit;
}
/**
 * @brief Метод проверки приёма упреждающих данных собеседником
 *
 * @return признак того, что упреждающие данные приняты
 *
 */
bool nts::internal::Engine::accepted() const noexcept {
	// Выводим признак приёма упреждающих данных собеседником
	return this->_accepted;
}
/**
 * @brief Метод установки требования подлинности клиента
 *
 * @param request устанавливаемое требование подлинности клиента
 *
 */
void nts::internal::Engine::request(const bool request) noexcept {
	// Запоминаем требование подлинности клиента
	this->_request = request;
}
/**
 * @brief Метод установки порядка смены ключей по счётчику записей
 *
 * @param automatic сменяет ли движок ключи сам по счётчику записей
 * @param records   число записей направления, по которому идёт смена
 *
 */
void nts::internal::Engine::renewal(const bool automatic, const uint64_t records) noexcept {
	// Запоминаем порядок смены ключей по счётчику записей
	this->_automatic = automatic;
	// Запоминаем число записей направления, по которому сменяются ключи
	this->_renewal = records;
}
/**
 * @brief Метод получения счётчика записей направления связи
 *
 * @param incoming запрашивается ли направление собеседника
 * @return         число записей направления на текущих ключах
 *
 */
uint64_t nts::internal::Engine::sequence(const bool incoming) const noexcept {
	// Если связь ведётся поверх дейтаграмм: счёт ведут поры ключей
	if(this->_transport == context::transport_t::DATAGRAMS)
		// Выводим счёт записей текущей поры запрошенного направления
		return this->_flight.sequence(incoming);
	// Выводим счётчик записей запрошенного направления связи
	return (incoming ? this->_input.sequence() : this->_output.sequence());
}
/**
 * @brief Метод смены ключей своего направления по счётчику записей
 *
 * @return отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::internal::Engine::refreshing() noexcept {
	// Изданию TLS 1.2 смена ключей неведома: раздел 4.6.3 RFC 8446 принадлежит одному 1.3
	if(this->_legacy)
		// Выводим успешность: сменять нечего
		return context::error_t::NONE;
	// Если ключи по счётчику записей движком не сменяются либо связь не установлена
	if(!this->_automatic || (this->_state != context::state_t::ESTABLISHED))
		// Выводим успешность: смена ключей остаётся за тем, кто связь ведёт
		return context::error_t::NONE;
	/**
	 * Раздел 5.5 RFC 8446 велит сменять ключи впереди предела порядковых номеров.
	 * По умолчанию смена идёт с половины предела набора шифрования: столько же
	 * места остаётся собеседнику ответить на просьбу о встречной смене, сколько
	 * берёт себе своё направление
	 */
	const uint64_t threshold = ((this->_renewal > 0) ? this->_renewal : (protect::limit(this->_suite) / 2));
	// Если счётчик записей своего направления до смены ключей не дошёл
	if(this->sequence(false) < threshold)
		// Выводим успешность: ключи менять рано
		return context::error_t::NONE;
	// Поверх дейтаграмм смена ключей, ждущая подтверждения, повторно не просится
	if(this->rotating())
		// Выводим успешность: смена ключей уже идёт
		return context::error_t::NONE;
	// Выводим итог смены ключевого материала своего направления связи
	return this->update(false);
}
/**
 * @brief Метод установки способа переноса рукопожатия
 *
 * @param transport устанавливаемый способ переноса
 *
 */
void nts::internal::Engine::transport(const context::transport_t transport) noexcept {
	// Запоминаем способ переноса рукопожатия связи
	this->_transport = transport;
}
/**
 * @brief Метод получения способа переноса рукопожатия
 *
 * @return способ переноса рукопожатия связи
 *
 */
context::transport_t nts::internal::Engine::transport() const noexcept {
	// Выводим способ переноса рукопожатия связи
	return this->_transport;
}
/**
 * @brief Метод установки своих параметров переноса QUIC
 *
 * @param parameters устанавливаемые параметры переноса
 *
 */
void nts::internal::Engine::parameters(const vector <uint8_t> & parameters) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем свои параметры переноса QUIC
		this->_parameters = parameters;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс своих параметров переноса
		this->_parameters.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод получения параметров переноса QUIC собеседника
 *
 * @return параметры переноса, принятые от собеседника
 *
 */
const vector <uint8_t> & nts::internal::Engine::parameters() const noexcept {
	// Выводим параметры переноса, принятые от собеседника
	return this->_received;
}
/**
 * @brief Метод проверки приёма параметров переноса собеседника
 *
 * @return признак того, что параметры переноса собеседника приняты
 *
 */
bool nts::internal::Engine::acquired() const noexcept {
	// Выводим признак приёма параметров переноса собеседника
	return this->_acquired;
}
/**
 * @brief Метод подачи связи сообщений рукопожатия уровня защиты
 *
 * @param level уровень защиты, на котором сообщения приняты
 * @param data  принятые сообщения рукопожатия без обвязки записей
 * @return      отказ разбора принятых сообщений
 *
 */
context::error_t nts::internal::Engine::push(const context::level_t level, const view_t & data) noexcept {
	// Если связь ещё не заведена либо уже оборвана
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::FAILED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Перенос записями и дейтаграммами сообщений по уровням не принимает: подача их означает оплошность ведущего
	if(this->_transport != context::transport_t::LEVELS)
		// Выводим отказ подачи не тем способом переноса
		return context::error_t::LEVEL;
	/**
	 * Раздел 4.1.3 RFC 9001: сообщения рукопожатия идут начальным уровнем, уровнем
	 * рукопожатия и уровнем прикладных данных; уровень упреждающих данных их не несёт
	 * вовсе, а подача без уровня - оплошность того, кто связь ведёт
	 */
	if((level != context::level_t::INITIAL) && (level != context::level_t::HANDSHAKE) && (level != context::level_t::APPLICATION))
		// Выводим отказ подачи не на своём уровне
		return context::error_t::LEVEL;
	// Получаем сторону связи собеседника
	const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
	/**
	 * Раздел 4.1.4 RFC 9001: сообщение, пришедшее не на своём уровне, обрывает связь
	 * извещением unexpected_message; недособранное сообщение обязано досылаться тем же
	 * уровнем, каким начато
	 */
	if((this->_messages.pending() > 0) && (level != this->_pushed))
		// Выводим отказ сообщения не на своём уровне
		return this->abort(context::error_t::LEVEL, alert::description_t::UNEXPECTED);
	// Если уровень подачи с порой ключей собеседника не сошёлся
	if(level != this->layer(side))
		// Выводим отказ сообщения не на своём уровне
		return this->abort(context::error_t::LEVEL, alert::description_t::UNEXPECTED);
	/**
	 * Сборщик сообщений отказывает единственно нехваткой памяти под накопитель: сам
	 * разбор идёт позже, отдельным вызовом
	 */
	const context::error_t failure = translate(this->_messages.push(data), context::error_t::MEMORY);
	// Если памяти под накопитель сообщений не хватило
	if(failure != context::error_t::NONE)
		// Выводим отказ нехватки памяти под накопитель сообщений
		return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
	// Запоминаем уровень, на котором подано сообщение
	this->_pushed = level;
	// Заголовок принятого сообщения рукопожатия
	handshake::header_t item;
	// Тело принятого сообщения рукопожатия
	view_t body;
	// Отказ, которым сборщик ответил на выдачу очередного сообщения
	handshake::error_t outcome = handshake::error_t::NONE;
	/**
	 * Выполняем перебор принятых сообщений рукопожатия
	 */
	while((outcome = this->_messages.next(item, body)) == handshake::error_t::NONE){
		/**
		 * Пора ключей собеседника переменяется самими сообщениями: приветствие сервера
		 * уводит его выход на уровень рукопожатия, и сообщение за ним в той же подаче
		 * пришло бы не на своём уровне
		 */
		if(level != this->layer(side))
			// Выводим отказ сообщения не на своём уровне
			return this->abort(context::error_t::LEVEL, alert::description_t::UNEXPECTED);
		// Выполняем разбор принятого сообщения рукопожатия
		const context::error_t error = this->handle(item.type, body, this->_messages.message());
		// Если сообщение рукопожатия разобрать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ разбора сообщения рукопожатия
			return error;
	}
	// Если сборщику довелось столкнуться с неведомым видом сообщения
	if(outcome == handshake::error_t::TYPE)
		// Выводим отказ неведомого вида сообщения рукопожатия
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Если памяти сборщику сообщений не хватило
	if(outcome == handshake::error_t::MEMORY)
		// Выводим отказ нехватки памяти под накопитель сообщений
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	/**
	 * Нехваткой данных круг разбора кончается законно: остаток дождётся следующей
	 * подачи того же уровня. Превышение дозволенной длины тела означает накопление
	 * чужого мусора
	 */
	if(outcome != handshake::error_t::HUNGRY)
		// Выводим отказ разбора сообщения рукопожатия
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	// Выводим успешность разбора принятых сообщений
	return context::error_t::NONE;
}
/**
 * @brief Метод получения сообщений рукопожатия, отправляемых на уровне защиты
 *
 * @param level уровень защиты, сообщения которого запрашиваются
 * @return      накопленные сообщения рукопожатия уровня
 *
 */
view_t nts::internal::Engine::output(const context::level_t level) const noexcept {
	// Если уровень защиты не задан
	if(level == context::level_t::NONE)
		// Выводим пустой просмотр
		return view_t();
	// Получаем накопитель сообщений уровня защиты
	const vector <uint8_t> & storage = this->_levels[static_cast <uint8_t> (level) - 1];
	// Выводим накопленные сообщения уровня
	return view_t(storage.data(), storage.size());
}
/**
 * @brief Метод снятия отправленных сообщений с накопителя уровня защиты
 *
 * @param level уровень защиты, с накопителя которого снимаются сообщения
 * @param size  размер снимаемых байтов
 *
 */
void nts::internal::Engine::consume(const context::level_t level, const size_t size) noexcept {
	// Если уровень защиты не задан
	if(level == context::level_t::NONE)
		// Выходим из метода
		return;
	// Получаем накопитель сообщений уровня защиты
	vector <uint8_t> & storage = this->_levels[static_cast <uint8_t> (level) - 1];
	// Если снимается весь накопитель уровня
	if(size >= storage.size())
		// Выполняем сброс накопителя уровня
		storage.clear();
	// Если снимается часть накопителя уровня
	else storage.erase(storage.begin(), storage.begin() + size);
}
/**
 * @brief Метод получения значения направления связи уровня защиты
 *
 * @param level     уровень защиты, значение которого запрашивается
 * @param direction направление связи относительно своей стороны
 * @param result    место, в которое помещается значение направления
 * @param size      место, в которое помещается длина значения по хешу набора
 * @return          признак того, что значение уровня уже выведено
 *
 */
bool nts::internal::Engine::secret(const context::level_t level, const context::direction_t direction, uint8_t * result, size_t & size) const noexcept {
	// Место уровня защиты среди сохранённых значений
	size_t place = 0;
	/**
	 * Определяем уровень защиты запрашиваемого значения
	 */
	switch(static_cast <uint8_t> (level)){
		// Если запрашивается значение упреждающих данных
		case static_cast <uint8_t> (context::level_t::EARLY): place = 0; break;
		// Если запрашивается значение рукопожатия
		case static_cast <uint8_t> (context::level_t::HANDSHAKE): place = 1; break;
		// Если запрашивается значение прикладных данных
		case static_cast <uint8_t> (context::level_t::APPLICATION): place = 2; break;
		/**
		 * Начальный уровень значений TLS не имеет: раздел 5.2 RFC 9001 выводит его ключи из
		 * опознавателя связи, ведомого лишь переносу
		 */
		default: return false;
	}
	// Определяем сторону связи, значение которой запрашивается
	const session::side_t side = (((direction == context::direction_t::WRITE) == this->_server) ? session::side_t::SERVER : session::side_t::CLIENT);
	// Получаем место стороны связи в наборах связи
	const size_t item = index(side);
	// Если значение направления ещё не выведено
	if((this->_ready[place] & static_cast <uint8_t> (1 << item)) == 0)
		// Выводим признак отсутствия значения
		return false;
	// Если место для значения передано
	if(result != nullptr)
		// Переносим значение направления связи
		::memcpy(result, this->_keys->traffic[place][item], this->_width);
	// Выводим длину значения направления связи
	size = this->_width;
	// Выводим признак готовности значения
	return true;
}
/**
 * @brief Метод получения уровня защиты, ключи которого готовы направлению
 *
 * @param direction направление связи относительно своей стороны
 * @return          наивысший уровень защиты, ключи которого у направления есть
 *
 */
context::level_t nts::internal::Engine::level(const context::direction_t direction) const noexcept {
	// Если связь не заведена
	if(this->_state == context::state_t::NONE)
		// Выводим отсутствие уровня
		return context::level_t::NONE;
	// Определяем сторону связи, уровень которой запрашивается
	const session::side_t side = (((direction == context::direction_t::WRITE) == this->_server) ? session::side_t::SERVER : session::side_t::CLIENT);
	// Получаем уровень защиты стороны по поре её ключей
	const context::level_t level = this->layer(side);
	/**
	 * Упреждающие данные клиента идут своим уровнем, пока стороны не перешли к ключам
	 * рукопожатия: уровень этот выше начального и ниже рукопожатия
	 */
	if((level == context::level_t::INITIAL) && (side == session::side_t::CLIENT) && this->_earlying)
		// Выводим уровень упреждающих данных
		return context::level_t::EARLY;
	// Выводим уровень защиты стороны
	return level;
}
/**
 * @brief Метод проверки хода упреждающих данных прямо сейчас
 *
 * @return признак того, что упреждающие данные идут прямо сейчас
 *
 */
bool nts::internal::Engine::earlying() const noexcept {
	// Выводим признак хода упреждающих данных
	return this->_earlying;
}
/**
 * @brief Метод проверки отказа сервера от предложенных упреждающих данных
 *
 * @return признак того, что упреждение предлагалось и сервером отвергнуто
 *
 */
bool nts::internal::Engine::rejected() const noexcept {
	// Выводим признак отвергнутого сервером упреждения
	return (this->_ventured && this->_judged && !this->_accepted);
}
/**
 * @brief Метод заведения связи
 *
 * @return отказ заведения связи
 *
 */
context::error_t nts::internal::Engine::start() noexcept {
	// Если связь уже заведена
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Настройкам связи памяти не хватило: установщики настроек отказа не выводят, и
	 * отвечать за них приходится заведению связи, ибо вести её с потерянными
	 * настройками значило бы выдавать нехватку памяти за нехватку настроек
	 */
	if(this->_starved){
		// Нехватка памяти при настройке сообщается один раз: настройки заданы заново потребителем
		this->_starved = false;
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	/**
	 * Заслон этот через общедоступный договор недостижим: установщики наборов
	 * шифрования и кривых обмена ключами пустой список пропускают, сохраняя
	 * умолчания, и опустошить наборы потребителю нечем. Стоит он ради самого движка,
	 * если наборы эти когда-либо станут опустошаемы
	 */
	/**
	 * Заслон этот через фасад недостижим: сеттеры перечней пустой перечень пропускают,
	 * оставляя умолчание, и пустыми перечни быть не могут. Стоит он ради связности:
	 * рукопожатие без единого набора шифрования молча начинаться не должно
	 */
	if(this->_suites.empty() || this->_groups.empty() || this->_signatures.empty())
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Под QUIC (RFC 9001) связь знает одно лишь издание 1.3, и пределы, издание 1.3
	 * исключающие, оставляют такой связи нечем вестись; поверх дейтаграмм издания оба
	 * (RFC 9147 и RFC 6347)
	 */
	if((this->_transport == context::transport_t::LEVELS) && (this->_highest < MODERN))
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Издание 1.1 (DTLS 1.0 по RFC 4347) ведётся лишь дейтаграммами: потоком TLS 1.0 и 1.1
	 * не заводятся - у AWH пол переноса записями 1.2, и опускаться ниже незачем
	 */
	if((this->_transport != context::transport_t::DATAGRAMS) && (this->_lowest < LEGACY))
		// Выводим отказ негодных настроек
		return context::error_t::SETTINGS;
	/**
	 * Выполняем перебор алгоритмов сжатия, предоставленных потребителем
	 */
	for(size_t i = 0; i < this->_codecs.size(); i++){
		/**
		 * Алгоритм без обоих вызовов либо с опознавателем «нет сжатия» объявить
		 * собеседнику нельзя: объявленное придётся исполнять, а исполнять нечем
		 */
		if((this->_codecs[i].algorithm == 0) || (this->_codecs[i].compress == nullptr) || (this->_codecs[i].decompress == nullptr))
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
	}
	// Если перечень доверенных удостоверяющих центров задан
	if(!this->_trusted.empty()){
		// Тело перечня, составленное ради проверки имён
		vector <uint8_t> names;
		// Отказ проверки перечня: пустое имя либо имя не SEQUENCE отвергается заведением связи
		const context::error_t named = translate(extension::authorities(this->_trusted, names), context::error_t::SETTINGS);
		// Если перечень негоден либо памяти под проверку не хватило
		if(named != context::error_t::NONE)
			// Выводим отказ негодных настроек либо нехватки памяти
			return named;
	}
	// Если перечень меток времени своего сертификата задан
	if(!this->_stamps.empty()){
		// Записи перечня, разобранные ради проверки вида
		vector <vector <uint8_t>> entries;
		/**
		 * Раздел 3.3 RFC 6962: перечень выдаётся как записан, оттого негодная запись
		 * отвергается заведением связи, а не собеседником
		 */
		// Отказ проверки перечня
		const context::error_t checked = translate(extension::timestamps(view_t(this->_stamps.data(), this->_stamps.size()), entries), context::error_t::SETTINGS);
		// Если перечень негоден либо памяти под проверку не хватило
		if(checked != context::error_t::NONE)
			// Выводим отказ негодных настроек либо нехватки памяти
			return checked;
	}
	/**
	 * Выполняем перебор объявленных прикладных настроек
	 */
	for(size_t i = 0; i < this->_settings.size(); i++){
		// Признак того, что протокол настроек предлагается связью
		bool offered = false;
		/**
		 * Выполняем перебор прикладных протоколов связи
		 */
		for(size_t j = 0; (j < this->_protocols.size()) && !offered; j++)
			// Запоминаем, предлагается ли протокол настроек связью
			offered = (this->_settings[i].protocol.compare(this->_protocols[j]) == 0);
		/**
		 * Черновик draft-vvv-tls-alps: настройки объявляются лишь для протокола из перечня
		 * ALPN, а имя протокола по проводу занимает от одного до 255 байтов
		 */
		if(!offered || this->_settings[i].protocol.empty() || (this->_settings[i].protocol.size() > 0xFF))
			// Выводим отказ протокола, связью не предлагаемого
			return context::error_t::PROTOCOL;
	}
	/**
	 * Сервер без своей подлинности связь завести не вправе: подтверждать её ему нечем;
	 * без сертификата годен лишь сервер с вызовом ключа по опознавателю - рукопожатие
	 * на заранее разделённом ключе (RFC 4279, RFC 5489) обходится без сертификата
	 */
	if(this->_server && (this->_credential.chain.empty() || this->_credential.secret.empty()) && (this->_psk.respond == nullptr))
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Раздел 5.3 RFC 4279: опознаватель и подсказка не длиннее 128 байтов, ключ - не
	 * длиннее 64; пустой опознаватель законен (раздел 2 RFC 4279: psk_identity<0..2^16-1>),
	 * и клиент с ключом без опознавателя предъявляет пустой
	 */
	if((this->_psk.identity.size() > IDENTITY) || (this->_psk.key.size() > PRESHARED))
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	// Если ключ билетов сеансов серверу не задан
	if(this->_server && !this->_keeper.ready()){
		// Место, в которое помещается случайный секрет ключа билетов
		uint8_t secret[32];
		// Раздел 4 RFC 5077: ключ порождается энтропией, и билеты тогда признаёт лишь эта связь
		if(!entropy::bytes(secret, sizeof(secret)))
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		// Признак успешности заведения ключа билетов из случайного секрета
		const bool stashed = this->_keeper.stash(view_t(secret, sizeof(secret)));
		// Выполняем затирание случайного секрета
		this->purge(secret, sizeof(secret));
		// Если ключ билетов завести не удалось
		if(!stashed)
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
	}
	/**
	 * Раздел 8.1 RFC 9001: под QUIC прикладной протокол обязателен обеим сторонам, и
	 * связь без единого предлагаемого протокола заводиться не вправе
	 */
	if((this->_transport == context::transport_t::LEVELS) && this->_protocols.empty())
		// Выводим отказ нехватки настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Раздел 8.2 RFC 9001: параметры переноса обязательны обеим сторонам; пустой набор
	 * стандарт записать дозволяет, но потребителю такое приветствие не нужно ни при
	 * каких условиях, и заводить связь без параметров значило бы молча слать пустое
	 * расширение вместо того, чтобы назвать недостающую настройку
	 */
	if((this->_transport == context::transport_t::LEVELS) && this->_parameters.empty())
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Восстанавливаем наборы из настройки
		this->_suites = this->_catalog;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если связь ведётся поверх дейтаграмм
	if(this->_transport == context::transport_t::DATAGRAMS){
		/**
		 * Упреждающие данные поверх дейтаграмм связью не ведутся: первая пора ключей
		 * (раздел 4.2.1 RFC 9147) не заводится, и предложение упреждения - ошибка настройки
		 */
		if(this->_advance)
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Наборы шифрования, у которых есть маска номера записи
			vector <protect::suite_t> suites;
			/**
			 * RFC 9147 знает лишь наборы AES-GCM и ChaCha20-Poly1305: наборы ГОСТ маски
			 * номера записи не имеют и поверх дейтаграмм не предлагаются; наборы издания
			 * 1.2 (RFC 6347) остаются
			 */
			for(size_t i = 0; i < this->_suites.size(); i++){
				// Если набор шифрования классический либо принадлежит изданию 1.2
				if((this->_suites[i] == protect::suite_t::AES_128_GCM_SHA256) || (this->_suites[i] == protect::suite_t::AES_256_GCM_SHA384) || (this->_suites[i] == protect::suite_t::CHACHA20_POLY1305_SHA256) || protect::legacy(this->_suites[i]))
					// Оставляем набор шифрования в предложении
					suites.push_back(this->_suites[i]);
			}
			// Заменяем предложение наборов оставленными
			this->_suites = ::move(suites);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Если ни одного набора с маской номера не осталось
		if(this->_suites.empty())
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		/**
		 * Раздел 5.1 RFC 9147: метка возврата состояния привязывается к адресу
		 * собеседника, и сервер без адреса метку ни сложить, ни проверить не может -
		 * связь без него молча отбрасывала бы всякое повторное приветствие
		 */
		if(this->_server && !this->_flight.addressed())
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		// Если секреты метки возврата состояния сервера выработать не удалось
		if(this->_server && !this->_flight.prepare())
			// Выводим отказ нехватки настроек связи
			return context::error_t::SETTINGS;
		// Раздел 5.1 RFC 9147 и раздел 4.2.1 RFC 6347: до метки адрес собеседника серверу не подтверждён
		if(this->_server)
			// Снимаем подтверждённость адреса собеседника
			this->_flight.verified(false);
	}
	// Если ход рукопожатия связи завести не удалось
	if(!this->_machine.start(this->_server ? flow::role_t::SERVER : flow::role_t::CLIENT))
		// Выводим отказ заведения хода рукопожатия
		return context::error_t::STATE;
	// Выполняем начало переписки рукопожатия связи
	this->_transcript.start();
	// Переводим связь в состояние рукопожатия
	this->_state = context::state_t::HANDSHAKE;
	// Выполняем выработку случайного значения своего приветствия
	if(!entropy::bytes(this->_random, sizeof(this->_random)))
		// Выводим отказ выработки случайного значения приветствия
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	/**
	 * Зерно значений GREASE вырабатывается на связь один раз: повторное приветствие
	 * после просьбы о повторе несёт те же значения, а сервер выводит из него
	 * расширения билета и запроса подлинности
	 */
	if(!entropy::bytes(this->_seed, sizeof(this->_seed)))
		// Выводим отказ выработки зерна значений GREASE
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	// Раздел 4.2 RFC 8446: два расширения GREASE одного значения означали бы повторное объявление
	if((this->_seed[static_cast <uint8_t> (grease_t::FIRST)] & 0xF0) == (this->_seed[static_cast <uint8_t> (grease_t::SECOND)] & 0xF0))
		// Разводим значение второго расширения со значением первого
		this->_seed[static_cast <uint8_t> (grease_t::SECOND)] ^= 0x10;
	// Если связь ведётся стороной сервера
	if(this->_server)
		// Выводим успешность заведения связи: сервер ждёт приветствия клиента
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Занимаем место под опознаватель связи: по профилю отпечатка - той же длины, что у обозревателя
		this->_session.assign((this->_profiled ? this->_profile.session.size() : hello::HELLO_SESSION), 0);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Если опознаватель связи выработать не удалось
	if(!this->_session.empty() && !entropy::bytes(this->_session.data(), this->_session.size()))
		// Выводим отказ выработки опознавателя связи
		return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
	/**
	 * Доли ключа шлются по группам, назначенным потребителем, а без назначения - по
	 * первой из поддерживаемых и по первой группе каждого ещё не представленного рода:
	 * кривые ГОСТ, гибриды с ML-KEM, классические кривые. Так у умолчаний доли идут по
	 * X25519MLKEM768 и X25519, как шлют браузеры, и сервер без ML-KEM берёт долю кривой
	 * без просьбы о повторе; а у связи с объявленным ГОСТ доля ГОСТ есть всегда, и сервер
	 * с ГОСТ впереди своего перечня берёт её без повтора (намеренное решение 19). Группы
	 * конечного поля свою долю получают лишь первыми либо по назначению. Раздел 4.2.8
	 * RFC 8446 велит слать доли лишь по группам из объявленной поддержки, и группа доли
	 * вне поддержки есть ошибка настройки
	 */
	vector <extension::group_t> shares;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если группы долей назначены потребителем
		if(!this->_shares.empty())
			// Берём назначенные группы долей ключа
			shares = this->_shares;
		// Если групп долей потребитель не назначал
		else {
			// Доля идёт по первой из поддерживаемых групп, какого бы рода та ни была
			shares.push_back(this->_groups[0]);
			// Признаки родов групп, доли по которым уже составлены: кривые ГОСТ, гибриды с ML-KEM, классические кривые
			bool covered[3] = {false, false, false};
			// Род первой группы
			const int8_t first = family(this->_groups[0]);
			// Если первая группа одного из трёх родов
			if(first >= 0)
				// Запоминаем, что доля этого рода составлена
				covered[first] = true;
			/**
			 * Выполняем перебор прочих поддерживаемых групп: по первой группе каждого ещё
			 * не представленного рода идёт своя доля
			 */
			for(size_t i = 1; i < this->_groups.size(); i++){
				// Род группы
				const int8_t kind = family(this->_groups[i]);
				// Если группа одного из трёх родов и доли этого рода ещё нет
				if((kind >= 0) && !covered[kind]){
					// Добавляем долю по первой группе рода
					shares.push_back(this->_groups[i]);
					// Запоминаем, что доля этого рода составлена
					covered[kind] = true;
				}
			}
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	/**
	 * Выполняем перебор групп, по которым шлются доли ключа
	 */
	for(size_t i = 0; i < shares.size(); i++){
		// Признак того, что группа доли объявлена поддерживаемой
		bool declared = false;
		/**
		 * Выполняем перебор групп, поддерживаемых связью
		 */
		for(size_t j = 0; (j < this->_groups.size()) && !declared; j++)
			// Запоминаем совпадение группы доли с поддерживаемой
			declared = (shares[i] == this->_groups[j]);
		// Если группа доли поддерживаемой не объявлена
		if(!declared)
			// Выводим отказ нехватки настроек связи
			return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
		// Выполняем выработку мимолётной пары ключей своей стороны
		const context::error_t error = this->exchange(shares[i]);
		// Если мимолётную пару ключей выработать не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ выработки мимолётной пары ключей
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Выполняем отправку приветствия клиента
	const context::error_t outcome = this->greeting();
	// Если приветствие клиента отправить не удалось
	if(outcome != context::error_t::NONE)
		// Выводим отказ заведения связи
		return this->abort(outcome, alert::description_t::INTERNAL);
	// Если связь ведётся поверх дейтаграмм
	if(this->_transport == context::transport_t::DATAGRAMS){
		// Отказ раскладки залпа по дейтаграммам
		const context::error_t error = this->_flight.dispatch(false);
		// Если залп разложить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ заведения связи
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Выводим успешность заведения связи
	return context::error_t::NONE;
}
/**
 * @brief Метод сброса состояния связи
 *
 */
void nts::internal::Engine::clear() noexcept {
	// Выполняем сброс состояния связи: без укрытой памяти ключей связь негодна
	this->_state = ((this->_keys != nullptr) ? context::state_t::NONE : context::state_t::FAILED);
	// Выполняем сброс отказа, которым связь оборвана
	this->_error = context::error_t::NONE;
	// Выполняем сброс извещения, которым связь оборвана
	this->_alert = alert::alert_t();
	// Выполняем сброс набора шифрования связи
	this->_suite = protect::suite_t::NONE;
	// Выполняем сброс кривой обмена ключами связи
	this->_group = extension::group_t::NONE;
	// Выполняем сброс места выбранного ключа в предложении
	this->_chosen = 0;
	// Выполняем сброс признака задолженной смены ключей
	this->_owed = false;
	// Сбрасываем признак завершения своей передачи
	this->_closed = false;
	// Сбрасываем признак завершения передачи собеседником
	this->_drained = false;
	// Выполняем сброс признака отвергнутого возрастом упреждения
	this->_misaged = false;
	// Выполняем сброс предела упреждающих данных билета
	this->_granted = 0;
	// Выполняем сброс признака запроса подлинности клиента
	this->_requested = false;
	// Выполняем сброс признака повтора приветствия клиента
	this->_retried = false;
	// Выполняем сброс признака возобновления связи билетом
	this->_shared = false;
	// Выполняем сброс признака хода упреждающих данных
	this->_earlying = false;
	// Выполняем сброс набора шифрования билета возобновления связи
	this->_ticket = protect::suite_t::NONE;
	// Выполняем сброс признака приёма упреждающих данных
	this->_accepted = false;
	// Выполняем сброс числа пропущенных записей упреждающих данных
	this->_skipped = 0;
	// Выполняем сброс признака испрошенной у собеседника смены ключей
	this->_asked = false;
	// Выполняем сброс размера прошедших упреждающих данных
	this->_passed = 0;
	// Выполняем сброс перечня расширений, предложенных приветствием
	this->_offered.clear();
	// Выполняем сброс пределов длины записей к умолчанию протокола: пределы договариваются заново каждым рукопожатием (раздел 4 RFC 8449)
	this->_outgoing = record::RECORD_PLAINTEXT;
	// Переносим предел собеседника переносу дейтаграммами: записи режутся по нему (RFC 8449, RFC 6066)
	this->_flight.limit(this->_outgoing);
	// Выполняем сброс предела длины принимаемых записей
	this->_incoming = record::RECORD_PLAINTEXT;
	// Выполняем сброс признака действующего расширения предела и присланных клиентом значений
	this->_sizing = 0;
	// Сбрасываем присланное клиентом значение record_size_limit
	this->_bounding = 0;
	// Сбрасываем присланный клиентом код max_fragment_length
	this->_fragmenting = 0;
	// Выполняем сброс признака предложенного heartbeat
	this->_heartbeating = false;
	// Сбрасываем дозволение слать собеседнику запросы сердцебиения
	this->_permitted = false;
	// Сбрасываем свой режим heartbeat
	this->_answering = false;
	// Сбрасываем признак запроса сердцебиения в пути
	this->_beating = false;
	// Сбрасываем число принятых ответов на свои запросы сердцебиения
	this->_pulses = 0;
	// Сбрасываем нагрузку запроса сердцебиения в пути
	this->_pulse.clear();
	// Выполняем сброс признака запроса меток времени сертификата собеседником
	this->_stamped = false;
	// Выполняем сброс перечня меток времени сертификата собеседника
	this->_timestamps.clear();
	// Выполняем сброс перечня доверенных центров собеседника
	this->_authorities.clear();
	// Выполняем сброс признака издания DTLS 1.0
	this->_ancient = false;
	// Выполняем сброс признака выработки NPN
	this->_negotiated = false;
	// Выполняем сброс признака прохождения NextProtocol
	this->_announced = false;
	// Выполняем сброс признака согласования прикладных настроек
	this->_settled = false;
	// Выполняем сброс признака прохождения защищённых расширений клиента
	this->_stated = false;
	// Выполняем сброс своих прикладных настроек связи
	this->_applied.clear();
	// Выполняем сброс прикладных настроек собеседника
	this->_obtained.clear();
	// Выполняем сброс признака согласования настроек у выдавшей билет связи
	this->_bequeathed = false;
	// Выполняем сброс своих настроек выдавшей билет связи
	this->_bequest.clear();
	// Выполняем сброс настроек собеседника выдавшей билет связи
	this->_heritage.clear();
	// Выполняем сброс метки возврата состояния, принятой от собеседника
	this->_label.clear();
	// Выполняем сброс схем подписи, признаваемых собеседником
	this->_schemes.clear();
	// Выполняем сброс опознавателя принятого запроса подлинности
	this->_binding.clear();
	// Выполняем сброс алгоритмов сжатия, объявленных собеседником
	this->_compressible.clear();
	// Выполняем сброс алгоритма сжатия отправленной цепочки
	this->_squeezed = 0;
	// Выполняем сброс алгоритма сжатия принятой цепочки
	this->_inflated = 0;
	// Выполняем сброс признака запроса состояния собеседником
	this->_inquired = false;
	// Выполняем сброс ответа о состоянии сертификата собеседника
	this->_status.clear();
	// Выполняем сброс состояния сертификата собеседника
	this->_certified = ocsp::status_t::NONE;
	// Выполняем сброс прикладного протокола связи, выдавшей билет
	this->_previous.clear();
	// Выполняем сброс защиты записей упреждающих данных
	this->_early.clear();
	// Выполняем сброс хода рукопожатия связи
	this->_machine.clear();
	// Выполняем сброс переписки рукопожатия связи
	this->_transcript.clear();
	// Выполняем сброс значений расписания ключей связи
	this->_secrets.clear();
	// Выполняем сброс сборщика входящих записей связи
	this->_records.clear();
	// Выполняем сброс сборщика входящих сообщений рукопожатия
	this->_messages.clear();
	// Возвращаем сборщику сообщений предел, положенный рукопожатию
	this->_messages.limit(handshake::HANDSHAKE_LIMIT);
	// Выполняем сброс защиты отправляемых записей связи
	this->_output.clear();
	// Выполняем сброс защиты принимаемых записей связи
	this->_input.clear();
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Если укрытая память ключей заведена: без участка (отказ хранилища под demand) затирать нечего
	if(this->_keys != nullptr)
		// Выполняем затирание ключевого материала связи целиком: главный секрет, ключи завершения, ключи, векторы, имитовставки и направления
		this->_shelter.wipe();
	/**
	 * Выполняем перебор мимолётных пар ключей своей стороны
	 */
	for(size_t i = 0; i < this->_exchanges.size(); i++){
		// Если секретный мимолётный ключ пары выработан
		if(!this->_exchanges[i].secret.empty())
			// Выполняем затирание секретного мимолётного ключа
			this->purge(this->_exchanges[i].secret.data(), this->_exchanges[i].secret.size());
		// Если общий секрет инкапсуляции есть
		if(!this->_exchanges[i].shared.empty())
			// Выполняем затирание общего секрета инкапсуляции
			this->purge(this->_exchanges[i].shared.data(), this->_exchanges[i].shared.size());
	}
	// Выполняем сброс мимолётных пар ключей своей стороны
	this->_exchanges.clear();
	// Выполняем затирание принятых прикладных данных по классу PLAINTEXT
	this->cleanse(this->_plain);
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выполняем затирание накопителя открытого содержимого записи по классу PLAINTEXT
	this->cleanse(this->_opened);
	// Сбрасываем накопитель открытого содержимого записи
	this->_opened.clear();
	// Выполняем сброс накопителя отправляемых байтов связи
	this->_wire.clear();
	/**
	 * Выполняем перебор накопителей сообщений по уровням защиты
	 */
	for(size_t i = 0; i < (sizeof(this->_levels) / sizeof(this->_levels[0])); i++)
		// Выполняем сброс накопителя сообщений очередного уровня
		this->_levels[i].clear();
	// Выполняем сброс уровня недособранного сообщения
	this->_pushed = context::level_t::NONE;
	// Выполняем сброс параметров переноса собеседника
	this->_received.clear();
	// Выполняем сброс признака приёма параметров переноса собеседника
	this->_acquired = false;
	// Выполняем сброс признаков готовности значений направлений
	::memset(this->_ready, 0, sizeof(this->_ready));
	// Выполняем сброс длины значений направлений связи
	this->_width = 0;
	// Выполняем сброс признака предложения упреждающих данных
	this->_ventured = false;
	// Выполняем сброс признака решения сервера об упреждающих данных
	this->_judged = false;
	// Выполняем сброс цепочки сертификатов собеседника
	this->_peer.clear();
	// Выполняем сброс прикладного протокола, выбранного сторонами
	this->_protocol.clear();
	/**
	 * Имя узла сбрасывается лишь стороной сервера: у клиента оно объявляет, за каким
	 * узлом он идёт, и настройкой этой связь распоряжаться не вправе
	 */
	if(this->_server)
		// Выполняем сброс имени узла, запрошенного клиентом
		this->_name.clear();
	/**
	 * Метка возврата состояния сбрасывается лишь стороной клиента: у сервера она
	 * настройка, которой связь распоряжаться не вправе, а у клиента - состояние,
	 * доставшееся от просьбы о повторе приветствия
	 */
	if(!this->_server)
		// Выполняем сброс метки возврата состояния сервера
		this->_cookie.clear();
	/**
	 * Выполняем перебор билетов возобновления связи
	 */
	for(size_t i = 0; i < this->_tickets.size(); i++)
		// Выполняем затирание ключа очередного билета возобновления связи
		this->purge(this->_tickets[i].secret.data(), this->_tickets[i].secret.size());
	// Выполняем сброс билетов возобновления связи
	this->_tickets.clear();
	// Выполняем сброс опознавателя связи
	this->_session.clear();
	// Выполняем сброс принятого приветствия клиента
	this->_salutation.clear();
	// Выполняем сброс состояния зашифрованного приветствия ECH: конфигурации и ключ - настройки, они остаются
	this->_ech = ech_t::NONE;
	// Выполняем сброс внутреннего приветствия
	this->_inner.clear();
	// Выполняем сброс видов расширений внутреннего приветствия
	this->_hidden.clear();
	// Выполняем сброс запасных конфигураций
	this->_retries.clear();
	// Выполняем сброс признаков сервера
	this->_echaccepted = false;
	// Сбрасываем признак отказа сервером ECH
	this->_echrejected = false;
	// Сбрасываем признак разбора восстановленного внутреннего приветствия
	this->_unshrouding = false;
	// Выполняем сброс состояний HPKE
	this->_sealer.clear();
	// Выполняем сброс состояния HPKE получателя
	this->_opener.clear();
	// Выполняем затирание случайного значения внутреннего приветствия
	this->purge(this->_innerandom, sizeof(this->_innerandom));
	// Выполняем затирание случайного значения своего приветствия
	this->purge(this->_random, sizeof(this->_random));
	// Сбрасываем признак просьбы о доле ключа
	this->_reshare = true;
	// Выполняем сброс переноса дейтаграммами
	this->_flight.clear();
	// Выполняем сброс согласованного издания протокола
	this->_version = 0;
	// Выполняем сброс признака издания TLS 1.2
	this->_legacy = false;
	// Выполняем сброс признака расширенного главного секрета связи
	this->_extending = false;
	// Выполняем сброс метки возврата состояния DTLS 1.2
	this->_token.clear();
	// Выполняем сброс числа принятых просьб о подтверждении адреса
	this->_queries = 0;
	// Выполняем сброс признака подтверждённого адреса собеседника
	this->_confirmed = false;
	// Выполняем сброс номера последнего выданного сообщения
	this->_delivered = 0;
	// Выполняем сброс признака смены набора, ждущей своего черёда
	this->_switched = false;
	// Выполняем сброс признака предложения издания TLS 1.3
	this->_proposed = false;
	// Выполняем сброс ступени рукопожатия издания TLS 1.2
	this->_phase = phase_t::NONE;
	// Сбрасываем признак защиты своих записей издания TLS 1.2
	this->_sealing = false;
	// Сбрасываем признак защиты записей собеседника издания TLS 1.2
	this->_opening = false;
	// Сбрасываем признак отдельного сообщения состояния сертификата
	this->_stapling = false;
	// Выполняем затирание случайного значения собеседника
	this->purge(this->_foreign, sizeof(this->_foreign));
	// Выполняем затирание секретов издания TLS 1.2
	this->scrub();
	// Выполняем сброс переписки подряд издания TLS 1.2
	this->_history.clear();
	// Выполняем сброс опознавателя заранее разделённого ключа связи
	this->_identity.clear();
	// Выполняем сброс издания заголовка приветствия клиента
	this->_claimed = 0;
	// Сбрасываем порядок «шифрование, затем имитовставка»
	this->_etm = false;
	// Сбрасываем признак обещанного билета сеанса
	this->_ticketing = false;
	// Сбрасываем признак предъявленного билета сеанса
	this->_presented = false;
	// Сбрасываем признак сокращённого рукопожатия
	this->_resumed = false;
	// Выполняем сброс мига первичного удостоверения
	this->_authenticated = 0;
	// Если ожидавший билет сеанса принят
	if(!this->_promise.secret.empty())
		// Выполняем затирание главного секрета ожидавшего билета
		this->purge(this->_promise.secret.data(), this->_promise.secret.size());
	// Выполняем сброс ожидавшего билета сеанса
	this->_promise = context::ticket_t();
}
/**
 * @brief Метод подачи связи принятых байтов
 *
 * @param data принятые байты связи
 * @return     отказ разбора принятых байтов
 *
 */
context::error_t nts::internal::Engine::push(const view_t & data) noexcept {
	// Отказ связи, отвечающий отказу модуля
	context::error_t failure = context::error_t::NONE;
	// Если связь ещё не заведена либо уже оборвана
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::FAILED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Перенос по уровням записей не разбирает: байты записей ему подавать нечем, и
	 * подача их означает оплошность того, кто связь ведёт, а не собеседника
	 */
	if(this->_transport == context::transport_t::LEVELS)
		// Выводим отказ подачи не тем способом переноса
		return context::error_t::LEVEL;
	// Перенос дейтаграммами разбирает дейтаграмму целиком своим путём
	if(this->_transport == context::transport_t::DATAGRAMS)
		// Выводим итог разбора принятой дейтаграммы
		return this->receive(data);
	/**
	 * Сборщик записей отказывает единственно нехваткой памяти под накопитель: сам
	 * разбор идёт позже, отдельным вызовом. Отвечать здесь извещением о переросшей
	 * записи значило бы выдавать свою беду за оплошность собеседника, и раздел 6.2
	 * RFC 8446 велит на свои беды отвечать извещением о внутреннем отказе
	 */
	// Отказ нехватки памяти под накопитель записей
	failure = translate(this->_records.push(data), context::error_t::MEMORY);
	// Если накопить запись не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ нехватки памяти под накопитель записей
		return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
	// Заголовок принятой записи связи
	record::header_t header;
	// Содержимое принятой записи связи
	view_t payload;
	/**
	 * Выполняем перебор принятых записей связи
	 */
	while(true){
		// Выполняем сборку очередной принятой записи связи
		const record::error_t taken = this->_records.next(header, payload);
		// Если данных для целой записи ещё не набралось
		if(taken == record::error_t::HUNGRY)
			// Прекращаем перебор принятых записей связи
			break;
		/**
		 * Негодная запись прежде молча оставалась в накопителе, и связь на ней
		 * замирала: раздел 5.1 RFC 8446 велит отвечать на неё извещением, а слишком
		 * длинной записи - именно извещением «record_overflow»
		 */
		if(taken != record::error_t::NONE){
			// Отказ разбора принятой записи связи
			failure = translate(taken, context::error_t::RECORD);
			// Выводим отказ разбора принятой записи связи
			return this->abort(failure, blame(failure, ((taken == record::error_t::LENGTH) ? alert::description_t::OVERSIZE : alert::description_t::UNEXPECTED)));
		}
		/**
		 * Приложение E.1 RFC 5246: за согласованием издания 1.2 всякая запись несёт в
		 * заголовке согласованное издание; иное означает собеседника, сменившего издание
		 * посреди связи. Первому приветствию клиента дозволены и меньшие издания заголовка,
		 * а издание 1.3 заголовка не судит вовсе (раздел 5.1 RFC 8446)
		 */
		if(this->_legacy && (header.version != record::version_t::TLS12))
			// Выводим отказ несовпадения издания заголовка записи
			return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		// Если принята запись смены набора шифрования
		if(header.type == record::type_t::CHANGE){
			/**
			 * Изданию TLS 1.2 смена набора шифрования значима (раздел 7.1 RFC 5246): за нею
			 * записи собеседника идут под выведенными ключами, и приходит она ровно однажды
			 * на своей ступени, не разрывая сообщения рукопожатия
			 */
			if(this->_legacy){
				// Если клиент с предъявленным билетом ждёт первого сообщения за приветствием сервера: смена набора означает сокращённое рукопожатие
				if(!this->_server && (this->_phase == phase_t::EITHER) && (this->_messages.pending() == 0)){
					// Отказ суждения о виде рукопожатия
					const context::error_t judged = this->deciding(true);
					// Если ключевой материал возобновлённой связи вывести не удалось либо набор разошёлся с билетом
					if(judged != context::error_t::NONE)
						// Выводим отказ суждения
						return this->abort(judged, blame(judged, (((judged == context::error_t::SUITE) || (judged == context::error_t::ETM) || (judged == context::error_t::VERSION)) ? alert::description_t::PARAMETER : alert::description_t::INTERNAL)));
				}
				// Если смена пришла не в свой черёд либо сложена не по правилам
				if((this->_phase != phase_t::CHANGE) || this->_opening || (payload.size != 1) || (payload.data[0] != 0x01) || (this->_messages.pending() > 0))
					// Выводим отказ прихода смены набора не в свой черёд
					return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
				// Запоминаем, что записи собеседника отныне защищены
				this->_opening = true;
				// Переходим к ожиданию завершения рукопожатия собеседником
				this->_phase = phase_t::FINISHED;
				// Переходим к следующей принятой записи связи
				continue;
			}
			/**
			 * Раздел 5 RFC 8446 велит пропускать эту запись лишь по ходу рукопожатия и
			 * лишь с единственным дозволенным значением: за установленной связью она
			 * не значит ничего, а иное её содержимое - это уже не она
			 */
			if((this->_state == context::state_t::ESTABLISHED) || (this->_state == context::state_t::CLOSED) || (this->_server && !this->_retried && (this->_machine.stage() == flow::stage_t::GREETING)) || (payload.size != 1) || (payload.data[0] != 0x01))
				// Выводим отказ прихода записи смены набора не в свой черёд
				return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
			// Пропускаем запись, доставшуюся от предыдущих изданий протокола
			continue;
		}
		// Получаем сторону связи собеседника
		const session::side_t side = (this->_server ? session::side_t::CLIENT : session::side_t::SERVER);
		// Вид содержимого принятой записи связи
		record::type_t type = header.type;
		// Выполняем затирание открытого содержимого предыдущей записи по классу PLAINTEXT
		this->cleanse(this->_opened);
		// Опустошаем накопитель открытого содержимого записи: память его остаётся с движком
		this->_opened.clear();
		// Просмотр открытого содержимого принятой записи
		view_t content = payload;
		// Длина накопителя прикладных данных до вскрытия записи: запись ключей связи вскрывается прямо в него
		const size_t before = this->_plain.size();
		// Признак того, что содержимое записи уже лежит в накопителе прикладных данных
		bool inplace = false;
		// Если связь ведётся изданием TLS 1.2 под ключами собеседника
		if(this->_legacy && this->_opening){
			// Отказ снятия защиты с принятой записи
			failure = translate(this->_input.open(header, payload, type, this->_opened), context::error_t::PROTECTION);
			/**
			 * Раздел 6.2.3.3 RFC 5246: несошедшаяся метка целостности обрывает связь
			 * извещением bad_record_mac - в отличие от DTLS, где запись лишь отбрасывается
			 */
			if(failure != context::error_t::NONE)
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(failure, blame(failure, alert::description_t::MAC));
			// Получаем открытое содержимое принятой записи
			content = view_t(this->_opened.data(), this->_opened.size());
		// Если принимаются упреждающие данные клиента
		} else if(this->_server && this->_earlying){
			// Отказ снятия защиты с принятой записи
			failure = translate(this->_early.open(header, payload, type, this->_opened), context::error_t::PROTECTION);
			// Если снять защиту упреждающих данных с принятой записи не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(failure, blame(failure, alert::description_t::MAC));
			// Получаем открытое содержимое принятой записи
			content = view_t(this->_opened.data(), this->_opened.size());
		// Если записи собеседника защищены ключами связи
		} else if(!this->_legacy && (this->_machine.epoch(side) != flow::epoch_t::PLAIN)){
			/**
			 * Запись вскрывается прямо в накопитель прикладных данных (решение 21 шапки):
			 * снятие защиты дописывает в конец, прикладные данные остаются на месте без
			 * копии, содержимое иного вида переносится в накопитель открытого содержимого,
			 * а при отказе снятия защиты длина накопителя уже возвращена к прежней
			 */
			failure = translate(this->_input.open(header, payload, type, this->_plain), context::error_t::PROTECTION);
			// Если снять защиту с принятой записи не удалось
			if(failure != context::error_t::NONE){
				/**
				 * Упреждающие данные, сервером отвергнутые, прочесть нечем: раздел 4.2.10
				 * RFC 8446 велит такие записи пропускать, а не рвать по ним связь.
				 * Нехватка памяти же к защите записи не относится и пропуском не лечится
				 */
				if((failure != context::error_t::MEMORY) && this->_server && (this->_skipped >= header.size)){
					// Уменьшаем объём байтов, дозволенных к пропуску
					this->_skipped -= header.size;
					// Переходим к следующей принятой записи связи
					continue;
				}
				// Выводим отказ снятия защиты с принятой записи
				return this->abort(failure, blame(failure, alert::description_t::MAC));
			}
			/**
			 * Первая прочтённая запись закрывает пропуск отвергнутых упреждающих
			 * данных: за нею идут записи, защищённые ключами рукопожатия
			 */
			this->_skipped = 0;
			// Если приняты прикладные данные: они остаются в накопителе прикладных данных
			if(type == record::type_t::APPLICATION){
				// Получаем открытое содержимое принятой записи из накопителя прикладных данных
				content = view_t(this->_plain.data() + before, this->_plain.size() - before);
				// Запоминаем, что содержимое записи уже лежит в накопителе прикладных данных
				inplace = true;
			// Иначе содержимое записи переносится в накопитель открытого содержимого
			} else {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Выполняем перенос содержимого записи в накопитель открытого содержимого
					this->_opened.assign(this->_plain.begin() + static_cast <ptrdiff_t> (before), this->_plain.end());
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Отзываем содержимое записи из накопителя прикладных данных
					this->retract(before);
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
				// Отзываем содержимое записи из накопителя прикладных данных
				this->retract(before);
				// Получаем открытое содержимое принятой записи
				content = view_t(this->_opened.data(), this->_opened.size());
			}
			/**
			 * Раздел 5.5 RFC 8446 велит сменять ключи впереди предела порядковых номеров.
			 * Направление собеседника сменить самим нельзя - оттого у него испрашивается
			 * смена просьбою в собственном KeyUpdate, и просьба повторяется лишь после
			 * того, как собеседник ключи сменил. Записи рукопожатия за установленной
			 * связью - сама смена ключей и билеты - просьбы не будят: по ним счётчик
			 * собеседника вот-вот обнулится либо будет испрошен следующей записью
			 */
			if(type != record::type_t::HANDSHAKE){
				// Отказ испрашивания смены ключей у собеседника
				const context::error_t error = this->soliciting();
				/**
				 * Заслон этот недостижим извне: смена ключей за установленной связью
				 * отказывает лишь на составлении собственного сообщения либо на
				 * нехватке памяти, а данными собеседника не управляется
				 */
				if(error != context::error_t::NONE){
					// Отзываем содержимое записи из накопителя прикладных данных
					this->retract(before);
					// Выводим отказ смены ключевого материала своего направления
					return this->abort(error, alert::description_t::INTERNAL);
				}
			}
		}
		/**
		 * Раздел 5.1 RFC 8446 запрещает перемежать сообщения рукопожатия записями
		 * иного содержимого: недособранное сообщение, разорванное чужой записью,
		 * означает собеседника, складывающего поток не по правилам
		 */
		if((type != record::type_t::HANDSHAKE) && (this->_messages.pending() > 0)){
			// Отзываем содержимое записи из накопителя прикладных данных
			this->retract(before);
			// Выводим отказ разрыва сообщения рукопожатия чужой записью
			return this->abort(context::error_t::MESSAGE, alert::description_t::UNEXPECTED);
		}
		/**
		 * Раздел 5.4 RFC 8446: запись рукопожатия либо извещения с пустым содержимым
		 * обрывает связь извещением unexpected_message. Заслон этот стережёт ИМЕННО
		 * защищённый путь: у незащищённой записи пустоту отвергает разбор заголовка,
		 * а у защищённой длину заголовка составляют шифртекст с меткой целостности, и
		 * пустота вскрывается лишь по снятии защиты
		 */
		if((content.size == 0) && !record::empty(type)){
			// Отзываем содержимое записи из накопителя прикладных данных
			this->retract(before);
			// Выводим отказ пустого содержимого принятой записи
			return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
		}
		/**
		 * Раздел 5.2 RFC 8446 кладёт открытому содержимому записи предел в 16384 байта:
		 * защита вправе раздуть запись набивкой, и предел этот стережёт уже вскрытое
		 * содержимое, а не пришедшую запись
		 */
		if(content.size > ((this->_server && this->_retried && !this->_earlying && (this->_state == context::state_t::HANDSHAKE)) ? record::RECORD_CIPHERTEXT : this->_incoming)){
			// Отзываем содержимое записи из накопителя прикладных данных
			this->retract(before);
			// Выводим отказ выхода открытого содержимого за дозволенный предел: записи упреждения до просьбы о повторе ещё не вскрыты и меряются пределом шифртекста (раздел 4.2.10 RFC 8446)
			return this->abort(context::error_t::RECORD, alert::description_t::OVERSIZE);
		}
		/**
		 * Раздел 6.1 RFC 8446 велит пропускать всё, что пришло за извещением о
		 * закрытии: собеседник свою передачу завершил, и пришедшее следом означает
		 * либо его собственную оплошность, либо чужую подделку. Обрыв связи здесь был
		 * бы неверен - стандарт велит именно пропускать. Своё же закрытие приёма
		 * не глушит: тот же раздел дозволяет закрывшему передачу читать дальше, пока
		 * собеседник не завершит свою
		 */
		if(this->_drained){
			// Отзываем содержимое записи из накопителя прикладных данных
			this->retract(before);
			// Переходим к следующей принятой записи
			continue;
		}
		// Отказ разбора открытого содержимого принятой записи
		context::error_t error = context::error_t::NONE;
		/**
		 * Выполняем определение вида содержимого принятой записи
		 */
		switch(static_cast <uint8_t> (type)){
			// Если принято извещение собеседника
			case static_cast <uint8_t> (record::type_t::ALERT): {
				// Выполняем разбор принятого извещения собеседника
				error = this->notice(content);
				// Если связь оборвана извещением собеседника
				if(error != context::error_t::NONE)
					// Выводим отказ обрыва связи собеседником
					return error;
			} break;
			// Если приняты сообщения рукопожатия собеседника
			case static_cast <uint8_t> (record::type_t::HANDSHAKE): {
				/**
				 * Сборщик сообщений отказывает единственно нехваткой памяти под
				 * накопитель: сам разбор идёт позже, отдельным вызовом. Извещение о
				 * негодном разборе выдало бы свою беду за оплошность собеседника
				 */
				// Отказ нехватки памяти под накопитель сообщений
				failure = translate(this->_messages.push(content), context::error_t::MEMORY);
				// Если накопить сообщение не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ нехватки памяти под накопитель сообщений
					return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
				// Заголовок принятого сообщения рукопожатия
				handshake::header_t item;
				// Тело принятого сообщения рукопожатия
				view_t body;
				// Отказ, которым сборщик ответил на выдачу очередного сообщения
				handshake::error_t outcome = handshake::error_t::NONE;
				/**
				 * Выполняем перебор принятых сообщений рукопожатия
				 */
				while((outcome = this->_messages.next(item, body)) == handshake::error_t::NONE){
					// Выполняем разбор принятого сообщения рукопожатия
					error = this->handle(item.type, body, this->_messages.message());
					// Если сообщение рукопожатия разобрать не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ разбора сообщения рукопожатия
						return error;
					/**
					 * Раздел 5.1 RFC 8446: сообщение, за которым сменяются ключи, обязано
					 * кончаться на границе записи - остаток той же записи принадлежал бы
					 * прежним ключам
					 */
					if(!this->_legacy && ((item.type == handshake::type_t::SERVER) || (item.type == handshake::type_t::FINISHED) || (item.type == handshake::type_t::EARLY) || (item.type == handshake::type_t::UPDATE)) && (this->_messages.pending() > 0))
						// Выводим отказ сообщения, пересекающего смену ключей
						return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				}
				/**
				 * Нехваткой данных круг разбора кончается законно: остаток дождётся
				 * следующих записей. Прочие же отказы означают оплошность собеседника,
				 * и молчать о них нельзя: сборщик неразобранного сообщения с места не
				 * сдвигает, оттого связь после него не оборвалась бы, а замерла
				 * навсегда, приняв всё дальнейшее рукопожатие и не разобрав ничего
				 */
				if(outcome != handshake::error_t::HUNGRY){
					// Если сборщику довелось столкнуться с неведомым видом сообщения
					if(outcome == handshake::error_t::TYPE)
						// Выводим отказ неведомого вида сообщения рукопожатия
						return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
					// Если памяти сборщику сообщений не хватило
					else if(outcome == handshake::error_t::MEMORY)
						// Выводим отказ нехватки памяти под накопитель сообщений
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					/**
					 * Превышение дозволенной длины тела сообщения: до установления связи
					 * предел сборщика равен наибольшему, какой вмещает трёхбайтовое поле
					 * длины, а после установления понижен до положенного билетам и сменам
					 * ключей - сообщение шире означает накопление чужого мусора
					 */
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				}
			} break;
			// Если приняты прикладные данные собеседника
			case static_cast <uint8_t> (record::type_t::APPLICATION): {
				/**
				 * Упреждающие данные приходят до установления связи: тем они и
				 * упреждающие, что посланы, не дождавшись ответа сервера
				 */
				const bool early = (this->_server && this->_earlying);
				/**
				 * Записи упреждения, ушедшие от клиента до просьбы о повторе, приходят
				 * серверу открытой порой ключей: раздел 4.2.10 RFC 8446 велит их
				 * пропускать в пределах объявленного объёма
				 */
				if(this->_server && !early && this->_retried && (this->_state == context::state_t::HANDSHAKE) && (this->_skipped >= header.size)){
					// Уменьшаем объём байтов, дозволенных к пропуску
					this->_skipped -= header.size;
					// Отзываем содержимое записи из накопителя прикладных данных
					this->retract(before);
					// Переходим к следующей принятой записи связи
					continue;
				}
				// Если связь ещё не установлена и упреждающие данные не идут: закрывшему свою передачу приём открыт
				if(!early && (this->_state != context::state_t::ESTABLISHED) && (this->_state != context::state_t::CLOSED)){
					// Отзываем содержимое записи из накопителя прикладных данных
					this->retract(before);
					// Выводим отказ прихода прикладных данных не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				}
				// Если упреждающие данные связью принимаются
				if(early){
					/**
					 * Предел упреждающих данных объявлен билетом: раздел 4.2.10 RFC 8446
					 * велит серверу оборвать связь, если клиент за него вышел. Сверяется
					 * предел того билета, которым связь возобновлена, а не нынешняя
					 * настройка, и сумма считается прежде сложения
					 */
					if((static_cast <uint64_t> (this->_passed) + content.size) > static_cast <uint64_t> (this->_granted))
						// Выводим отказ выхода за предел упреждающих данных
						return this->abort(context::error_t::LIMIT, alert::description_t::UNEXPECTED);
					// Считаем размер прошедших через связь упреждающих данных
					this->_passed += static_cast <uint32_t> (content.size);
				}
				/**
				 * Выполняем складывание принятых прикладных данных в накопитель, если они
				 * ещё не там: запись ключей связи издания 1.3 вскрыта прямо в него
				 */
				if(!inplace){
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Выполняем перенос принятых прикладных данных в накопитель
						this->_plain.insert(this->_plain.end(), content.data, content.data + content.size);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
				}
			} break;
			// Если принята запись сердцебиения (RFC 6520)
			case static_cast <uint8_t> (record::type_t::HEARTBEAT): {
				// Выполняем разбор сердцебиения: запрос отвечается, ответ сличается, негодное роняется молча
				error = this->pulse(content);
				// Если связь оборвана
				if(error != context::error_t::NONE)
					// Выводим отрицательный результат - связь оборвана сердцебиением
					return error;
			} break;
			/**
			 * Ветвь эта достижима: раздел 5 RFC 8446 велит обрывать связь извещением
			 * unexpected_message на защищённую запись с внутренним видом
			 * change_cipher_spec, а снятие защиты этот вид признаёт и сюда пропускает
			 */
			default: return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
		}
	}
	// Выполняем затирание открытого содержимого последней записи по классу PLAINTEXT
	this->cleanse(this->_opened);
	// Если ответная смена ключей задолжена собеседнику и своя смена подтверждена
	if(this->_owed && (this->_state == context::state_t::ESTABLISHED) && !this->rotating()){
		// Сбрасываем признак задолженной смены ключей
		this->_owed = false;
		// Выполняем ответную смену ключей своего направления
		const context::error_t error = this->update(false);
		// Если ответную смену ключей выполнить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ смены ключевого материала своего направления
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Выводим успешность разбора принятых байтов связи
	return context::error_t::NONE;
}
/**
 * @brief Метод получения байтов, отправляемых собеседнику
 *
 * @return накопленные байты, отправляемые собеседнику
 *
 */
view_t nts::internal::Engine::output() const noexcept {
	// Перенос дейтаграммами выдаёт по одной готовой дейтаграмме
	if(this->_transport == context::transport_t::DATAGRAMS)
		// Выводим первую готовую дейтаграмму либо пустой просмотр
		return this->_flight.output();
	// Выводим накопленные байты, отправляемые собеседнику
	return view_t(this->_wire.data(), this->_wire.size());
}
/**
 * @brief Метод снятия отправленных байтов с накопителя
 *
 * @param size размер снимаемых байтов
 *
 */
void nts::internal::Engine::consume(const size_t size) noexcept {
	// Если связь ведётся поверх дейтаграмм: дейтаграмма снимается целиком
	if(this->_transport == context::transport_t::DATAGRAMS){
		// Снимаем первую готовую дейтаграмму
		this->_flight.consume();
		// Выходим из метода
		return;
	}
	// Если снимается весь накопитель отправляемых байтов
	if(size >= this->_wire.size())
		// Выполняем сброс накопителя отправляемых байтов
		this->_wire.clear();
	// Если снимается часть накопителя отправляемых байтов
	else this->_wire.erase(this->_wire.begin(), this->_wire.begin() + size);
}
/**
 * @brief Метод отправки прикладных данных собеседнику
 *
 * @param data отправляемые прикладные данные
 * @return     отказ отправки прикладных данных
 *
 */
context::error_t nts::internal::Engine::write(const view_t & data) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Упреждающие данные уходят до установления связи: тем они и упреждающие, что
		 * посылаются, не дождавшись ответа сервера
		 */
		const bool early = (!this->_server && this->_earlying && (this->_state == context::state_t::HANDSHAKE));
		// Если связь ещё не установлена и упреждающие данные не идут
		if(!early && (this->_state != context::state_t::ESTABLISHED))
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Под QUIC прикладные данные шифрует тот, кто связь ведёт: записями они не идут
		if(this->_transport == context::transport_t::LEVELS)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		/**
		 * Предел упреждающих данных объявлен билетом: раздел 4.2.10 RFC 8446 велит клиенту
		 * за него не выходить, а сервер за выход обрывает связь
		 */
		if(early && ((static_cast <uint64_t> (this->_passed) + data.size) > static_cast <uint64_t> (this->_resume.advance)))
			// Выводим отказ выхода за предел упреждающих данных
			return context::error_t::LIMIT;
		/**
		 * Если ответная смена ключей задолжена собеседнику: над дейтаграммами своя
		 * неподтверждённая смена не даёт начать следующую (раздел 8 RFC 9147) - долг
		 * остаётся за receive(), а данные уходят нынешними ключами; сброс долга лишь по
		 * удаче, иначе ответ по разделу 4.6.3 RFC 8446 терялся бы навсегда
		 */
		if(this->_owed && !early && !this->rotating()){
			// Выполняем ответную смену ключей прежде отправки прикладных данных
			const context::error_t settled = this->update(false);
			// Если ответную смену ключей выполнить не удалось
			if(settled != context::error_t::NONE)
				// Выводим отказ смены ключевого материала своего направления
				return settled;
			// Сбрасываем признак задолженной смены ключей
			this->_owed = false;
		}
		// Если отправляемые прикладные данные не переданы
		if((data.data == nullptr) || (data.size == 0))
			// Выводим успешность отправки прикладных данных
			return context::error_t::NONE;
		// Если упреждающие данные связью отправляются
		if(early)
			// Считаем размер прошедших через связь упреждающих данных
			this->_passed += static_cast <uint32_t> (data.size);
		/**
		 * Изданию TLS 1.2 ключи не сменить: KeyUpdate там нет. Пределом служит предел набора
		 * (раздел 5.5 RFC 8446 обосновывает 2^24.5 записей AES-GCM) либо порог ручки renewal,
		 * коли он поставлен: дойдя до него, связь закрывается извещением close_notify
		 */
		const uint64_t exhaustion = ((this->_legacy && this->_automatic && (this->_renewal > 0)) ? this->_renewal : protect::limit(this->_suite));
		// Размер отправленных прикладных данных
		size_t offset = 0;
		/**
		 * Выполняем нарезку прикладных данных на записи протокола
		 */
		while(offset < data.size){
			// Если записи своего направления издания TLS 1.2 дошли до предела ключа
			if(this->_legacy && (this->sequence(false) >= exhaustion)){
				// Отказ закрытия связи извещением close_notify
				const context::error_t closing = this->close();
				// Если закрыть связь не удалось нехваткой памяти
				if(closing == context::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return closing;
				// Выводим отказ исчерпания записей на ключе
				return context::error_t::EXHAUSTED;
			}
			// Определяем размер очередной отправляемой записи
			const size_t size = ((data.size - offset) > record::RECORD_PLAINTEXT ? record::RECORD_PLAINTEXT : (data.size - offset));
			// Выполняем складывание очередной записи в накопитель
			const context::error_t error = this->emit(record::type_t::APPLICATION, view_t(data.data + offset, size));
			// Если запись прикладных данных сложить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки прикладных данных
				return error;
			// Увеличиваем размер отправленных прикладных данных
			offset += size;
		}
		// Выводим итог смены ключей своего направления по счётчику записей
		return this->refreshing();
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод получения принятых прикладных данных
 *
 * @param result накопитель, в который переносятся принятые данные
 * @return       отказ получения принятых прикладных данных
 *
 */
context::error_t nts::internal::Engine::read(vector <uint8_t> & result) noexcept {
	// Под QUIC прикладные данные расшифровывает тот, кто связь ведёт: записями они не идут
	if(this->_transport == context::transport_t::LEVELS)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Принятые данные выдаются обменом накопителей (решение 21 шапки): копии открытого
	 * текста не делается, а прежний накопитель потребителя остаётся движку под
	 * следующие записи и затирается по классу PLAINTEXT
	 */
	result.swap(this->_plain);
	// Выполняем затирание прежнего содержимого накопителя потребителя по классу PLAINTEXT
	this->cleanse(this->_plain);
	// Выполняем сброс накопителя принятых прикладных данных
	this->_plain.clear();
	// Выводим успешность получения принятых прикладных данных
	return context::error_t::NONE;
}
/**
 * @brief Метод смены ключевого материала своего направления связи
 *
 * @param request признак просьбы к собеседнику сменить свои ключи в ответ
 * @return        отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::internal::Engine::update(const bool request) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если связь ещё не установлена
		if(this->_state != context::state_t::ESTABLISHED)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Изданию TLS 1.2 смена ключей неведома: сообщения KeyUpdate там нет
		if(this->_legacy)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		/**
		 * Раздел 6 RFC 9001: под QUIC смена ключей сообщением KeyUpdate не делается -
		 * следующее поколение ключей выводит из текущего значения тот, кто связь ведёт
		 */
		if(this->_transport == context::transport_t::LEVELS)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		/**
		 * Раздел 8 RFC 9147: новая смена ключей поверх дейтаграмм не шлётся, пока
		 * предыдущая не подтверждена, - иначе поры сторон разошлись бы
		 */
		if(this->rotating())
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Получаем сторону связи, которую ведёт модуль
		const session::side_t side = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
		// Накопитель, в который складывается тело сообщения смены ключей
		vector <uint8_t> body;
		// Отказ составления сообщения смены ключевого материала
		failure = translate(message::build((request ? message::update_t::REQUEST : message::update_t::NOTIFY), body), context::error_t::MESSAGE);
		// Если тело сообщения смены ключевого материала составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения смены ключевого материала
			return failure;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Отказ составления сообщения смены ключевого материала
		failure = translate(writer.push(handshake::type_t::UPDATE, view_t(body.data(), body.size())), context::error_t::MESSAGE);
		// Если сообщение смены ключевого материала составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения смены ключевого материала
			return failure;
		/**
		 * Сообщение уходит прежними ключами, а новые ставятся уже за ним: раздел 4.6.3
		 * RFC 8446 велит сменять ключи отправки лишь после отправки самого сообщения
		 */
		const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
		// Если сообщение смены ключевого материала отправить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки сообщения смены ключевого материала
			return error;
		/**
		 * Сообщения, идущие за рукопожатием, в переписку не добавляются: переписка
		 * закрыта завершениями сторон, и ключи из неё больше не выводятся
		 */
		if(this->_machine.accept(handshake::type_t::UPDATE, side) != flow::error_t::NONE)
			/**
			 * Заслон недостижим тем же доводом, что и у приёма чужой смены ключей.
			 * Лежит он нарочно за отправкой: раздел 4.6.3 RFC 8446 велит сменять ключи
			 * отправки лишь после ухода самого сообщения, и объявление ходу идёт в паре
			 * со сменою, а не с составлением
			 */
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Раздел 8 RFC 9147: поверх дейтаграмм новая пора вступает лишь по подтверждении
		 * сообщения о смене ключей, а до того сообщение раскладывается по дейтаграммам
		 */
		if(this->_transport == context::transport_t::DATAGRAMS){
			// Запоминаем, что своя смена ключей ждёт подтверждения
			this->_flight.rotating(true);
			// Выводим итог раскладки залпа по дейтаграммам
			return this->_flight.dispatch(false);
		}
		// Выводим итог смены ключевого материала своего направления связи
		return this->rotate(side);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод выдачи билета возобновления связи
 *
 * @return отказ выдачи билета возобновления связи
 *
 */
context::error_t nts::internal::Engine::issue() noexcept {
	/**
	 * Ключ выдаваемого билета (resumption-PSK) заводится ДО try, на уровне функции:
	 * выделения в теле (расширения билета, тело сообщения, отправка) вправе ответить
	 * нехваткой памяти выбросом bad_alloc, а он разматывается к внешнему catch. Место
	 * внутри try тот catch не видит (иная область видимости), оттого объявление здесь -
	 * иначе ключ остался бы в брошенном кадре стека (класс находок круга 8: секрет не
	 * затирался на всех путях выхода). До вывода ключа буфер не заполнен, затирание пустого безвредно.
	 */
	uint8_t secret[schedule::SCHEDULE_WIDEST];
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Если связь ведётся стороной клиента
		if(!this->_server)
			// Выводим отказ негодной стороны связи: билеты выдаёт сервер
			return context::error_t::STATE;
		// Если связь ещё не установлена
		if(this->_state != context::state_t::ESTABLISHED)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Билеты RFC 5077 изданию TLS 1.2 связью не выдаются: возобновления там нет
		if(this->_legacy)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Выдаваемый билет возобновления связи
		context::ticket_t item;
		// Устанавливаем набор шифрования связи, выдавшей билет
		item.suite = this->_suite;
		// Устанавливаем миг выдачи билета
		item.moment = this->_moment;
		// Миг первичного удостоверения: у возобновлённой связи - из признанного билета, иначе - этот
		item.authenticated = ((this->_authenticated != 0) ? this->_authenticated : this->_moment);
		// Устанавливаем срок жизни выдаваемого билета
		item.lifetime = this->_lifetime;
		/**
		 * Предел упреждающих данных объявляется билетом: раздел 4.6.1 RFC 8446 велит
		 * объявлять его расширением билета, а не приветствием, - и клиент по нему судит,
		 * дозволено ли ему упреждение вовсе и сколько его дозволено
		 */
		if(this->_advance)
			// Устанавливаем предел упреждающих данных выдаваемого билета
			item.advance = this->_limit;
		/**
		 * Неповторимое значение билета берётся числом выданных билетов: раздел 4.6.1
		 * RFC 8446 велит разводить ключи билетов одной связи именно им
		 */
		const uint8_t nonce[4] = {
			// Байты неповторимого значения старшим байтом вперёд
			static_cast <uint8_t> ((this->_tickets.size() >> 24) & 0xFF),
			static_cast <uint8_t> ((this->_tickets.size() >> 16) & 0xFF),
			static_cast <uint8_t> ((this->_tickets.size() >> 8) & 0xFF),
			static_cast <uint8_t> (this->_tickets.size() & 0xFF)
		};
		// Место, в которое помещается тело выдаваемого билета
		uint8_t identity[32];
		// Если тело выдаваемого билета выработать не удалось
		if(!entropy::bytes(identity, sizeof(identity)))
			// Выводим отказ выработки тела билета
			return context::error_t::SETTINGS;
		// Место, в которое помещается добавка к возрасту билета
		uint8_t addition[4];
		// Если добавку к возрасту билета выработать не удалось
		if(!entropy::bytes(addition, sizeof(addition)))
			// Выводим отказ выработки добавки к возрасту билета
			return context::error_t::SETTINGS;
		// Устанавливаем добавку к возрасту выдаваемого билета
		item.age = ((static_cast <uint32_t> (addition[0]) << 24) | (static_cast <uint32_t> (addition[1]) << 16) | (static_cast <uint32_t> (addition[2]) << 8) | static_cast <uint32_t> (addition[3]));
		// Если ключ выдаваемого билета вывести не удалось
		if(this->_secrets.ticket(view_t(nonce, sizeof(nonce)), secret) != session::error_t::NONE)
			// Выводим отказ вывода ключа билета возобновления связи
			return context::error_t::SCHEDULE;
		// Составляемый билет возобновления связи
		message::ticket_t ticket;
		// Устанавливаем срок жизни составляемого билета
		ticket.lifetime = item.lifetime;
		// Устанавливаем добавку к возрасту составляемого билета
		ticket.age = item.age;
		// Устанавливаем неповторимое значение составляемого билета
		ticket.nonce = view_t(nonce, sizeof(nonce));
		// Устанавливаем тело составляемого билета
		ticket.data = view_t(identity, sizeof(identity));
		// Накопитель, в который складывается тело расширения упреждающих данных
		vector <uint8_t> advance;
		// Если упреждающие данные билетом дозволяются
		if(item.advance > 0){
			// Отказ составления предела упреждающих данных
			failure = translate(extension::early(item.advance, advance), context::error_t::MESSAGE);
			// Если предел упреждающих данных составить не удалось
			if(failure != context::error_t::NONE){
				// Выполняем затирание ключа выдаваемого билета
				this->purge(secret, sizeof(secret));
				// Выводим отказ составления сообщения билета
				return failure;
			}
			// Добавляем расширение предела упреждающих данных
			ticket.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(advance.data(), advance.size())));
		}
		// Раздел 3.2 RFC 8701: расширение GREASE билета идёт пустым за пределом упреждения, как у BoringSSL
		if(this->greased())
			// Добавляем расширение GREASE билета
			ticket.extensions.push_back(hello::extension_t(this->greasing(grease_t::TICKET), view_t(nullptr, 0)));
		// Накопитель, в который складывается тело сообщения билета
		vector <uint8_t> body;
		// Отказ составления тела сообщения билета
		failure = translate(message::build(ticket, body), context::error_t::MESSAGE);
		// Если тело сообщения билета составить не удалось
		if(failure != context::error_t::NONE){
			// Выполняем затирание ключа выдаваемого билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ составления сообщения билета
			return failure;
		}
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Отказ составления сообщения билета возобновления связи
		failure = translate(writer.push(handshake::type_t::TICKET, view_t(body.data(), body.size())), context::error_t::MESSAGE);
		// Если сообщение билета возобновления связи составить не удалось
		if(failure != context::error_t::NONE){
			// Выполняем затирание ключа выдаваемого билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ составления сообщения билета
			return failure;
		}
		// Выполняем складывание сообщения билета в накопитель отправляемых байтов
		const context::error_t error = this->emit(record::type_t::HANDSHAKE, writer.data());
		// Если сообщение билета отправить не удалось
		if(error != context::error_t::NONE){
			// Выполняем затирание ключа выдаваемого билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ отправки сообщения билета
			return error;
		}
		/**
		 * Сообщения, идущие за рукопожатием, в переписку не добавляются: значение
		 * возобновления связи выведено и от них уже не зависит
		 */
		if(this->_machine.accept(handshake::type_t::TICKET, session::side_t::SERVER) != flow::error_t::NONE){
			/**
			 * Сторона задана постоянной, и ход рукопожатия за установленной связью
			 * сличает её сам с собою: заслон недостижим и стоит обороною
			 */
			// Выполняем затирание ключа выдаваемого билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ объявления сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		}
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Запоминаем прикладной протокол связи, выдающей билет
			item.protocol = this->_protocol;
			// Устанавливаем признак согласования прикладных настроек связи
			item.settled = this->_settled;
			// Устанавливаем свои прикладные настройки связи
			item.settings = this->_applied;
			// Устанавливаем прикладные настройки собеседника
			item.obtained = this->_obtained;
			// Переносим тело выданного билета возобновления связи
			item.identity.assign(identity, identity + sizeof(identity));
			// Переносим ключ выданного билета возобновления связи длиною в хеш набора
			item.secret.assign(secret, secret + this->_secrets.size());
			// Добавляем выданный билет в перечень билетов связи
			this->_tickets.push_back(::move(item));
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выполняем затирание ключа выданного билета
			this->purge(secret, sizeof(secret));
			// Выводим отказ нехватки памяти: сообщение уже снято со сборщика, связь обрывается
			return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
		}
		// Выполняем затирание ключа выданного билета
		this->purge(secret, sizeof(secret));
		// Если связь ведётся поверх дейтаграмм
		if(this->_transport == context::transport_t::DATAGRAMS)
			// Выводим итог раскладки залпа по дейтаграммам
			return this->_flight.dispatch(false);
		// Выводим успешность выдачи билета возобновления связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Затираем ключ билета: выделение ниже вывода ключа могло бросить, оставив его в кадре
		this->purge(secret, sizeof(secret));
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод получения билетов возобновления связи
 *
 * @return выданные либо принятые билеты возобновления связи
 *
 */
const vector <context::ticket_t> & nts::internal::Engine::tickets() const noexcept {
	// Выводим выданные либо принятые билеты возобновления связи
	return this->_tickets;
}
/**
 * @brief Метод закрытия связи
 *
 * @return отказ закрытия связи
 *
 */
context::error_t nts::internal::Engine::close() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если связь не заведена
		if(this->_state == context::state_t::NONE)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Если своя передача уже завершена либо связь оборвана
		if(this->_closed || (this->_state == context::state_t::FAILED))
			// Выводим отказ закрытия закрытой связи
			return context::error_t::CLOSED;
		/**
		 * Раздел 4.8 RFC 9001: под QUIC извещение о закрытии не посылается - связь
		 * закрывает сам перенос своим сообщением закрытия
		 */
		if(this->_transport == context::transport_t::LEVELS)
			// Выводим отказ негодного состояния связи
			return context::error_t::STATE;
		// Составляем извещение о завершении передачи данных
		const alert::alert_t alert(alert::level_t::WARNING, alert::description_t::CLOSE);
		// Место, в которое записывается извещение о завершении передачи
		uint8_t buffer[alert::ALERT_LENGTH];
		// Если извещение о завершении передачи записать не удалось
		if(alert::build(alert, buffer) != alert::error_t::NONE)
			// Выводим отказ составления извещения
			return context::error_t::MESSAGE;
		// Выполняем складывание извещения в накопитель отправляемых байтов
		const context::error_t error = this->emit(record::type_t::ALERT, view_t(buffer, sizeof(buffer)));
		// Если извещение о завершении передачи сложить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ отправки извещения
			return error;
		// Запоминаем, что своя передача завершена
		this->_closed = true;
		// Переводим связь в состояние закрытия
		this->_state = context::state_t::CLOSED;
		// Выводим успешность закрытия связи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора сообщения рукопожатия издания TLS 1.2
 *
 * @param type    вид принятого сообщения рукопожатия
 * @param body    тело принятого сообщения рукопожатия
 * @param message принятое сообщение рукопожатия вместе с обвязкой
 * @return        отказ разбора сообщения рукопожатия
 *
 */
context::error_t nts::internal::Engine::legacy(const handshake::type_t type, const view_t & body, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если принята просьба о пересогласовании HelloRequest
		if(type == handshake::type_t::HELLO_REQUEST){
			// Раздел 7.4.1.1 RFC 5246: просьбу шлёт лишь сервер, у сервера она не в свой черёд
			if(this->_server)
				// Выводим отказ сообщения не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Раздел 7.4.1.1 RFC 5246: тело просьбы пусто
			if(body.size > 0)
				// Выводим отказ лишних байтов за телом сообщения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			/**
			 * Раздел 7.4.1.1 RFC 5246: по ходу рукопожатия клиент просьбу пропускает, и в
			 * переписку рукопожатия она не кладётся никогда
			 */
			if(this->_phase != phase_t::ESTABLISHED)
				// Выводим успешность: просьба пропущена
				return context::error_t::NONE;
		}
		/**
		 * Раздел 4.2 RFC 5746 и раздел 7.2.2 RFC 5246: пересогласований связь не ведёт, и за
		 * установленной связью просьба HelloRequest у клиента и приветствие клиента у сервера
		 * отвечаются извещением no_renegotiation уровня предупреждения - связь при этом
		 * продолжается прежними ключами, а обрывает её лишь собеседник, сочтя отказ роковым
		 */
		if(this->_phase == phase_t::ESTABLISHED){
			// Если принято не приветствие клиента у сервера и не просьба у клиента
			if(this->_server ? (type != handshake::type_t::CLIENT) : (type != handshake::type_t::HELLO_REQUEST))
				// Выводим отказ сообщения не в свой черёд
				return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
			// Отказ отправки извещения об отказе пересогласования
			const context::error_t refused = this->declining();
			// Если извещение отправить не удалось
			if(refused != context::error_t::NONE)
				// Выводим отказ отправки извещения, которым связь обрывается
				return this->abort(refused, alert::description_t::INTERNAL);
			// Выводим успешность: пересогласование отвергнуто, связь продолжается
			return context::error_t::NONE;
		}
		/**
		 * Раздел 4.6.3 RFC 8446 и раздел 4 RFC 8879: смены ключей, сжатой цепочки, защищённых
		 * расширений и конца упреждающих данных у издания TLS 1.2 нет, и приход их выдаёт
		 * собеседника, ведущего иное издание под видом 1.2; билет сеанса (RFC 5077) идёт
		 * клиенту лишь обещанным и лишь перед сменой набора сервера
		 */
		if((type == handshake::type_t::UPDATE) || (type == handshake::type_t::COMPRESSED) || (type == handshake::type_t::EXTENSIONS) || (type == handshake::type_t::EARLY) || (type == handshake::type_t::DIGEST))
			// Выводим отказ сообщения, изданию не положенного
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Если клиент с предъявленным билетом ждёт первого сообщения за приветствием сервера
		if(!this->_server && (this->_phase == phase_t::EITHER)){
			// Отказ суждения о виде рукопожатия: билет либо завершение сервера означают сокращённое
			const context::error_t judged = this->deciding((type == handshake::type_t::TICKET) || (type == handshake::type_t::FINISHED));
			// Если ключевой материал возобновлённой связи вывести не удалось либо набор разошёлся с билетом
			if(judged != context::error_t::NONE)
				// Выводим отказ суждения
				return this->abort(judged, blame(judged, (((judged == context::error_t::SUITE) || (judged == context::error_t::ETM) || (judged == context::error_t::VERSION)) ? alert::description_t::PARAMETER : alert::description_t::INTERNAL)));
		}
		// Если принят билет сеанса не в свой черёд: серверу, без обещания, за сменой набора либо повторно
		if((type == handshake::type_t::TICKET) && (this->_server || !this->_ticketing || (this->_phase != phase_t::CHANGE) || !this->_promise.identity.empty()))
			// Выводим отказ сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		// Приветствия сторон по ходу рукопожатия дважды не приходят
		if((type == handshake::type_t::CLIENT) || (type == handshake::type_t::SERVER))
			// Выводим отказ сообщения не в свой черёд
			return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		/**
		 * Подпись владения ключом и завершение рукопожатия сличаются с перепиской ДО
		 * себя: себя самих они не покрывают, и в переписку ложатся лишь по проверке
		 */
		const bool deferred = ((type == handshake::type_t::VERIFY) || (type == handshake::type_t::FINISHED));
		// Если сообщение в переписку кладётся прежде разбора
		if(!deferred){
			// Отказ ведения переписки рукопожатия
			const context::error_t recorded = this->chronicle(message, this->_delivered);
			// Если сообщение в переписку рукопожатия добавить не удалось
			if(recorded != context::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(recorded, alert::description_t::INTERNAL);
		}
		// Отказ разбора принятого сообщения рукопожатия
		context::error_t error = context::error_t::NONE;
		/**
		 * Выполняем определение вида принятого сообщения рукопожатия
		 */
		switch(static_cast <uint8_t> (type)){
			// Если принята цепочка сертификатов собеседника
			case static_cast <uint8_t> (handshake::type_t::CERTIFICATE): {
				// Раздел 7.3 RFC 5246: цепочка идёт за приветствием сервера у клиента и за концом приветствия у сервера
				if(this->_phase != (this->_server ? phase_t::ANSWER : phase_t::CERTIFICATE))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор цепочки сертификатов собеседника
				error = this->presented(body);
				// Если цепочку сертификатов разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора цепочки: негодная запись - decode_error, непригодный сертификат - bad_certificate
					return this->abort(error, blame(error, ((error == context::error_t::MESSAGE) ? alert::description_t::DECODE : alert::description_t::BADCERT)));
				// Переходим к ожидаемому следующим сообщению: у обмена RSA обмена ключами сервера нет (раздел 7.4.3 RFC 5246)
				this->_phase = (this->_server ? phase_t::PREMASTER : (this->_stapling ? phase_t::STATUS : (ephemeral(this->_suite) ? phase_t::AGREEMENT : phase_t::REQUEST)));
			} break;
			// Если принят билет сеанса
			case static_cast <uint8_t> (handshake::type_t::TICKET): {
				// Выполняем разбор билета сеанса
				error = this->granted(body);
				// Если билет сеанса разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора билета сеанса
					return this->abort(error, blame(error, alert::description_t::DECODE));
				// Обещанный билет принят: второй не ждётся и повторно не принимается
				this->_ticketing = false;
				// Если смена набора собеседника обогнала билет и ждала его
				if(this->_switched){
					// Выполняем принятие смены набора шифрования
					error = this->switched();
					// Если пору ключей завести не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ заведения поры ключей
						return this->abort(error, alert::description_t::INTERNAL);
				}
			} break;
			// Если принято состояние сертификата сервера
			case static_cast <uint8_t> (handshake::type_t::STATUS): {
				// Раздел 8 RFC 6066: состояние идёт сразу за цепочкой и лишь по объявлению сервера
				if(this->_server || (this->_phase != phase_t::STATUS))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор состояния сертификата сервера: запись та же, что у расширения TLS 1.3
				error = this->stapled(body);
				// Если состояние сертификата разобрать либо проверить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора состояния сертификата
					return this->abort(error, blame(error, alert::description_t::STATUS));
				// Переходим к ожиданию обмена ключами сервера либо запроса подлинности у обмена RSA
				this->_phase = (ephemeral(this->_suite) ? phase_t::AGREEMENT : phase_t::REQUEST);
			} break;
			// Если принят обмен ключами сервера
			case static_cast <uint8_t> (handshake::type_t::AGREEMENT): {
				// Раздел 7.3 RFC 5246: обмен идёт за цепочкой либо за состоянием сертификата
				if(this->_server || ((this->_phase != phase_t::STATUS) && (this->_phase != phase_t::AGREEMENT)))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор обмена ключами сервера
				error = this->agreed(body);
				// Если обмен ключами сервера разобрать не удалось
				if(error != context::error_t::NONE)
					/**
					 * Раздел 7.4.3 RFC 5246: негодная запись - decode_error, несошедшаяся подпись -
					 * decrypt_error, чужая схема либо кривая - illegal_parameter
					 */
					return this->abort(error, blame(error, ((error == context::error_t::MESSAGE) ? alert::description_t::DECODE :
						((error == context::error_t::SIGNATURE) ? alert::description_t::DECRYPT : alert::description_t::PARAMETER))));
				// Переходим к ожиданию запроса подлинности либо конца приветствия сервера
				this->_phase = phase_t::REQUEST;
			} break;
			// Если принят запрос подлинности клиента
			case static_cast <uint8_t> (handshake::type_t::REQUEST): {
				// Раздел 7.3 RFC 5246: запрос идёт за обменом ключами сервера; у чистого PSK обмен необязателен (раздел 2 RFC 4279); у наборов без мимолётных ключей объявленное состояние сертификата слать необязательно (раздел 8 RFC 6066)
				if(this->_server || ((this->_phase != phase_t::REQUEST) && !((this->_phase == phase_t::AGREEMENT) && (protect::exchange(this->_suite) == protect::exchange_t::PSK)) && !((this->_phase == phase_t::STATUS) && !ephemeral(this->_suite))))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Раздел 2 RFC 4279 и раздел 3.2 RFC 5489: при наборах PSK сервер запроса подлинности не шлёт
				if(preshared(this->_suite))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор запроса подлинности клиента
				error = this->demanded(body);
				// Если запрос подлинности разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора запроса подлинности
					return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::DECODE)));
				// Запоминаем, что подлинность клиента запрошена сервером
				this->_requested = true;
				// Переходим к ожиданию конца приветствия сервера
				this->_phase = phase_t::DONE;
			} break;
			// Если принят конец приветствия сервера
			case static_cast <uint8_t> (handshake::type_t::DONE): {
				// Раздел 7.3 RFC 5246: конец приветствия идёт за обменом ключами либо за запросом подлинности; у чистого PSK обмен необязателен; у наборов без мимолётных ключей объявленное состояние сертификата необязательно (раздел 8 RFC 6066)
				if(this->_server || ((this->_phase != phase_t::REQUEST) && (this->_phase != phase_t::DONE) && !((this->_phase == phase_t::AGREEMENT) && (protect::exchange(this->_suite) == protect::exchange_t::PSK)) && !((this->_phase == phase_t::STATUS) && !ephemeral(this->_suite))))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Раздел 7.4.5 RFC 5246: тело конца приветствия пусто
				if(body.size > 0)
					// Выводим отказ лишних байтов за телом сообщения
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				// Если подлинность клиента запрошена сервером
				if(this->_requested){
					// Выполняем отправку цепочки сертификатов клиента, пустой без подлинности
					error = this->presenting();
					// Если цепочку сертификатов отправить не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ отправки цепочки сертификатов
						return this->abort(error, alert::description_t::INTERNAL);
				}
				// Выполняем отправку обмена ключами клиента с выводом ключевого материала
				error = this->exchanging();
				// Если обмен ключами клиента отправить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ отправки обмена ключами клиента
					return this->abort(error, blame(error, alert::description_t::INTERNAL));
				// Если подлинность клиента запрошена и предъявлена
				if(this->_requested && !this->_credential.chain.empty()){
					// Выполняем отправку подписи владения ключом клиента
					error = this->attesting();
					// Если подпись владения ключом отправить не удалось
					if(error != context::error_t::NONE)
						// Раздел 7.4.8 RFC 5246: отсутствие общей схемы подписи - несхождение сторон
						return this->abort(error, blame(error, ((error == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL)));
				}
				// Выполняем отправку смены набора шифрования
				error = this->switching();
				// Если смену набора шифрования отправить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ отправки смены набора шифрования
					return this->abort(error, alert::description_t::INTERNAL);
				// Выполняем отправку выбранного протокола выработки NPN
				error = this->announcing();
				// Если выбранный протокол отправить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ отправки выбранного протокола
					return this->abort(error, alert::description_t::INTERNAL);
				// Выполняем отправку завершения рукопожатия клиентом
				error = this->finishing();
				// Если завершение рукопожатия отправить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ отправки завершения рукопожатия
					return this->abort(error, alert::description_t::INTERNAL);
				// Переходим к ожиданию смены набора шифрования сервером
				this->_phase = phase_t::CHANGE;
			} break;
			// Если принят обмен ключами клиента
			case static_cast <uint8_t> (handshake::type_t::PREMASTER): {
				// Раздел 7.3 RFC 5246: обмен клиента идёт за концом приветствия либо за цепочкой клиента
				if(!this->_server || (this->_phase != phase_t::PREMASTER))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем разбор обмена ключами клиента с выводом ключевого материала
				error = this->exchanged(body);
				// Если обмен ключами клиента разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора обмена ключами клиента: неизвестный опознаватель PSK - unknown_psk_identity (раздел 2 RFC 4279)
					return this->abort(error, blame(error, ((error == context::error_t::MESSAGE) ? alert::description_t::DECODE : ((error == context::error_t::EXCHANGE) ? alert::description_t::PARAMETER : ((error == context::error_t::IDENTITY) ? alert::description_t::PSK : alert::description_t::INTERNAL)))));
				/**
				 * Раздел 7.4.8 RFC 5246: за непустой цепочкой клиента обязана идти подпись
				 * владения ключом; пустая цепочка означает клиента без подлинности
				 */
				this->_phase = (this->_peer.empty() ? phase_t::CHANGE : phase_t::VERIFY);
				// Если смена набора собеседника обогнала обмен ключами и ждала его
				if((this->_phase == phase_t::CHANGE) && this->_switched){
					// Выполняем принятие смены набора шифрования
					error = this->switched();
					// Если пору ключей завести не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ заведения поры ключей
						return this->abort(error, alert::description_t::INTERNAL);
				}
			} break;
			// Если принята подпись владения ключом клиента
			case static_cast <uint8_t> (handshake::type_t::VERIFY): {
				// Раздел 7.3 RFC 5246: подпись владения идёт за обменом ключами клиента
				if(!this->_server || (this->_phase != phase_t::VERIFY))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем проверку подписи владения ключом клиента
				error = this->attested(body);
				// Если подпись владения ключом не сошлась
				if(error != context::error_t::NONE)
					// Раздел 7.4.8 RFC 5246: несошедшаяся подпись - decrypt_error, чужая схема - illegal_parameter
					return this->abort(error, blame(error, ((error == context::error_t::MESSAGE) ? alert::description_t::DECODE :
						((error == context::error_t::SCHEME) ? alert::description_t::PARAMETER : alert::description_t::DECRYPT))));
				// Переходим к ожиданию смены набора шифрования клиентом
				this->_phase = phase_t::CHANGE;
				// Если смена набора собеседника обогнала подпись владения и ждала её
				if(this->_switched){
					// Выполняем принятие смены набора шифрования
					error = this->switched();
					// Если пору ключей завести не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ заведения поры ключей
						return this->abort(error, alert::description_t::INTERNAL);
				}
			} break;
			// Если принят выбранный протокол выработки NPN
			case static_cast <uint8_t> (handshake::type_t::NEXT_PROTOCOL): {
				/**
				 * Черновик draft-agl-tls-nextprotoneg: сообщение идёт от клиента за сменой набора
				 * и прежде завершения, лишь при выработке и лишь однажды
				 */
				if(!this->_server || !this->_negotiated || this->_announced || (this->_phase != phase_t::FINISHED))
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Объект сканера тела сообщения
				field::scanner_t scanner;
				// Заводим сканер по телу сообщения
				scanner.start(body);
				// Выбранный протокол и заполнение
				view_t selected, padding;
				// Если тело сообщения сложено не по правилам
				if((scanner.vector(selected, 1) != field::error_t::NONE) || (scanner.vector(padding, 1) != field::error_t::NONE) || (scanner.left() > 0) || (padding.size != (32 - ((selected.size + 2) % 32))))
					// Выводим отказ разбора сообщения
					return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				/**
				 * Выполняем перебор байтов заполнения: черновик велит нули
				 */
				for(size_t i = 0; i < padding.size; i++){
					// Если байт заполнения не нуль
					if(padding.data[i] != 0x00)
						// Выводим отказ разбора сообщения
						return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
				}
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Запоминаем протокол связи, выбранный клиентом
					this->_protocol.assign(reinterpret_cast <const char *> (selected.data), selected.size);
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const std::bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
				// Запоминаем, что сообщение NextProtocol прошло
				this->_announced = true;
			} break;
			// Если принято завершение рукопожатия собеседником
			case static_cast <uint8_t> (handshake::type_t::FINISHED): {
				// Раздел 7.1 RFC 5246: завершение идёт сразу за сменой набора шифрования
				if(this->_phase != phase_t::FINISHED)
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Черновик draft-agl-tls-nextprotoneg: при выработке завершению клиента обязан предшествовать NextProtocol
				if(this->_server && this->_negotiated && !this->_announced)
					// Выводим отказ сообщения не в свой черёд
					return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
				// Выполняем проверку завершения рукопожатия собеседником
				error = this->finished(body);
				// Если завершение рукопожатия не сошлось
				if(error != context::error_t::NONE)
					// Раздел 7.4.9 RFC 5246: несошедшееся завершение - decrypt_error
					return this->abort(error, blame(error, alert::description_t::DECRYPT));
			} break;
			// Если принято сообщение, изданию не положенное
			default: return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
		}
		// Если сообщение в переписку кладётся по разборе
		if(deferred){
			// Отказ ведения переписки рукопожатия
			const context::error_t recorded = this->chronicle(message, this->_delivered);
			// Если сообщение в переписку рукопожатия добавить не удалось
			if(recorded != context::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(recorded, alert::description_t::INTERNAL);
		}
		// Если принято не завершение рукопожатия собеседником
		if(type != handshake::type_t::FINISHED)
			// Выводим успешность разбора сообщения рукопожатия
			return context::error_t::NONE;
		/**
		 * Раздел 7.3 RFC 5246: в полном рукопожатии завершение клиента отвечается завершением
		 * сервера, в сокращённом (раздел 3.3 RFC 5077) - завершение сервера отвечается
		 * завершением клиента; сторона, отвечающая последней, шлёт свой залп здесь
		 */
		if(this->_server != this->_resumed){
			// Выполняем отправку заключительного залпа: билет (лишь сервером и лишь обещанный), смена набора, завершение
			error = this->concluding();
			// Если заключительный залп отправить не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ отправки заключительного залпа
				return this->abort(error, alert::description_t::INTERNAL);
			// Раздел 4.2.4 RFC 6347: последний залп часов не ждёт и повторяется по повтору завершения собеседника
			if(this->_transport == context::transport_t::DATAGRAMS)
				// Отмечаем залп последним
				this->_flight.conclude();
		}
		/**
		 * Раздел 3.3 RFC 5077: билет сеанса годен лишь по проверке завершения сервера - до
		 * того он ждал; клиент кладёт его в перечень билетов связи вместе с главным секретом
		 */
		if(!this->_server && !this->_promise.identity.empty()){
			// Добавляем принятый билет в перечень билетов связи
			this->_tickets.push_back(this->_promise);
			// Выполняем затирание главного секрета ожидавшего билета
			this->purge(this->_promise.secret.data(), this->_promise.secret.size());
			// Выполняем сброс ожидавшего билета
			this->_promise = context::ticket_t();
		}
		// Рукопожатие издания TLS 1.2 завершено обеими сторонами
		this->_phase = phase_t::ESTABLISHED;
		// Переводим связь в состояние установленной связи
		this->_state = context::state_t::ESTABLISHED;
		// Понижаем сборщику сообщений предел до положенного установленной связи
		this->_messages.limit(AFTERMATH);
		// Переписка подряд более не нужна: подписей владения ключом за рукопожатием нет
		this->_history.clear();
		// Выполняем затирание главного секрета: завершения сторон сличены, и выводить из него более нечего
		this->scrub();
		// Выводим успешность разбора сообщения рукопожатия
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод ответа сервера на приветствие клиента изданием TLS 1.2
 *
 * @param greeting разобранное приветствие клиента
 * @param message  принятое приветствие клиента вместе с обвязкой
 * @return         отказ ответа на приветствие клиента
 *
 */
context::error_t nts::internal::Engine::welcome(const hello::client_t & greeting, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Запоминаем, что связь ведётся изданием TLS 1.2
		this->_legacy = true;
		// Запоминаем согласованное издание протокола кодом TLS 1.2 либо 1.1: единая шкала изданий на любом переносе
		this->_version = (this->_ancient ? ANCIENT : LEGACY);
		// Раздел 6.2.3 RFC 5246: защищённая запись издания TLS 1.2 вмещает до 2^14 + 2048 байтов
		this->_records.limit(record::RECORD_PROTECTED);
		// Раздел 4.1 RFC 6347: перенос дейтаграммами отныне ведётся изданием DTLS 1.2
		if(this->_transport == context::transport_t::DATAGRAMS)
			// Переводим перенос на издание DTLS 1.2
			this->_flight.legacy(true);
		// Раздел 4.1 RFC 4347: изданием DTLS 1.0 записи несут 0xFEFF
		if(this->_transport == context::transport_t::DATAGRAMS)
			// Переводим перенос на издание DTLS 1.0 либо оставляем 1.2
			this->_flight.ancient(this->_ancient);
		// Признак того, что клиент предложил расширенный главный секрет (раздел 5.1 RFC 7627)
		const bool extended = (hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::MASTER)) != nullptr);
		/**
		 * Решение 16: обычный главный секрет открыт подмене тройным рукопожатием, потому
		 * обязательный расширенный главный секрет отвергает клиента без расширения; умолчанием,
		 * как у openssl, связь с ним ведётся обычным главным секретом (раздел 8.1 RFC 5246)
		 */
		if(!extended && this->_mandatory)
			// Выводим отказ отсутствия расширенного главного секрета
			return this->abort(context::error_t::MASTER, alert::description_t::HANDSHAKE);
		// Запоминаем, ведётся ли связь расширенным главным секретом
		this->_extending = extended;
		// Разыскиваем расширение безопасного пересогласования
		const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::RENEGOTIATION));
		/**
		 * Раздел 3.6 RFC 5746: на первом рукопожатии расширение обязано быть пустым; иное
		 * содержимое означает клиента, помнящего связь, которой сервер не вёл
		 */
		if((extension != nullptr) && ((extension->data.size != sizeof(RENEGOTIATION)) || (extension->data.data[0] != 0x00)))
			// Выводим отказ негодного расширения пересогласования
			return this->abort(context::error_t::MESSAGE, alert::description_t::HANDSHAKE);
		// Признак того, что клиент объявил безопасное пересогласование расширением либо набором-сигналом
		bool renegotiable = (extension != nullptr);
		/**
		 * Выполняем перебор наборов шифрования, предложенных клиентом
		 */
		for(size_t i = 0; (i < greeting.suites.size()) && !renegotiable; i++)
			// Запоминаем объявление набора-сигнала безопасного пересогласования
			renegotiable = (greeting.suites[i] == SCSV);
		// Разыскиваем расширение записей точек кривой
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::FORMATS));
		// Признак того, что клиент объявил записи точек кривой
		const bool listed = (extension != nullptr);
		// Если записи точек кривой клиентом объявлены
		if(listed){
			// Отказ разбора расширения записей точек кривой
			failure = this->formatted(extension->data);
			// Если записи точек кривой сложены не по правилам либо несжатой среди них нет
			if(failure != context::error_t::NONE)
				// Раздел 5.1.2 RFC 8422: негодная запись - decode_error, отсутствие несжатой - handshake_failure
				return this->abort(failure, blame(failure, ((failure == context::error_t::MESSAGE) ? alert::description_t::DECODE : alert::description_t::HANDSHAKE)));
		}
		// Разыскиваем расширение имени запрашиваемого узла
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::NAME));
		// Имя узла, запрошенное клиентом у сервера этим приветствием: пусто без расширения
		string requested;
		// Если имя запрашиваемого узла приветствием объявлено
		if(extension != nullptr){
			// Имя узла, запрошенное клиентом у сервера
			view_t host;
			// Отказ разбора расширения приветствия
			failure = translate(extension::name(extension->data, host), context::error_t::MESSAGE);
			// Если имя запрашиваемого узла разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
			// Запоминаем имя узла этого приветствия
			requested.assign(reinterpret_cast <const char *> (host.data), host.size);
			// Имя узла сервером лишь принимается: выбор подлинности по нему за потребителем
			this->_name = requested;
		}
		// Если прикладные протоколы сервером признаются
		if(!this->_protocols.empty()){
			// Разыскиваем расширение перечня прикладных протоколов
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
			// Если прикладные протоколы приветствием объявлены
			if(extension != nullptr){
				// Перечень прикладных протоколов, предложенных клиентом
				vector <string> offer;
				// Отказ разбора расширения приветствия
				failure = translate(extension::protocols(extension->data, offer), context::error_t::MESSAGE);
				// Если перечень прикладных протоколов разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор прикладных протоколов сервера: выбор идёт его порядком (раздел 3.2 RFC 7301)
				 */
				for(size_t i = 0; (i < this->_protocols.size()) && this->_protocol.empty(); i++){
					/**
					 * Выполняем перебор прикладных протоколов, предложенных клиентом
					 */
					for(size_t j = 0; (j < offer.size()) && this->_protocol.empty(); j++){
						// Если прикладной протокол предложен обеими сторонами
						if(offer[j].compare(this->_protocols[i]) == 0)
							// Запоминаем выбранный сторонами прикладной протокол
							this->_protocol = this->_protocols[i];
					}
				}
				// Если общего прикладного протокола у сторон не нашлось
				if(this->_protocol.empty())
					// Выводим отказ отсутствия общего прикладного протокола
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
			}
		}
		// Если профили защиты RTP сервером признаются
		if(!this->_srtps.empty()){
			// Разыскиваем расширение перечня профилей защиты RTP
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::PROFILES));
			// Если профили защиты RTP приветствием объявлены
			if(extension != nullptr){
				// Перечень профилей защиты RTP, предложенных клиентом
				vector <uint16_t> offer;
				// Отказ разбора расширения приветствия
				failure = translate(extension::profiles(extension->data, offer), context::error_t::MESSAGE);
				// Если перечень профилей защиты RTP разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
				/**
				 * Выполняем перебор профилей защиты RTP сервера: выбор идёт его порядком (раздел 3.2 RFC 7301)
				 */
				for(size_t i = 0; (i < this->_srtps.size()) && (this->_srtp == 0); i++){
					/**
					 * Выполняем перебор профилей защиты RTP, предложенных клиентом
					 */
					for(size_t j = 0; (j < offer.size()) && (this->_srtp == 0); j++){
						// Если профиль защиты RTP предложен обеими сторонами
						if(offer[j] == this->_srtps[i])
							// Запоминаем выбранный сторонами профиль защиты RTP
							this->_srtp = this->_srtps[i];
					}
				}
				// Если общего профиля защиты RTP у сторон не нашлось
				if(this->_srtp == 0)
					// Выводим отказ отсутствия общего профиля защиты RTP
					return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
			}
		}
		// Разбираем предложенные клиентом пределы длины записи (RFC 8449, раздел 4 RFC 6066)
		failure = this->sizing(greeting);
		// Если пределы не приняты
		if(failure != context::error_t::NONE)
			// Выводим ошибку
			return failure;
		// Если клиент предложил heartbeat (RFC 6520), его записи вида 24 будут роняться молча
		{
			// Расширение heartbeat приветствия клиента
			const hello::extension_t * beat = hello::extension(greeting.extensions, HEARTBEAT_EXTENSION);
			// Раздел 2 RFC 6520: режим - один октет со значением 1 либо 2, иное обрывает связь illegal_parameter
			if((beat != nullptr) && ((beat->data.size != 1) || ((beat->data.data[0] != 1) && (beat->data.data[0] != 2))))
				// Выводим отказ негодных параметров
				return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			// Запоминаем предложение
			this->_heartbeating = (beat != nullptr);
			// Раздел 2 RFC 6520: запросы клиенту шлются лишь при peer_allowed_to_send (1)
			this->_permitted = ((beat != nullptr) && (beat->data.data[0] == 1));
		}
		// Выполняем сброс признака выработки NPN
		this->_negotiated = false;
		// Разыскиваем расширение выработки NPN
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::NEGOTIATION));
		// Если выработка NPN клиентом предложена
		if(extension != nullptr){
			// Черновик draft-agl-tls-nextprotoneg: тело у клиента пусто, а непустое выдаёт негодное приветствие
			if(extension->data.size > 0)
				// Выводим отказ негодного расширения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			// NPN объявляется лишь по настройке потребителя и лишь когда ALPN не выбран (как у BoringSSL)
			this->_negotiated = (this->_negotiating && this->_protocol.empty());
		}
		// Выполняем сброс признака запроса состояния прежним приветствием
		this->_inquired = false;
		// Выполняем сброс признака запроса меток времени сертификата
		this->_stamped = false;
		// Разыскиваем расширение запроса меток времени сертификата
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::TIMESTAMPS));
		// Если метки времени сертификата клиентом запрошены
		if(extension != nullptr){
			// Раздел 3.3.1 RFC 6962: тело запроса пусто, а непустое выдаёт негодное приветствие
			if(extension->data.size > 0)
				// Выводим отказ негодного расширения
				return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
			// Запоминаем, что метки времени сертификата запрошены
			this->_stamped = true;
		}
		// Разыскиваем расширение запроса состояния сертификата
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::STATUS));
		// Если состояние сертификата приветствием клиента запрошено
		if(extension != nullptr){
			// Отказ разбора запроса состояния сертификата
			failure = this->inquiry(extension->data);
			// Если запрос состояния сертификата разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::DECODE));
		}
		// Раздел 8 RFC 6066: состояние идёт отдельным сообщением лишь при запросе и при наличии ответа у сервера
		this->_stapling = (this->_inquired && !this->_staples.empty() && !this->_staples[0].empty() && (this->_staples[0].size() <= CHAIN));
		// Разыскиваем расширение схем подписи, признаваемых клиентом
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SCHEMES));
		/**
		 * Раздел 7.4.1.4.1 RFC 5246: без расширения клиент признаёт лишь подписи на SHA-1,
		 * которых связь не ведёт, - сторонам нечем сойтись
		 */
		// Раздел 7.4.1.4.1 RFC 5246: схемы подписи - расширение издания 1.2; у DTLS 1.0 (TLS 1.1) их нет, и подписи идут без схем
		if((extension == nullptr) && !this->_ancient)
			// Выводим отказ отсутствия схем подписи в приветствии клиента
			return this->abort(context::error_t::SCHEME, alert::description_t::HANDSHAKE);
		// Отказ разбора расширения приветствия
		failure = ((extension == nullptr) ? context::error_t::NONE : translate(extension::schemes(extension->data, this->_schemes), context::error_t::MESSAGE));
		// Если схемы подписи, признаваемые клиентом, разобрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ разбора расширения приветствия
			return this->abort(failure, blame(failure, alert::description_t::DECODE));
		// Запоминаем издание заголовка приветствия клиента: оно идёт в общее значение обмена RSA (раздел 7.4.7.1 RFC 5246)
		this->_claimed = greeting.version;
		// Раздел 2 RFC 7366: клиент предлагает порядок «шифрование, затем имитовставка» пустым расширением
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::ETM));
		// Если расширение объявлено с непустым телом
		if((extension != nullptr) && (extension->data.size > 0))
			// Выводим отказ негодного расширения
			return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
		// Признак того, что порядок «шифрование, затем имитовставка» клиентом предложен
		const bool chained = (extension != nullptr);
		// Раздел 3.2 RFC 5077: билет сеанса предъявляется расширением session_ticket, пустое означает готовность билет принять
		extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::TICKET));
		// Запоминаем, что билет сеанса клиентом запрошен: он будет обещан приветствием и выдан
		this->_ticketing = (extension != nullptr);
		// Распечатанное состояние предъявленного билета: главный секрет затирается им самим
		ticket::state_t recalled;
		/**
		 * Раздел 4 RFC 5077: билет распечатывается ключом сервера; негодный, чужой либо
		 * просроченный билет ведёт к полному рукопожатию, а не к отказу. Раздел 5.3
		 * RFC 7627: возобновляется лишь связь с расширенным главным секретом - у связи он
		 * безусловен, и билет без него не выдаётся вовсе
		 */
		if((extension != nullptr) && (extension->data.size > 0) && this->_keeper.redeem(extension->data, recalled)){
			// Если билет годен связи: главный секрет, порядок и сертификат клиента уже перенесены
			if(this->recalling(greeting, chained, requested, recalled)){
				// Запоминаем, что рукопожатие сокращённое
				this->_resumed = true;
				// Запоминаем, что связь возобновлена билетом
				this->_shared = true;
			}
			// Выполняем сброс состояния билета с затиранием главного секрета
			recalled.clear();
		}
		// Если рукопожатие полное: подлинность выбирается по имени узла приветствия
		if(!this->_resumed){
			// Отказ выбора подлинности сервера по имени узла приветствия
			failure = this->choosing();
			// Если выбор подлинности обрывал рукопожатие
			if(failure != context::error_t::NONE)
				// Выводим отказ выбора подлинности
				return failure;
		}
		// Алгоритм подписи ключа своего сертификата: NONE у сервера без сертификата
		protect::signer_t signer = protect::signer_t::NONE;
		// Если своя подлинность у сервера есть
		if(!this->_credential.chain.empty()){
			// Объект разбора своего сертификата
			x509::certificate_t leaf;
			// Отказ разбора своего сертификата
			failure = translate(leaf.parse(view_t(this->_credential.chain[0].data(), this->_credential.chain[0].size())), context::error_t::CERTIFICATE);
			// Если свой сертификат разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора своего сертификата
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			/**
			 * Раздел 2 RFC 8422: набор ECDHE_ECDSA требует от сертификата ключа ECDSA либо
			 * EdDSA, набор ECDHE_RSA и обмен RSA - ключа RSA; набор, ключу не отвечающий,
			 * серверу не годен
			 */
			signer = (((leaf.key().algorithm.compare(RSA_KEY) == 0) || (leaf.key().algorithm.compare(RSAPSS_KEY) == 0)) ? protect::signer_t::RSA :
				(((leaf.key().algorithm.compare(EC_KEY) == 0) || (leaf.key().algorithm.compare(ED_KEY) == 0) || (leaf.key().algorithm.compare(ED448_KEY) == 0)) ? protect::signer_t::ECDSA : protect::signer_t::NONE));
		}
		// Если рукопожатие полное: набор выбирается заново
		if(!this->_resumed){
			// Сбрасываем выбранный набор шифрования
			this->_suite = protect::suite_t::NONE;
			/**
			 * Выполняем перебор наборов шифрования порядком стороны, чьё предпочтение ведёт выбор:
			 * раздел 7.4.1.2 RFC 5246 велит выбирать серверу, а порядок задаёт ручка preference
			 */
			for(size_t i = 0; (i < (this->_own ? this->_suites.size() : greeting.suites.size())) && (this->_suite == protect::suite_t::NONE); i++){
				/**
				 * Выполняем перебор наборов шифрования встречной стороны
				 */
				for(size_t j = 0; (j < (this->_own ? greeting.suites.size() : this->_suites.size())) && (this->_suite == protect::suite_t::NONE); j++){
					// Набор шифрования сервера в перебираемой паре
					const protect::suite_t mine = (this->_own ? this->_suites[i] : this->_suites[j]);
					// Набор шифрования клиента в перебираемой паре
					const uint16_t theirs = (this->_own ? greeting.suites[j] : greeting.suites[i]);
					// Если набор предложен не обеими сторонами либо не принадлежит изданию TLS 1.2
					if((static_cast <uint16_t> (mine) != theirs) || !protect::legacy(mine))
						// Переходим к следующей паре
						continue;
					// Раздел 1.2 RFC 5246: изданию 1.1 годны лишь наборы CBC с HMAC-SHA1
					if(this->_ancient && !archaic(mine))
						// Переходим к следующей паре
						continue;
					/**
					 * RFC 4279 и RFC 5489: наборы PSK годны лишь при заданном вызове ключа по
					 * опознавателю; прочие наборы требуют сертификата с ключом своего алгоритма
					 */
					if(preshared(mine) ? (this->_psk.respond == nullptr) : ((signer == protect::signer_t::NONE) || (protect::signer(mine) != signer)))
						// Переходим к следующей паре
						continue;
					// Запоминаем выбранный набор шифрования связи
					this->_suite = mine;
				}
			}
			// Если общего набора шифрования у сторон не нашлось
			if(this->_suite == protect::suite_t::NONE)
				// Выводим отказ отсутствия общего набора шифрования
				return this->abort(context::error_t::SUITE, alert::description_t::HANDSHAKE);
		}
		/**
		 * Раздел 3 RFC 7366: порядок «шифрование, затем имитовставка» вступает лишь при
		 * наборе CBC и предложении клиента; раздел 3.1 RFC 7366: у возобновлённой связи
		 * порядок унаследован от выдавшей билет и приветствием не пересогласуется
		 */
		if(!this->_resumed)
			// Запоминаем согласованный порядок
			this->_etm = (chained && (protect::mac(this->_suite) != digest::hash_t::NONE));
		// Если порядок связью требуется, набор CBC, а клиент порядка не предложил
		if(this->_strict && !this->_etm && (protect::mac(this->_suite) != digest::hash_t::NONE))
			// Выводим отказ отсутствия порядка «шифрование, затем имитовставка»
			return this->abort(context::error_t::ETM, alert::description_t::HANDSHAKE);
		// Сбрасываем выбранную кривую обмена ключами
		this->_group = extension::group_t::NONE;
		// Если набор шифрования требует мимолётных ключей, а рукопожатие полное
		if(!this->_resumed && ephemeral(this->_suite)){
			// Разыскиваем расширение перечня кривых обмена ключами
			extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::GROUPS));
			// Перечень кривых обмена ключами, поддерживаемых клиентом
			vector <extension::group_t> supported;
			// Если расширение перечня кривых найдено
			if(extension != nullptr){
				// Отказ разбора расширения приветствия
				failure = translate(extension::groups(extension->data, supported), context::error_t::MESSAGE);
				// Если перечень кривых обмена ключами разобрать не удалось
				if(failure != context::error_t::NONE)
					// Выводим отказ разбора расширения приветствия
					return this->abort(failure, blame(failure, alert::description_t::DECODE));
			}
			/**
			 * Раздел 5.1.1 RFC 8422: без перечня кривых серверу не узнать, какую кривую клиент
			 * примет; обмен ECDHE без общей кривой невозможен. Раздел 4 RFC 7919: перечень
			 * может не прийти вовсе - клиент тем выбор не ограничил, и набору DHE сервер
			 * вправе взять группу конечного поля своим порядком
			 */
			if((extension == nullptr) && (protect::exchange(this->_suite) != protect::exchange_t::DHE))
				// Выводим отказ отсутствия кривых обмена ключами
				return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
			// Признак того, что набор ведёт обмен ключами конечного поля
			const bool fielded = (protect::exchange(this->_suite) == protect::exchange_t::DHE);
			/**
			 * Выполняем перебор кривых обмена ключами, предлагаемых связью: выбор идёт порядком сервера
			 */
			for(size_t i = 0; (i < this->_groups.size()) && (this->_group == extension::group_t::NONE); i++){
				// Изданию TLS 1.2 наборами DHE годны конечные поля RFC 7919, наборами ECDHE - лишь кривые RFC 8422: X25519, X448, кривые NIST и secp256k1; конечное поле точкой кривой не бывает
				if(fielded ? (extension::finite(this->_groups[i]) == 0) : ((extension::finite(this->_groups[i]) > 0) || !classic(this->_groups[i]) || !fitting(this->_groups[i], true)))
					// Переходим к следующей группе обмена ключами
					continue;
				// Если перечня у клиента не было, выбор идёт одним порядком сервера
				if(extension == nullptr){
					// Запоминаем выбранную группу обмена ключами
					this->_group = this->_groups[i];
					// Переходим к следующей группе обмена ключами
					continue;
				}
				/**
				 * Выполняем перебор кривых обмена ключами, поддерживаемых клиентом
				 */
				for(size_t j = 0; (j < supported.size()) && (this->_group == extension::group_t::NONE); j++){
					// Если кривая обмена ключами поддержана обеими сторонами
					if(supported[j] == this->_groups[i])
						// Запоминаем выбранную кривую обмена ключами
						this->_group = this->_groups[i];
				}
			}
			// Если общей кривой обмена ключами у сторон не нашлось
			if(this->_group == extension::group_t::NONE)
				// Выводим отказ отсутствия общей кривой обмена ключами
				return this->abort(context::error_t::GROUP, alert::description_t::HANDSHAKE);
		}
		// Запоминаем случайное значение приветствия клиента
		::memcpy(this->_foreign, greeting.random, sizeof(this->_foreign));
		// Выполняем выработку случайного значения своего приветствия
		if(!entropy::bytes(this->_random, sizeof(this->_random)))
			// Выводим отказ выработки случайного значения приветствия
			return this->abort(context::error_t::SETTINGS, alert::description_t::INTERNAL);
		/**
		 * Раздел 4.1.3 RFC 8446: сервер, способный к изданию 1.3, но ведущий связь изданием
		 * 1.2, кладёт заслон понижения в хвост своего случайного значения - клиент,
		 * предлагавший 1.3, на нём оборвётся. Способность складывается из предела издания и
		 * наличия наборов 1.3: сервер одного лишь издания 1.2 - по пределу либо по наборам -
		 * заслона не кладёт, ибо выбор 1.2 у него единственно возможный, а клиент издания
		 * 1.3 (openssl в том числе) счёл бы его подменой и оборвал бы связь
		 */
		if(!this->_ancient && (this->_highest >= MODERN) && carries(this->_suites, false))
			// Записываем заслон понижения издания протокола
			::memcpy(this->_random + (sizeof(this->_random) - sizeof(DOWNGRADE[0])), DOWNGRADE[0], sizeof(DOWNGRADE[0]));
		// Раздел 4.1.3 RFC 8446: сервер, способный к изданию 1.2, но ведущий связь изданием 1.1, кладёт заслон DOWNGRD00
		else if(this->_ancient && (this->_highest >= LEGACY) && carries(this->_suites, true))
			// Записываем заслон понижения издания протокола ниже 1.2
			::memcpy(this->_random + (sizeof(this->_random) - sizeof(DOWNGRADE[1])), DOWNGRADE[1], sizeof(DOWNGRADE[1]));
		// Выполняем выбор хеша переписки по набору шифрования
		failure = this->hashing();
		// Если хеш переписки выбрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выбора хеша переписки
			return this->abort(failure, alert::description_t::INTERNAL);
		// Переписка подряд начинается приветствием клиента
		this->_history.clear();
		// Отказ ведения переписки рукопожатия
		const context::error_t recorded = this->chronicle(message, this->_delivered);
		// Если приветствие клиента в переписку рукопожатия добавить не удалось
		if(recorded != context::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(recorded, alert::description_t::INTERNAL);
		// Составляемое приветствие сервера
		hello::server_t answer;
		// Устанавливаем издание протокола: TLS 1.2, DTLS 1.2 либо DTLS 1.0
		answer.version = (this->_ancient ? this->eldest() : this->elder());
		// Переносим случайное значение своего приветствия
		::memcpy(answer.random, this->_random, sizeof(this->_random));
		/**
		 * Раздел 3.4 RFC 5077: приняв билет, сервер повторяет опознаватель связи клиента - так
		 * клиент отличает сокращённое рукопожатие от полного; кэша сеансов сервер не ведёт, и
		 * в полном рукопожатии опознаватель пуст (раздел 7.4.1.3 RFC 5246)
		 */
		answer.session = (this->_resumed ? greeting.session : vector <uint8_t> ());
		// Устанавливаем выбранный набор шифрования
		answer.suite = static_cast <uint16_t> (this->_suite);
		// Устанавливаем нулевой способ сжатия
		answer.method = 0x00;
		// Накопитель, в котором лежит тело расширения выбранного прикладного протокола
		vector <uint8_t> protocol;
		// Накопитель, в котором лежит тело расширения профиля защиты RTP
		vector <uint8_t> protection;
		// Раздел 5.2 RFC 7627: сервер отвечает пустым расширением расширенного главного секрета лишь клиенту, его предложившему
		if(this->_extending)
			// Добавляем подтверждение расширенного главного секрета
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MASTER), view_t(nullptr, 0)));
		// Раздел 3.6 RFC 5746: безопасное пересогласование подтверждается пустым перечнем
		if(renegotiable)
			// Добавляем расширение безопасного пересогласования
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::RENEGOTIATION), view_t(RENEGOTIATION, sizeof(RENEGOTIATION))));
		// Раздел 5.2 RFC 8422: записи точек объявляются в ответ лишь на объявление клиента
		if(listed)
			// Добавляем расширение записей точек кривой
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::FORMATS), view_t(FORMATS, sizeof(FORMATS))));
		// Раздел 3 RFC 6066: имя узла подтверждается пустым расширением
		if(!this->_name.empty())
			// Добавляем расширение имени запрашиваемого узла
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
		// Если прикладной протокол сторонами выбран
		if(!this->_protocol.empty()){
			// Отказ составления расширения приветствия
			failure = translate(extension::protocol(this->_protocol, protocol), context::error_t::MESSAGE);
			// Если выбранный прикладной протокол составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Добавляем расширение выбранного прикладного протокола
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(protocol.data(), protocol.size())));
		}
		// Если профиль защиты RTP сторонами выбран
		if(this->_srtp != 0){
			// Отказ составления расширения приветствия
			failure = translate(extension::profiles(vector <uint16_t> (1, this->_srtp), protection), context::error_t::MESSAGE);
			// Если выбранный профиль защиты RTP составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления расширения приветствия
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Добавляем расширение выбранного профиля защиты RTP
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROFILES), view_t(protection.data(), protection.size())));
		}
		// Если предел длины записи договорён, отвечаем клиенту своим расширением
		if(this->_sizing != 0){
			// Добавляем ответное расширение предела
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> ((this->_sizing == 1) ? extension::type_t::LIMIT : extension::type_t::FRAGMENT), view_t(this->_sized, ((this->_sizing == 1) ? 2 : 1))));
			// С ответом договорённая длина max_fragment_length связывает и приём (раздел 4 RFC 6066)
			if(this->_sizing == 2)
				// Ограничиваем приём договорённой длиной
				this->_incoming = this->_outgoing;
		}
		// Раздел 8 RFC 6066: состояние сертификата объявляется пустым расширением, а идёт отдельным сообщением
		if(this->_stapling && !this->_resumed && !preshared(this->_suite))
			// Добавляем расширение запроса состояния сертификата
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::STATUS), view_t(nullptr, 0)));
		// Раздел 3.3.1 RFC 6962: изданием 1.2 перечень меток времени идёт приветствием сервера по запросу, не при возобновлении и лишь при подлинности сертификатом
		if(this->_stamped && !this->_stamps.empty() && !this->_resumed && !preshared(this->_suite))
			// Добавляем расширение меток времени сертификата
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TIMESTAMPS), view_t(this->_stamps.data(), this->_stamps.size())));
		// Накопитель, в котором лежит тело расширения выработки NPN
		vector <uint8_t> advertised;
		// Черновик draft-agl-tls-nextprotoneg: сервер объявляет свои протоколы по запросу клиента, и при возобновлении тоже
		if(this->_negotiated){
			// Отказ составления перечня протоколов
			failure = translate(extension::negotiation(this->_protocols, advertised), context::error_t::MESSAGE);
			// Если перечень составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления приветствия
				return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
			// Добавляем расширение выработки NPN
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NEGOTIATION), view_t(advertised.data(), advertised.size())));
		}
		// Раздел 3 RFC 7366: порядок «шифрование, затем имитовставка» подтверждается пустым расширением
		if(this->_etm)
			// Добавляем расширение encrypt_then_mac
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::ETM), view_t(nullptr, 0)));
		// Если клиент предложил heartbeat: раздел 2 RFC 6520 велит ответить своим режимом - запросы собеседника принимаются
		if(this->_heartbeating){
			// Добавляем расширение heartbeat с режимом peer_allowed_to_send
			answer.extensions.push_back(hello::extension_t(HEARTBEAT_EXTENSION, view_t(&HEARTBEAT_ALLOWED, 1)));
			// Запросы собеседника принимаются
			this->_answering = true;
		}
		// Раздел 3.3 RFC 5077: пустое расширение session_ticket обещает клиенту билет сеанса
		if(this->_ticketing)
			// Добавляем расширение билета сеанса
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::TICKET), view_t(nullptr, 0)));
		// Накопитель, в который складывается тело приветствия сервера
		vector <uint8_t> body;
		// Отказ составления приветствия сервера
		failure = translate(hello::build(answer, body), context::error_t::MESSAGE);
		// Если тело приветствия сервера составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия сервера
			return this->abort(failure, alert::description_t::INTERNAL);
		// Выполняем отправку приветствия сервера
		failure = this->send(handshake::type_t::SERVER, view_t(body.data(), body.size()));
		// Если приветствие сервера отправить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки приветствия сервера
			return this->abort(failure, alert::description_t::INTERNAL);
		/**
		 * Раздел 3.3 RFC 5077 и раздел 7.3 RFC 5246: сокращённое рукопожатие - главный секрет
		 * из билета, ключевой материал по случайным значениям, билет заново, смена набора и
		 * завершение сервера первым; клиент отвечает своими сменой набора и завершением
		 */
		if(this->_resumed){
			// Выполняем вывод ключевого материала связи из главного секрета билета
			failure = this->keying();
			// Если ключевой материал вывести не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ вывода ключевого материала
				return this->abort(failure, alert::description_t::INTERNAL);
			// Выполняем отправку заключительного залпа: билет (коли обещан), смена набора, завершение
			failure = this->concluding();
			// Если заключительный залп отправить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ отправки заключительного залпа
				return this->abort(failure, alert::description_t::INTERNAL);
			// Переходим к ожиданию смены набора шифрования клиентом
			this->_phase = phase_t::CHANGE;
			// Выводим успешность ответа на приветствие клиента
			return context::error_t::NONE;
		}
		// RFC 4279 и RFC 5489: наборы PSK ведут рукопожатие без сертификата сервера
		if(!preshared(this->_suite)){
			// Выполняем отправку цепочки сертификатов сервера
			failure = this->presenting();
			// Если цепочку сертификатов отправить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ отправки цепочки сертификатов
				return this->abort(failure, alert::description_t::INTERNAL);
		}
		// Если состояние сертификата идёт отдельным сообщением
		if(this->_stapling && !preshared(this->_suite)){
			// Объект составителя тела состояния сертификата
			field::builder_t builder;
			// Отказ составления тела состояния сертификата
			failure = translate(builder.number(OCSP, 1), context::error_t::MESSAGE);
			// Если вид состояния записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления состояния сертификата
				return this->abort(failure, alert::description_t::INTERNAL);
			// Отказ открытия поля записи ответа
			failure = translate(builder.open(3), context::error_t::MESSAGE);
			// Если поле записи ответа открыть не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления состояния сертификата
				return this->abort(failure, alert::description_t::INTERNAL);
			// Отказ записи ответа о состоянии
			failure = translate(builder.bytes(view_t(this->_staples[0].data(), this->_staples[0].size())), context::error_t::MESSAGE);
			// Если ответ о состоянии записать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления состояния сертификата
				return this->abort(failure, alert::description_t::INTERNAL);
			// Отказ закрытия поля записи ответа
			failure = translate(builder.close(), context::error_t::MESSAGE);
			// Если поле записи ответа закрыть не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления состояния сертификата
				return this->abort(failure, alert::description_t::INTERNAL);
			// Выполняем отправку состояния сертификата сервера
			failure = this->send(handshake::type_t::STATUS, builder.data());
			// Если состояние сертификата отправить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ отправки состояния сертификата
				return this->abort(failure, alert::description_t::INTERNAL);
		}
		/**
		 * Раздел 7.4.3 RFC 5246: обмен ключами сервера идёт у ECDHE (RFC 8422), у ECDHE_PSK
		 * (RFC 5489) и у PSK с подсказкой (раздел 2 RFC 4279); у обмена RSA и у PSK без
		 * подсказки его нет
		 */
		if(ephemeral(this->_suite) || ((protect::exchange(this->_suite) == protect::exchange_t::PSK) && !this->_psk.identity.empty())){
			// Выполняем отправку обмена ключами сервера
			failure = this->agreeing();
			// Если обмен ключами сервера отправить не удалось
			if(failure != context::error_t::NONE)
				// Раздел 7.4.3 RFC 5246: отсутствие общей схемы подписи - несхождение сторон
				return this->abort(failure, blame(failure, ((failure == context::error_t::SCHEME) ? alert::description_t::HANDSHAKE : alert::description_t::INTERNAL)));
		}
		// Раздел 2 RFC 4279: при наборах PSK запрос подлинности клиента не шлётся
		if(this->_request && !preshared(this->_suite)){
			// Выполняем отправку запроса подлинности клиента
			failure = this->demanding();
			// Если запрос подлинности клиента отправить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ отправки запроса подлинности клиента
				return this->abort(failure, alert::description_t::INTERNAL);
		}
		// Выполняем отправку конца приветствия сервера
		failure = this->send(handshake::type_t::DONE, view_t(nullptr, 0));
		// Если конец приветствия сервера отправить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки конца приветствия сервера
			return this->abort(failure, alert::description_t::INTERNAL);
		// Переходим к ожиданию цепочки клиента либо его обмена ключами
		this->_phase = ((this->_request && !preshared(this->_suite)) ? phase_t::ANSWER : phase_t::PREMASTER);
		// Выводим успешность ответа на приветствие клиента
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора клиентом приветствия сервера издания TLS 1.2
 *
 * @param answer  разобранное приветствие сервера
 * @param message принятое приветствие сервера вместе с обвязкой
 * @return        отказ разбора приветствия сервера
 *
 */
context::error_t nts::internal::Engine::greeted(const hello::server_t & answer, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		/**
		 * Приложение D.1 RFC 8446: издание, объявленное заголовком, обязано быть из
		 * предложенных; издание TLS 1.2 предлагается лишь переносом записями и лишь в
		 * пределах, поставленных потребителю, а ниже 1.2 связь не опускается никогда
		 */
		// Признак того, что сервер выбрал издание DTLS 1.0 (RFC 4347), дозволенное связи
		const bool oldest = ((this->_transport == context::transport_t::DATAGRAMS) && (this->_lowest <= ANCIENT) && (answer.version == this->eldest()) && archaical(this->_suites));
		// Если издание заголовка ответа дозволено связи не было
		if((this->_transport == context::transport_t::LEVELS) || ((this->_lowest > LEGACY) && !oldest) || ((answer.version != this->elder()) && !oldest) || ((answer.version == this->elder()) && (this->_highest < LEGACY)))
			// Выводим отказ несовпадения издания протокола
			return this->abort(context::error_t::VERSION, alert::description_t::VERSION);
		// Запоминаем, ведётся ли связь изданием DTLS 1.0
		this->_ancient = oldest;
		/**
		 * Раздел 4.1.3 RFC 8446: клиент, предлагавший издание 1.3, обрывается на обоих
		 * заслонах понижения; клиент одного лишь издания 1.2 судит лишь заслон понижения
		 * ниже 1.2 - заслон 1.3 законно кладёт сервер, знающий издание 1.3. Изданием 1.1
		 * заслон 1.3 (DOWNGRD01) - подмена всегда, заслон 1.2 (DOWNGRD00) - подмена лишь для
		 * клиента, предлагавшего 1.2
		 */
		for(size_t i = ((this->_proposed || oldest) ? 0 : 1); i < (sizeof(DOWNGRADE) / sizeof(DOWNGRADE[0])); i++){
			// Если заслон 1.2 у клиента одного лишь издания 1.1 - он законен
			if(oldest && (i == 1) && (this->_highest < LEGACY))
				// Переходим к следующему заслону
				continue;
			// Если заслон понижения лежит в хвосте случайного значения сервера
			if(::memcmp(answer.random + (sizeof(answer.random) - sizeof(DOWNGRADE[i])), DOWNGRADE[i], sizeof(DOWNGRADE[i])) == 0)
				// Выводим отказ понижения издания протокола
				return this->abort(context::error_t::VERSION, alert::description_t::PARAMETER);
		}
		/**
		 * Раздел 7.4.1.3 RFC 5246: опознаватель связи сервер вправе назначить новый ради
		 * своего запаса сеансов, вернуть прежний либо оставить пустым; связь возобновления
		 * не ведёт и опознаватель не толкует - разбор приветствия лишь ограничил его длину.
		 * Раздел 6.2.2 RFC 5246: сжатие записей связью не ведётся, и способ обязан быть нулевым
		 */
		if(answer.method != 0x00)
			// Выводим отказ негодного способа сжатия
			return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
		// Набор шифрования, выбранный сервером
		const protect::suite_t suite = static_cast <protect::suite_t> (answer.suite);
		// Признак того, что выбранный сервером набор шифрования связью предложен
		bool suitable = false;
		/**
		 * Выполняем перебор наборов шифрования, предлагаемых связью
		 */
		for(size_t i = 0; (i < this->_suites.size()) && !suitable; i++)
			// Запоминаем совпадение выбранного набора шифрования с предложенным
			suitable = (suite == this->_suites[i]);
		// Если сервер выбрал набор профиля отпечатка, связи неведомый: профиль исполнить нельзя
		// Раздел 4 RFC 5288: изданием DTLS 1.0 набор AEAD не ведётся - клиент с перечнем из обоих родов обязан отвергнуть такой ответ
		if(suitable && oldest && !archaic(suite))
			// Выводим отказ набора
			return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		// Если набор не из перечня, а профиль обязует его исполнить
		if(!suitable && this->_profiled && this->carried(answer.suite))
			// Выводим отказ исполнения профиля
			return this->abort(context::error_t::PROFILE, alert::description_t::PARAMETER);
		// Раздел 7.4.1.3 RFC 5246: набор обязан быть из предложенных, а изданию 1.2 годны лишь его наборы
		if(!suitable || !protect::legacy(suite))
			// Выводим отказ несовпадения набора шифрования
			return this->abort(context::error_t::SUITE, alert::description_t::PARAMETER);
		// Признак того, что сервер подтвердил расширенный главный секрет
		bool extended = false;
		/**
		 * Выполняем перебор расширений, объявленных приветствием сервера
		 */
		// Признак того, что сервер ответил расширением heartbeat: без ответа расширение не согласовано (раздел 2 RFC 6520)
		bool beating = false;
		/**
		 * Выполняем перебор расширений приветствия сервера
		 */
		for(size_t i = 0; i < answer.extensions.size(); i++){
			// Вид очередного расширения приветствия сервера
			const uint16_t type = answer.extensions[i].type;
			// Тело очередного расширения приветствия сервера
			const view_t & data = answer.extensions[i].data;
			// Признак того, что расширение связью предлагалось
			bool proposed = false;
			/**
			 * Выполняем перебор расширений, предложенных связью приветствием
			 */
			for(size_t j = 0; (j < this->_offered.size()) && !proposed; j++)
				// Запоминаем, предлагалось ли расширение связью
				proposed = (type == this->_offered[j]);
			// Раздел 7.4.1.4 RFC 5246: расширение, клиентом не предложенное, обрывает связь
			if(!proposed)
				// Выводим отказ объявления непрошенного расширения
				return this->abort(context::error_t::EXTENSION, alert::description_t::EXTENSION);
			/**
			 * Выполняем определение вида расширения
			 */
			switch(type){
				// Если сервер подтвердил предел длины записи record_size_limit (RFC 8449)
				case static_cast <uint16_t> (extension::type_t::LIMIT): {
					// Если тело расширения не двухбайтовое
					if(data.size != 2)
						// Выходим с ошибкой разбора
						return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
					// Применяем присланный предел к отправке
					const context::error_t bounded = this->bounding(static_cast <uint16_t> ((static_cast <uint16_t> (data.data[0]) << 8) | data.data[1]), true);
					// Если предел не принят
					if(bounded != context::error_t::NONE)
						// Выводим ошибку
						return bounded;
				} break;
				// Если сервер подтвердил длину max_fragment_length (раздел 4 RFC 6066)
				case static_cast <uint16_t> (extension::type_t::FRAGMENT): {
					// Если тело расширения не однобайтовое
					if(data.size != 1)
						// Выходим с ошибкой разбора
						return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
					// Применяем присланный код длины к обеим сторонам
					const context::error_t fragmented = this->fragmenting(data.data[0], true);
					// Если код не принят
					if(fragmented != context::error_t::NONE)
						// Выводим ошибку
						return fragmented;
				} break;
				// Раздел 5.3 RFC 7627: подтверждение расширенного главного секрета пусто
				case static_cast <uint16_t> (extension::type_t::MASTER): {
					// Если тело расширения не пусто
					if(data.size > 0)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Запоминаем подтверждение расширенного главного секрета
					extended = true;
				} break;
				// Раздел 3.4 RFC 5746: на первом рукопожатии сервер отвечает пустым перечнем
				case static_cast <uint16_t> (extension::type_t::RENEGOTIATION): {
					// Если тело расширения сложено не по правилам
					if((data.size != sizeof(RENEGOTIATION)) || (data.data[0] != 0x00))
						// Выводим отказ негодного расширения пересогласования
						return this->abort(context::error_t::MESSAGE, alert::description_t::HANDSHAKE);
				} break;
				// Раздел 5.2 RFC 8422: записи точек сервера обязаны нести несжатую
				case static_cast <uint16_t> (extension::type_t::FORMATS): {
					// Отказ разбора расширения записей точек кривой
					failure = this->formatted(data);
					// Если записи точек кривой сложены не по правилам либо несжатой среди них нет
					if(failure != context::error_t::NONE)
						// Раздел 5.2 RFC 8422: негодная запись - decode_error, отсутствие несжатой - handshake_failure
						return this->abort(failure, blame(failure, ((failure == context::error_t::MESSAGE) ? alert::description_t::DECODE : alert::description_t::HANDSHAKE)));
				} break;
				// Раздел 3 RFC 6066: имя узла подтверждается пустым расширением
				case static_cast <uint16_t> (extension::type_t::NAME): {
					// Если тело расширения не пусто
					if(data.size > 0)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
				} break;
				// Раздел 3.1 RFC 7301: сервер объявляет выбранный прикладной протокол
				case static_cast <uint16_t> (extension::type_t::PROTOCOLS): {
					// Название прикладного протокола, выбранного сервером
					string selected;
					// Отказ разбора расширения приветствия
					failure = translate(extension::protocol(data, selected), context::error_t::MESSAGE);
					// Если выбранный сервером прикладной протокол разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора расширения приветствия
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Признак того, что выбранный протокол связью предлагался
					bool suitable = false;
					/**
					 * Выполняем перебор прикладных протоколов, предложенных связью
					 */
					for(size_t j = 0; (j < this->_protocols.size()) && !suitable; j++)
						// Запоминаем, предлагался ли выбранный сервером протокол связью
						suitable = (selected.compare(this->_protocols[j]) == 0);
					// Раздел 3.2 RFC 7301: протокол вне предложения принимать нельзя
					if(!suitable)
						// Выводим отказ отсутствия общего прикладного протокола
						return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
					// Запоминаем выбранный сторонами прикладной протокол
					this->_protocol = ::move(selected);
				} break;
				// Раздел 4.1.1 RFC 5764: сервер объявляет выбранный профиль защиты RTP
				case static_cast <uint16_t> (extension::type_t::PROFILES): {
					// Перечень профилей защиты RTP, выбранный сервером
					vector <uint16_t> offer;
					// Отказ разбора расширения приветствия
					failure = translate(extension::profiles(data, offer), context::error_t::MESSAGE);
					// Если выбранный сервером профиль защиты RTP разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора расширения приветствия
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Раздел 4.1.1 RFC 5764: сервер выбирает ровно один профиль из предложенных
					if(offer.size() != 1)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Признак того, что выбранный профиль связью предлагался
					bool suitable = false;
					/**
					 * Выполняем перебор профилей защиты RTP, предложенных связью
					 */
					for(size_t j = 0; (j < this->_srtps.size()) && !suitable; j++)
						// Запоминаем, предлагался ли выбранный сервером профиль связью
						suitable = (offer[0] == this->_srtps[j]);
					// Профиль вне предложения принимать нельзя, как и протокол вне предложения (раздел 3.2 RFC 7301)
					if(!suitable)
						// Выводим отказ отсутствия общего профиля защиты RTP
						return this->abort(context::error_t::PROTOCOL, alert::description_t::PROTOCOL);
					// Запоминаем выбранный сторонами профиль защиты RTP
					this->_srtp = offer[0];
				} break;
				// Раздел 8 RFC 6066: состояние сертификата объявляется пустым расширением
				// Черновик draft-agl-tls-nextprotoneg: перечень протоколов сервера для выработки NPN
				case static_cast <uint16_t> (extension::type_t::NEGOTIATION): {
					// Если прикладной протокол уже выбран через ALPN: NPN и ALPN вместе не бывает
					if(!this->_protocol.empty())
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Перечень протоколов, объявленных сервером
					vector <string> advertised;
					// Отказ разбора перечня
					failure = translate(extension::negotiation(data, advertised), context::error_t::MESSAGE);
					// Если перечень разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора приветствия сервера
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// Выбранный протокол
					string selected;
					/**
					 * Выполняем перебор своих протоколов: выбор идёт порядком клиента среди объявленных сервером
					 */
					for(size_t j = 0; (j < this->_protocols.size()) && selected.empty(); j++){
						/**
						 * Выполняем перебор протоколов, объявленных сервером
						 */
						for(size_t k = 0; (k < advertised.size()) && selected.empty(); k++){
							// Если протокол объявлен сервером
							if(advertised[k].compare(this->_protocols[j]) == 0)
								// Запоминаем выбранный протокол
								selected = this->_protocols[j];
						}
					}
					/**
					 * Черновик и SSL_select_next_proto: без общего протокола берётся первый свой, без
					 * своих - первый объявленный; без того и другого NextProtocol идёт с пустым
					 * именем (как у BoringSSL): сервер, объявивший выработку, ждёт сообщения
					 */
					if(selected.empty() && !this->_protocols.empty())
						// Берём первый свой протокол
						selected = this->_protocols.front();
					// Если своих протоколов нет, а сервер объявил
					else if(selected.empty() && !advertised.empty())
						// Берём первый объявленный
						selected = advertised.front();
					/**
					 * Выполняем перехват ошибок
					 */
					try {
						// Запоминаем протокол связи
						this->_protocol = ::move(selected);
					/**
					 * Выполняем перехват ошибок
					 */
					} catch(const std::bad_alloc &) {
						// Выводим отказ нехватки памяти
						return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
					}
					// Запоминаем, что выработка NPN состоялась
					this->_negotiated = true;
				} break;
				case static_cast <uint16_t> (extension::type_t::STATUS): {
					// Если тело расширения не пусто
					if(data.size > 0)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Запоминаем, что состояние сертификата идёт отдельным сообщением
					this->_stapling = true;
				} break;
				// Раздел 3.3.1 RFC 6962: перечень меток времени сертификата сервера изданием 1.2
				case static_cast <uint16_t> (extension::type_t::TIMESTAMPS): {
					// Записи перечня, разобранные ради проверки вида
					vector <vector <uint8_t>> entries;
					// Отказ разбора перечня меток времени
					failure = translate(extension::timestamps(data, entries), context::error_t::MESSAGE);
					// Если перечень разобрать не удалось
					if(failure != context::error_t::NONE)
						// Выводим отказ разбора перечня меток времени
						return this->abort(failure, blame(failure, alert::description_t::DECODE));
					// При возобновлении перечень не хранится: сертификата в сокращённом рукопожатии нет
					if(!this->_resumed){
						/**
						 * Выполняем перехват ошибок
						 */
						try {
							// Запоминаем перечень меток времени как записан
							this->_timestamps.assign(data.data, data.data + data.size);
						/**
						 * Выполняем перехват ошибок
						 */
						} catch(const std::bad_alloc &) {
							// Выводим отказ нехватки памяти
							return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
						}
					}
				} break;
				// Если сервер ответил расширением heartbeat (RFC 6520)
				case HEARTBEAT_EXTENSION: {
					// Раздел 7.4.1.4 RFC 5246: расширение, связью не предложенное, обрывает связь
					if(!this->_heartbeating)
						// Выводим отказ неподдержанного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::UNSUPPORTED);
					// Раздел 2 RFC 6520: режим - один октет со значением 1 либо 2
					if((data.size != 1) || ((data.data[0] != 1) && (data.data[0] != 2)))
						// Выводим отказ негодных параметров
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Запоминаем дозволение слать запросы
					this->_permitted = (data.data[0] == 1);
					// Расширение согласовано
					beating = true;
				} break;
				// Раздел 3 RFC 7366: порядок «шифрование, затем имитовставка» подтверждается пустым расширением
				case static_cast <uint16_t> (extension::type_t::ETM): {
					// Если тело расширения не пусто
					if(data.size > 0)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Раздел 3 RFC 7366: подтверждение при наборе AEAD сервер слать не вправе
					if(protect::mac(suite) == digest::hash_t::NONE)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Запоминаем согласованный порядок «шифрование, затем имитовставка»
					this->_etm = true;
				} break;
				// Раздел 3.3 RFC 5077: сервер обещает билет сеанса пустым расширением
				case static_cast <uint16_t> (extension::type_t::TICKET): {
					// Если тело расширения не пусто
					if(data.size > 0)
						// Выводим отказ негодного расширения
						return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
					// Запоминаем, что билет сеанса обещан сервером
					this->_ticketing = true;
				} break;
				/**
				 * Прочие расширения приветствия сервера изданию TLS 1.2 не положены: издание,
				 * доли ключа, заранее разделённый ключ и метка возврата принадлежат изданию
				 * 1.3, а группы, схемы и сжатие - одному лишь приветствию клиента
				 */
				default: return this->abort(context::error_t::MESSAGE, alert::description_t::PARAMETER);
			}
		}
		// Если heartbeat предлагался, а сервер не ответил: расширение не согласовано - записи вида 24 неожиданны, запросы не шлются и не принимаются
		if(this->_heartbeating && !beating){
			// Снимаем признак предложенного heartbeat
			this->_heartbeating = false;
			// Снимаем свой режим ответов на запросы heartbeat
			this->_answering = false;
			// Снимаем дозволение приёма записей heartbeat
			this->_permitted = false;
		}
		/**
		 * Раздел 5.3 RFC 7627: без подтверждения сервером расширенного главного секрета
		 * связь ведётся обычным главным секретом (раздел 8.1 RFC 5246), как у openssl, а
		 * обязательный расширенный главный секрет такого сервера отвергает (решение 16)
		 */
		if(!extended && this->_mandatory)
			// Выводим отказ отсутствия расширенного главного секрета
			return this->abort(context::error_t::MASTER, alert::description_t::HANDSHAKE);
		// Запоминаем, ведётся ли связь расширенным главным секретом
		this->_extending = extended;
		// Запоминаем, что связь ведётся изданием TLS 1.2
		this->_legacy = true;
		// Запоминаем согласованное издание протокола кодом TLS 1.2 либо 1.1: единая шкала изданий на любом переносе
		this->_version = (this->_ancient ? ANCIENT : LEGACY);
		// Раздел 6.2.3 RFC 5246: защищённая запись издания TLS 1.2 вмещает до 2^14 + 2048 байтов
		this->_records.limit(record::RECORD_PROTECTED);
		// Запоминаем выбранный сервером набор шифрования
		this->_suite = suite;
		// Запоминаем случайное значение приветствия сервера
		::memcpy(this->_foreign, answer.random, sizeof(this->_foreign));
		/**
		 * Раздел 3.4 RFC 5077 велит серверу, принявшему билет, повторять опознаватель связи
		 * клиента, но чужие узлы (openssl) шлют иной либо пустой: признаком сокращённого
		 * рукопожатия служит первое сообщение за приветствием, а главный секрет билета
		 * кладётся в связь заранее и затирается, если рукопожатие оказалось полным
		 */
		if(this->_presented)
			// Переносим главный секрет из билета
			::memcpy(this->_keys->master, this->_resume.secret.data(), sizeof(this->_keys->master));
		/**
		 * Раздел 4.2.6 RFC 6347: переписка DTLS 1.2 ведётся в обвязке DTLS, а приветствие
		 * клиента легло в неё в обвязке TLS ради издания 1.3 - переписка начинается заново с
		 * приветствия в обвязке DTLS, накопленного подряд
		 */
		if(this->_transport == context::transport_t::DATAGRAMS){
			// Переводим перенос на издание DTLS 1.2
			this->_flight.legacy(true);
			// Раздел 4.1 RFC 4347: изданием DTLS 1.0 записи несут 0xFEFF
			this->_flight.ancient(this->_ancient);
			// Начинаем переписку рукопожатия заново
			this->_transcript.start();
			// Если приветствие клиента в обвязке DTLS в переписку добавить не удалось
			if(this->_transcript.update(view_t(this->_history.data(), this->_history.size())) != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return this->abort(context::error_t::MESSAGE, alert::description_t::INTERNAL);
		}
		// Выполняем выбор хеша переписки по набору шифрования
		failure = this->hashing();
		// Если хеш переписки выбрать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выбора хеша переписки
			return this->abort(failure, alert::description_t::PARAMETER);
		// Отказ ведения переписки рукопожатия
		const context::error_t recorded = this->chronicle(message, this->_delivered);
		// Если приветствие сервера в переписку рукопожатия добавить не удалось
		if(recorded != context::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return this->abort(recorded, alert::description_t::INTERNAL);
		// Если порядок «шифрование, затем имитовставка» связью требуется, набор CBC, а сервер порядка не подтвердил
		if(this->_strict && !this->_etm && (protect::mac(suite) != digest::hash_t::NONE))
			// Выводим отказ отсутствия порядка «шифрование, затем имитовставка»
			return this->abort(context::error_t::ETM, alert::description_t::HANDSHAKE);
		// Если билет сеанса предъявлен: вид рукопожатия решает первое сообщение за приветствием
		if(this->_presented){
			// Переходим к ожиданию либо полного, либо сокращённого рукопожатия
			this->_phase = phase_t::EITHER;
			// Выводим успешность разбора приветствия сервера
			return context::error_t::NONE;
		}
		/**
		 * Раздел 7.3 RFC 5246: за приветствием сервера идёт его цепочка сертификатов; у
		 * наборов PSK сертификата нет (RFC 4279, RFC 5489) - идёт обмен ключами сервера,
		 * у чистого PSK необязательный
		 */
		this->_phase = (preshared(suite) ? phase_t::AGREEMENT : phase_t::CERTIFICATE);
		// Выводим успешность разбора приветствия сервера
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора расширения записей точек кривой издания TLS 1.2
 *
 * @param data тело расширения записей точек кривой
 * @return     отказ разбора расширения либо отсутствия несжатой записи
 *
 */
context::error_t nts::internal::Engine::formatted(const view_t & data) noexcept {
	// Перечень объявленных собеседником записей точек кривой
	vector <uint8_t> formats;
	// Отказ разбора расширения записей точек: раздел 5.1.2 RFC 8422
	const context::error_t failure = translate(extension::formats(data, formats), context::error_t::MESSAGE);
	// Если перечень записей точек разобрать не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ разбора расширения
		return failure;
	/**
	 * Выполняем перебор объявленных записей точек кривой
	 */
	for(size_t i = 0; i < formats.size(); i++){
		// Раздел 5.1.2 RFC 8422: несжатая запись uncompressed(0) обязательна всякой стороне
		if(formats[i] == 0x00)
			// Выводим успешность: несжатая запись объявлена
			return context::error_t::NONE;
	}
	// Выводим отказ отсутствия несжатой записи точки
	return context::error_t::EXCHANGE;
}
/**
 * @brief Метод отправки цепочки сертификатов издания TLS 1.2
 *
 * @return отказ отправки цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::presenting() noexcept {
	// Объект составителя тела цепочки сертификатов
	field::builder_t builder;
	// Отказ, которым ответил составитель полей
	field::error_t failure = builder.open(3);
	// Если место под длину перечня сертификатов занять не удалось
	if(failure != field::error_t::NONE)
		// Выводим отказ составления цепочки сертификатов
		return translate(failure, context::error_t::MESSAGE);
	/**
	 * Выполняем перебор сертификатов цепочки своей стороны: раздел 7.4.2 RFC 5246
	 */
	for(size_t i = 0; (i < this->_credential.chain.size()) && (failure == field::error_t::NONE); i++){
		// Занимаем место под длину очередного сертификата
		failure = builder.open(3);
		// Если место под длину сертификата занято
		if(failure == field::error_t::NONE)
			// Записываем очередной сертификат цепочки
			failure = builder.bytes(view_t(this->_credential.chain[i].data(), this->_credential.chain[i].size()));
		// Если сертификат записан
		if(failure == field::error_t::NONE)
			// Проставляем длину очередного сертификата
			failure = builder.close();
	}
	// Если перечень сертификатов записан
	if(failure == field::error_t::NONE)
		// Проставляем длину перечня сертификатов
		failure = builder.close();
	// Если цепочку сертификатов составить не удалось
	if(failure != field::error_t::NONE)
		// Выводим отказ составления цепочки сертификатов
		return translate(failure, context::error_t::MESSAGE);
	// Выводим итог отправки цепочки сертификатов
	return this->send(handshake::type_t::CERTIFICATE, builder.data());
}
/**
 * @brief Метод разбора принятой цепочки сертификатов издания TLS 1.2
 *
 * @param body тело принятого сообщения цепочки сертификатов
 * @return     отказ разбора цепочки сертификатов
 *
 */
context::error_t nts::internal::Engine::presented(const view_t & body) noexcept {
	// Объект разборщика тела цепочки сертификатов
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело цепочки сертификатов
	scanner.start(body);
	// Перечень сертификатов цепочки
	view_t list;
	// Раздел 7.4.2 RFC 5246: перечень с трёхбайтовой длиной без лишних байтов
	if((scanner.vector(list, 3) != field::error_t::NONE) || (scanner.left() > 0))
		// Выводим отказ разбора цепочки сертификатов
		return context::error_t::MESSAGE;
	// Объект разборщика перечня сертификатов
	field::scanner_t reader;
	// Устанавливаем разбираемый перечень сертификатов
	reader.start(list);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Выполняем сброс прежней цепочки сертификатов собеседника
		this->_peer.clear();
		/**
		 * Выполняем перебор сертификатов перечня
		 */
		while(reader.left() > 0){
			// Тело очередного сертификата
			view_t data;
			// Раздел 7.4.2 RFC 5246: сертификат с трёхбайтовой длиной, пустым быть не вправе
			if((reader.vector(data, 3) != field::error_t::NONE) || (data.size == 0))
				// Выводим отказ разбора цепочки сертификатов
				return context::error_t::MESSAGE;
			// Добавляем сертификат в цепочку собеседника
			this->_peer.push_back(vector <uint8_t> (data.data, data.data + data.size));
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выполняем сброс прежнего ответа о состоянии сертификата собеседника
	this->_status.clear();
	// Выполняем сброс прежнего состояния сертификата собеседника
	this->_certified = ocsp::status_t::NONE;
	/**
	 * Раздел 7.4.2 RFC 5246: сервер шлёт цепочку непустой всегда, а клиент вправе слать
	 * пустую, годного сертификата не найдя (раздел 7.4.6)
	 */
	if(this->_peer.empty())
		// Выводим итог: пустая цепочка сервера отвергается, клиента - принимается
		return (this->_server ? context::error_t::NONE : context::error_t::CERTIFICATE);
	// Объект разбора сертификата собеседника
	x509::certificate_t leaf;
	// Отказ разбора сертификата собеседника
	const context::error_t failure = translate(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())), context::error_t::CERTIFICATE);
	// Если сертификат собеседника разобрать не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ разбора сертификата собеседника
		return failure;
	// Признак того, что ключ сертификата - ключ RSA
	const bool rsa = ((leaf.key().algorithm.compare(RSA_KEY) == 0) || (leaf.key().algorithm.compare(RSAPSS_KEY) == 0));
	// Признак того, что ключ сертификата - ключ ECDSA либо EdDSA
	const bool ecdsa = ((leaf.key().algorithm.compare(EC_KEY) == 0) || (leaf.key().algorithm.compare(ED_KEY) == 0) || (leaf.key().algorithm.compare(ED448_KEY) == 0));
	/**
	 * Раздел 2 RFC 8422: ключ сертификата сервера обязан отвечать набору шифрования;
	 * ключ клиента отвечает видам, запрошенным сервером: rsa_sign и ecdsa_sign
	 */
	if(this->_server ? !(rsa || ecdsa) : (protect::signer(this->_suite) != (rsa ? protect::signer_t::RSA : (ecdsa ? protect::signer_t::ECDSA : protect::signer_t::NONE))))
		// Выводим отказ непригодности ключа сертификата набору
		return context::error_t::CERTIFICATE;
	// Если клиент ведёт обмен шифрованием RSA: ключ сервера судится ещё по длине
	if(!this->_server && (protect::exchange(this->_suite) == protect::exchange_t::RSA)){
		// Объект открытого ключа RSA сервера
		sign::rsa_t key;
		// Раздел 7.4.7.1 RFC 5246: негодная запись ключа - непригодный сертификат; ключ короче наименьшего дозволенного оставляет общее значение подбору
		if((leaf.key().unused != 0) || !key.decode(leaf.key().key) || !key.ready() || key.secret() || (key.bits() < RSA_LEAST))
			// Выводим отказ непригодности сертификата сервера
			return context::error_t::CERTIFICATE;
	}
	// Получаем расширение назначения ключа сертификата
	const x509::extension_t * usage = leaf.extension(USAGE);
	// Если назначение ключа сертификатом объявлено
	if(usage != nullptr){
		// Назначение открытого ключа
		uint16_t purpose = 0;
		// Раздел 4.2.1.3 RFC 5280: назначение сложено не по правилам - сертификат непригоден
		if(x509::usage(*usage, purpose) != x509::error_t::NONE)
			// Выводим отказ непригодности сертификата
			return context::error_t::CERTIFICATE;
		/**
		 * Раздел 7.4.2 RFC 5246: обмен шифрованием RSA требует у ключа сервера назначения
		 * keyEncipherment, подписанный обмен ключами (ECDHE) и подпись владения ключом
		 * клиента - назначения digitalSignature; ключ с чужим назначением набору не годен
		 */
		const uint16_t required = static_cast <uint16_t> ((!this->_server && (protect::exchange(this->_suite) == protect::exchange_t::RSA)) ? x509::usage_t::ENCIPHER : x509::usage_t::SIGNATURE);
		// Если назначение ключа набору не отвечает
		if((purpose & required) == 0)
			// Выводим отказ непригодности сертификата
			return context::error_t::CERTIFICATE;
	}
	// Выводим успешность разбора цепочки сертификатов
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки обмена ключами сервера издания TLS 1.2
 *
 * @return отказ отправки обмена ключами сервера
 *
 */
context::error_t nts::internal::Engine::agreeing() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(this->_suite);
		// Объект составителя параметров обмена ключами
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t outcome = field::error_t::NONE;
		// Если набор ведёт рукопожатие заранее разделённым ключом
		if(preshared(this->_suite)){
			// Раздел 2 RFC 4279 и раздел 3.2 RFC 5489: подсказка psk_identity_hint идёт первым полем с двухбайтовой длиной
			outcome = builder.open(2);
			// Если место под длину подсказки занято
			if(outcome == field::error_t::NONE)
				// Записываем подсказку опознавателя
				outcome = builder.bytes(view_t(this->_psk.identity.data(), this->_psk.identity.size()));
			// Если подсказка записана
			if(outcome == field::error_t::NONE)
				// Проставляем длину подсказки
				outcome = builder.close();
			// Если подсказку составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления обмена ключами
				return translate(outcome, context::error_t::MESSAGE);
			// Раздел 2 RFC 4279: у чистого PSK обмен ключами сервера несёт одну лишь подсказку
			if(exchange == protect::exchange_t::PSK)
				// Выводим итог отправки обмена ключами сервера
				return this->send(handshake::type_t::AGREEMENT, builder.data());
		}
		// Выполняем сброс мимолётных пар ключей своей стороны
		this->_exchanges.clear();
		// Выполняем выработку мимолётной пары ключей на выбранной кривой
		context::error_t failure = this->exchange(this->_group);
		// Если мимолётную пару ключей выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки мимолётной пары ключей
			return failure;
		// Открытая часть мимолётной пары ключей своей стороны
		const vector <uint8_t> & opened = this->_exchanges.back().opened;
		// Если набор ведёт обмен ключами конечного поля
		if(exchange == protect::exchange_t::DHE){
			// Модуль группы конечного поля
			const view_t modulus = agreement::prime(extension::finite(this->_group));
			// Генератор групп RFC 7919: два от старшего байта
			const uint8_t generator[] = {0x02};
			// Раздел 7.4.3 RFC 5246: модуль, генератор и открытый ключ идут с двухбайтовыми длинами
			if((modulus.data == nullptr) || (modulus.size == 0) || opened.empty() || (opened.size() != modulus.size))
				// Выводим отказ негодной длины доли
				return context::error_t::EXCHANGE;
			// Занимаем место под длину модуля
			outcome = builder.open(2);
			// Если место под длину модуля занято
			if(outcome == field::error_t::NONE)
				// Записываем модуль группы
				outcome = builder.bytes(modulus);
			// Если модуль записан
			if(outcome == field::error_t::NONE)
				// Проставляем длину модуля
				outcome = builder.close();
			// Если модуль записан
			if(outcome == field::error_t::NONE)
				// Занимаем место под длину генератора
				outcome = builder.open(2);
			// Если место под длину генератора занято
			if(outcome == field::error_t::NONE)
				// Записываем генератор группы
				outcome = builder.bytes(view_t(generator, sizeof(generator)));
			// Если генератор записан
			if(outcome == field::error_t::NONE)
				// Проставляем длину генератора
				outcome = builder.close();
			// Если генератор записан
			if(outcome == field::error_t::NONE)
				// Занимаем место под длину открытого ключа
				outcome = builder.open(2);
			// Если место под длину открытого ключа занято
			if(outcome == field::error_t::NONE)
				// Записываем открытый ключ своей мимолётной пары
				outcome = builder.bytes(view_t(opened.data(), opened.size()));
			// Если открытый ключ записан
			if(outcome == field::error_t::NONE)
				// Проставляем длину открытого ключа
				outcome = builder.close();
		// Иначе набор ведёт обмен ключами на кривой
		} else {
			// Раздел 5.4 RFC 8422: точка идёт с однобайтовой длиной
			if(opened.empty() || (opened.size() > 255))
				// Выводим отказ негодной длины точки
				return context::error_t::EXCHANGE;
			// Записываем вид параметров named_curve
			outcome = builder.number(0x03, 1);
			// Если вид параметров named_curve записан
			if(outcome == field::error_t::NONE)
				// Записываем именованную кривую обмена ключами
				outcome = builder.number(static_cast <uint32_t> (this->_group), 2);
			// Если именованная кривая записана
			if(outcome == field::error_t::NONE)
				// Занимаем место под длину точки
				outcome = builder.open(1);
			// Если место под длину точки занято
			if(outcome == field::error_t::NONE)
				// Записываем точку своей мимолётной пары
				outcome = builder.bytes(view_t(opened.data(), opened.size()));
			// Если точка записана
			if(outcome == field::error_t::NONE)
				// Проставляем длину точки
				outcome = builder.close();
		}
		// Если параметры обмена ключами составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления параметров обмена ключами
			return translate(outcome, context::error_t::MESSAGE);
		// Раздел 3.2 RFC 5489: у ECDHE_PSK параметры обмена не подписываются - подлинность даёт заранее разделённый ключ
		if(exchange == protect::exchange_t::ECDHE_PSK)
			// Выводим итог отправки обмена ключами сервера
			return this->send(handshake::type_t::AGREEMENT, builder.data());
		// Получаем составленные параметры обмена ключами
		const view_t parameters = builder.data();
		// Накопитель, в который складывается подписываемое содержимое
		vector <uint8_t> content;
		// Раздел 5.4 RFC 8422: подписываются случайные значения клиента и сервера и параметры обмена
		content.insert(content.end(), this->_foreign, this->_foreign + sizeof(this->_foreign));
		// Добавляем случайное значение сервера
		content.insert(content.end(), this->_random, this->_random + sizeof(this->_random));
		// Добавляем параметры обмена ключами
		content.insert(content.end(), parameters.data, parameters.data + parameters.size);
		// Схема подписи обмена ключами
		extension::scheme_t scheme = extension::scheme_t::NONE;
		// Накопитель, в который складывается подпись обмена ключами
		vector <uint8_t> signature;
		// Отказ выработки подписи обмена ключами
		failure = this->signing(view_t(content.data(), content.size()), scheme, signature);
		// Если подпись обмена ключами выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки подписи обмена ключами
			return failure;
		// Записываем схему подписи обмена ключами
		outcome = (this->_ancient ? field::error_t::NONE : builder.number(static_cast <uint32_t> (scheme), 2));
		// Если схема подписи записана
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину подписи
			outcome = builder.open(2);
		// Если место под длину подписи занято
		if(outcome == field::error_t::NONE)
			// Записываем подпись обмена ключами
			outcome = builder.bytes(view_t(signature.data(), signature.size()));
		// Если подпись записана
		if(outcome == field::error_t::NONE)
			// Проставляем длину подписи
			outcome = builder.close();
		// Если обмен ключами сервера составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления обмена ключами сервера
			return translate(outcome, context::error_t::MESSAGE);
		// Выводим итог отправки обмена ключами сервера
		return this->send(handshake::type_t::AGREEMENT, builder.data());
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятого обмена ключами сервера издания TLS 1.2
 *
 * @param body тело принятого сообщения обмена ключами сервера
 * @return     отказ разбора обмена ключами сервера
 *
 */
context::error_t nts::internal::Engine::agreed(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Объект разборщика тела обмена ключами сервера
		field::scanner_t scanner;
		// Устанавливаем разбираемое тело обмена ключами
		scanner.start(body);
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(this->_suite);
		// Раздел 7.4.3 RFC 5246: у обмена RSA обмена ключами сервера нет
		if(exchange == protect::exchange_t::RSA)
			// Выводим отказ разбора обмена ключами сервера
			return context::error_t::MESSAGE;
		// Если набор ведёт рукопожатие заранее разделённым ключом
		if(preshared(this->_suite)){
			// Подсказка опознавателя psk_identity_hint
			view_t hint;
			// Раздел 2 RFC 4279: подсказка идёт с двухбайтовой длиной
			if(scanner.vector(hint, 2) != field::error_t::NONE)
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Если подсказка непуста и вызов выбора ключа по подсказке задан потребителю
			if((hint.size > 0) && (this->_psk.advise != nullptr)){
				// Опознаватель и ключ, выбранные потребителем по подсказке
				vector <uint8_t> identity, key;
				// Если потребитель выбрал опознаватель и ключ заново
				if(this->_psk.advise(hint, identity, key, this->_psk.context)){
					// Раздел 5.3 RFC 4279: опознаватель до 128 байтов (пустой законен), ключ до 64 и непуст
					if((identity.size() > IDENTITY) || key.empty() || (key.size() > PRESHARED))
						// Выводим отказ обмена ключами
						return context::error_t::EXCHANGE;
					// Переносим выбранный опознаватель
					this->_identity = ::move(identity);
					// Если прежний ключ связи выработан
					if(!this->_preshared.empty())
						// Выполняем затирание прежнего ключа
						this->purge(this->_preshared.data(), this->_preshared.size());
					// Переносим выбранный ключ в укрытую память
					this->_preshared.assign(key.begin(), key.end());
					// Выполняем затирание ключа в обычной куче
					this->purge(key.data(), key.size());
				}
			}
			// Раздел 2 RFC 4279: у чистого PSK за подсказкой ничего не идёт
			if(exchange == protect::exchange_t::PSK)
				// Выводим итог: лишние байты - отказ разбора
				return ((scanner.left() > 0) ? context::error_t::MESSAGE : context::error_t::NONE);
		}
		// Группа обмена ключами, выбранная сервером
		extension::group_t group = extension::group_t::NONE;
		// Доля открытого ключа сервера: точка кривой либо ключ конечного поля
		view_t point;
		// Модуль и образующая поля обмена сервера: заполняются лишь у конечного поля
		view_t modulus, generator;
		// Смещение параметров обмена ключами в теле сообщения
		size_t start = 0;
		// Если набор ведёт обмен ключами конечного поля
		if(exchange == protect::exchange_t::DHE){
			// Открытый ключ сервера
			view_t share;
			// Раздел 7.4.3 RFC 5246: всякое поле идёт с двухбайтовой длиной
			if((scanner.vector(modulus, 2) != field::error_t::NONE) || (scanner.vector(generator, 2) != field::error_t::NONE) || (scanner.vector(share, 2) != field::error_t::NONE))
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Смещение параметров обмена ключами: у DHE подсказки заранее разделённого ключа не бывает, шесть байтов уходит на длины полей
			start = (scanner.offset() - (modulus.size + generator.size + share.size + 6));
			// Раздел 7.4.3 RFC 5246: параметры именованной группы RFC 7919 распознаются по значению
			group = finiteof(modulus, generator);
			// Если параметры задают именованную группу RFC 7919
			if(group != extension::group_t::NONE){
				// Признак того, что группа связью предлагалась
				bool offered = false;
				/**
				 * Выполняем перебор групп обмена ключами, предлагаемых связью
				 */
				for(size_t i = 0; (i < this->_groups.size()) && !offered; i++)
					// Запоминаем совпадение выбранной группы с предложенной
					offered = (group == this->_groups[i]);
				// Если группа вне предложения связи
				if(!offered)
					// Выводим отказ группы вне предложения связи
					return context::error_t::GROUP;
				// Доля сервера идёт длиною в модуль группы
				if(share.size != extension::finite(group))
					// Выводим отказ негодной длины доли
					return context::error_t::EXCHANGE;
			/**
			 * Раздел 4 RFC 7919: перечень групп клиента выбор сервера не сковывает - встречные
			 * серверы ведут поле своим порядком (modp RFC 3526 у openssl, свой dhparam), оттого
			 * неопознанные параметры принимаются полем своего состава: модуль 2048-8192 разрядов
			 * долей стола полей движка, доля - длиною в модуль
			 */
			} else if((modulus.size < 256) || (modulus.size > 1024) || (share.size != modulus.size))
				// Выводим отказ негодного поля обмена ключами
				return context::error_t::EXCHANGE;
			// Запоминаем долю открытого ключа сервера
			point = share;
		// Иначе набор ведёт обмен ключами на кривой
		} else {
			// Вид параметров обмена ключами
			uint32_t kind = 0;
			// Если вид параметров прочитать не удалось
			if(scanner.number(kind, 1) != field::error_t::NONE)
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Раздел 5.4 RFC 8422: связь ведёт лишь именованные кривые
			if(kind != 0x03)
				// Выводим отказ чужого вида параметров обмена
				return context::error_t::GROUP;
			// Именованная кривая обмена ключами
			uint32_t named = 0;
			// Если именованную кривую прочитать не удалось
			if(scanner.number(named, 2) != field::error_t::NONE)
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Если точку прочитать не удалось
			if(scanner.vector(point, 1) != field::error_t::NONE)
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Смещение параметров обмена ключами: за подсказкой у ECDHE_PSK
			start = (scanner.offset() - (4 + point.size));
			// Запоминаем кривую обмена ключами, выбранную сервером
			group = static_cast <extension::group_t> (named);
			// Признак того, что кривая связью предлагалась
			bool offered = false;
			/**
			 * Выполняем перебор кривых обмена ключами, предлагаемых связью
			 */
			for(size_t i = 0; (i < this->_groups.size()) && !offered; i++)
				// Запоминаем совпадение выбранной кривой с предложенной
				offered = (group == this->_groups[i]);
			// Раздел 5.4 RFC 8422: кривая обязана быть из предложенных и вестись связью; конечное поле точкой кривой не бывает
			if(!offered || !classic(group) || (extension::finite(group) > 0))
				// Выводим отказ кривой вне предложения связи
				return context::error_t::GROUP;
			/**
			 * Раздел 5.4 RFC 8422: точка идёт длиною своей кривой и лишь несжатой записью 0x04 у
			 * кривых NIST; сжатая либо чужая точка отвергается illegal_parameter прежде подписи -
			 * подпись над негодной точкой сверять незачем
			 */
			if(!classic(group) || !fitting(group, true) || (point.size != extension::length(group)) || (!montgomery(group) && (point.data[0] != 0x04)))
				// Выводим отказ негодной записи точки
				return context::error_t::EXCHANGE;
		}
		// Длина параметров обмена ключами
		const size_t width = scanner.offset();
		// Схема подписи обмена ключами
		uint32_t scheme = 0;
		// Подпись обмена ключами
		view_t signature;
		// Раздел 3.2 RFC 5489: у ECDHE_PSK подписи нет - за параметрами ничего не идёт
		if(exchange == protect::exchange_t::ECDHE_PSK){
			// Если за параметрами идут лишние байты
			if(scanner.left() > 0)
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
		// Если обмен подписывается сертификатом
		} else {
			// Если схему подписи прочитать не удалось
			if(!this->_ancient && (scanner.number(scheme, 2) != field::error_t::NONE))
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
			// Если подпись прочитать не удалось либо за нею идут лишние байты
			if((scanner.vector(signature, 2) != field::error_t::NONE) || (scanner.left() > 0))
				// Выводим отказ разбора обмена ключами сервера
				return context::error_t::MESSAGE;
		}
		// Отказ разбора обмена ключами
		context::error_t failure = context::error_t::NONE;
		// Если обмен подписывается сертификатом
		if(exchange != protect::exchange_t::ECDHE_PSK){
			// Накопитель, в который складывается подписанное содержимое
			vector <uint8_t> content;
			// Раздел 7.4.3 RFC 5246 и раздел 5.4 RFC 8422: подписаны случайные значения клиента и сервера и параметры обмена
			content.insert(content.end(), this->_random, this->_random + sizeof(this->_random));
			// Добавляем случайное значение сервера
			content.insert(content.end(), this->_foreign, this->_foreign + sizeof(this->_foreign));
			// Добавляем параметры обмена ключами
			content.insert(content.end(), body.data + start, body.data + width);
			// Выполняем проверку подписи обмена ключами ключом сертификата сервера
			failure = this->checking(static_cast <extension::scheme_t> (scheme), view_t(content.data(), content.size()), signature);
			// Если подпись обмена ключами не сошлась
			if(failure != context::error_t::NONE)
				// Выводим отказ проверки подписи обмена ключами
				return failure;
		}
		// Выполняем сброс мимолётных пар ключей своей стороны: доли издания 1.3 более не нужны
		this->_exchanges.clear();
		/**
		 * Поле своего состава ведётся по своему модулю и образующей: именованные группы - порядком таблицы
		 */
		if(group == extension::group_t::NONE){
			// Мимолётная пара ключей своей стороны по полю сервера
			exchange_t item;
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Секретный показатель длиною в модуль поля
				item.secret.assign(modulus.size, 0);
				// Открытый ключ длиною в модуль поля
				item.opened.assign(modulus.size, 0);
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			}
			// Выполняем порождение мимолётной пары ключей по модулю и образующей сервера
			if(!agreement::pairffdhe(modulus, generator, modulus.size, item.secret.data(), item.opened.data()))
				// Выводим отказ порождения пары ключей поля
				return context::error_t::EXCHANGE;
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Запоминаем мимолётную пару ключей своей стороны
				this->_exchanges.push_back(::move(item));
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			}
		// Именованная группа ведётся порядком таблицы движка
		} else {
			// Выполняем выработку мимолётной пары ключей на выбранной группе
			failure = this->exchange(group);
			// Если мимолётную пару ключей выработать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ выработки мимолётной пары ключей
				return failure;
		}
		// Место, в которое помещается общее значение обмена ключами
		uint8_t shared[agreement::MLKEM_SHARED + agreement::FFDHE_MOST];
		// Длина общего значения обмена ключами
		size_t length = 0;
		// Если сервер вёл поле своего состава: общее значение выводится по модулю и образующей сервера
		if(group == extension::group_t::NONE){
			// Выполняем выработку общего значения по модулю и образующей сервера
			if(!agreement::ffdhe(modulus, generator, view_t(this->_exchanges.back().secret.data(), this->_exchanges.back().secret.size()), point, shared)){
				// Выполняем затирание общего значения
				this->purge(shared, sizeof(shared));
				// Выводим отказ выработки общего значения
				return context::error_t::EXCHANGE;
			}
			// Длина общего значения - длина модуля поля
			length = modulus.size;
		// Иначе общее значение выводится порядком таблицы движка
		} else {
			// Выполняем выработку общего значения обмена ключами
			failure = this->agree(group, point, shared, length);
			// Если общее значение выработать не удалось
			if(failure != context::error_t::NONE){
				// Выполняем затирание общего значения
				this->purge(shared, sizeof(shared));
				// Выводим отказ выработки общего значения
				return failure;
			}
		}
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим общее значение обмена ключами
			this->_premaster.assign(shared, shared + length);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выполняем затирание общего значения
			this->purge(shared, sizeof(shared));
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		}
		// Выполняем затирание общего значения
		this->purge(shared, sizeof(shared));
		// Выводим успешность разбора обмена ключами сервера
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(...) {
		// Выводим отказ обмена ключами: чужое исключение из вызова потребителя PSK
		return context::error_t::EXCHANGE;
	}
}
/**
 * @brief Метод отправки запроса подлинности клиента издания TLS 1.2
 *
 * @return отказ отправки запроса подлинности клиента
 *
 */
context::error_t nts::internal::Engine::demanding() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Объект составителя тела запроса подлинности
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t outcome = builder.open(1);
		// Если место под длину видов сертификатов занято
		if(outcome == field::error_t::NONE)
			// Записываем виды сертификатов: раздел 7.4.4 RFC 5246 и раздел 5.5 RFC 8422
			outcome = builder.bytes(view_t(TYPES, sizeof(TYPES)));
		// Если виды сертификатов записаны
		if(outcome == field::error_t::NONE)
			// Проставляем длину видов сертификатов
			outcome = builder.close();
		// Если виды сертификатов составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности
			return translate(outcome, context::error_t::MESSAGE);
		// Схемы подписи, объявляемые запросом подлинности
		vector <extension::scheme_t> declared;
		/**
		 * Выполняем перебор схем подписи, признаваемых связью
		 */
		for(size_t i = 0; i < this->_signatures.size(); i++){
			// Изданию TLS 1.2 годны лишь классические схемы подписи
			if(legible(this->_signatures[i]))
				// Добавляем схему подписи в объявляемый перечень
				declared.push_back(this->_signatures[i]);
		}
		// Накопитель, в который складывается перечень схем подписи
		vector <uint8_t> schemes;
		// Отказ составления перечня схем подписи: запись та же, что у расширения
		context::error_t failure = (this->_ancient ? context::error_t::NONE : translate(extension::schemes(declared, schemes), context::error_t::MESSAGE));
		// Если перечень схем подписи составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления запроса подлинности
			return failure;
		// Записываем перечень схем подписи
		outcome = (this->_ancient ? field::error_t::NONE : builder.bytes(view_t(schemes.data(), schemes.size())));
		// Накопитель, в котором лежит перечень доверенных удостоверяющих центров
		vector <uint8_t> names;
		// Раздел 7.4.4 RFC 5246: перечень издателей записан так же, как тело расширения 47, - пустым без настройки потребителя
		if(!this->_trusted.empty()){
			// Отказ составления перечня
			failure = translate(extension::authorities(this->_trusted, names), context::error_t::MESSAGE);
			// Если перечень составить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ составления запроса подлинности
				return failure;
		}
		// Если перечень схем подписи записан и перечень издателей задан
		if((outcome == field::error_t::NONE) && !names.empty())
			// Записываем перечень издателей как есть
			outcome = builder.bytes(view_t(names.data(), names.size()));
		// Если перечень схем подписи записан, а перечень издателей не задан
		else if(outcome == field::error_t::NONE)
			// Занимаем место под длину перечня издателей
			outcome = builder.open(2);
		// Если место под длину пустого перечня издателей занято: издатель любой
		if((outcome == field::error_t::NONE) && names.empty())
			// Проставляем длину пустого перечня издателей
			outcome = builder.close();
		// Если запрос подлинности составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления запроса подлинности
			return translate(outcome, context::error_t::MESSAGE);
		// Выводим итог отправки запроса подлинности клиента
		return this->send(handshake::type_t::REQUEST, builder.data());
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятого запроса подлинности клиента издания TLS 1.2
 *
 * @param body тело принятого сообщения запроса подлинности
 * @return     отказ разбора запроса подлинности
 *
 */
context::error_t nts::internal::Engine::demanded(const view_t & body) noexcept {
	// Объект разборщика тела запроса подлинности
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело запроса подлинности
	scanner.start(body);
	// Виды сертификатов, запрашиваемых сервером
	view_t types;
	// Раздел 7.4.4 RFC 5246: виды сертификатов с однобайтовой длиной, непустые
	if((scanner.vector(types, 1) != field::error_t::NONE) || (types.size == 0))
		// Выводим отказ разбора запроса подлинности
		return context::error_t::MESSAGE;
	// Смещение перечня схем подписи вместе с его длиной в теле запроса
	const size_t start = scanner.offset();
	// Перечень схем подписи, признаваемых сервером
	view_t schemes;
	// Если перечень схем подписи прочитать не удалось
	if(!this->_ancient && (scanner.vector(schemes, 2) != field::error_t::NONE))
		// Выводим отказ разбора запроса подлинности
		return context::error_t::MESSAGE;
	// Место перечня издателей в теле запроса
	const size_t place = scanner.offset();
	// Перечень издателей, признаваемых сервером
	view_t authorities;
	// Если перечень издателей прочитать не удалось либо за ним идут лишние байты
	if((scanner.vector(authorities, 2) != field::error_t::NONE) || (scanner.left() > 0))
		// Выводим отказ разбора запроса подлинности
		return context::error_t::MESSAGE;
	// Выполняем сброс перечня доверенных центров собеседника
	this->_authorities.clear();
	// Раздел 7.4.4 RFC 5246: непустой перечень издателей разбирается как тело расширения 47 и хранится как записан
	if(authorities.size > 0){
		// Отказ разбора перечня
		const context::error_t named = translate(extension::authorities(view_t(body.data + place, 2 + authorities.size), this->_authorities), context::error_t::MESSAGE);
		// Если перечень разобрать не удалось
		if(named != context::error_t::NONE)
			// Выводим отказ разбора запроса подлинности
			return named;
	}
	/**
	 * Раздел 7.4.4 RFC 5246: перечень схем с двухбайтовой длиной записан в запросе так же,
	 * как в теле расширения signature_algorithms, и читается прямо с места, без переноса
	 */
	const context::error_t failure = (this->_ancient ? context::error_t::NONE : translate(extension::schemes(view_t(body.data + start, 2 + schemes.size), this->_schemes), context::error_t::MESSAGE));
	// Если перечень схем подписи разобрать не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ разбора запроса подлинности
		return failure;
	/**
	 * Раздел 7.4.4 RFC 5246: без единой схемы подписи клиенту нечем подписать владение
	 * ключом; перечень издателей связь не толкует - сертификат выбирает потребитель
	 */
	if(!this->_ancient && this->_schemes.empty())
		// Выводим отказ отсутствия схем подписи
		return context::error_t::SCHEME;
	// Выводим успешность разбора запроса подлинности
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки обмена ключами клиента издания TLS 1.2
 *
 * @return отказ отправки обмена ключами клиента
 *
 */
context::error_t nts::internal::Engine::exchanging() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(this->_suite);
		// Объект составителя тела обмена ключами клиента
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t outcome = field::error_t::NONE;
		// Отказ связи
		context::error_t failure = context::error_t::NONE;
		// Если набор ведёт рукопожатие заранее разделённым ключом
		if(preshared(this->_suite)){
			// Если ключ по подсказке не выбран: берутся настроенные потребителем (опознаватель вправе быть пустым)
			if(this->_preshared.empty()){
				// Переносим настроенный опознаватель
				this->_identity = this->_psk.identity;
				// Переносим настроенный ключ в укрытую память
				this->_preshared.assign(this->_psk.key.begin(), this->_psk.key.end());
			}
			// Раздел 2 RFC 4279: без ключа рукопожатие вести нечем
			if(this->_preshared.empty())
				// Выводим отказ обмена ключами
				return context::error_t::EXCHANGE;
			// Раздел 2 RFC 4279: опознаватель идёт первым полем с двухбайтовой длиной
			outcome = builder.open(2);
			// Если место под длину опознавателя занято
			if(outcome == field::error_t::NONE)
				// Записываем опознаватель
				outcome = builder.bytes(view_t(this->_identity.data(), this->_identity.size()));
			// Если опознаватель записан
			if(outcome == field::error_t::NONE)
				// Проставляем длину опознавателя
				outcome = builder.close();
			// Если опознаватель составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления обмена ключами клиента
				return translate(outcome, context::error_t::MESSAGE);
		}
		// Если набор шифрования требует мимолётных ключей
		if(ephemeral(this->_suite)){
			// Если мимолётной пары ключей либо общего значения обмена нет
			if(this->_exchanges.empty() || this->_premaster.empty())
				// Выводим отказ отсутствия ключа обмена
				return context::error_t::EXCHANGE;
			// Открытая часть мимолётной пары ключей своей стороны
			const vector <uint8_t> & opened = this->_exchanges.back().opened;
			// Если набор ведёт обмен ключами конечного поля
			if(exchange == protect::exchange_t::DHE){
				// Раздел 7.4.7.2 RFC 5246: открытый ключ идёт с двухбайтовой длиной
				if(opened.empty() || (opened.size() > 0xFFFF))
					// Выводим отказ негодной длины доли
					return context::error_t::EXCHANGE;
				// Занимаем место под длину открытого ключа
				outcome = builder.open(2);
				// Если место под длину открытого ключа занято
				if(outcome == field::error_t::NONE)
					// Записываем открытый ключ своей мимолётной пары
					outcome = builder.bytes(view_t(opened.data(), opened.size()));
				// Если открытый ключ записан
				if(outcome == field::error_t::NONE)
					// Проставляем длину открытого ключа
					outcome = builder.close();
			// Иначе набор ведёт обмен ключами на кривой
			} else {
				// Раздел 5.7 RFC 8422: точка идёт с однобайтовой длиной
				if(opened.empty() || (opened.size() > 255))
					// Выводим отказ негодной длины точки
					return context::error_t::EXCHANGE;
				// Занимаем место под длину точки
				outcome = builder.open(1);
				// Если место под длину точки занято
				if(outcome == field::error_t::NONE)
					// Записываем точку своей мимолётной пары
					outcome = builder.bytes(view_t(opened.data(), opened.size()));
				// Если точка записана
				if(outcome == field::error_t::NONE)
					// Проставляем длину точки
					outcome = builder.close();
			}
			// Если обмен ключами клиента составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления обмена ключами клиента
				return translate(outcome, context::error_t::MESSAGE);
		// Если обмен ключами идёт шифрованием RSA
		} else if(exchange == protect::exchange_t::RSA) {
			// Если цепочка сертификатов сервера пуста
			if(this->_peer.empty())
				// Выводим отказ отсутствия сертификата сервера
				return context::error_t::CERTIFICATE;
			// Объект разбора сертификата сервера
			x509::certificate_t leaf;
			// Отказ разбора сертификата сервера
			failure = translate(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())), context::error_t::CERTIFICATE);
			// Если сертификат сервера разобрать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ разбора сертификата сервера
				return failure;
			// Объект открытого ключа RSA сервера
			sign::rsa_t rsa;
			// Раздел 7.4.7.1 RFC 5246: ключ берётся из сертификата сервера; чужой алгоритм либо негодная запись - непригодный сертификат
			if((leaf.key().algorithm.compare(RSA_KEY) != 0) || (leaf.key().unused != 0) || !rsa.decode(leaf.key().key) || !rsa.ready() || rsa.secret())
				// Выводим отказ непригодности сертификата сервера
				return context::error_t::CERTIFICATE;
			// Раздел 7.4.7.1 RFC 5246: общее значение - издание из приветствия клиента и 46 случайных байтов
			this->_premaster.assign(PREMASTER, 0);
			// Записываем старший байт объявленного издания
			this->_premaster[0] = static_cast <uint8_t> ((this->_claimed >> 8) & 0xFF);
			// Записываем младший байт объявленного издания
			this->_premaster[1] = static_cast <uint8_t> (this->_claimed & 0xFF);
			// Если случайную часть общего значения выработать не удалось
			if(!entropy::bytes(this->_premaster.data() + 2, PREMASTER - 2))
				// Выводим отказ выработки общего значения
				return context::error_t::EXCHANGE;
			// Накопитель, в который помещается зашифрованное общее значение длиною в модуль ключа
			vector <uint8_t> encrypted(rsa.size(), 0);
			// Раздел 7.4.7.1 RFC 5246: общее значение шифруется по RSAES-PKCS1-v1_5
			if(!rsa.encrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(this->_premaster.data(), this->_premaster.size()), encrypted.data()))
				// Выводим отказ шифрования общего значения
				return context::error_t::EXCHANGE;
			// Раздел 7.4.7.1 RFC 5246: зашифрованное значение идёт с двухбайтовой длиной
			outcome = builder.open(2);
			// Если место под длину занято
			if(outcome == field::error_t::NONE)
				// Записываем зашифрованное общее значение
				outcome = builder.bytes(view_t(encrypted.data(), encrypted.size()));
			// Если зашифрованное значение записано
			if(outcome == field::error_t::NONE)
				// Проставляем длину зашифрованного значения
				outcome = builder.close();
			// Если обмен ключами клиента составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления обмена ключами клиента
				return translate(outcome, context::error_t::MESSAGE);
		}
		// Если набор ведёт рукопожатие заранее разделённым ключом: общее значение по разделу 2 RFC 4279 и разделу 3.2 RFC 5489
		if(preshared(this->_suite)){
			// Первая половина общего значения: общее значение кривой у ECDHE_PSK, нули длиною в ключ у PSK
			sys::bytes_t other = ((exchange == protect::exchange_t::ECDHE_PSK) ? this->_premaster : sys::bytes_t(this->_preshared.size(), 0));
			// Если прежнее общее значение выработано
			if(!this->_premaster.empty())
				// Выполняем затирание прежнего общего значения
				this->purge(this->_premaster.data(), this->_premaster.size());
			// Составляем общее значение обмена: len(other) ‖ other ‖ len(psk) ‖ psk
			outcome = premastering(view_t(other.data(), other.size()), view_t(this->_preshared.data(), this->_preshared.size()), this->_premaster);
			// Выполняем затирание первой половины
			this->purge(other.data(), other.size());
			// Если общее значение составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления общего значения
				return translate(outcome, context::error_t::MESSAGE);
		}
		// Выполняем отправку обмена ключами клиента
		failure = this->send(handshake::type_t::PREMASTER, builder.data());
		// Если обмен ключами клиента отправить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки обмена ключами клиента
			return failure;
		// Выполняем вывод главного секрета и ключевого материала связи
		const context::error_t expanded = this->expanding(view_t(this->_premaster.data(), this->_premaster.size()));
		// Выполняем затирание общего значения обмена ключами
		this->purge(this->_premaster.data(), this->_premaster.size());
		// Выполняем сброс общего значения обмена ключами
		this->_premaster.clear();
		// Выводим итог вывода ключевого материала связи
		return expanded;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора принятого обмена ключами клиента издания TLS 1.2
 *
 * @param body тело принятого сообщения обмена ключами клиента
 * @return     отказ разбора обмена ключами клиента
 *
 */
context::error_t nts::internal::Engine::exchanged(const view_t & body) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Объект разборщика тела обмена ключами клиента
		field::scanner_t scanner;
		// Устанавливаем разбираемое тело обмена ключами
		scanner.start(body);
		// Способ обмена ключами набора
		const protect::exchange_t exchange = protect::exchange(this->_suite);
		// Отказ разбора обмена ключами
		context::error_t failure = context::error_t::NONE;
		// Если набор ведёт рукопожатие заранее разделённым ключом
		if(preshared(this->_suite)){
			// Опознаватель, предъявленный клиентом
			view_t identity;
			// Раздел 2 RFC 4279: опознаватель идёт первым полем с двухбайтовой длиной
			if(scanner.vector(identity, 2) != field::error_t::NONE)
				// Выводим отказ разбора обмена ключами клиента
				return context::error_t::MESSAGE;
			// Раздел 5.3 RFC 4279: опознаватель не длиннее 128 байтов; пустой законен (раздел 2 RFC 4279)
			if(identity.size > IDENTITY)
				// Выводим отказ негодного опознавателя
				return context::error_t::EXCHANGE;
			// Запоминаем опознаватель клиента
			this->_identity.assign(identity.data, identity.data + identity.size);
			// Если прежний ключ связи выработан
			if(!this->_preshared.empty())
				// Выполняем затирание прежнего ключа
				this->purge(this->_preshared.data(), this->_preshared.size());
			// Выполняем сброс прежнего ключа
			this->_preshared.clear();
			// Если вызов ключа по опознавателю не задан: набор не был бы выбран, заслон стоит обороною
			if(this->_psk.respond == nullptr)
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			// Ключ, выданный потребителем: вызов принимает обычный набор, укрытая память ему не подставляется
			vector <uint8_t> issued;
			// Признак того, что опознаватель клиенту известен и ключ выдан
			const bool known = this->_psk.respond(identity, issued, this->_psk.context);
			// Переносим выданный ключ в укрытую память
			this->_preshared.assign(issued.begin(), issued.end());
			// Выполняем затирание ключа в обычной куче
			this->purge(issued.data(), issued.size());
			// Раздел 5.3 RFC 4279: выданный ключ не длиннее 64 байтов и непуст - иное есть отказ настроек потребителя, а не неизвестный опознаватель
			if(known && (this->_preshared.empty() || (this->_preshared.size() > PRESHARED))){
				// Выполняем затирание негодного ключа
				this->purge(this->_preshared.data(), this->_preshared.size());
				// Выполняем сброс негодного ключа
				this->_preshared.clear();
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			}
			/**
			 * Раздел 2 RFC 4279: неизвестный опознаватель сервер вправе отвергнуть извещением
			 * unknown_psk_identity либо продолжить случайным ключом, чтобы рукопожатие
			 * оборвалось на завершении decrypt_error, не выдавая, что опознаватель неизвестен
			 */
			if(!known){
				// Если неизвестный опознаватель отвечается извещением
				if(this->_psk.disclose)
					// Выводим отказ неизвестного опознавателя
					return context::error_t::IDENTITY;
				// Занимаем место под случайный ключ
				this->_preshared.assign(PRESHARED / 2, 0);
				// Если случайный ключ выработать не удалось
				if(!entropy::bytes(this->_preshared.data(), this->_preshared.size()))
					// Выводим отказ выработки ключа
					return context::error_t::EXCHANGE;
			}
		}
		// Общее значение обмена: общее значение кривой, конечного поля либо расшифрованное значение RSA
		vector <uint8_t> other;
		// Если набор шифрования требует мимолётных ключей
		if(ephemeral(this->_suite)){
			// Доля открытого ключа клиента
			view_t share;
			// Длина поля длины доли: два байта у конечного поля, один у точки кривой
			const size_t width = ((exchange == protect::exchange_t::DHE) ? 2 : 1);
			// Раздел 7.4.7.2 RFC 5246 и раздел 5.7 RFC 8422: доля со своей длиной без лишних байтов
			if((scanner.vector(share, width) != field::error_t::NONE) || (scanner.left() > 0))
				// Выводим отказ разбора обмена ключами клиента
				return context::error_t::MESSAGE;
			// Место, в которое помещается общее значение обмена ключами
			uint8_t shared[agreement::MLKEM_SHARED + agreement::FFDHE_MOST];
			// Длина общего значения обмена ключами
			size_t length = 0;
			// Выполняем выработку общего значения обмена ключами на группе, выбранной сервером
			failure = this->agree(this->_group, share, shared, length);
			// Если общее значение выработано
			if(failure == context::error_t::NONE)
				// Переносим общее значение обмена
				other.assign(shared, shared + length);
			// Выполняем затирание общего значения
			this->purge(shared, sizeof(shared));
			// Если общее значение выработать не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ выработки общего значения
				return failure;
		// Если обмен ключами идёт шифрованием RSA
		} else if(exchange == protect::exchange_t::RSA) {
			// Зашифрованное общее значение
			view_t encrypted;
			// Раздел 7.4.7.1 RFC 5246: зашифрованное значение с двухбайтовой длиной без лишних байтов
			if((scanner.vector(encrypted, 2) != field::error_t::NONE) || (scanner.left() > 0))
				// Выводим отказ разбора обмена ключами клиента
				return context::error_t::MESSAGE;
			// Подготовленный секретный ключ своей стороны
			const keys::signer_t * signer = nullptr;
			// Отказ подготовки секретного ключа своей стороны
			failure = this->signer(signer);
			// Если секретный ключ своей стороны подготовить не удалось
			if(failure != context::error_t::NONE)
				// Выводим отказ подготовки секретного ключа
				return failure;
			// Если подготовленный ключ - не ключ RSA
			if(signer->kind() != keys::kind_t::RSA)
				// Выводим отказ установки секретного ключа
				return context::error_t::SIGNATURE;
			// Модуль секретного ключа RSA подготовленного ключа
			const sign::rsa_t & rsa = signer->rsa();
			/**
			 * Раздел 7.4.7.1 RFC 5246: защита от Бляйхенбахера - случайное значение
			 * вырабатывается заранее, а при всяком отказе расшифрования, негодной длине либо
			 * несовпадении издания оно подменяет расшифрованное; выбор идёт масками, без
			 * ветвления по содержимому, и рукопожатие обрывается лишь на завершении
			 */
			other.assign(PREMASTER, 0);
			// Если случайное значение выработать не удалось
			if(!entropy::bytes(other.data(), other.size()))
				// Выводим отказ выработки общего значения
				return context::error_t::EXCHANGE;
			// Место, в которое помещается расшифрованное значение: не меньше модуля ключа
			vector <uint8_t> decrypted(rsa.size() + PREMASTER, 0);
			// Длина расшифрованного значения
			size_t length = 0;
			// Признак успешности расшифрования: длина шифртекста, ключ и дополнение сошлись; разбор дополнения идёт за постоянное время
			const bool opened = rsa.decrypt(sign::scheme_t::PKCS1, digest::hash_t::NONE, encrypted, decrypted.data(), length);
			// Маска годности: расшифрование удалось
			uint8_t mask = static_cast <uint8_t> (0 - static_cast <uint8_t> (opened));
			// Учитываем длину расшифрованного значения: ровно сорок восемь байтов
			mask = static_cast <uint8_t> (mask & static_cast <uint8_t> (0 - static_cast <uint8_t> (length == PREMASTER)));
			// Различие издания расшифрованного значения с объявленным приветствием клиента
			const uint8_t diff = static_cast <uint8_t> ((decrypted[0] ^ static_cast <uint8_t> ((this->_claimed >> 8) & 0xFF)) | (decrypted[1] ^ static_cast <uint8_t> (this->_claimed & 0xFF)));
			// Учитываем совпадение издания
			mask = static_cast <uint8_t> (mask & static_cast <uint8_t> (0 - static_cast <uint8_t> (diff == 0)));
			/**
			 * Выполняем выбор общего значения под маской: годное расшифрованное либо случайное
			 */
			for(size_t i = 0; i < PREMASTER; i++)
				// Выбираем очередной байт под маской
				other[i] = static_cast <uint8_t> ((decrypted[i] & mask) | (other[i] & static_cast <uint8_t> (~mask)));
			// Выполняем затирание расшифрованного значения
			this->purge(decrypted.data(), decrypted.size());
		// Если набор чистого PSK: за опознавателем ничего не идёт
		} else if(scanner.left() > 0)
			// Выводим отказ разбора обмена ключами клиента
			return context::error_t::MESSAGE;
		// Если набор ведёт рукопожатие заранее разделённым ключом: общее значение по разделу 2 RFC 4279 и разделу 3.2 RFC 5489
		if(preshared(this->_suite)){
			// Если первая половина общего значения не выработана: нули длиною в ключ
			if(exchange == protect::exchange_t::PSK)
				// Заполняем первую половину нулями
				other.assign(this->_preshared.size(), 0);
			// Составленное общее значение обмена: в укрытой памяти
			sys::bytes_t composed;
			// Составляем общее значение обмена: len(other) ‖ other ‖ len(psk) ‖ psk
			const field::error_t outcome = premastering(view_t(other.data(), other.size()), view_t(this->_preshared.data(), this->_preshared.size()), composed);
			// Выполняем затирание первой половины
			this->purge(other.data(), other.size());
			// Если общее значение составить не удалось
			if(outcome != field::error_t::NONE)
				// Выводим отказ составления общего значения
				return translate(outcome, context::error_t::MESSAGE);
			// Переносим составленное общее значение: распределители разные, перенос идёт копией
			other.assign(composed.begin(), composed.end());
			// Выполняем затирание прежней первой половины, ушедшей обменом
			this->purge(composed.data(), composed.size());
		}
		// Выполняем вывод главного секрета и ключевого материала связи
		failure = this->expanding(view_t(other.data(), other.size()));
		// Выполняем затирание общего значения
		this->purge(other.data(), other.size());
		// Выводим итог разбора обмена ключами клиента
		return failure;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(...) {
		// Выводим отказ обмена ключами: чужое исключение из вызова потребителя PSK
		return context::error_t::EXCHANGE;
	}
}
/**
 * @brief Метод вывода главного секрета и ключевого материала издания TLS 1.2
 *
 * @param premaster общее значение обмена ключами сторон
 * @return          отказ вывода ключевого материала
 *
 */
context::error_t nts::internal::Engine::expanding(const view_t & premaster) noexcept {
	// Длина хеша переписки рукопожатия по изданию связи
	size_t width = 0;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_WIDEST];
	// Раздел 4 RFC 7627: хеш переписки берётся с обменом ключами клиента включительно
	if(!this->digesting(transcript, width))
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::SCHEDULE;
	/**
	 * Решение 16: без расширения RFC 7627 главный секрет выводится по разделу 8.1 RFC 5246 -
	 * меткой «master secret» и затравкой из случайных значений клиента и сервера
	 */
	if(!this->_extending){
		// Затравка обычного главного секрета: случайные значения клиента и сервера
		uint8_t seed[64];
		// Записываем случайное значение клиента
		::memcpy(seed, (this->_server ? this->_foreign : this->_random), 32);
		// Записываем случайное значение сервера
		::memcpy(seed + 32, (this->_server ? this->_random : this->_foreign), 32);
		// Метка выработки обычного главного секрета
		const view_t master(reinterpret_cast <const uint8_t *> (MASTER), ::strlen(MASTER));
		// Раздел 8.1 RFC 5246: главный секрет из общего значения меткой и случайными значениями
		if(!this->sequencing(premaster, master, view_t(seed, sizeof(seed)), this->_keys->master, sizeof(this->_keys->master)))
			// Выводим отказ вывода главного секрета
			return context::error_t::SCHEDULE;
		// Вызываем журнал секретов связи
		this->keylog("CLIENT_RANDOM", view_t(this->_keys->master, sizeof(this->_keys->master)));
		// Выводим итог вывода ключевого материала из главного секрета
		return this->keying();
	}
	// Метка выработки расширенного главного секрета
	const view_t extended(reinterpret_cast <const uint8_t *> (EXTENDED), ::strlen(EXTENDED));
	// Раздел 4 RFC 7627: главный секрет из общего значения меткой и хешем переписки
	if(!this->sequencing(premaster, extended, view_t(transcript, width), this->_keys->master, sizeof(this->_keys->master)))
		// Выводим отказ вывода главного секрета
		return context::error_t::SCHEDULE;
	// Вызываем журнал секретов связи
	this->keylog("CLIENT_RANDOM", view_t(this->_keys->master, sizeof(this->_keys->master)));
	// Выводим итог вывода ключевого материала из главного секрета
	return this->keying();
}
/**
 * @brief Метод отправки подписи владения ключом клиента издания TLS 1.2
 *
 * @return отказ отправки подписи владения ключом
 *
 */
context::error_t nts::internal::Engine::attesting() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Схема подписи владения ключом
		extension::scheme_t scheme = extension::scheme_t::NONE;
		// Накопитель, в который складывается подпись владения ключом
		vector <uint8_t> signature;
		// Раздел 7.4.8 RFC 5246: подписываются все сообщения рукопожатия подряд до этого
		context::error_t failure = this->signing(view_t(this->_history.data(), this->_history.size()), scheme, signature);
		// Если подпись владения ключом выработать не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return failure;
		// Объект составителя тела подписи владения ключом
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t outcome = (this->_ancient ? field::error_t::NONE : builder.number(static_cast <uint32_t> (scheme), 2));
		// Если схема подписи записана
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину подписи
			outcome = builder.open(2);
		// Если место под длину подписи занято
		if(outcome == field::error_t::NONE)
			// Записываем подпись владения ключом
			outcome = builder.bytes(view_t(signature.data(), signature.size()));
		// Если подпись записана
		if(outcome == field::error_t::NONE)
			// Проставляем длину подписи
			outcome = builder.close();
		// Если подпись владения ключом составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления подписи владения ключом
			return translate(outcome, context::error_t::MESSAGE);
		// Выводим итог отправки подписи владения ключом
		return this->send(handshake::type_t::VERIFY, builder.data());
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки принятой подписи владения ключом клиента издания TLS 1.2
 *
 * @param body тело принятого сообщения подписи владения ключом
 * @return     отказ проверки подписи владения ключом
 *
 */
context::error_t nts::internal::Engine::attested(const view_t & body) noexcept {
	// Объект разборщика тела подписи владения ключом
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело подписи владения ключом
	scanner.start(body);
	// Схема подписи владения ключом
	uint32_t scheme = 0;
	// Если схему подписи прочитать не удалось
	if(!this->_ancient && (scanner.number(scheme, 2) != field::error_t::NONE))
		// Выводим отказ разбора подписи владения ключом
		return context::error_t::MESSAGE;
	// Подпись владения ключом
	view_t signature;
	// Если подпись прочитать не удалось либо за нею идут лишние байты
	if((scanner.vector(signature, 2) != field::error_t::NONE) || (scanner.left() > 0))
		// Выводим отказ разбора подписи владения ключом
		return context::error_t::MESSAGE;
	// Раздел 7.4.8 RFC 5246: подписаны все сообщения рукопожатия подряд до этого
	return this->checking(static_cast <extension::scheme_t> (scheme), view_t(this->_history.data(), this->_history.size()), signature);
}
/**
 * @brief Метод отправки смены набора шифрования издания TLS 1.2
 *
 * @return отказ отправки смены набора шифрования
 *
 */
context::error_t nts::internal::Engine::switching() noexcept {
	// Раздел 7.1 RFC 5246: тело смены набора шифрования - единственный байт со значением один
	const uint8_t change[1] = {0x01};
	// Если ключевой материал отправки не установлен
	if(!this->_output.ready())
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Выполняем складывание смены набора шифрования в накопитель открытой записью
	const context::error_t failure = this->emit(record::type_t::CHANGE, view_t(change, sizeof(change)));
	// Если смену набора шифрования сложить не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ отправки смены набора шифрования
		return failure;
	// Раздел 4.1 RFC 6347: поверх дейтаграмм смена набора шифрования открывает первую пору записи
	if(this->_transport == context::transport_t::DATAGRAMS){
		// Место ключевого материала своей стороны
		const size_t own = (this->_server ? 1 : 0);
		// Отказ заведения поры ключей записи
		const context::error_t adopted = this->_flight.adopt(false, this->_suite, view_t(this->_keys->key[own], protect::key(this->_suite)), view_t(this->_keys->vector[own], protect::block(this->_suite)), view_t(this->_keys->stamp[own], digest::length(protect::mac(this->_suite))), this->_etm);
		// Если пору ключей завести не удалось
		if(adopted != context::error_t::NONE)
			// Выводим отказ заведения поры ключей
			return adopted;
	}
	// Запоминаем, что свои записи отныне защищаются
	this->_sealing = true;
	// Выводим успешность отправки смены набора шифрования
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки завершения рукопожатия издания TLS 1.2
 *
 * @return отказ отправки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::finishing() noexcept {
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_WIDEST];
	// Длина хеша переписки рукопожатия по изданию связи
	size_t width = 0;
	// Если хеш переписки рукопожатия получить не удалось
	if(!this->digesting(transcript, width))
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Метка завершения рукопожатия своей стороны
	const char * label = (this->_server ? SERVER_FINISHED : CLIENT_FINISHED);
	// Место, в которое помещается завершение рукопожатия
	uint8_t completion[VERIFIED];
	// Раздел 7.4.9 RFC 5246: завершение из главного секрета меткой стороны и хешем переписки
	if(!this->sequencing(view_t(this->_keys->master, sizeof(this->_keys->master)), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(transcript, width), completion, sizeof(completion)))
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим итог отправки завершения рукопожатия
	return this->send(handshake::type_t::FINISHED, view_t(completion, sizeof(completion)));
}
/**
 * @brief Метод проверки принятого завершения рукопожатия издания TLS 1.2
 *
 * @param body тело принятого сообщения завершения рукопожатия
 * @return     отказ проверки завершения рукопожатия
 *
 */
context::error_t nts::internal::Engine::finished(const view_t & body) noexcept {
	// Раздел 7.4.9 RFC 5246: завершение занимает ровно двенадцать байтов
	if(body.size != VERIFIED)
		// Выводим отказ схождения завершения рукопожатия
		return context::error_t::COMPLETION;
	// Место, в которое помещается хеш переписки рукопожатия
	uint8_t transcript[schedule::SCHEDULE_WIDEST];
	// Длина хеша переписки рукопожатия по изданию связи
	size_t width = 0;
	// Если хеш переписки рукопожатия получить не удалось
	if(!this->digesting(transcript, width))
		// Выводим отказ ведения переписки рукопожатия
		return context::error_t::MESSAGE;
	// Метка завершения рукопожатия собеседника
	const char * label = (this->_server ? CLIENT_FINISHED : SERVER_FINISHED);
	// Место, в которое помещается ожидаемое завершение рукопожатия
	uint8_t completion[VERIFIED];
	// Раздел 7.4.9 RFC 5246: ожидаемое завершение из главного секрета меткой собеседника
	if(!this->sequencing(view_t(this->_keys->master, sizeof(this->_keys->master)), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(transcript, width), completion, sizeof(completion)))
		// Выводим отказ выработки завершения рукопожатия
		return context::error_t::COMPLETION;
	// Сличение ведётся за постоянное время: время сличения не выдаёт ожидаемого завершения
	if(!message::compare(body, view_t(completion, sizeof(completion))))
		// Выводим отказ схождения завершения рукопожатия
		return context::error_t::COMPLETION;
	// Выводим успешность проверки завершения рукопожатия
	return context::error_t::NONE;
}
/**
 * @brief Метод вывода ключевого материала издания TLS 1.2 из главного секрета
 *
 * @return отказ вывода ключевого материала
 *
 */
context::error_t nts::internal::Engine::keying() noexcept {
	// Хеш набора шифрования связи
	const digest::hash_t algorithm = protect::hash(this->_suite);
	// Длина ключа набора шифрования
	const size_t width = protect::key(this->_suite);
	// Длина вектора замены набора шифрования: ноль у наборов CBC с явным вектором
	const size_t size = protect::block(this->_suite);
	// Длина ключа имитовставки набора: ноль у наборов AEAD
	const size_t stamp = digest::length(protect::mac(this->_suite));
	// Если набор шифрования неизвестен
	if((width == 0) || (algorithm == digest::hash_t::NONE))
		// Выводим отказ неизвестности набора шифрования
		return context::error_t::SUITE;
	// Раздел 6.3 RFC 5246: затравкой ключевого материала идут случайные значения сервера и клиента
	uint8_t seed[64];
	// Записываем случайное значение сервера
	::memcpy(seed, (this->_server ? this->_random : this->_foreign), 32);
	// Записываем случайное значение клиента
	::memcpy(seed + 32, (this->_server ? this->_foreign : this->_random), 32);
	// Метка выработки ключевого материала
	const view_t expansion(reinterpret_cast <const uint8_t *> (EXPANSION), ::strlen(EXPANSION));
	// Место, в которое помещается ключевой материал: ключи имитовставки, ключи и векторы обеих сторон
	uint8_t material[(protect::PROTECT_MAC + protect::PROTECT_KEY + protect::PROTECT_VECTOR) * 2];
	// Раздел 6.3 RFC 5246: ключевой материал из главного секрета меткой и затравкой
	if(!this->sequencing(view_t(this->_keys->master, sizeof(this->_keys->master)), expansion, view_t(seed, sizeof(seed)), material, (stamp + width + size) * 2)){
		// Выполняем затирание ключевого материала
		this->purge(material, sizeof(material));
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	}
	/**
	 * Раздел 6.3 RFC 5246: порядок ключевого материала - ключ имитовставки клиента, ключ
	 * имитовставки сервера, ключ клиента, ключ сервера, вектор клиента, вектор сервера;
	 * имитовставок у наборов AEAD нет (RFC 5288, RFC 7905), векторов у наборов CBC нет
	 */
	const view_t clientMac(material, stamp), serverMac(material + stamp, stamp);
	// Ключи шифрования сторон
	const view_t clientKey(material + (stamp * 2), width), serverKey(material + (stamp * 2) + width, width);
	// Векторы замены сторон
	const view_t clientVector(material + (stamp * 2) + (width * 2), size), serverVector(material + (stamp * 2) + (width * 2) + size, size);
	// Раздел 4.1 RFC 6347: поверх дейтаграмм ключи ставятся порам по сменам набора шифрования, а до того хранятся связью
	if(this->_transport == context::transport_t::DATAGRAMS){
		// Запоминаем ключ клиента
		::memcpy(this->_keys->key[0], clientKey.data, width);
		// Запоминаем ключ сервера
		::memcpy(this->_keys->key[1], serverKey.data, width);
		// Если векторы замены положены набору
		if(size > 0){
			// Запоминаем вектор замены клиента
			::memcpy(this->_keys->vector[0], clientVector.data, size);
			// Запоминаем вектор замены сервера
			::memcpy(this->_keys->vector[1], serverVector.data, size);
		}
		// Если ключи имитовставки положены набору
		if(stamp > 0){
			// Запоминаем ключ имитовставки клиента
			::memcpy(this->_keys->stamp[0], clientMac.data, stamp);
			// Запоминаем ключ имитовставки сервера
			::memcpy(this->_keys->stamp[1], serverMac.data, stamp);
		}
	}
	// Признак успешности установки ключевого материала обеим защитам
	bool ok = this->_output.start(this->_suite, (this->_server ? serverKey : clientKey), (this->_server ? serverVector : clientVector), (this->_server ? serverMac : clientMac));
	// Если ключевой материал отправки установлен
	if(ok)
		// Устанавливаем ключевой материал приёма
		ok = this->_input.start(this->_suite, (this->_server ? clientKey : serverKey), (this->_server ? clientVector : serverVector), (this->_server ? clientMac : serverMac));
	// Выполняем затирание ключевого материала
	this->purge(material, sizeof(material));
	// Если ключевой материал установить не удалось
	if(!ok)
		// Выводим отказ установки ключевого материала
		return context::error_t::SCHEDULE;
	// Раздел 3 RFC 7366: согласованный порядок «шифрование, затем имитовставка» ставится обеим защитам
	this->_output.etm(this->_etm);
	// Устанавливаем порядок защите приёма
	this->_input.etm(this->_etm);
	// Выводим успешность вывода ключевого материала
	return context::error_t::NONE;
}
/**
 * @brief Метод отправки билета сеанса NewSessionTicket сервером
 *
 * @return отказ отправки билета сеанса
 *
 */
context::error_t nts::internal::Engine::granting() noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Накопитель, в который помещаются октеты билета сеанса
		vector <uint8_t> ticket;
		// Состояние связи, запечатываемое в билет: главный секрет затирается им самим
		ticket::state_t state;
		// Устанавливаем набор шифрования связи
		state.suite = this->_suite;
		// Переносим главный секрет связи
		::memcpy(state.master, this->_keys->master, sizeof(state.master));
		// Раздел 3.1 RFC 7366: билет помнит порядок защиты записей выдавшей связи
		state.etm = this->_etm;
		// Издание выдавшей связи
		state.ancient = this->_ancient;
		// Раздел 7.4.8 RFC 5246: подлинность клиента проверена, коли цепочка непуста - подпись владения ключом сошлась до завершения
		state.verified = !this->_peer.empty();
		// Устанавливаем миг выдачи билета
		state.moment = this->_moment;
		// Раздел 5.6 RFC 5077: миг первичного удостоверения перевыдачей не продлевается
		state.authenticated = ((this->_authenticated != 0) ? this->_authenticated : this->_moment);
		// Устанавливаем срок жизни билета
		state.lifetime = this->_lifetime;
		// Запоминаем прикладной протокол связи: выбранный выработкой NPN билет не несёт, NPN идёт заново всяким рукопожатием
		state.protocol = (this->_negotiated ? string() : this->_protocol);
		// Запоминаем имя узла, запрошенное клиентом (раздел 3 RFC 6066)
		state.name = this->_name;
		// Если подлинность клиента проверена
		if(state.verified)
			// Запоминаем сертификат клиента: возобновлённая связь предъявит его потребителю вновь
			state.leaf = this->_peer[0];
		// Отказ запечатывания билета сеанса
		const ticket::error_t minted = this->_keeper.mint(state, ticket);
		// Если билет сеанса запечатать не удалось (состояние, не входящее в билет, - не отказ)
		if((minted != ticket::error_t::NONE) && (minted != ticket::error_t::LENGTH))
			// Выводим отказ: нехватка памяти своим отказом, прочее - настроек
			return ((minted == ticket::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::SETTINGS);
		/**
		 * Раздел 3.3 RFC 5077: состояние, не входящее в билет (цепочка клиента у самого
		 * предела записи), билетом не выдаётся - сервер шлёт пустой билет с нулевым сроком,
		 * и сложившееся рукопожатие не обрывается
		 */
		if(minted == ticket::error_t::LENGTH)
			// Выполняем сброс билета: сообщение идёт пустым
			ticket.clear();
		// Отказ отправки билета
		context::error_t failure = context::error_t::NONE;
		// Объект составителя тела сообщения билета
		field::builder_t builder;
		// Раздел 3.3 RFC 5077: подсказка срока жизни билета в секундах, у пустого билета - нуль
		field::error_t outcome = builder.number(((minted == ticket::error_t::LENGTH) ? 0 : this->_lifetime), 4);
		// Если подсказка срока записана
		if(outcome == field::error_t::NONE)
			// Занимаем место под длину билета
			outcome = builder.open(2);
		// Если место под длину билета занято
		if(outcome == field::error_t::NONE)
			// Записываем октеты билета
			outcome = builder.bytes(view_t(ticket.data(), ticket.size()));
		// Если билет записан
		if(outcome == field::error_t::NONE)
			// Проставляем длину билета
			outcome = builder.close();
		// Если тело сообщения билета составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления сообщения билета
			return translate(outcome, context::error_t::MESSAGE);
		// Выполняем отправку билета сеанса
		failure = this->send(handshake::type_t::TICKET, builder.data());
		// Если билет сеанса отправить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки билета сеанса
			return failure;
		// Если билет выдан пустым
		if(minted == ticket::error_t::LENGTH)
			// Выводим успешность: потребителю билета нет
			return context::error_t::NONE;
		// Выданный билет сеанса в записи потребителя
		context::ticket_t item;
		// Устанавливаем набор шифрования связи, выдавшей билет
		item.suite = this->_suite;
		// Устанавливаем миг выдачи билета
		item.moment = this->_moment;
		// Устанавливаем срок жизни билета
		item.lifetime = this->_lifetime;
		// Запоминаем прикладной протокол связи, выдавшей билет: выбранный выработкой NPN билет не несёт
		item.protocol = (this->_negotiated ? string() : this->_protocol);
		// Запоминаем порядок защиты записей связи, выдавшей билет
		item.etm = this->_etm;
		// Переносим октеты билета телом билета потребителя
		item.identity = ::move(ticket);
		// Переносим главный секрет ключом билета
		item.secret.assign(this->_keys->master, this->_keys->master + sizeof(this->_keys->master));
		// Добавляем выданный билет в перечень билетов связи
		this->_tickets.push_back(item);
		// Выполняем затирание главного секрета в записи билета
		this->purge(item.secret.data(), item.secret.size());
		// Выводим успешность отправки билета сеанса
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора клиентом принятого билета сеанса NewSessionTicket
 *
 * @param body тело принятого сообщения билета
 * @return     отказ разбора билета сеанса
 *
 */
context::error_t nts::internal::Engine::granted(const view_t & body) noexcept {
	// Объект разборщика тела сообщения билета
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело сообщения билета
	scanner.start(body);
	// Подсказка срока жизни билета
	uint32_t lifetime = 0;
	// Раздел 3.3 RFC 5077: подсказка срока в четыре байта
	if(scanner.number(lifetime, 4) != field::error_t::NONE)
		// Выводим отказ разбора билета сеанса
		return context::error_t::MESSAGE;
	// Октеты билета сеанса
	view_t ticket;
	// Раздел 3.3 RFC 5077: билет с двухбайтовой длиной без лишних байтов
	if((scanner.vector(ticket, 2) != field::error_t::NONE) || (scanner.left() > 0))
		// Выводим отказ разбора билета сеанса
		return context::error_t::MESSAGE;
	// Раздел 3.3 RFC 5077: пустой билет означает, что сервер передумал его выдавать
	if(ticket.size == 0)
		// Выводим успешность разбора: хранить нечего
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Устанавливаем набор шифрования связи, выдавшей билет
		this->_promise.suite = this->_suite;
		// Устанавливаем миг выдачи билета
		this->_promise.moment = this->_moment;
		// Издание выдавшей связи: возобновление ведётся лишь им (раздел 3.4 RFC 5077)
		this->_promise.ancient = this->_ancient;
		// Миг первичного удостоверения: у возобновлённой связи - из предъявленного билета, иначе - этот
		this->_promise.authenticated = ((this->_shared && (this->_resume.authenticated != 0)) ? this->_resume.authenticated : this->_moment);
		// Раздел 3.3 RFC 5077: нулевая подсказка срока означает срок неизвестный - берётся предел RFC 8446
		this->_promise.lifetime = ((lifetime == 0) ? LIFETIME : lifetime);
		// Запоминаем прикладной протокол связи, выдавшей билет: выбранный выработкой NPN билет не несёт
		this->_promise.protocol = (this->_negotiated ? string() : this->_protocol);
		// Раздел 3.1 RFC 7366: билет помнит порядок защиты записей связи, его выдавшей
		this->_promise.etm = this->_etm;
		// Переносим октеты билета телом билета потребителя
		this->_promise.identity.assign(ticket.data, ticket.data + ticket.size);
		// Переносим главный секрет ключом билета
		this->_promise.secret.assign(this->_keys->master, this->_keys->master + sizeof(this->_keys->master));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность разбора билета сеанса
	return context::error_t::NONE;
}
/**
 * @brief Метод суждения сервера о годности предъявленного билета сеанса связи
 *
 * @param greeting приветствие клиента, предъявившее билет
 * @param chained  предложен ли клиентом порядок «шифрование, затем имитовставка»
 * @param host     имя узла, запрошенное приветствием клиента
 * @param state    распечатанное состояние билета
 * @return         признак того, что связь возобновляется билетом
 *
 */
bool nts::internal::Engine::recalling(const hello::client_t & greeting, const bool chained, const string & host, ticket::state_t & state) noexcept {
	// Раздел 3.3 RFC 5077: билет с вышедшим сроком и билет чужого издания ведут к полному рукопожатию
	if(!protect::legacy(state.suite))
		// Выводим негодность билета
		return false;
	// Раздел 3.4 RFC 5077: билет возобновляет связь лишь тем же изданием; набор GCM ниже 1.2 запрещён (раздел 4 RFC 5288)
	if((this->_ancient != state.ancient) || (this->_ancient && !archaic(state.suite)))
		// Выводим негодность билета
		return false;
	// Раздел 3.1 RFC 7366: строгий порядок при билете без него ведёт к полному рукопожатию, а не к обрыву
	if(this->_strict && !state.etm && (protect::mac(state.suite) != digest::hash_t::NONE))
		// Выводим негодность билета
		return false;
	// Билет в записи потребителя ради суждения о сроке
	context::ticket_t item;
	// Устанавливаем миг выдачи
	item.moment = state.moment;
	// Устанавливаем срок жизни
	item.lifetime = state.lifetime;
	// Если срок билета вышел
	if(expired(item, this->_moment))
		// Выводим негодность билета
		return false;
	// Раздел 5.6 RFC 5077: удостоверение клиента старше дозволенного - полное рукопожатие
	if(outdated(state.authenticated, this->_moment))
		// Выводим негодность билета
		return false;
	// Запоминаем миг первичного удостоверения из билета
	this->_authenticated = state.authenticated;
	// Признак того, что набор билета предложен клиентом вновь
	bool suitable = false;
	/**
	 * Выполняем перебор наборов шифрования, предложенных клиентом: набор билета обязан
	 * быть предложен вновь и оставаться в предложении сервера, иначе связь возобновлять нечем
	 */
	for(size_t i = 0; (i < greeting.suites.size()) && !suitable; i++)
		// Запоминаем совпадение набора билета с предложенным клиентом и сервером
		suitable = ((greeting.suites[i] == static_cast <uint16_t> (state.suite)) && listed(this->_suites, state.suite));
	// Если набор билета более не предлагается
	if(!suitable)
		// Выводим негодность билета
		return false;
	/**
	 * Раздел 3.1 RFC 7301: прикладной протокол - свойство связи, не сеанса; при
	 * возобновлении берётся лишь протокол нового рукопожатия, прежний в билете не
	 * судится (сверка с ним отказывала бы в возобновлении там, где стандарт велит)
	 */
	/**
	 * Раздел 3.1 RFC 7366: порядок «шифрование, затем имитовставка» не понижается -
	 * связь с ETM возобновляется лишь клиентом, предложившим его вновь; иначе
	 * рукопожатие полное, и порядок согласуется заново
	 */
	if(state.etm && !chained)
		// Выводим негодность билета
		return false;
	/**
	 * Раздел 7.4.6 RFC 5246: при запросе подлинности клиента сокращённым рукопожатием
	 * наследуется лишь проверенная подлинность; билет связи без неё ведёт к полному
	 * рукопожатию, где подлинность будет запрошена
	 */
	if(this->_request && !state.verified)
		// Выводим негодность билета
		return false;
	// Раздел 3 RFC 6066: имя узла возобновлённой связи обязано сойтись с именем выдавшей билет
	if(state.name.compare(host) != 0)
		// Выводим негодность билета
		return false;
	// Если подлинность клиента унаследована
	if(state.verified){
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Выполняем сброс прежней цепочки собеседника
			this->_peer.clear();
			// Переносим сертификат клиента цепочкой собеседника
			this->_peer.push_back(state.leaf);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выполняем сброс цепочки собеседника
			this->_peer.clear();
			// Выводим негодность билета
			return false;
		}
	}
	// Переносим главный секрет билета в связь
	::memcpy(this->_keys->master, state.master, sizeof(this->_keys->master));
	// Устанавливаем набор шифрования билета
	this->_suite = state.suite;
	// Наследуем порядок защиты записей выдавшей связи
	this->_etm = state.etm;
	// Выводим годность билета
	return true;
}
/**
 * @brief Метод отправки заключительного залпа своей стороны издания TLS 1.2
 *
 * @return отказ отправки заключительного залпа
 *
 */
context::error_t nts::internal::Engine::concluding() noexcept {
	// Отказ отправки залпа
	context::error_t failure = context::error_t::NONE;
	// Раздел 3.3 RFC 5077: билет сеанса шлёт лишь сервер, лишь обещанный приветствием и всегда перед сменой набора
	if(this->_server && this->_ticketing){
		// Выполняем отправку билета сеанса
		failure = this->granting();
		// Если билет сеанса отправить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки билета сеанса
			return failure;
	}
	// Выполняем отправку смены набора шифрования
	failure = this->switching();
	// Если смену набора шифрования отправить не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ отправки смены набора шифрования
		return failure;
	// Выполняем отправку выбранного протокола выработки NPN (лишь клиентом)
	failure = this->announcing();
	// Если выбранный протокол отправить не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ отправки выбранного протокола
		return failure;
	// Выводим итог отправки завершения рукопожатия своей стороной
	return this->finishing();
}
/**
 * @brief Метод установки заранее разделённого ключа издания TLS 1.2
 *
 * @param psk настройки заранее разделённого ключа
 *
 */
void nts::internal::Engine::psk(const context::psk_t & psk) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если прежний ключ задан
		if(!this->_psk.key.empty())
			// Выполняем затирание прежнего ключа
			this->purge(this->_psk.key.data(), this->_psk.key.size());
		// Запоминаем настройки заранее разделённого ключа
		this->_psk = psk;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс настроек заранее разделённого ключа
		this->_psk = context::psk_t();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки выбора подлинности сервера по имени узла
 *
 * @param select настройки выбора подлинности по имени узла
 *
 */
void nts::internal::Engine::select(const context::select_t & select) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем настройки выбора подлинности по имени узла
		this->_select = select;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс настроек выбора подлинности по имени узла
		this->_select = context::select_t();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Метод установки требования порядка «шифрование, затем имитовставка» RFC 7366
 *
 * @param required обязателен ли порядок encrypt_then_mac при наборе CBC
 *
 */
void nts::internal::Engine::etm(const bool required) noexcept {
	// Запоминаем требование порядка
	this->_strict = required;
}
/**
 * @brief Метод решения, вставляет ли связь свои значения GREASE
 *
 * @return признак того, что значения GREASE вставляются умолчанием движка
 *
 */
bool nts::internal::Engine::greased() const noexcept {
	/**
	 * Точка перекрытия профилем отпечатка: при заданном профиле места и число значений
	 * GREASE берёт профиль, а не признак потребителя - ветвь профиля становится сюда
	 */
	// Выводим признак вставки значений GREASE по настройке потребителя: профиль отпечатка расставляет свои
	return (this->_greasing && !this->_profiled);
}
/**
 * @brief Метод получения значения GREASE места связи
 *
 * @param place место значения GREASE
 * @return      значение вида 0x?A?A, выведенное из зерна связи
 *
 */
uint16_t nts::internal::Engine::greasing(const grease_t place) const noexcept {
	// Раздел 2 RFC 8701: старшие четыре разряда байта зерна, младшие - 0xA, байт повторён дважды
	const uint8_t value = static_cast <uint8_t> ((this->_seed[static_cast <uint8_t> (place)] & 0xF0) | 0x0A);
	// Выводим значение GREASE места
	return static_cast <uint16_t> ((static_cast <uint16_t> (value) << 8) | value);
}
/**
 * @brief Метод установки вставки своих значений GREASE (RFC 8701)
 *
 * @param grease вставляются ли значения GREASE
 *
 */
void nts::internal::Engine::grease(const bool grease) noexcept {
	// Запоминаем, вставляются ли значения GREASE
	this->_greasing = grease;
}
/**
 * @brief Метод проверки вставки своих значений GREASE
 *
 * @return признак того, что значения GREASE вставляются
 *
 */
bool nts::internal::Engine::grease() const noexcept {
	// Выводим признак вставки значений GREASE
	return this->_greasing;
}
/**
 * @brief Метод установки классов затирания памяти связи
 *
 * @param classes классы затирания (context::wiping_t)
 *
 */
void nts::internal::Engine::wiping(const vector <context::wiping_t> & classes) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем классы затирания
		this->_wiping = classes;
		// Сбрасываем признак затирания секретов
		this->_scrubbing = false;
		// Сбрасываем признак затирания открытого текста
		this->_cleansing = false;
		/**
		 * Выполняем перебор классов затирания
		 */
		for(size_t i = 0; i < classes.size(); i++){
			/**
			 * Определяем класс затирания
			 */
			switch(static_cast <uint8_t> (classes[i])){
				// Если класс - секреты
				case static_cast <uint8_t> (context::wiping_t::SECRETS):
					// Включаем затирание секретов
					this->_scrubbing = true;
				break;
				// Если класс - открытый текст записей
				case static_cast <uint8_t> (context::wiping_t::PLAINTEXT):
					// Включаем затирание открытого текста
					this->_cleansing = true;
				break;
			}
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем перечень классов
		this->_wiping.clear();
		// Сбрасываем признак затирания секретов
		this->_scrubbing = false;
		// Сбрасываем признак затирания открытого текста
		this->_cleansing = false;
		// Запоминаем нехватку памяти
		this->_starved = true;
	}
}
/**
 * @brief Метод получения классов затирания памяти связи
 *
 * @return классы затирания, объявленные потребителем
 *
 */
const vector <context::wiping_t> & nts::internal::Engine::wiping() const noexcept {
	// Выводим классы затирания
	return this->_wiping;
}
/**
 * @brief Метод проверки, есть ли набор шифрования среди наборов профиля отпечатка
 *
 * @param suite набор шифрования по проводу
 * @return      признак того, что набор есть в профиле
 *
 */
bool nts::internal::Engine::carried(const uint16_t suite) const noexcept {
	/**
	 * Выполняем перебор наборов профиля
	 */
	for(size_t i = 0; i < this->_profile.suites.size(); i++){
		// Если набор совпал
		if(static_cast <uint16_t> (this->_profile.suites[i]) == suite)
			// Выводим наличие набора
			return true;
	}
	// Выводим отсутствие набора
	return false;
}
/**
 * @brief Метод установки профиля отпечатка, по которому складывается приветствие клиента
 *
 * @param profile профиль отпечатка, снятый с приветствия обозревателя
 * @return        отказ установки
 *
 */
context::error_t nts::internal::Engine::profile(const fingerprint::profile_t & profile) noexcept {
	// Профиль ставится лишь до заведения связи
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Настройкам связи памяти не хватило: за них отвечает нехватка памяти, а не настройки
	if(this->_starved)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Профиль складывает приветствие клиента: серверу и пустому профилю он не годен
	if(this->_server || profile.suites.empty() || profile.extensions.empty())
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Наборы профиля, ведомые связи, в порядке профиля
		vector <protect::suite_t> suites;
		/**
		 * Выполняем перебор наборов профиля
		 */
		for(size_t i = 0; i < profile.suites.size(); i++){
			/**
			 * Выполняем перебор наборов, ведомых связи
			 */
			for(size_t j = 0; j < this->_suites.size(); j++){
				// Если набор профиля ведом связи
				if(profile.suites[i] == this->_suites[j]){
					// Добавляем набор в перечень
					suites.push_back(profile.suites[i]);
					// Выходим из перебора
					break;
				}
			}
		}
		// Если ни одного набора профиля связь не ведает
		if(suites.empty())
			// Выводим отказ настроек связи
			return context::error_t::SETTINGS;
		// Группы, доли и схемы профиля, ведомые связи, в порядке профиля
		vector <extension::group_t> groups, shares;
		// Схемы подписи профиля, ведомые связи
		vector <extension::scheme_t> schemes;
		// Прикладные протоколы профиля
		vector <string> protocols;
		// Пределы изданий по профилю
		uint16_t lowest = 0, highest = 0;
		// Признак запроса состояния сертификата в профиле
		// Точка кода ALPS профиля и пустые настройки его протоколов: переносятся после проверок
		uint16_t codepoint = 0;
		// Настройки прикладных протоколов ALPS профиля
		vector <setting_t> settings;
		// Признак запроса состояния сертификата в профиле
		bool inquiring = false;
		/**
		 * Выполняем перебор расширений профиля
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Расширение профиля
			const fingerprint::extension_t & extension = profile.extensions[i];
			/**
			 * Определяем вид расширения
			 */
			switch(extension.type){
				// Группы обмена ключами
				case static_cast <uint16_t> (extension::type_t::GROUPS): {
					/**
					 * Выполняем перебор групп профиля
					 */
					for(size_t j = 0; j < extension.groups.size(); j++){
						/**
						 * Выполняем перебор групп, ведомых связи
						 */
						for(size_t k = 0; k < this->_groups.size(); k++){
							// Если группа профиля ведома связи
							if(extension.groups[j] == this->_groups[k]){
								// Добавляем группу в перечень
								groups.push_back(extension.groups[j]);
								// Выходим из перебора
								break;
							}
						}
					}
				} break;
				// Доли ключа
				case static_cast <uint16_t> (extension::type_t::SHARE): {
					/**
					 * Выполняем перебор долей профиля
					 */
					for(size_t j = 0; j < extension.shares.size(); j++){
						/**
						 * Выполняем перебор групп, ведомых связи
						 */
						for(size_t k = 0; k < this->_groups.size(); k++){
							// Если группа доли ведома связи
							if(extension.shares[j].group == this->_groups[k]){
								// Добавляем группу доли в перечень
								shares.push_back(extension.shares[j].group);
								// Выходим из перебора
								break;
							}
						}
					}
				} break;
				// Схемы подписи
				case static_cast <uint16_t> (extension::type_t::SCHEMES): {
					/**
					 * Выполняем перебор схем профиля
					 */
					for(size_t j = 0; j < extension.schemes.size(); j++){
						/**
						 * Выполняем перебор схем, ведомых связи
						 */
						for(size_t k = 0; k < this->_signatures.size(); k++){
							// Если схема профиля ведома связи
							if(extension.schemes[j] == this->_signatures[k]){
								// Добавляем схему в перечень
								schemes.push_back(extension.schemes[j]);
								// Выходим из перебора
								break;
							}
						}
					}
				} break;
				// Издания протокола
				case static_cast <uint16_t> (extension::type_t::VERSIONS): {
					/**
					 * Выполняем перебор изданий профиля
					 */
					for(size_t j = 0; j < extension.versions.size(); j++){
						// Издание в кодах TLS: поверх дейтаграмм издания зеркальны
						uint16_t edition = extension.versions[j];
						// Если издание есть DTLS 1.2
						if(edition == datagram::DATAGRAM_LEGACY)
							// Переводим в код TLS 1.2
							edition = LEGACY;
						// Если издание есть DTLS 1.3
						else if(edition == datagram::DATAGRAM_VERSION)
							// Переводим в код TLS 1.3
							edition = MODERN;
						// Если издание связи неведомо
						if((edition != LEGACY) && (edition != MODERN))
							// Переходим к следующему изданию
							continue;
						// Если наименьшее издание не задано либо старше найденного
						if((lowest == 0) || (edition < lowest))
							// Запоминаем наименьшее издание
							lowest = edition;
						// Если наибольшее издание младше найденного
						if(edition > highest)
							// Запоминаем наибольшее издание
							highest = edition;
					}
				} break;
				// Прикладные протоколы
				case static_cast <uint16_t> (extension::type_t::PROTOCOLS):
					// Переносим прикладные протоколы профиля
					protocols = extension.protocols;
				break;
				// Прикладные настройки ALPS: точка кода профиля и его протоколы с пустыми настройками
				case static_cast <uint16_t> (extension::type_t::SETTINGS):
				case static_cast <uint16_t> (extension::type_t::SETTINGS_OLD): {
					// Точка кода - точка профиля: переносится в связь лишь после всех проверок
					codepoint = extension.type;
					/**
					 * Выполняем перебор протоколов расширения профиля
					 */
					for(size_t j = 0; j < extension.protocols.size(); j++){
						// Настройки протокола профиля
						setting_t item;
						// Устанавливаем протокол настроек
						item.protocol = extension.protocols[j];
						// Объявляем пустые настройки протокола
						settings.push_back(item);
					}
				} break;
				// Запрос состояния сертификата
				case static_cast <uint16_t> (extension::type_t::STATUS):
					// Запоминаем запрос состояния
					inquiring = true;
				break;
				/**
				 * Запрос меток времени сертификата (расширение 18) профиль несёт сырым телом,
				 * и ответ на него клиент принимает по перечню предложенных: отдельного признака
				 * не нужно
				 */
				// Прочие расширения на настройки связи не влияют
				default: break;
			}
		}
		// Если ни одной группы профиля связь не ведает
		if(groups.empty())
			// Выводим отказ настроек связи
			return context::error_t::SETTINGS;
		// Раздел 6.1 RFC 9849: с конфигурациями ECH издание ниже 1.3 не предлагается - профиль с ним отвергается, как и versions(); все проверки идут до переноса, чтобы отвергнутый профиль не оставил связь в половинчатом состоянии
		if((lowest != 0) && !this->_configs.empty() && (lowest < MODERN))
			// Выводим отказ настроек
			return context::error_t::SETTINGS;
		// Переносим профиль
		this->_profile = profile;
		// Переносим наборы шифрования
		this->_suites = suites;
		// Запоминаем настройку наборов
		this->_catalog = suites;
		// Переносим группы обмена ключами
		this->_groups = groups;
		// Переносим группы долей: без долей в профиле доля идёт по первой группе умолчанием
		this->_shares = shares;
		// Если схемы профиля связи ведомы
		if(!schemes.empty())
			// Переносим схемы подписи
			this->_signatures = schemes;
		// Если прикладные протоколы потребителем не заданы
		if(this->_protocols.empty())
			// Переносим прикладные протоколы профиля
			this->_protocols = protocols;
		// Если издания профиля связи ведомы
		if(lowest != 0){
			// Устанавливаем наименьшее дозволенное издание
			this->_lowest = lowest;
			// Устанавливаем наибольшее дозволенное издание
			this->_highest = highest;
		}
		// Если профиль запрашивает состояние сертификата
		if(inquiring)
			// Включаем запрос состояния сертификата
			this->_inquiring = true;
		// Если профиль несёт точку кода ALPS (перенос последним: копии выше вправе отказать памятью)
		if(codepoint != 0){
			// Переносим точку кода
			this->_codepoint = codepoint;
			// Если настройки потребителем не объявлены
			if(this->_settings.empty())
				// Переносим пустые настройки протоколов профиля
				this->_settings = settings;
		}
		// Запоминаем, что приветствие складывается по профилю
		this->_profiled = true;
		// Выводим успешность установки профиля
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод установки конфигураций ECH клиенту
 *
 * @param configs перечень ECHConfigList байтами
 * @return        отказ установки
 *
 */
context::error_t nts::internal::Engine::ech(const view_t & configs) noexcept {
	// Конфигурации ставятся лишь до заведения связи
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Настройкам связи памяти не хватило
	if(this->_starved)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Конфигурации годны лишь клиенту
	if(this->_server)
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Разобранные конфигурации
		vector <ech::config_t> list;
		// Отказ разбора перечня
		const ech::error_t failure = ech::parse(configs, list);
		// Если памяти не хватило
		if(failure == ech::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если перечень негоден либо без единой признаваемой конфигурации
		if(failure != ech::error_t::NONE)
			// Выводим отказ конфигураций ECH
			return context::error_t::ECH;
		// Переносим конфигурации
		this->_configs = list;
		// Запоминаем перечень как записан
		this->_echlist.assign(configs.data, configs.data + configs.size);
		// Выбирается первая признаваемая конфигурация
		this->_shroud = 0;
		// Публичное имя известно с момента установки: по нему потребитель судит сертификат при отказе
		this->_public = list[0].name;
		/**
		 * Раздел 6.1 RFC 9849: внутреннее приветствие не вправе предлагать издания ниже 1.3,
		 * а внешнее обязано предлагать 1.3 - связь с ECH ведёт одно лишь издание 1.3
		 */
		this->_lowest = MODERN;
		// Наибольшее издание не ниже 1.3
		this->_highest = MODERN;
		// Выводим успешность установки
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод установки ключа ECH серверу
 *
 * @param secret секретный ключ X25519 либо пусто
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации
 * @param length наибольшая длина имени для заполнения клиента
 * @return       отказ установки
 *
 */
context::error_t nts::internal::Engine::ech(const view_t & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Добавляем объявляемую конфигурацию
	return this->serving(secret, name, id, length, true);
}
/**
 * @brief Метод установки ключа ECH серверу со способом инкапсуляции
 *
 * @param kem    способ инкапсуляции ключа
 * @param secret секретный ключ способа либо пусто
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации
 * @param length наибольшая длина имени для заполнения клиента
 * @return       отказ установки
 *
 */
context::error_t nts::internal::Engine::ech(const hpke::kem_t kem, const view_t & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Добавляем объявляемую конфигурацию со способом
	return this->serving(kem, secret, name, id, length, true);
}
/**
 * @brief Метод установки удержанной конфигурации ECH серверу: принимается, но не объявляется
 *
 * @param secret секретный ключ X25519 либо пусто
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации
 * @param length наибольшая длина имени
 * @return       отказ установки
 *
 */
context::error_t nts::internal::Engine::retain(const view_t & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Добавляем удержанную конфигурацию
	return this->serving(secret, name, id, length, false);
}
/**
 * @brief Метод установки удержанной конфигурации ECH серверу со способом инкапсуляции: принимается, но не объявляется
 *
 * @param kem    способ инкапсуляции ключа
 * @param secret секретный ключ способа либо пусто
 * @param name   публичное имя конфигурации
 * @param id     опознаватель конфигурации
 * @param length наибольшая длина имени
 * @return       отказ установки
 *
 */
context::error_t nts::internal::Engine::retain(const hpke::kem_t kem, const view_t & secret, const string & name, const uint8_t id, const uint8_t length) noexcept {
	// Добавляем удержанную конфигурацию со способом
	return this->serving(kem, secret, name, id, length, false);
}
/**
 * @brief Метод добавления служимой конфигурации ECH
 *
 * @param secret     секретный ключ X25519 либо пусто
 * @param name       публичное имя конфигурации
 * @param id         опознаватель конфигурации
 * @param length     наибольшая длина имени
 * @param advertised признак объявления конфигурации в перечне
 * @return           отказ установки
 *
 */
context::error_t nts::internal::Engine::serving(const view_t & secret, const string & name, const uint8_t id, const uint8_t length, const bool advertised) noexcept {
	// Добавляем конфигурацию со способом X25519
	return this->serving(hpke::kem_t::X25519_HKDF_SHA256, secret, name, id, length, advertised);
}
/**
 * @brief Метод добавления служимой конфигурации ECH со способом инкапсуляции
 *
 * @param kem        способ инкапсуляции ключа
 * @param secret     секретный ключ способа либо пусто
 * @param name       публичное имя конфигурации
 * @param id         опознаватель конфигурации
 * @param length     наибольшая длина имени
 * @param advertised признак объявления конфигурации в перечне
 * @return           отказ установки
 *
 */
context::error_t nts::internal::Engine::serving(const hpke::kem_t kem, const view_t & secret, const string & name, const uint8_t id, const uint8_t length, const bool advertised) noexcept {
	// Ключ ставится лишь до заведения связи
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Настройкам связи памяти не хватило
	if(this->_starved)
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	// Ключ годен лишь серверу, имя обязательно и не длиннее дозволенного, способ поддерживаемый
	if(!this->_server || name.empty() || (name.size() > ech::ECH_NAME) || (hpke::length(kem) == 0))
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	// Место прежней конфигурации с тем же опознавателем: она заменяется, ведь клиенту не подобрать ключ по одному опознавателю на два ключа (раздел 7.1 RFC 9849)
	size_t replaced = this->_serving.size();
	/**
	 * Выполняем перебор служимых конфигураций
	 */
	for(size_t i = 0; (i < this->_serving.size()) && (replaced == this->_serving.size()); i++){
		// Если опознаватель занят
		if(this->_serving[i].config.id == id)
			// Запоминаем место замены
			replaced = i;
	}
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Служимая конфигурация
		served_t item;
		// Признак объявления
		item.advertised = advertised;
		// Отказ заведения ключа: заданный секрет либо порождение
		const hpke::error_t keyed = ((secret.size == 0) ? item.key.generate(kem) : item.key.set(kem, secret));
		// Если ключ завести не удалось
		if(keyed != hpke::error_t::NONE)
			// Выводим отказ: нехватка памяти своим кодом, прочее - настройками
			return ((keyed == hpke::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::SETTINGS);
		// Составляемая конфигурация
		ech::config_t config;
		// Опознаватель
		config.id = id;
		// Наибольшая длина имени
		config.length = length;
		// Способ инкапсуляции
		config.kem = kem;
		// Открытая часть ключа
		config.key.assign(item.key.point().data, item.key.point().data + item.key.point().size);
		// Наборы: обязательный AES-128-GCM и ChaCha20-Poly1305, оба на HKDF-SHA256
		config.suites.push_back(ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::AES_128_GCM));
		config.suites.push_back(ech::suite_t(hpke::kdf_t::HKDF_SHA256, hpke::aead_t::CHACHA20_POLY1305));
		// Публичное имя
		config.name = name;
		// Конфигурация как записана
		vector <uint8_t> raw;
		// Если конфигурацию составить не удалось
		if(ech::build(config, raw) != ech::error_t::NONE)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Служимая конфигурация разбирается из записи, чтобы хранить себя как записана
		if(ech::parse(view_t(raw.data(), raw.size()), item.config) != ech::error_t::NONE)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Объявляемые конфигурации для перечня DNS и retry_configs
		vector <ech::config_t> listed;
		/**
		 * Выполняем перебор служимых конфигураций без заменяемой
		 */
		for(size_t i = 0; i < this->_serving.size(); i++){
			// Если конфигурация объявляется и не заменяется
			if(this->_serving[i].advertised && (i != replaced))
				// Добавляем конфигурацию в перечень
				listed.push_back(this->_serving[i].config);
		}
		// Если новая конфигурация объявляется
		if(advertised)
			// Добавляем её в перечень
			listed.push_back(item.config);
		// Перечень для DNS
		vector <uint8_t> list;
		// Если перечень непуст и составить его не удалось
		if(!listed.empty() && (ech::build(listed, list) != ech::error_t::NONE))
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Если конфигурация заменяет прежнюю
		if(replaced < this->_serving.size())
			// Заменяем конфигурацию
			this->_serving[replaced] = item;
		// Если конфигурация новая
		else
			// Запоминаем конфигурацию
			this->_serving.push_back(item);
		// Запоминаем перечень для DNS
		this->_echlist.swap(list);
		// Выводим успешность установки
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод получения перечня конфигураций ECH
 *
 * @return перечень ECHConfigList
 *
 */
const vector <uint8_t> & nts::internal::Engine::ech() const noexcept {
	// Выводим перечень
	return this->_echlist;
}
/**
 * @brief Метод проверки принятия ECH сервером
 *
 * @return признак того, что рукопожатие идёт по внутреннему приветствию
 *
 */
bool nts::internal::Engine::shrouded() const noexcept {
	// Выводим признак принятия: у сервера - своё, у клиента - подтверждённое
	return (this->_server ? this->_echaccepted : (this->_ech == ech_t::ACCEPTED));
}
/**
 * @brief Метод получения имени, которым шло внешнее приветствие
 *
 * @return публичное имя конфигурации ECH либо пусто без ECH
 *
 */
const string & nts::internal::Engine::visible() const noexcept {
	// Выводим публичное имя
	return this->_public;
}
/**
 * @brief Метод получения запасных конфигураций ECH, присланных сервером
 *
 * @return перечень ECHConfigList из защищённых расширений
 *
 */
const vector <uint8_t> & nts::internal::Engine::retries() const noexcept {
	// Выводим запасные конфигурации
	return this->_retries;
}
/**
 * @brief Метод складывания зашифрованного приветствия ECH
 *
 * @param greeting приветствие, сложенное движком: становится внешним
 * @param storage  хранилище тел расширений внешнего приветствия
 * @return         отказ складывания
 *
 */
context::error_t nts::internal::Engine::shrouding(hello::client_t & greeting, const bool resume, vector <vector <uint8_t>> & storage) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Расширение ECH внутреннего вида
		static const uint8_t INWARD[] = {0x01};
		// Если выбранной конфигурации нет
		if(this->_shroud >= this->_configs.size())
			// Выводим отказ конфигураций ECH
			return context::error_t::ECH;
		// Выбранная конфигурация
		const ech::config_t & config = this->_configs[this->_shroud];
		// Набор симметричных алгоритмов: первый признаваемый из конфигурации
		ech::suite_t suite;
		// Признак того, что набор найден
		bool found = false;
		/**
		 * Выполняем перебор наборов конфигурации
		 */
		for(size_t i = 0; (i < config.suites.size()) && !found; i++){
			// Если набор признаётся
			if(ech::supported(config.kem, config.suites[i])){
				// Запоминаем набор
				suite = config.suites[i];
				// Отмечаем находку
				found = true;
			}
		}
		// Если набор не найден
		if(!found)
			// Выводим отказ конфигураций ECH
			return context::error_t::ECH;
		// Инкапсулированный ключ: у первого приветствия свой, у повторного - пустой
		vector <uint8_t> enc;
		// Если приветствие первое: случайное значение внутреннего и заведение HPKE
		if(!this->_retried){
			// Если случайное значение выработать не удалось
			if(!entropy::bytes(this->_innerandom, sizeof(this->_innerandom)))
				// Выводим отказ настроек связи
				return context::error_t::SETTINGS;
			// Привязка HPKE
			vector <uint8_t> info;
			// Если привязку составить не удалось
			if(ech::binding(view_t(config.raw.data(), config.raw.size()), info) != ech::error_t::NONE)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Набор HPKE
			hpke::suite_t item;
			// Способ инкапсуляции
			item.kem = config.kem;
			// Функция вывода
			item.kdf = suite.kdf;
			// Шифр
			item.aead = suite.aead;
			// Место инкапсулированного ключа способа конфигурации
			uint8_t encapsulated[hpke::KEM_CIPHER];
			// Отказ заведения отправителя HPKE
			const hpke::error_t established = hpke::sender(item, hpke::regime_t::BASE, view_t(config.key.data(), config.key.size()), view_t(info.data(), info.size()), hpke::shared_t(), nullptr, encapsulated, this->_sealer);
			// Если отправителя завести не удалось
			if(established != hpke::error_t::NONE)
				// Выводим отказ: нехватка памяти своим кодом, прочее - конфигурациями
				return ((established == hpke::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::ECH);
			// Переносим инкапсулированный ключ
			enc.assign(encapsulated, encapsulated + hpke::overhead(item.kem));
		// Если приветствие повторное, а отправитель не заведён
		} else if(!this->_sealer.ready())
			// Выводим отказ конфигураций ECH
			return context::error_t::ECH;
		// Внутреннее приветствие: сложенное движком со своим случайным значением и расширением ECH внутреннего вида
		hello::client_t inner = greeting;
		// Устанавливаем случайное значение внутреннего приветствия
		::memcpy(inner.random, this->_innerandom, sizeof(inner.random));
		// Добавляем расширение ECH внутреннего вида
		/**
		 * Раздел 4.2.11 RFC 8446: заранее разделённые ключи обязаны идти последним расширением и
		 * во внутреннем приветствии, оттого внутреннее расширение ECH встаёт перед ними
		 */
		inner.extensions.insert(inner.extensions.end() - ((resume && !inner.extensions.empty() && (inner.extensions.back().type == static_cast <uint16_t> (extension::type_t::SECRET))) ? 1 : 0), hello::extension_t(ech::ECH_EXTENSION, view_t(INWARD, sizeof(INWARD))));
		// Выполняем сброс видов расширений внутреннего приветствия
		this->_hidden.clear();
		/**
		 * Выполняем перебор расширений внутреннего приветствия
		 */
		for(size_t i = 0; i < inner.extensions.size(); i++)
			// Запоминаем вид расширения
			this->_hidden.push_back(inner.extensions[i].type);
		// Тело внутреннего приветствия
		vector <uint8_t> body;
		// Отказ составления внутреннего приветствия
		context::error_t failure = translate(hello::build(inner, body, (this->_transport == context::transport_t::DATAGRAMS)), context::error_t::MESSAGE);
		// Если внутреннее приветствие составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления
			return failure;
		// Объект составителя сообщения рукопожатия
		handshake::writer_t writer;
		// Отказ составления внутреннего приветствия с обвязкой
		failure = translate(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())), context::error_t::MESSAGE);
		// Если внутреннее приветствие с обвязкой составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления
			return failure;
		// Запоминаем внутреннее приветствие с обвязкой
		this->_inner.assign(writer.data().data, writer.data().data + writer.data().size);
		/**
		 * Раздел 6.1 RFC 9849: билет возобновления предъявляется во внутреннем приветствии,
		 * и привязка считается по его усечённому телу; внешнее приветствие билета не несёт,
		 * иначе опознаватель билета выдавал бы связь наблюдателю не хуже открытого имени
		 */
		if(resume){
			// Хеш набора билета: им считается привязка
			const digest::hash_t algorithm = ((protect::hash(this->_resume.suite) != digest::hash_t::NONE) ? protect::hash(this->_resume.suite) : this->_transcript.algorithm());
			// Длина привязки
			const size_t width = digest::length(algorithm);
			// Если внутреннее приветствие короче привязки с её длинами
			if(this->_inner.size() < (width + 3))
				// Выводим отказ составления
				return context::error_t::MESSAGE;
			// Длина усечённого приветствия: без привязки и длин перечня привязок
			const size_t truncation = (this->_inner.size() - (width + 3));
			// Если начальную ступень расписания ключей завести не удалось хешем набора билета
			if(this->_secrets.start(algorithm, view_t(this->_resume.secret.data(), this->_resume.secret.size())) != session::error_t::NONE)
				// Выводим отказ вывода ключевого материала связи
				return context::error_t::SCHEDULE;
			// Место, в которое помещается хеш усечённого внутреннего приветствия
			uint8_t transcript[schedule::SCHEDULE_WIDEST];
			// Если хеш усечённого приветствия снять не удалось
			if(this->_transcript.digest(algorithm, view_t(this->_inner.data(), truncation), transcript) != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return context::error_t::MESSAGE;
			// Если привязку предъявляемого билета выработать не удалось
			if(this->_secrets.binder(view_t(transcript, width), this->_inner.data() + (this->_inner.size() - width)) != session::error_t::NONE)
				// Выводим отказ выработки привязки билета
				return context::error_t::SCHEDULE;
			// Внутреннее приветствие с настоящей привязкой: тело без заголовка сообщения
			const view_t patched(this->_inner.data() + 4, this->_inner.size() - 4);
			// Разбор внутреннего приветствия с привязкой
			const hello::error_t patching = hello::parse(patched, inner, (this->_transport == context::transport_t::DATAGRAMS));
			// Если внутреннее приветствие с привязкой разобрать не удалось: нехватка памяти не есть порча сообщения
			if(patching != hello::error_t::NONE)
				// Выводим отказ составления либо нехватку памяти
				return ((patching == hello::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::MESSAGE);
			/**
			 * Выполняем изъятие билета из внешнего приветствия: он принадлежит внутреннему.
			 * Упреждение остаётся и снаружи: раздел 6.1 RFC 9849 велит нести early_data в обоих
			 * приветствиях, чтобы сервер, отвергший ECH, пропускал записи нулевого полёта
			 */
			for(size_t i = 0; i < greeting.extensions.size(); i++){
				// Если расширение есть заранее разделённые ключи
				if(greeting.extensions[i].type == static_cast <uint16_t> (extension::type_t::SECRET)){
					// Изымаем расширение из внешнего приветствия
					greeting.extensions.erase(greeting.extensions.begin() + i);
					// Возвращаемся на шаг
					i--;
				}
			}
		}
		// Виды расширений, выносимых во внешнее приветствие: ведущий ряд до имени узла и ECH
		vector <uint16_t> outsourced;
		/**
		 * Выполняем перебор расширений внутреннего приветствия
		 */
		for(size_t i = 0; i < inner.extensions.size(); i++){
			// Если расширение есть имя узла либо ECH: ряд кончился
			if((inner.extensions[i].type == static_cast <uint16_t> (extension::type_t::NAME)) || (inner.extensions[i].type == ech::ECH_EXTENSION))
				// Выходим из перебора
				break;
			// Добавляем вид расширения в ряд
			outsourced.push_back(inner.extensions[i].type);
		}
		// Закодированное внутреннее приветствие без заполнения: для подсчёта заполнения
		vector <uint8_t> encoded;
		// Если закодировать не удалось
		if(ech::encode(inner, outsourced, 0, (this->_transport == context::transport_t::DATAGRAMS), encoded) != ech::error_t::NONE)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Заполнение по разделу 6.1.3 RFC 9849
		const size_t padding = ech::padding(this->_name.size(), config.length, encoded.size());
		// Если закодировать с заполнением не удалось
		if(ech::encode(inner, outsourced, padding, (this->_transport == context::transport_t::DATAGRAMS), encoded) != ech::error_t::NONE)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Занимаем место под публичное имя
		storage.push_back(vector <uint8_t> ());
		// Тело публичного имени
		vector <uint8_t> & named = storage.back();
		// Отказ составления публичного имени
		failure = translate(extension::name(view_t(reinterpret_cast <const uint8_t *> (config.name.c_str()), config.name.size()), named), context::error_t::MESSAGE);
		// Если публичное имя составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления
			return failure;
		// Признак того, что имя узла во внешнем приветствии подменено
		bool renamed = false;
		/**
		 * Выполняем перебор расширений внешнего приветствия
		 */
		for(size_t i = 0; i < greeting.extensions.size(); i++){
			// Если расширение есть имя узла
			if(greeting.extensions[i].type == static_cast <uint16_t> (extension::type_t::NAME)){
				// Подменяем имя публичным
				greeting.extensions[i].data = view_t(named.data(), named.size());
				// Отмечаем подмену
				renamed = true;
			}
		}
		// Раздел 6.1 RFC 9849: внешнее приветствие несёт публичное имя конфигурации
		if(!renamed)
			// Добавляем публичное имя
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(named.data(), named.size())));
		// Расширение ECH внешнего вида
		ech::hello_t outward;
		// Набор
		outward.suite = suite;
		// Опознаватель конфигурации
		outward.id = config.id;
		// Инкапсулированный ключ
		outward.enc = enc;
		// Шифротекст: место под закодированное приветствие с меткой шифра, пока нулевое
		outward.payload.assign(encoded.size() + hpke::overhead(suite.aead), 0x00);
		// Занимаем место под тело расширения
		storage.push_back(vector <uint8_t> ());
		// Тело расширения ECH
		vector <uint8_t> & sealed = storage.back();
		// Если тело расширения составить не удалось
		if(ech::build(outward, sealed) != ech::error_t::NONE)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Добавляем расширение ECH перед вторым расширением GREASE, коли оно есть: то остаётся последним, как у BoringSSL
		greeting.extensions.insert(greeting.extensions.end() - (this->greased() ? 1 : 0), hello::extension_t(ech::ECH_EXTENSION, view_t(sealed.data(), sealed.size())));
		// Добавочные данные: внешнее приветствие с обнулённым шифротекстом
		vector <uint8_t> aad;
		// Отказ составления внешнего приветствия
		failure = translate(hello::build(greeting, aad, (this->_transport == context::transport_t::DATAGRAMS)), context::error_t::MESSAGE);
		// Если внешнее приветствие составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления
			return failure;
		// Шифротекст
		vector <uint8_t> payload;
		// Отказ шифрования закодированного приветствия
		const hpke::error_t enciphered = this->_sealer.seal(view_t(aad.data(), aad.size()), view_t(encoded.data(), encoded.size()), payload);
		// Если зашифровать не удалось
		if(enciphered != hpke::error_t::NONE)
			// Выводим отказ: нехватка памяти своим кодом, прочее - конфигурациями
			return ((enciphered == hpke::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::ECH);
		// Если длина шифротекста разошлась с местом
		if(payload.size() != outward.payload.size())
			// Выводим отказ конфигураций ECH
			return context::error_t::ECH;
		// Вписываем шифротекст в хвост тела расширения: оно кончается шифротекстом
		::memcpy(sealed.data() + (sealed.size() - payload.size()), payload.data(), payload.size());
		// Запоминаем публичное имя: по нему судится подлинность отвергшего сервера
		this->_public = config.name;
		// Если принятие ещё не подтверждено: приветствие предложено
		if(this->_ech != ech_t::ACCEPTED)
			// Запоминаем, что зашифрованное приветствие предложено
			this->_ech = ech_t::OFFERED;
		// Выводим успешность складывания
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод суждения о принятии ECH по приветствию сервера либо просьбе о повторе
 *
 * @param answer  разобранное приветствие сервера
 * @param message приветствие сервера вместе с обвязкой
 * @return        отказ суждения
 *
 */
context::error_t nts::internal::Engine::confirming(const hello::server_t & answer, const view_t & message) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Признак просьбы о повторе
		const bool retry = hello::retry(answer);
		// Место подтверждения внутри сообщения
		size_t offset = 0;
		// Если приветствие сервера: последние восемь байтов случайного значения
		if(!retry)
			// Место: обвязка, издание и первые двадцать четыре байта случайного значения
			offset = (handshake::HANDSHAKE_HEADER + 2 + (hello::HELLO_RANDOM - ech::ECH_CONFIRMATION));
		// Если просьба о повторе: тело расширения ECH
		else {
			// Расширение подтверждения
			const hello::extension_t * extension = hello::extension(answer.extensions, ech::ECH_EXTENSION);
			// Если расширения нет: сервер ECH отверг
			if(extension == nullptr){
				// Если принятие уже подтверждалось: сервер обязан подтверждать и дальше
				if(this->_ech == ech_t::ACCEPTED)
					// Выводим отказ сообщения
					return context::error_t::MESSAGE;
				// Запоминаем, что ECH отвергнут
				this->_ech = ech_t::REJECTED;
				// Выводим успешность суждения
				return context::error_t::NONE;
			}
			// Если подтверждение не в восемь байтов
			if(extension->data.size != ech::ECH_CONFIRMATION)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Место: тело расширения указывает в сообщение
			offset = static_cast <size_t> (extension->data.data - message.data);
		}
		// Если место в сообщение не входит
		if((offset + ech::ECH_CONFIRMATION) > message.size)
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Сообщение с обнулённым подтверждением
		vector <uint8_t> shaped(message.data, message.data + message.size);
		// Присланное подтверждение
		uint8_t presented[ech::ECH_CONFIRMATION];
		// Запоминаем присланное подтверждение
		::memcpy(presented, shaped.data() + offset, sizeof(presented));
		// Обнуляем место подтверждения
		::memset(shaped.data() + offset, 0x00, ech::ECH_CONFIRMATION);
		// Хеш набора шифрования связи
		const digest::hash_t algorithm = this->_transcript.algorithm();
		// Длина хеша
		const size_t width = digest::length(algorithm);
		// Место хеша переписки
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если переписка уже ведётся внутренним приветствием: просьба о повторе принята раньше
		if(this->_retried){
			// Если хеш переписки с обнулённым сообщением взять не удалось
			if(this->_transcript.digest(view_t(shaped.data(), shaped.size()), transcript) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
		// Если переписка ведётся внешним приветствием: хеш берётся с внутреннего отдельно
		} else {
			// Переписка внутреннего приветствия
			session::transcript_t shadow;
			// Если переписку завести не удалось
			if(shadow.start(algorithm) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Если внутреннее приветствие добавить не удалось
			if(shadow.update(view_t(this->_inner.data(), this->_inner.size())) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Раздел 4.4.1 RFC 8446: за просьбой о повторе первое приветствие идёт в переписке своим хешем
			if(retry && (shadow.replace() != session::error_t::NONE))
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Если хеш переписки с обнулённым сообщением взять не удалось
			if(shadow.digest(view_t(shaped.data(), shaped.size()), transcript) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
		}
		// Ожидаемое подтверждение
		uint8_t expected[ech::ECH_CONFIRMATION];
		// Если подтверждение вычислить не удалось
		if(!ech::confirmation(algorithm, view_t(this->_innerandom, sizeof(this->_innerandom)), view_t(transcript, width), retry, expected))
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Расхождение подтверждений: сличение постоянным временем
		uint8_t differing = 0;
		/**
		 * Выполняем перебор байтов подтверждения
		 */
		for(size_t i = 0; i < ech::ECH_CONFIRMATION; i++)
			// Накапливаем расхождение
			differing |= static_cast <uint8_t> (presented[i] ^ expected[i]);
		// Если подтверждение разошлось
		if(differing != 0){
			// Если принятие уже подтверждалось: сервер обязан подтверждать и дальше
			if(this->_ech == ech_t::ACCEPTED)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Запоминаем, что ECH отвергнут
			this->_ech = ech_t::REJECTED;
			// Выводим успешность суждения
			return context::error_t::NONE;
		}
		// Если переписка ведётся внешним приветствием: переводим её на внутреннее
		if(!this->_retried){
			// Начинаем переписку заново
			this->_transcript.start();
			// Если внутреннее приветствие добавить не удалось
			if(this->_transcript.update(view_t(this->_inner.data(), this->_inner.size())) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Если хеш переписки выбрать не удалось
			if(this->_transcript.select(algorithm) != session::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
		}
		// Предложенными становятся расширения внутреннего приветствия
		this->_offered = this->_hidden;
		// Случайное значение связи - внутреннее
		::memcpy(this->_random, this->_innerandom, sizeof(this->_random));
		// Запоминаем принятие
		this->_ech = ech_t::ACCEPTED;
		// Выводим успешность суждения
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод раскрытия зашифрованного приветствия ECH сервером
 *
 * @param greeting разобранное внешнее приветствие
 * @param body     тело внешнего приветствия
 * @param accepted место, в которое помещается признак принятия
 * @param inner    накопитель, в который помещается тело восстановленного внутреннего приветствия
 * @return         отказ раскрытия
 *
 */
context::error_t nts::internal::Engine::unshrouding(const hello::client_t & greeting, const view_t & body, bool & accepted, vector <uint8_t> & inner) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// ECH не принят, пока не доказано обратное
		accepted = false;
		// Расширение ECH внешнего приветствия
		const hello::extension_t * extension = hello::extension(greeting.extensions, ech::ECH_EXTENSION);
		// Если расширения нет
		if(extension == nullptr){
			// Раздел 7.1 RFC 9849: за принятой просьбой о повторе приветствие обязано нести ECH
			if(this->_retried && this->_echaccepted)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Выводим успешность: ECH не предлагалось
			return context::error_t::NONE;
		}
		// Разобранное расширение
		ech::hello_t hello;
		// Отказ разбора расширения
		const ech::error_t parsed = ech::parse(extension->data, hello);
		// Если памяти не хватило
		if(parsed == ech::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Раздел 7.1 RFC 9849: порченое расширение и внутренний вид во внешнем приветствии - illegal_parameter
		if((parsed != ech::error_t::NONE) || hello.inner)
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Добавочные данные: внешнее приветствие с обнулённым шифротекстом
		vector <uint8_t> aad;
		// Отказ составления добавочных данных
		const ech::error_t redacted = ech::redact(body, (this->_transport == context::transport_t::DATAGRAMS), aad);
		// Если добавочные данные составить не удалось
		if(redacted != ech::error_t::NONE)
			// Выводим отказ: нехватка памяти своим кодом, прочее - сообщением
			return ((redacted == ech::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::MESSAGE);
		// Закодированное внутреннее приветствие
		vector <uint8_t> encoded;
		// Если приветствие повторное за принятой просьбой о повторе: то же состояние HPKE, пустой enc
		if(this->_retried && this->_echaccepted){
			// Раздел 6.1.5 RFC 9849: повторное приветствие идёт с пустым enc тем же состоянием
			if(!hello.enc.empty() || !this->_opener.ready())
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
			// Если раскрыть не удалось: за принятой просьбой это обрыв
			if(this->_opener.open(view_t(aad.data(), aad.size()), view_t(hello.payload.data(), hello.payload.size()), encoded) != hpke::error_t::NONE)
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
		// Если приветствие первое: конфигурация подбирается по опознавателю и набору
		} else {
			/**
			 * Раздел 7.1.1 RFC 9849: если первое приветствие ECH не несло либо ECH был
			 * отвергнут, за просьбой о повторе связь идёт как обычная - свежий enc во втором
			 * приветствии не принимается, иначе первая половина переписки шла бы открытым
			 * именем, а вторая - скрытым
			 */
			if(this->_retried){
				// Запоминаем отказ ECH
				this->_echrejected = true;
				// Выводим успешность: связь идёт по внешнему приветствию
				return context::error_t::NONE;
			}
			// Служимая конфигурация, отвечающая опознавателю и набору приветствия
			const served_t * chosen = nullptr;
			/**
			 * Выполняем перебор служимых конфигураций: объявленные и удержанные равно годны
			 */
			for(size_t i = 0; (i < this->_serving.size()) && (chosen == nullptr); i++){
				// Если опознаватель не совпал
				if(this->_serving[i].config.id != hello.id)
					// Переходим к следующей конфигурации
					continue;
				/**
				 * Выполняем перебор наборов конфигурации
				 */
				for(size_t j = 0; (j < this->_serving[i].config.suites.size()) && (chosen == nullptr); j++){
					// Если набор совпал
					if((this->_serving[i].config.suites[j].kdf == hello.suite.kdf) && (this->_serving[i].config.suites[j].aead == hello.suite.aead))
						// Запоминаем конфигурацию
						chosen = &this->_serving[i];
				}
			}
			// Если конфигурации по опознавателю и набору нет либо ключ негодной длины: ECH отвергается
			if((chosen == nullptr) || (hello.enc.size() != hpke::overhead(chosen->config.kem))){
				// Запоминаем отказ ECH: клиент получит запасные конфигурации
				this->_echrejected = true;
				// Выводим успешность: связь идёт по внешнему приветствию
				return context::error_t::NONE;
			}
			// Привязка HPKE
			vector <uint8_t> info;
			// Если привязку составить не удалось
			if(ech::binding(view_t(chosen->config.raw.data(), chosen->config.raw.size()), info) != ech::error_t::NONE)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Набор HPKE
			hpke::suite_t item;
			// Способ инкапсуляции
			item.kem = chosen->config.kem;
			// Функция вывода
			item.kdf = hello.suite.kdf;
			// Шифр
			item.aead = hello.suite.aead;
			// Отказ заведения получателя HPKE
			const hpke::error_t established = hpke::recipient(item, hpke::regime_t::BASE, chosen->key, view_t(hello.enc.data(), hello.enc.size()), view_t(info.data(), info.size()), hpke::shared_t(), view_t(nullptr, 0), this->_opener);
			// Если памяти не хватило
			if(established == hpke::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return context::error_t::MEMORY;
			// Если получателя завести либо шифротекст раскрыть не удалось: ECH отвергается
			if((established != hpke::error_t::NONE) || (this->_opener.open(view_t(aad.data(), aad.size()), view_t(hello.payload.data(), hello.payload.size()), encoded) != hpke::error_t::NONE)){
				// Сбрасываем получателя
				this->_opener.clear();
				// Запоминаем отказ ECH
				this->_echrejected = true;
				// Выводим успешность: связь идёт по внешнему приветствию
				return context::error_t::NONE;
			}
		}
		// Отказ восстановления внутреннего приветствия
		const ech::error_t decoded = ech::decode(view_t(encoded.data(), encoded.size()), greeting, (this->_transport == context::transport_t::DATAGRAMS), inner);
		// Если памяти не хватило
		if(decoded == ech::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		// Раздел 7.1 RFC 9849: раскрытое, но негодное приветствие - illegal_parameter
		if(decoded != ech::error_t::NONE)
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Восстановленное приветствие
		hello::client_t restored;
		// Разбор восстановленного приветствия
		const hello::error_t restoring = hello::parse(view_t(inner.data(), inner.size()), restored, (this->_transport == context::transport_t::DATAGRAMS));
		/**
		 * Нехватка памяти при разборе не есть порча сообщения: собеседник ни при чём,
		 * и извещение illegal_parameter ему слать нельзя - отказ идёт как MEMORY
		 */
		if(restoring != hello::error_t::NONE)
			// Выводим отказ сообщения либо нехватку памяти
			return ((restoring == hello::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::MESSAGE);
		// Расширение ECH внутреннего приветствия
		const hello::extension_t * inward = hello::extension(restored.extensions, ech::ECH_EXTENSION);
		// Разобранное внутреннее расширение
		ech::hello_t mark;
		// Раздел 7.1 RFC 9849: внутреннее приветствие обязано нести ECH внутреннего вида
		if(inward == nullptr)
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Разбор внутреннего расширения ECH
		const ech::error_t marking = ech::parse(inward->data, mark);
		// Если расширение не разобралось либо оно не внутреннего вида
		if((marking != ech::error_t::NONE) || !mark.inner)
			// Выводим отказ сообщения либо нехватку памяти
			return ((marking == ech::error_t::MEMORY) ? context::error_t::MEMORY : context::error_t::MESSAGE);
		// Расширение изданий внутреннего приветствия
		const hello::extension_t * versions = hello::extension(restored.extensions, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Перечень изданий
		vector <uint16_t> editions;
		// Раздел 6.1 RFC 9849: внутреннее приветствие предлагает лишь издание 1.3
		if((versions == nullptr) || (extension::versions(versions->data, editions) != extension::error_t::NONE))
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		/**
		 * Выполняем перебор изданий
		 */
		for(size_t i = 0; i < editions.size(); i++){
			// Если издание не 1.3 и не значение GREASE
			if((editions[i] != this->edition()) && !fingerprint::grease(editions[i]))
				// Выводим отказ сообщения
				return context::error_t::MESSAGE;
		}
		// Запоминаем случайное значение внутреннего приветствия: им судится подтверждение
		::memcpy(this->_innerandom, restored.random, sizeof(this->_innerandom));
		// Запоминаем принятие
		this->_echaccepted = true;
		// Отказ ECH снимается
		this->_echrejected = false;
		// Выводим принятие
		accepted = true;
		// Выводим успешность раскрытия
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод вписывания подтверждения принятия ECH в приветствие сервера либо просьбу о повторе
 *
 * @param body  тело сообщения сервера с местом подтверждения
 * @param retry признак просьбы о повторе
 * @return      отказ вписывания
 *
 */
context::error_t nts::internal::Engine::marking(vector <uint8_t> & body, const bool retry) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Место подтверждения: у приветствия - хвост случайного значения, у просьбы - хвост тела (расширение последнее)
		const size_t offset = (retry ? (body.size() - ech::ECH_CONFIRMATION) : (2 + (hello::HELLO_RANDOM - ech::ECH_CONFIRMATION)));
		// Если место в тело не входит
		if(body.size() < (offset + ech::ECH_CONFIRMATION))
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Обнуляем место подтверждения
		::memset(body.data() + offset, 0x00, ech::ECH_CONFIRMATION);
		// Объект составителя сообщения рукопожатия
		handshake::writer_t writer;
		// Отказ составления сообщения с обвязкой
		const context::error_t failure = translate(writer.push(handshake::type_t::SERVER, view_t(body.data(), body.size())), context::error_t::MESSAGE);
		// Если сообщение составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления
			return failure;
		// Место хеша переписки
		uint8_t transcript[schedule::SCHEDULE_WIDEST];
		// Если хеш переписки с обнулённым сообщением взять не удалось
		if(this->_transcript.digest(writer.data(), transcript) != session::error_t::NONE)
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Подтверждение
		uint8_t confirmation[ech::ECH_CONFIRMATION];
		// Если подтверждение вычислить не удалось
		if(!ech::confirmation(this->_transcript.algorithm(), view_t(this->_innerandom, sizeof(this->_innerandom)), view_t(transcript, this->_transcript.size()), retry, confirmation))
			// Выводим отказ сообщения
			return context::error_t::MESSAGE;
		// Вписываем подтверждение
		::memcpy(body.data() + offset, confirmation, sizeof(confirmation));
		// Если подтверждение вписано в приветствие: случайное значение связи меняется вместе с ним
		if(!retry)
			// Переносим подтверждение в случайное значение
			::memcpy(this->_random + (hello::HELLO_RANDOM - ech::ECH_CONFIRMATION), confirmation, sizeof(confirmation));
		// Выводим успешность вписывания
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки, задан ли профиль отпечатка
 *
 * @return признак того, что приветствие клиента складывается по профилю
 *
 */
bool nts::internal::Engine::profiled() const noexcept {
	// Выводим признак профиля
	return this->_profiled;
}
/**
 * @brief Метод получения принятого сервером приветствия клиента
 *
 * @return байты приветствия клиента вместе с обвязкой рукопожатия
 *
 */
const vector <uint8_t> & nts::internal::Engine::received() const noexcept {
	// Выводим принятое приветствие
	return this->_salutation;
}
/**
 * @brief Метод складывания приветствия клиента по профилю отпечатка
 *
 * @param greeting   приветствие, сложенное умолчанием движка; перекладывается по профилю
 * @param name       тело расширения имени узла, сложенное движком
 * @param protocols  тело расширения прикладных протоколов, сложенное движком
 * @param algorithms тело расширения алгоритмов сжатия цепочки, сложенное движком
 * @param modes      тело расширения способов обмена ключом при предъявлении билета
 * @param secret     тело расширения заранее разделённых ключей при предъявлении билета
 * @param resume     признак предъявления билета возобновления
 * @param storage    хранилище тел расширений, сложенных по профилю
 * @return           отказ складывания приветствия
 *
 */
context::error_t nts::internal::Engine::imitate(hello::client_t & greeting, const vector <uint8_t> & name, const vector <uint8_t> & protocols, const vector <uint8_t> & algorithms, const vector <uint8_t> & modes, const vector <uint8_t> & secret, const bool resume, vector <vector <uint8_t>> & storage) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Заполнение по RFC 7685
		static constexpr uint16_t PADDING = 0x0015;
		// Зашифрованное приветствие: до появления настоящего ECH идёт значением GREASE случайным телом
		static constexpr uint16_t ECH = 0xFE0D;
		// Виды расширений профиля, идущие в приветствие
		vector <uint16_t> types;
		// Тела расширений профиля, идущие в приветствие
		vector <view_t> bodies;
		// Признак присутствия заполнения в профиле и его место
		bool padded = false;
		// Место заполнения среди расширений приветствия
		size_t place = 0;
		// Сбрасываем предложенные пределы длины записи: их заново диктует профиль
		this->_bounded = 0;
		// Сбрасываем предложенный код длины записи max_fragment_length
		this->_fragmented = 0;
		// Поверх записей издание приветствия берётся из профиля; поверх дейтаграмм - своё
		if(this->_transport != context::transport_t::DATAGRAMS)
			// Устанавливаем издание приветствия профиля
			greeting.version = this->_profile.version;
		// Запоминаем издание заголовка приветствия: оно идёт в общее значение обмена RSA
		this->_claimed = greeting.version;
		// Устанавливаем способы сжатия профиля
		greeting.methods = this->_profile.methods;
		// Выполняем сброс наборов, сложенных умолчанием
		greeting.suites.clear();
		/**
		 * Выполняем перебор наборов профиля
		 */
		for(size_t i = 0; i < this->_profile.suites.size(); i++){
			// Набор профиля по проводу
			const uint16_t suite = static_cast <uint16_t> (this->_profile.suites[i]);
			// Добавляем набор: значение GREASE - своё и свежее, прочие - как записаны
			greeting.suites.push_back(fingerprint::grease(suite) ? this->greasing(grease_t::SUITE) : suite);
		}
		// Хранилище занимает место заранее: указатели на тела не должны переезжать (заполнение, публичное имя и ECH - три места)
		storage.reserve(this->_profile.extensions.size() + 5);
		// Счётчик расширений GREASE профиля
		size_t greased = 0;
		/**
		 * Выполняем перебор расширений профиля
		 */
		for(size_t i = 0; i < this->_profile.extensions.size(); i++){
			// Расширение профиля
			const fingerprint::extension_t & extension = this->_profile.extensions[i];
			// Вид расширения приветствия
			uint16_t type = extension.type;
			// Тело расширения приветствия: по умолчанию как записано
			view_t body(extension.data.data(), extension.data.size());
			// Если расширение есть значение GREASE
			if(extension.grease){
				// Первое значение GREASE - своё первое, прочие - своё второе
				type = this->greasing((greased == 0) ? grease_t::FIRST : grease_t::SECOND);
				// Считаем расширение GREASE
				greased++;
			// Если расширение обычное
			} else {
				/**
				 * Определяем вид расширения
				 */
				switch(type){
					// Имя узла: своё, а без имени расширение не идёт
					case static_cast <uint16_t> (extension::type_t::NAME): {
						// Если имя узла не задано
						if(name.empty())
							// Переходим к следующему расширению
							continue;
						// Тело имени узла, сложенное движком
						body = view_t(name.data(), name.size());
					} break;
					// Прикладные протоколы: свои, если заданы потребителем
					case static_cast <uint16_t> (extension::type_t::PROTOCOLS): {
						// Если протоколы сложены движком
						if(!protocols.empty())
							// Тело протоколов, сложенное движком
							body = view_t(protocols.data(), protocols.size());
					} break;
					// Алгоритмы сжатия цепочки: свои, если заданы потребителем
					case static_cast <uint16_t> (extension::type_t::COMPRESS): {
						// Если алгоритмы сложены движком
						if(!algorithms.empty())
							// Тело алгоритмов, сложенное движком
							body = view_t(algorithms.data(), algorithms.size());
					} break;
					// Группы обмена ключами: как записаны, значения GREASE свои
					case static_cast <uint16_t> (extension::type_t::GROUPS): {
						// Группы приветствия
						vector <extension::group_t> groups;
						/**
						 * Выполняем перебор групп профиля
						 */
						for(size_t j = 0; j < extension.groups.size(); j++)
							// Добавляем группу: значение GREASE - своё
							groups.push_back(fingerprint::grease(static_cast <uint16_t> (extension.groups[j])) ? static_cast <extension::group_t> (this->greasing(grease_t::GROUP)) : extension.groups[j]);
						// Занимаем место под тело
						storage.push_back(vector <uint8_t> ());
						// Отказ составления перечня групп
						const context::error_t failure = translate(extension::groups(groups, storage.back()), context::error_t::MESSAGE);
						// Если перечень групп составить не удалось
						if(failure != context::error_t::NONE)
							// Выводим отказ составления расширения
							return failure;
						// Тело групп
						body = view_t(storage.back().data(), storage.back().size());
					} break;
					// Издания протокола: как записаны, значения GREASE свои
					case static_cast <uint16_t> (extension::type_t::VERSIONS): {
						// Издания приветствия
						vector <uint16_t> editions;
						/**
						 * Выполняем перебор изданий профиля
						 */
						for(size_t j = 0; j < extension.versions.size(); j++){
							// Раздел 6.1 RFC 9849: с конфигурациями ECH издания ниже 1.3 в приветствие не идут (GREASE остаётся)
							if(!this->_configs.empty() && !fingerprint::grease(extension.versions[j]) && (extension.versions[j] != MODERN) && (extension.versions[j] != datagram::DATAGRAM_VERSION))
								// Переходим к следующему изданию
								continue;
							// Добавляем издание: значение GREASE - своё
							editions.push_back(fingerprint::grease(extension.versions[j]) ? this->greasing(grease_t::VERSION) : extension.versions[j]);
						}
						// Занимаем место под тело
						storage.push_back(vector <uint8_t> ());
						// Отказ составления перечня изданий
						const context::error_t failure = translate(extension::versions(editions, storage.back()), context::error_t::MESSAGE);
						// Если перечень изданий составить не удалось
						if(failure != context::error_t::NONE)
							// Выводим отказ составления расширения
							return failure;
						// Тело изданий
						body = view_t(storage.back().data(), storage.back().size());
					} break;
					// Доли ключа: свои свежие по записанным группам, GREASE своё, неведомые группы опускаются
					case static_cast <uint16_t> (extension::type_t::SHARE): {
						// Доли приветствия
						vector <extension::share_t> shares;
						/**
						 * Раздел 4.2.8 RFC 8446: за просьбой о повторе с долей приветствие несёт долю
						 * по одной лишь запрошенной группе - её выработал движок, а профиль тут не судья
						 */
						if(this->_retried && this->_reshare){
							/**
							 * Выполняем перебор мимолётных пар ключей своей стороны
							 */
							for(size_t k = 0; k < this->_exchanges.size(); k++)
								// Добавляем свою долю по запрошенной группе
								shares.push_back(extension::share_t(this->_exchanges[k].group, view_t(this->_exchanges[k].opened.data(), this->_exchanges[k].opened.size())));
						}
						/**
						 * Выполняем перебор долей профиля
						 */
						for(size_t j = 0; (j < extension.shares.size()) && !(this->_retried && this->_reshare); j++){
							// Группа доли по проводу
							const uint16_t group = static_cast <uint16_t> (extension.shares[j].group);
							// Если доля есть значение GREASE
							if(fingerprint::grease(group)){
								// Раздел 4.2.8 RFC 8446: за просьбой о повторе с долей идёт лишь запрошенная доля
								if(!(this->_retried && this->_reshare))
									// Добавляем долю GREASE своим значением и телом в один байт
									shares.push_back(extension::share_t(static_cast <extension::group_t> (this->greasing(grease_t::GROUP)), view_t(GREASE_STUB, sizeof(GREASE_STUB))));
								// Переходим к следующей доле
								continue;
							}
							/**
							 * Выполняем перебор мимолётных пар ключей своей стороны
							 */
							for(size_t k = 0; k < this->_exchanges.size(); k++){
								// Если пара ключей выработана по группе доли
								if(this->_exchanges[k].group == extension.shares[j].group){
									// Добавляем свою долю
									shares.push_back(extension::share_t(this->_exchanges[k].group, view_t(this->_exchanges[k].opened.data(), this->_exchanges[k].opened.size())));
									// Выходим из перебора
									break;
								}
							}
						}
						// Занимаем место под тело
						storage.push_back(vector <uint8_t> ());
						// Отказ составления перечня долей
						const context::error_t failure = translate(extension::shares(shares, storage.back()), context::error_t::MESSAGE);
						// Если перечень долей составить не удалось
						if(failure != context::error_t::NONE)
							// Выводим отказ составления расширения
							return failure;
						// Тело долей
						body = view_t(storage.back().data(), storage.back().size());
					} break;
					// Метка возврата состояния сервера: лишь полученная
					case static_cast <uint16_t> (extension::type_t::COOKIE): {
						// Если метка не получена
						if(this->_cookie.empty())
							// Переходим к следующему расширению
							continue;
						// Тело метки
						body = view_t(this->_cookie.data(), this->_cookie.size());
					} break;
					// Способы обмена ключом: при предъявлении билета - свои
					case static_cast <uint16_t> (extension::type_t::MODES): {
						// Если билет предъявляется
						if(resume)
							// Тело способов, сложенное движком
							body = view_t(modes.data(), modes.size());
					} break;
					// Заранее разделённые ключи: лишь при предъявлении билета, и последними
					case static_cast <uint16_t> (extension::type_t::SECRET):
					// Упреждающие данные: лишь по логике движка
					case static_cast <uint16_t> (extension::type_t::EARLY):
						// Переходим к следующему расширению
						continue;
					// Билет сеанса издания 1.2: предъявляется движком, иначе пустым
					case static_cast <uint16_t> (extension::type_t::TICKET):
						// Тело билета
						body = (this->_presented ? view_t(this->_resume.identity.data(), this->_resume.identity.size()) : view_t(nullptr, 0));
					break;
					// Прикладные настройки ALPS: перечень протоколов с настройками, сложенный движком
					case static_cast <uint16_t> (extension::type_t::SETTINGS):
					case static_cast <uint16_t> (extension::type_t::SETTINGS_OLD): {
						// Если настройки не объявлены либо прикладные протоколы не предлагаются
						if(this->_settings.empty() || this->_protocols.empty())
							// Переходим к следующему расширению
							continue;
						// Перечень протоколов, для которых настройки объявлены
						vector <string> names;
						/**
						 * Выполняем перебор объявленных прикладных настроек
						 */
						for(size_t j = 0; j < this->_settings.size(); j++)
							// Добавляем протокол в перечень
							names.push_back(this->_settings[j].protocol);
						// Заводим хранилище тела расширения
						storage.push_back(vector <uint8_t> ());
						// Отказ составления перечня протоколов с настройками
						const context::error_t composed = translate(extension::protocols(names, storage.back()), context::error_t::SETTINGS);
						// Если перечень протоколов с настройками составить не удалось
						if(composed != context::error_t::NONE)
							// Выводим отказ складывания приветствия
							return composed;
						// Точка кода - та, которой ведётся связь
						type = this->_codepoint;
						// Тело перечня, сложенное движком
						body = view_t(storage.back().data(), storage.back().size());
					} break;
					// Если профиль предлагает предел record_size_limit, запоминаем значение: ответ сервера нас обяжет (RFC 8449)
					case static_cast <uint16_t> (extension::type_t::LIMIT): {
						// Если тело двухбайтовое, запоминаем значение
						if(extension.data.size() == 2)
							// Запоминаем предложенный предел
							this->_bounded = static_cast <uint16_t> ((static_cast <uint16_t> (extension.data[0]) << 8) | extension.data[1]);
					} break;
					// Если профиль предлагает длину max_fragment_length, запоминаем код: ответ сервера нас обяжет (RFC 6066)
					case static_cast <uint16_t> (extension::type_t::FRAGMENT): {
						// Если тело однобайтовое, запоминаем код
						if(extension.data.size() == 1)
							// Запоминаем предложенный код
							this->_fragmented = extension.data[0];
					} break;
					// Параметры переноса QUIC: лишь по уровням
					case TRANSPORT: {
						// Если перенос не по уровням
						if(this->_transport != context::transport_t::LEVELS)
							// Переходим к следующему расширению
							continue;
						// Тело параметров переноса
						body = view_t(this->_parameters.data(), this->_parameters.size());
					} break;
					// Заполнение: место запоминается, длина считается по итогу
					case PADDING: {
						// Запоминаем присутствие и место заполнения
						padded = true;
						// Запоминаем место
						place = types.size();
						// Переходим к следующему расширению
						continue;
					}
					// Зашифрованное приветствие: значение GREASE случайным телом записанной длины
					case ECH: {
						/**
						 * Раздел 6.2 RFC 9849: при настоящих конфигурациях ECH расширение
						 * складывает shrouding() - значение GREASE из профиля на его место не
						 * идёт, иначе приветствие несло бы два расширения одного вида
						 */
						if(!this->_configs.empty())
							// Переходим к следующему расширению
							continue;
						// Занимаем место под тело
						storage.push_back(vector <uint8_t> (extension.data.size(), 0));
						// Если тело выработать не удалось
						if(!storage.back().empty() && !entropy::bytes(storage.back().data(), storage.back().size()))
							// Выводим отказ настроек связи
							return context::error_t::SETTINGS;
						// Тело значения GREASE ECH
						body = view_t(storage.back().data(), storage.back().size());
					} break;
					// Прочие расширения идут как записаны
					default: break;
				}
			}
			// Добавляем вид расширения
			types.push_back(type);
			// Добавляем тело расширения
			bodies.push_back(body);
		}
		// Если билет предъявляется: заранее разделённые ключи идут последними (раздел 4.2.11 RFC 8446)
		if(resume){
			// Добавляем вид расширения
			types.push_back(static_cast <uint16_t> (extension::type_t::SECRET));
			// Добавляем тело расширения
			bodies.push_back(view_t(secret.data(), secret.size()));
		}
		// Выполняем сброс расширений, сложенных умолчанием
		greeting.extensions.clear();
		/**
		 * Выполняем перебор расширений профиля
		 */
		for(size_t i = 0; i < types.size(); i++)
			// Добавляем расширение в приветствие
			greeting.extensions.push_back(hello::extension_t(types[i], bodies[i]));
		// Если заполнение профилем не предусмотрено
		if(!padded)
			// Выводим успешность складывания
			return context::error_t::NONE;
		// Накопитель, в который складывается приветствие без заполнения
		vector <uint8_t> body;
		// Отказ составления приветствия без заполнения
		const context::error_t failure = translate(hello::build(greeting, body, (this->_transport == context::transport_t::DATAGRAMS)), context::error_t::MESSAGE);
		// Если приветствие без заполнения составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия
			return failure;
		/**
		 * RFC 7685 правилом BoringSSL: приветствие длиной с обвязкой от 256 до 511 байтов
		 * дополняется до 512; длина заполнения считается без четырёх байтов его обвязки
		 */
		const size_t total = (body.size() + ((this->_transport == context::transport_t::DATAGRAMS) ? 12 : 4));
		// Длина заполнения
		size_t length = 0;
		// Если приветствие подлежит заполнению
		if((total > 0xFF) && (total < 0x200)){
			// Считаем длину заполнения с обвязкой
			length = (0x200 - total);
			// Если заполнение вмещает свою обвязку
			if(length >= 5)
				// Снимаем обвязку с длины
				length -= 4;
			// Если заполнение обвязки не вмещает
			else length = 1;
		}
		// Занимаем место под заполнение
		storage.push_back(vector <uint8_t> (length, 0));
		// Вставляем заполнение на записанное место
		greeting.extensions.insert(greeting.extensions.begin() + static_cast <ptrdiff_t> (place), hello::extension_t(PADDING, view_t(storage.back().data(), storage.back().size())));
		// Выводим успешность складывания
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки согласованного порядка «шифрование, затем имитовставка»
 *
 * @return признак того, что записи CBC идут в порядке encrypt_then_mac RFC 7366
 *
 */
bool nts::internal::Engine::etm() const noexcept {
	// Выводим согласованный порядок
	return this->_etm;
}
/**
 * @brief Метод установки ключа билетов сеансов сервера издания TLS 1.2
 *
 * @param secret секрет любой длины
 *
 */
void nts::internal::Engine::vault(const vector <uint8_t> & secret) noexcept {
	// Выполняем заведение ключа билетов из секрета хранителем: отказ оставляет ключ прежним
	(void) this->_keeper.stash(view_t(secret.data(), secret.size()));
}
/**
 * @brief Метод суждения клиента о сокращённом рукопожатии по первому сообщению за приветствием сервера
 *
 * @param resumed сокращённое ли рукопожатие
 * @return        отказ вывода ключевого материала возобновлённой связи
 *
 */
context::error_t nts::internal::Engine::deciding(const bool resumed) noexcept {
	// Запоминаем вид рукопожатия
	this->_resumed = resumed;
	// Если рукопожатие полное: билет сервером не признан, за приветствием идёт цепочка либо обмен ключами
	if(!resumed){
		// Выполняем затирание главного секрета билета: он не пригодился
		this->purge(this->_keys->master, sizeof(this->_keys->master));
		// Переходим к ожиданию цепочки сертификатов либо обмена ключами у наборов PSK
		this->_phase = (preshared(this->_suite) ? phase_t::AGREEMENT : phase_t::CERTIFICATE);
		// Выводим успешность суждения
		return context::error_t::NONE;
	}
	// Раздел 3.4 RFC 5077: набор возобновлённой связи обязан сойтись с набором билета
	if(this->_suite != this->_resume.suite)
		// Выводим отказ несовпадения набора шифрования
		return context::error_t::SUITE;
	// Раздел 3.4 RFC 5077 и E.1 RFC 5246: билет годен лишь изданию выдачи - главный секрет под иной PRF не идёт
	if(this->_ancient != this->_resume.ancient)
		// Выводим отказ несовпадения издания
		return context::error_t::VERSION;
	// Раздел 3.1 RFC 7366: порядок защиты записей возобновлённой связи обязан сойтись с порядком выдавшей билет - понижения нет
	if(this->_etm != this->_resume.etm)
		// Выводим отказ порядка «шифрование, затем имитовставка»
		return context::error_t::ETM;
	// Запоминаем, что связь возобновлена билетом
	this->_shared = true;
	// Раздел 3.3 RFC 5077: за приветствием сервера идут билет (если обещан), смена набора и завершение сервера
	this->_phase = phase_t::CHANGE;
	// Выводим итог вывода ключевого материала связи из главного секрета билета
	return this->keying();
}
/**
 * @brief Метод установки журнала секретов связи
 *
 * @param keylog журнал секретов: вызов и контекст потребителя
 *
 */
void nts::internal::Engine::keylog(const context::keylog_t & keylog) noexcept {
	// Запоминаем журнал секретов
	this->_keylog = keylog;
}
/**
 * @brief Метод вызова журнала секретов связи
 *
 * @param label  метка записи
 * @param secret секрет связи
 *
 */
void nts::internal::Engine::keylog(const char * label, const view_t & secret) const noexcept {
	// Если журнал не установлен
	if(this->_keylog.log == nullptr)
		// Выходим
		return;
	// Выбираем client_random: у клиента своё приветствие, у сервера - приветствие собеседника
	const view_t random = (this->_server ? view_t(this->_foreign, sizeof(this->_foreign)) : view_t(this->_random, sizeof(this->_random)));
	// Вызываем журнал
	this->_keylog.log(label, random, secret, this->_keylog.context);
}
/**
 * @brief Метод установки закреплённого сырого открытого ключа собеседника
 *
 * @param pinned закреплённый ключ SPKI DER; пустой - проверка X.509
 *
 */
void nts::internal::Engine::pinned(const view_t & pinned) noexcept {
	// Выполняем перехват ошибок работы с памятью
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем закреплённый ключ
		this->_pinned.assign(pinned.data, pinned.data + pinned.size);
	// Если памяти под ключ не хватило
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Оставляем ключ пустым
		this->_pinned.clear();
	}
}
/**
 * @brief Метод получения согласованного вида сертификата собеседника
 *
 * @return вид сертификата: X.509 либо RawPublicKey
 *
 */
nts::extension::cert_t nts::internal::Engine::certtype() const noexcept {
	// Выводим согласованный вид сертификата
	return this->_certtype;
}
/**
 * @brief Метод установки пределов издания протокола
 *
 * @param lowest  наименьшее дозволенное издание: 0x0303 либо 0x0304
 * @param highest наибольшее дозволенное издание: 0x0303 либо 0x0304
 * @return        отказ установки пределов издания протокола
 *
 */
context::error_t nts::internal::Engine::versions(const uint16_t lowest, const uint16_t highest) noexcept {
	// Пределы переставляются лишь до заведения связи: живой связи издание уже согласовано
	if(this->_state != context::state_t::NONE)
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	/**
	 * Ниже TLS 1.2 связь не опускается никогда, выше TLS 1.3 изданий нет, а перевёрнутые
	 * пределы не оставляют ни одного издания
	 */
	if((lowest < ANCIENT) || (highest > MODERN) || (lowest > highest))
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	/**
	 * Раздел 6.1 RFC 9849: с заданными конфигурациями ECH связь ведёт лишь издание 1.3, и
	 * предел ниже него - отказ, а не молчаливое опускание: иначе связь уехала бы по 1.2 к
	 * серверу публичного имени без единого признака (находка внешнего щупа)
	 */
	if(!this->_configs.empty() && (lowest < MODERN))
		// Выводим отказ настроек связи
		return context::error_t::SETTINGS;
	// Устанавливаем наименьшее дозволенное издание
	this->_lowest = lowest;
	// Устанавливаем наибольшее дозволенное издание
	this->_highest = highest;
	// Выводим успешность установки пределов
	return context::error_t::NONE;
}
/**
 * @brief Метод получения наименьшего дозволенного издания протокола
 *
 * @return наименьшее дозволенное издание протокола
 *
 */
uint16_t nts::internal::Engine::lowest() const noexcept {
	// Выводим наименьшее дозволенное издание протокола
	return this->_lowest;
}
/**
 * @brief Метод получения наибольшего дозволенного издания протокола
 *
 * @return наибольшее дозволенное издание протокола
 *
 */
uint16_t nts::internal::Engine::highest() const noexcept {
	// Выводим наибольшее дозволенное издание протокола
	return this->_highest;
}
/**
 * @brief Метод получения издания протокола, согласованного сторонами
 *
 * @return согласованное издание протокола кодом TLS 0x0303 либо 0x0304 на любом переносе, ноль до согласования
 *
 */
uint16_t nts::internal::Engine::version() const noexcept {
	// Выводим согласованное издание протокола: поверх дейтаграмм проводные 0xFEFD/0xFEFC наружу не показываются
	return this->_version;
}
/**
 * @brief Метод установки порядка выбора набора шифрования и кривой обмена ключами
 *
 * @param own выбираются ли набор и кривая порядком сервера, а не клиента
 *
 */
void nts::internal::Engine::preference(const bool own) noexcept {
	// Устанавливаем порядок выбора набора шифрования и кривой обмена ключами
	this->_own = own;
}
/**
 * @brief Метод получения издания протокола, согласуемого связью
 *
 * @return 0x0304 у TLS 1.3 и 0xFEFC у DTLS 1.3
 *
 */
uint16_t nts::internal::Engine::edition() const noexcept {
	// Выводим издание протокола по способу переноса
	return ((this->_transport == context::transport_t::DATAGRAMS) ? datagram::DATAGRAM_VERSION : 0x0304);
}
/**
 * @brief Метод получения издания 1.2 протокола по способу переноса
 *
 * @return 0x0303 у TLS 1.2 и 0xFEFD у DTLS 1.2
 *
 */
uint16_t nts::internal::Engine::elder() const noexcept {
	// Выводим издание 1.2 по способу переноса
	return ((this->_transport == context::transport_t::DATAGRAMS) ? datagram::DATAGRAM_LEGACY : LEGACY);
}
/**
 * @brief Метод получения издания 1.1 протокола по способу переноса: DTLS 1.0
 *
 * @return 0x0302 у TLS 1.1 и 0xFEFF у DTLS 1.0
 *
 */
uint16_t nts::internal::Engine::eldest() const noexcept {
	// Выводим издание: RFC 4347 кладёт DTLS 1.0 значение 0xFEFF
	return ((this->_transport == context::transport_t::DATAGRAMS) ? static_cast <uint16_t> (record::version_t::DTLS10) : ANCIENT);
}
/**
 * @brief Метод выработки хеша переписки изданием 1.1: MD5 ‖ SHA-1 накопленных сообщений
 *
 * @param result место в 36 байтов, в которое помещается хеш
 * @return       признак успешности выработки
 *
 */
bool nts::internal::Engine::archive(uint8_t * result) const noexcept {
	// Переписка, накопленная сообщениями как записаны
	const view_t history(this->_history.data(), this->_history.size());
	// Выводим итог выработки: раздел 7.4.9 RFC 4346 велит MD5, затем SHA-1
	return (digest::hash(digest::hash_t::MD5, history, result, 16) && digest::hash(digest::hash_t::SHA1, history, result + 16, 20));
}
/**
 * @brief Метод выработки псевдослучайной последовательности по изданию связи
 *
 * @param key    секрет
 * @param label  метка
 * @param seed   семя
 * @param result место, в которое помещается последовательность
 * @param size   длина последовательности
 * @return       признак успешности выработки
 *
 */
bool nts::internal::Engine::sequencing(const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) const noexcept {
	// Раздел 5 RFC 4346: изданием 1.1 PRF идёт на MD5 ⊕ SHA-1, изданием 1.2 - на хеше набора (раздел 5 RFC 5246)
	return (this->_ancient ? digest::legacy(key, label, seed, result, size) : digest::prf(protect::hash(this->_suite), key, label, seed, result, size));
}
/**
 * @brief Метод получения хеша переписки по изданию связи
 *
 * @param result место, в которое помещается хеш
 * @param size   место, в которое помещается длина хеша
 * @return       признак успешности выработки
 *
 */
bool nts::internal::Engine::digesting(uint8_t * result, size_t & size) const noexcept {
	// Если связь ведётся изданием 1.1
	if(this->_ancient){
		// Длина хеша MD5 ‖ SHA-1
		size = 36;
		// Выводим итог выработки хеша переписки изданием 1.1
		return this->archive(result);
	}
	// Длина хеша набора
	size = this->_transcript.size();
	// Выводим итог выработки хеша переписки хешем набора
	return (this->_transcript.digest(result) == session::error_t::NONE);
}
/**
 * @brief Метод выработки подписи изданием 1.1: RSA над MD5 ‖ SHA-1 без DigestInfo, ECDSA над SHA-1
 *
 * @param content   подписываемое содержимое
 * @param signature накопитель, в который помещается подпись
 * @return          отказ выработки подписи
 *
 */
context::error_t nts::internal::Engine::engraving(const view_t & content, vector <uint8_t> & signature) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Подготовленный ключ своей подлинности
		const keys::signer_t * signer = nullptr;
		// Отказ подготовки ключа
		const context::error_t failure = this->signer(signer);
		// Если ключ подготовить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ подготовки ключа
			return failure;
		// Если ключ RSA
		if(signer->kind() == keys::kind_t::RSA){
			// Модуль подписи RSA подготовленного ключа
			const sign::rsa_t & rsa = signer->rsa();
			// Хеш MD5 ‖ SHA-1 содержимого
			uint8_t digest[36];
			// Раздел 7.4.3 RFC 4346: RSA подписывает MD5 ‖ SHA-1 без DigestInfo
			if(!digest::hash(digest::hash_t::MD5, content, digest, 16) || !digest::hash(digest::hash_t::SHA1, content, digest + 16, 20))
				// Выводим отказ выработки подписи
				return context::error_t::SIGNATURE;
			// Занимаем место под подпись размером в модуль
			signature.assign(rsa.size(), 0);
			// Если подпись выработать не удалось
			if(!rsa.make(sign::scheme_t::PKCS1, digest::hash_t::NONE, view_t(digest, sizeof(digest)), signature.data(), SIZE_MAX, view_t()))
				// Выводим отказ выработки подписи
				return context::error_t::SIGNATURE;
			// Сообщаем об успешной выработке подписи
			return context::error_t::NONE;
		}
		// Если ключ не ECDSA
		if(signer->kind() != keys::kind_t::EC)
			// Выводим отказ выработки подписи
			return context::error_t::SIGNATURE;
		// Модуль подписи ECDSA подготовленного ключа
		const sign::ecdsa_t & ecdsa = signer->ecdsa();
		// Хеш SHA-1 содержимого
		uint8_t digest[20];
		// Раздел 5.4 RFC 4492: ECDSA изданием 1.1 подписывает SHA-1
		if(!digest::hash(digest::hash_t::SHA1, content, digest, sizeof(digest)))
			// Выводим отказ выработки подписи
			return context::error_t::SIGNATURE;
		// Сырая подпись r ‖ s
		uint8_t raw[math::NUMBER_SIZE * 2];
		// Если подпись выработать не удалось
		if(!ecdsa.make(digest::hash_t::SHA1, view_t(digest, sizeof(digest)), raw))
			// Выводим отказ выработки подписи
			return context::error_t::SIGNATURE;
		// Занимаем место под подпись в записи DER
		signature.assign(ecdsa.limit(), 0);
		// Длина записи подписи
		size_t written = signature.size();
		// Если подпись в DER записать не удалось
		if(!sign::encode(view_t(raw, ecdsa.size()), signature.data(), written))
			// Выводим отказ выработки подписи
			return context::error_t::SIGNATURE;
		// Усекаем подпись до записанной длины
		signature.resize(written);
		// Сообщаем об успешной выработке подписи
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
}
/**
 * @brief Метод проверки подписи изданием 1.1
 *
 * @param content   подписанное содержимое
 * @param signature проверяемая подпись
 * @return          отказ проверки подписи
 *
 */
context::error_t nts::internal::Engine::engraved(const view_t & content, const view_t & signature) noexcept {
	// Если цепочки собеседника нет
	if(this->_peer.empty())
		// Выводим отказ отсутствия сертификата
		return context::error_t::CERTIFICATE;
	// Лист собеседника
	x509::certificate_t leaf;
	// Отказ разбора листа
	context::error_t failure = translate(leaf.parse(view_t(this->_peer[0].data(), this->_peer[0].size())), context::error_t::CERTIFICATE);
	// Если лист разобрать не удалось
	if(failure != context::error_t::NONE)
		// Выводим отказ разбора листа
		return failure;
	// Хеш MD5 ‖ SHA-1 содержимого
	uint8_t digest[36];
	// Если хеш выработать не удалось
	if(!digest::hash(digest::hash_t::MD5, content, digest, 16) || !digest::hash(digest::hash_t::SHA1, content, digest + 16, 20))
		// Выводим отказ проверки подписи
		return context::error_t::SIGNATURE;
	// Отказ проверки голой подписи RSA над MD5 ‖ SHA-1
	const x509::error_t verified = x509::verify(view_t(digest, sizeof(digest)), signature, leaf.key());
	// Если ключ листа не RSA: раздел 5.4 RFC 4492 - ECDSA над SHA-1
	if(verified == x509::error_t::KEY)
		// Выводим итог проверки подписи ECDSA над SHA-1
		return translate(x509::check(leaf.key(), digest::hash_t::SHA1, content, signature), context::error_t::SIGNATURE);
	// Выводим итог проверки подписи RSA
	return translate(verified, context::error_t::SIGNATURE);
}
/**
 * @brief Метод добавления сообщения рукопожатия в переписку издания 1.2
 *
 * @param message  сообщение рукопожатия вместе с обвязкой TLS
 * @param sequence порядковый номер сообщения поверх дейтаграмм
 * @return         отказ ведения переписки
 *
 */
context::error_t nts::internal::Engine::chronicle(const view_t & message, const uint16_t sequence) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если переписка ведётся записями: сообщение ложится в обвязке TLS
		if(this->_transport != context::transport_t::DATAGRAMS){
			// Если сообщение в переписку рукопожатия добавить не удалось
			if(this->_transcript.update(message) != session::error_t::NONE)
				// Выводим отказ ведения переписки рукопожатия
				return context::error_t::MESSAGE;
			// Добавляем сообщение к переписке подряд
			this->_history.insert(this->_history.end(), message.data, message.data + message.size);
			// Выводим успешность ведения переписки
			return context::error_t::NONE;
		}
		// Сообщение в обвязке DTLS
		vector <uint8_t> shaped;
		// Раздел 4.2.6 RFC 6347: переписка ведётся сообщением в обвязке DTLS одним куском
		if(!reframe(message, sequence, shaped))
			// Выводим отказ нехватки памяти
			return context::error_t::MEMORY;
		/**
		 * Хешу переписки издания DTLS 1.2 сообщение подаётся в обвязке DTLS, а до согласования
		 * издания - в обвязке TLS ради издания 1.3; переписка подряд копит обвязку DTLS всегда,
		 * и по выбору издания 1.2 хеш начинается заново из неё (greeted)
		 */
		if(this->_transcript.update(this->_legacy ? view_t(shaped.data(), shaped.size()) : message) != session::error_t::NONE)
			// Выводим отказ ведения переписки рукопожатия
			return context::error_t::MESSAGE;
		// Добавляем сообщение в обвязке DTLS к переписке подряд
		this->_history.insert(this->_history.end(), shaped.begin(), shaped.end());
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return context::error_t::MEMORY;
	}
	// Выводим успешность ведения переписки
	return context::error_t::NONE;
}
/**
 * @brief Метод отказа разбора приветствия клиента по подтверждённости адреса
 *
 * @param error       отказ, которым связь оборвалась бы
 * @param description описание извещения, которым связь оборвалась бы
 * @return            отказ обрыва связи либо NONE у молчаливого отброса
 *
 */
context::error_t nts::internal::Engine::dismissing(const context::error_t error, const alert::description_t description) noexcept {
	/**
	 * Разделы 4.1.2.7 и 4.2.1 RFC 6347, раздел 5.1 RFC 9147: до подтверждения адреса меткой
	 * негодное приветствие отбрасывается молча - извещение неподтверждённому адресу
	 * усиливало бы чужой поток, а состояние сервера не меняется; нехватка памяти к
	 * приветствию не относится и обрывает связь всегда
	 */
	if((error != context::error_t::MEMORY) && (this->_transport == context::transport_t::DATAGRAMS) && !this->_confirmed){
		// Считаем отброшенное приветствие
		this->_flight.discard(datagram::reason_t::GREETING);
		// Отброшенное приветствие своего номера не занимает: настоящее придёт тем же номером
		this->_flight.retract();
		// Выводим успешность: приветствие отброшено
		return context::error_t::NONE;
	}
	// Выводим отказ обрыва связи извещением
	return this->abort(error, description);
}
/**
 * @brief Метод отправки просьбы о подтверждении адреса HelloVerifyRequest
 *
 * @param greeting разобранное первое приветствие клиента без метки
 * @return         отказ отправки просьбы
 *
 */
context::error_t nts::internal::Engine::querying(const hello::client_t & greeting) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Отказ связи, отвечающий отказу модуля
		context::error_t failure = context::error_t::NONE;
		// Накопитель приветствия клиента без метки: по нему складывается метка
		vector <uint8_t> rebuilt;
		// Отказ составления приветствия без метки
		failure = translate(hello::build(greeting, rebuilt, true), context::error_t::MESSAGE);
		// Если приветствие без метки составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления приветствия
			return this->abort(failure, blame(failure, alert::description_t::INTERNAL));
		// Метка возврата состояния
		vector <uint8_t> label;
		// Отказ составления короткой метки издания 1.2 по адресу собеседника и хешу приветствия: состояния она не оставляет
		failure = this->_flight.token(view_t(rebuilt.data(), rebuilt.size()), label);
		// Если метку составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления метки
			return this->abort(failure, alert::description_t::INTERNAL);
		// Объект составителя тела просьбы
		field::builder_t builder;
		// Отказ, которым ответил составитель полей
		field::error_t outcome = builder.number(static_cast <uint32_t> (record::version_t::DTLS10), 2);
		// Если издание записано: раздел 4.2.1 RFC 6347 велит серверу класть DTLS 1.0
		if(outcome == field::error_t::NONE)
			// Открываем поле метки с однобайтовой длиной
			outcome = builder.open(1);
		// Если поле метки открыто
		if(outcome == field::error_t::NONE)
			// Записываем метку
			outcome = builder.bytes(view_t(label.data(), label.size()));
		// Если метка записана
		if(outcome == field::error_t::NONE)
			// Проставляем длину метки
			outcome = builder.close();
		// Если тело просьбы составить не удалось
		if(outcome != field::error_t::NONE)
			// Выводим отказ составления просьбы
			return this->abort(translate(outcome, context::error_t::MESSAGE), alert::description_t::INTERNAL);
		// Объект составителя сообщения рукопожатия с обвязкой TLS
		handshake::writer_t writer;
		// Отказ составления сообщения с обвязкой
		failure = translate(writer.push(handshake::type_t::VERIFY_REQUEST, builder.data()), context::error_t::MESSAGE);
		// Если сообщение с обвязкой составить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ составления сообщения
			return this->abort(failure, alert::description_t::INTERNAL);
		/**
		 * Раздел 4.2.1 RFC 6347: просьба в переписку не ложится и повторно не передаётся -
		 * сервер состояния по ней не держит, а повторяет её лишь повтор приветствия клиента
		 */
		failure = this->emit(record::type_t::HANDSHAKE, writer.data());
		// Если просьбу сложить не удалось
		if(failure != context::error_t::NONE)
			// Выводим отказ отправки просьбы
			return this->abort(failure, alert::description_t::INTERNAL);
		// Переводим перенос в положение сервера без состояния
		this->_flight.stateless(true);
		// Выводим успешность отправки просьбы
		return context::error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
}
/**
 * @brief Метод разбора клиентом просьбы о подтверждении адреса HelloVerifyRequest
 *
 * @param body тело принятой просьбы
 * @return     отказ разбора просьбы
 *
 */
context::error_t nts::internal::Engine::queried(const view_t & body) noexcept {
	/**
	 * Раздел 4.2.1 RFC 6347: просьба приходит лишь клиенту, лишь поверх дейтаграмм, лишь
	 * до согласования издания и не более QUERIES раз - клиенту, дозволяющему издание 1.2;
	 * повторная просьба законна у сервера, сменившего секрет метки, а зацикливание - нет
	 */
	if(this->_server || (this->_transport != context::transport_t::DATAGRAMS) || (this->_version != 0) || (this->_queries >= QUERIES) || (this->_lowest > LEGACY))
		// Выводим отказ сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Раздел 5.1 RFC 9147: за принятой просьбой о повторе издание 1.3 уже выбрано - просьба подтверждения адреса изданием 1.2 не в свой черёд
	if(this->_retried)
		// Выводим отказ сообщения не в свой черёд
		return this->abort(context::error_t::ORDER, alert::description_t::UNEXPECTED);
	// Объект разборщика тела просьбы
	field::scanner_t scanner;
	// Устанавливаем разбираемое тело просьбы
	scanner.start(body);
	// Издание протокола в просьбе: клиент его не судит (раздел 4.2.1 RFC 6347)
	uint32_t version = 0;
	// Метка возврата состояния
	view_t label;
	// Раздел 4.2.1 RFC 6347: издание и метка с однобайтовой длиной без лишних байтов
	if((scanner.number(version, 2) != field::error_t::NONE) || (scanner.vector(label, 1) != field::error_t::NONE) || (scanner.left() > 0))
		// Выводим отказ разбора просьбы
		return this->abort(context::error_t::MESSAGE, alert::description_t::DECODE);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Запоминаем метку возврата состояния
		this->_token.assign(label.data, label.data + label.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти, которым связь обрывается
		return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
	}
	// Считаем принятую просьбу
	this->_queries++;
	// Раздел 4.2.1 RFC 6347: ни просьба, ни первое приветствие в переписку не входят
	this->_transcript.start();
	// Выполняем сброс переписки подряд
	this->_history.clear();
	// Рукопожатие начинается заново: ход рукопожатия ждёт приветствие клиента вновь
	if(!this->_machine.start(flow::role_t::CLIENT))
		// Выводим отказ заведения хода рукопожатия
		return this->abort(context::error_t::STATE, alert::description_t::INTERNAL);
	// Раздел 4.2.2 RFC 6347: приветствие в ответ на просьбу идёт номером один - и на повторную просьбу тоже
	this->_flight.outgoing(1);
	// Выполняем повторную отправку приветствия с меткой, прежними случайным значением и опознавателем
	const context::error_t error = this->greeting();
	// Если приветствие отправить не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ отправки приветствия
		return this->abort(error, alert::description_t::INTERNAL);
	// Выводим успешность разбора просьбы
	return context::error_t::NONE;
}
/**
 * @brief Метод принятия смены набора шифрования собеседника поверх дейтаграмм
 *
 * @return отказ заведения поры ключей чтения
 *
 */
context::error_t nts::internal::Engine::switched() noexcept {
	// Место ключевого материала собеседника
	const size_t peer = (this->_server ? 0 : 1);
	// Раздел 4.1 RFC 6347: смена набора шифрования открывает первую пору чтения
	const context::error_t error = this->_flight.adopt(true, this->_suite, view_t(this->_keys->key[peer], protect::key(this->_suite)), view_t(this->_keys->vector[peer], protect::block(this->_suite)), view_t(this->_keys->stamp[peer], digest::length(protect::mac(this->_suite))), this->_etm);
	// Если пору ключей завести не удалось
	if(error != context::error_t::NONE)
		// Выводим отказ заведения поры ключей
		return error;
	// Смена набора принята: ждать её больше нечего
	this->_switched = false;
	// Запоминаем, что записи собеседника отныне защищены
	this->_opening = true;
	// Переходим к ожиданию завершения рукопожатия собеседником
	this->_phase = phase_t::FINISHED;
	// Выводим успешность принятия смены набора
	return context::error_t::NONE;
}
/**
 * @brief Метод заведения поры ключей направления связи поверх дейтаграмм
 *
 * @param side  сторона связи, чьё направление заводится
 * @param level уровень защиты, ключи которого кладутся в пору
 * @return      отказ заведения поры ключей
 *
 */
context::error_t nts::internal::Engine::adopt(const session::side_t side, const context::level_t level) noexcept {
	// Получаем сторону связи, которую ведёт модуль
	const session::side_t own = (this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
	// Место уровня защиты среди сохранённых значений направлений
	const size_t place = ((level == context::level_t::HANDSHAKE) ? 1 : 2);
	// Если значение направления уровня ещё не выведено
	if((this->_ready[place] & static_cast <uint8_t> (1 << index(side))) == 0)
		// Выводим отказ вывода ключевого материала
		return context::error_t::SCHEDULE;
	// Место, в которое помещается корневой ключ направления связи
	uint8_t material[protect::PROTECT_KEY];
	// Место, в которое помещается вектор замены направления связи
	uint8_t element[protect::PROTECT_VECTOR];
	// Место, в которое помещается ключ шифрования номера записи
	uint8_t sn[protect::PROTECT_KEY];
	// Если ключевой материал направления связи вывести не удалось
	if(this->_secrets.material(side, this->_suite, material, element) != session::error_t::NONE)
		// Выводим отказ вывода ключевого материала направления
		return context::error_t::SCHEDULE;
	// Метка вывода ключа шифрования номера записи: раздел 4.2.3 RFC 9147
	static const uint8_t LABEL[2] = {'s', 'n'};
	// Признак того, что ключ шифрования номера записи выведен
	const bool derived = schedule::derive(protect::hash(this->_suite), view_t(this->_keys->traffic[place][index(side)], this->_width), view_t(LABEL, sizeof(LABEL)), view_t(nullptr, 0), sn, protect::key(this->_suite));
	// Отказ заведения поры ключей переносом
	const context::error_t error = (derived ? this->_flight.adopt((side != own), (level == context::level_t::HANDSHAKE), this->_suite, view_t(material, protect::key(this->_suite)), view_t(element, protect::block(this->_suite)), view_t(sn, protect::key(this->_suite))) : context::error_t::SCHEDULE);
	// Выполняем затирание ключа шифрования номера записи
	this->purge(sn, sizeof(sn));
	// Выполняем затирание вектора замены направления связи
	this->purge(element, sizeof(element));
	// Выполняем затирание корневого ключа направления связи
	this->purge(material, sizeof(material));
	// Выводим итог заведения поры ключей
	return error;
}
/**
 * @brief Метод разбора принятой дейтаграммы
 *
 * @param data принятая дейтаграмма
 * @return     отказ разбора дейтаграммы
 *
 */
context::error_t nts::internal::Engine::receive(const view_t & data) noexcept {
	/**
	 * Раздел 7.1 RFC 9147: явное подтверждение положено сообщениям за установленной
	 * связью; связь, установившаяся самой этой подачей, подтверждает залп собеседника
	 * своим залпом, а подтверждение новой порой собеседник прочесть ещё не может
	 */
	const bool settled = ((this->_state == context::state_t::ESTABLISHED) || (this->_state == context::state_t::CLOSED));
	// Пора ключей чтения до подачи: по её смене отложенные записи разбираются заново
	const uint16_t before = this->_flight.epoch(true);
	// Записи дейтаграммы, вскрытые переносом
	vector <opened_t> records;
	/**
	 * Сторож открытого текста дейтаграмм: по классу PLAINTEXT содержимое снятых записей
	 * затирается на всяком выходе из разбора, а не только на удачном
	 */
	struct guard_t {
		// Связь, чьи классы затирания действуют
		const Engine & engine;
		// Снятые записи дейтаграмм
		vector <opened_t> & records;
		/**
		 * @brief Деструктор: затирание содержимого снятых записей
		 *
		 */
		~guard_t() noexcept {
			/**
			 * Выполняем перебор снятых записей
			 */
			for(size_t i = 0; i < this->records.size(); i++)
				// Выполняем затирание содержимого записи по классу PLAINTEXT
				this->engine.cleanse(this->records[i].content);
		}
	} guard{*this, records};
	// Отказ вскрытия записей дейтаграммы
	context::error_t error = this->_flight.receive(data, records);
	// Если памяти под вскрытие записей не хватило
	if(error != context::error_t::NONE)
		// Выводим отказ нехватки памяти
		return this->abort(error, alert::description_t::INTERNAL);
	/**
	 * Выполняем перебор вскрытых записей дейтаграммы
	 */
	for(size_t i = 0; i < records.size(); i++){
		// Открытое содержимое очередной записи
		const view_t content(records[i].content.data(), records[i].content.size());
		/**
		 * Раздел 4.5.2 RFC 9147 и раздел 4 RFC 8449: содержимое шире предела обрывает связь
		 * record_overflow лишь у защищённой записи - её прислал собеседник; открытая запись
		 * ничем не подписана, и шире предела она роняется молча (иначе чужая дейтаграмма
		 * рвала бы связь с договорённым пределом приёма)
		 */
		if(content.size > this->_incoming){
			// Если запись защищена
			if(records[i].epoch != 0)
				// Выводим отказ выхода содержимого за предел
				return this->abort(context::error_t::RECORD, alert::description_t::OVERSIZE);
			// Считаем отброшенную запись
			this->_flight.discard(datagram::reason_t::LENGTH);
			// Переходим к следующей записи
			continue;
		}
		// Раздел 6.1 RFC 8446: принятое за извещением о закрытии пропускается
		if(this->_drained)
			// Переходим к следующей записи
			continue;
		/**
		 * Выполняем определение вида содержимого записи
		 */
		switch(static_cast <uint8_t> (records[i].type)){
			// Если принято извещение собеседника
			case static_cast <uint8_t> (record::type_t::ALERT): {
				// Выполняем разбор принятого извещения
				error = this->notice(content);
				// Если связь оборвана извещением собеседника
				if(error != context::error_t::NONE)
					// Выводим отказ обрыва связи собеседником
					return error;
			} break;
			// Если приняты куски сообщений рукопожатия
			case static_cast <uint8_t> (record::type_t::HANDSHAKE): {
				// Выполняем разбор кусков сообщений рукопожатия
				error = this->_flight.fragments(content, records[i].epoch, records[i].sequence, settled);
				// Если куски сообщений разобрать не удалось: защищённый кусок порчен собеседником
				if(error != context::error_t::NONE)
					// Выводим отказ разбора кусков сообщений
					return this->abort(error, blame(error, alert::description_t::DECODE));
				// Вид собранного сообщения
				handshake::type_t type = handshake::type_t::NONE;
				// Тело собранного сообщения
				vector <uint8_t> body;
				/**
				 * Выполняем выдачу собранных сообщений по порядку номеров
				 */
				while(this->_flight.deliver(type, body, this->_delivered)){
					/**
					 * Раздел 7.1 RFC 9147: залп, на который собеседник ответил своим,
					 * подтверждён неявно; за установленной связью подтверждение идёт лишь явное.
					 * Раздел 4.2.4 RFC 6347: у издания 1.2 залп подтверждается лишь ЦЕЛЫМ ответным
					 * залпом - часы стоят до его последнего сообщения (приветствие клиента, просьба
					 * о подтверждении адреса, конец приветствия сервера либо завершение), иначе
					 * потеря хвоста залпа (билет сеанса дошёл, завершение - нет) остановила бы
					 * часы обеих сторон навсегда
					 */
					if((this->_state == context::state_t::HANDSHAKE) && (!this->_legacy || (type == handshake::type_t::CLIENT) || (type == handshake::type_t::VERIFY_REQUEST) || (type == handshake::type_t::DONE) || (type == handshake::type_t::FINISHED)))
						// Выполняем сброс подтверждённого залпа
						this->_flight.answered();
					// Объект составителя сообщения рукопожатия с обвязкой TLS
					handshake::writer_t writer;
					// Отказ составления сообщения с обвязкой
					error = translate(writer.push(type, view_t(body.data(), body.size())), context::error_t::MESSAGE);
					// Если сообщение с обвязкой составить не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ составления сообщения
						return this->abort(error, alert::description_t::INTERNAL);
					// Получаем сообщение с обвязкой TLS: раздел 5.2 RFC 9147 ведёт переписку именно им
					const view_t message = writer.data();
					// Выполняем разбор собранного сообщения рукопожатия
					error = this->handle(type, view_t(message.data + handshake::HANDSHAKE_HEADER, body.size()), message);
					// Если сообщение рукопожатия разобрать не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ разбора сообщения
						return error;
				}
			} break;
			// Если принята смена набора шифрования собеседника
			case static_cast <uint8_t> (record::type_t::CHANGE): {
				// Изданию DTLS 1.3 смена набора неведома: перенос её отбрасывает, а сюда она дойти не может
				if(!this->_legacy){
					// Считаем отброшенную запись
					this->_flight.discard(datagram::reason_t::TYPE);
					// Переходим к следующей записи
					continue;
				}
				// Раздел 4.2.4 RFC 6347: повтор залпа собеседника несёт смену набора вновь - она уже принята; чужая открытая запись за сменой ключей судится прежде тела
				if(this->_opening || this->_switched)
					// Переходим к следующей записи
					continue;
				/**
				 * Раздел 7.1 RFC 5246: смена несёт единственный байт со значением один и идёт
				 * нулевой порой. По установленной связи открытая запись ничем не подписана, и
				 * негодная роняется молча (раздел 4.1.2.7 RFC 6347: связь сохраняется) - иначе
				 * одна поддельная дейтаграмма со стороны убивала бы связь; на рукопожатии
				 * негодная смена роняется так же (круг 8)
				 */
				/**
				 * Раздел 4.1.2.7 RFC 6347: клиенту между приветствием сервера и его концом
				 * настоящая смена прийти не может (она идёт лишь за залпом клиента), а
				 * подделанная открытая запись ничем не подписана - она роняется молча, каким
				 * бы ни было её тело, не обрывая рукопожатия извещением
				 */
				if(!this->_server && ((this->_phase == phase_t::CERTIFICATE) || (this->_phase == phase_t::STATUS) || (this->_phase == phase_t::AGREEMENT) || (this->_phase == phase_t::REQUEST) || (this->_phase == phase_t::DONE))){
					// Считаем отброшенную запись
					this->_flight.discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				// Если запись не годная открытая просьба о повторе
				if((records[i].epoch != 0) || (content.size != 1) || (content.data[0] != 0x01)){
					// Раздел 4.1.2.7 RFC 6347: негодная открытая запись ничем не подписана и роняется молча на любой ступени - иначе одна поддельная дейтаграмма убивала бы рукопожатие
					this->_flight.discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				// Если клиент с предъявленным билетом ждёт первого сообщения за приветствием сервера: смена набора означает сокращённое рукопожатие
				if(!this->_server && (this->_phase == phase_t::EITHER)){
					// Отказ суждения о виде рукопожатия
					error = this->deciding(true);
					// Если ключевой материал возобновлённой связи вывести не удалось либо набор разошёлся с билетом
					if(error != context::error_t::NONE)
						// Выводим отказ суждения
						return this->abort(error, blame(error, (((error == context::error_t::SUITE) || (error == context::error_t::ETM) || (error == context::error_t::VERSION)) ? alert::description_t::PARAMETER : alert::description_t::INTERNAL)));
				}
				/**
				 * Раздел 3.3 RFC 5077: билет сеанса идёт перед сменой набора сервера, а при
				 * перестановке дейтаграмм смена обгоняет обещанный билет; принятая раньше
				 * билета смена завела бы ключи чтения и оставила бы открытый билет отброшенным -
				 * у клиента, ждущего обещанный билет, смена ждёт его прихода
				 */
				if(!this->_server && (this->_phase == phase_t::CHANGE) && this->_ticketing){
					// Запоминаем, что смена набора ждёт своего черёда
					this->_switched = true;
					// Переходим к следующей записи
					continue;
				}
				/**
				 * Запись смены набора не несёт номера сообщения и при потерях либо перестановке
				 * обгоняет сообщения своего залпа: у сервера, ждущего цепочку, обмен ключами либо
				 * подпись клиента, она ждёт своего черёда; всюду прочее она не в свой черёд
				 */
				if(this->_phase != phase_t::CHANGE){
					// Если сервер ждёт сообщения залпа клиента, идущие перед сменой
					if(this->_server && ((this->_phase == phase_t::ANSWER) || (this->_phase == phase_t::PREMASTER) || (this->_phase == phase_t::VERIFY))){
						// Запоминаем, что смена набора ждёт своего черёда
						this->_switched = true;
						// Переходим к следующей записи
						continue;
					}
					// Выводим отказ прихода смены набора не в свой черёд
					return this->abort(context::error_t::RECORD, alert::description_t::UNEXPECTED);
				}
				// Выполняем принятие смены набора шифрования собеседника
				error = this->switched();
				// Если пору ключей завести не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ заведения поры ключей
					return this->abort(error, alert::description_t::INTERNAL);
			} break;
			// Если принято подтверждение записей
			case static_cast <uint8_t> (record::type_t::ACK): {
				// Признак вступления своей смены ключей
				bool rotate = false;
				// Выполняем разбор подтверждения записей
				error = this->_flight.acknowledged(content, records[i].epoch, rotate);
				// Если подтверждение разобрать не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ разбора подтверждения
					return this->abort(error, blame(error, alert::description_t::DECODE));
				// Раздел 8 RFC 9147: своя смена ключей вступает по подтверждении сообщения о ней
				if(rotate){
					// Выполняем смену ключевого материала своего направления
					error = this->rotate(this->_server ? session::side_t::SERVER : session::side_t::CLIENT);
					// Если ключевой материал сменить не удалось
					if(error != context::error_t::NONE)
						// Выводим отказ смены ключевого материала
						return this->abort(error, alert::description_t::INTERNAL);
				}
			} break;
			// Если приняты прикладные данные собеседника
			case static_cast <uint8_t> (record::type_t::APPLICATION): {
				/**
				 * Прикладные данные до установления связи означают потерянное завершение
				 * рукопожатия собеседника: раздел 5.8 RFC 9147 велит ждать повтора, а не
				 * рвать связь
				 */
				// Прикладные данные ходят лишь защищённой записью: открытая запись эпохи 0 роняется (раздел 4 RFC 9147)
				if(records[i].epoch == 0){
					// Считаем отброшенную запись
					this->_flight.discard(datagram::reason_t::PLAIN);
					// Переходим к следующей записи
					continue;
				}
				// Если запись пришла раньше установления либо после закрытия связи
				if((this->_state != context::state_t::ESTABLISHED) && (this->_state != context::state_t::CLOSED)){
					// Считаем отброшенную запись
					this->_flight.discard(datagram::reason_t::PREMATURE);
					// Переходим к следующей записи
					continue;
				}
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Выполняем перенос принятых прикладных данных в накопитель
					this->_plain.insert(this->_plain.end(), content.data, content.data + content.size);
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return this->abort(context::error_t::MEMORY, alert::description_t::INTERNAL);
				}
				// Раздел 4.2.4 RFC 6347: прикладные данные собеседника подтверждают последний залп рукопожатия
				if(this->_legacy)
					// Выполняем сброс подтверждённого залпа
					this->_flight.answered();
				// Отказ испрашивания смены ключей у собеседника: изданию 1.2 смена ключей неведома
				error = (this->_legacy ? context::error_t::NONE : this->soliciting());
				// Если смену ключей выполнить не удалось
				if(error != context::error_t::NONE)
					// Выводим отказ смены ключевого материала своего направления
					return this->abort(error, alert::description_t::INTERNAL);
			} break;
			// Если принята запись сердцебиения (RFC 6520): дейтаграммный перенос отвечает так же
			case static_cast <uint8_t> (record::type_t::HEARTBEAT): {
				// Выполняем разбор сердцебиения
				error = this->pulse(content);
				// Если связь оборвана
				if(error != context::error_t::NONE)
					// Выводим отрицательный результат - дейтаграммная связь оборвана сердцебиением
					return error;
			} break;
			// Если принята запись неведомого содержимого
			default: this->_flight.discard(datagram::reason_t::TYPE);
		}
	}
	/**
	 * Раздел 8 RFC 9147: ответная смена ключей ждёт подтверждения своей, ещё не
	 * подтверждённой, - две смены разом слать нельзя
	 */
	if(this->_owed && (this->_state == context::state_t::ESTABLISHED) && !this->rotating()){
		// Сбрасываем признак задолженной смены ключей
		this->_owed = false;
		// Выполняем ответную смену ключей своего направления
		error = this->update(false);
		// Если ответную смену ключей выполнить не удалось
		if(error != context::error_t::NONE)
			// Выводим отказ смены ключевого материала своего направления
			return this->abort(error, alert::description_t::INTERNAL);
	}
	// Отложенные записи, разбираемые заново
	vector <vector <uint8_t>> pending;
	/**
	 * Раздел 4.2.1 RFC 9147: ключи чтения сменились, и записи следующей поры,
	 * отложенные до их прихода, разбираются заново как дейтаграммы
	 */
	if(this->_flight.pending(before, pending)){
		/**
		 * Выполняем перебор отложенных записей
		 */
		for(size_t i = 0; i < pending.size(); i++){
			// Выполняем разбор отложенной записи как дейтаграммы
			error = this->receive(view_t(pending[i].data(), pending[i].size()));
			// Если отложенную запись разобрать не удалось
			if(error != context::error_t::NONE)
				// Выводим отказ разбора отложенной записи
				return error;
		}
	}
	// Выводим итог завершения подачи: подтверждение и раскладка залпа
	return this->resent(this->_flight.complete(settled));
}
/**
 * @brief Метод установки размера дейтаграммы связи
 *
 * @param mtu устанавливаемый размер дейтаграммы в байтах
 *
 */
void nts::internal::Engine::mtu(const size_t mtu) noexcept {
	// Устанавливаем размер дейтаграммы переносу
	this->_flight.mtu(mtu);
}
/**
 * @brief Метод получения размера дейтаграммы связи
 *
 * @return размер дейтаграммы в байтах
 *
 */
size_t nts::internal::Engine::mtu() const noexcept {
	// Выводим размер дейтаграммы связи
	return this->_flight.mtu();
}
/**
 * @brief Метод установки строгого сервера без состояния издания DTLS 1.2
 *
 * @param strict принимается ли приветствие клиента до метки лишь целиком одним куском
 *
 */
void nts::internal::Engine::strict(const bool strict) noexcept {
	// Устанавливаем строгость сервера без состояния переносу
	this->_flight.strict(strict);
}
/**
 * @brief Метод проверки строгости сервера без состояния издания DTLS 1.2
 *
 * @return признак того, что приветствие клиента до метки принимается лишь целиком
 *
 */
bool nts::internal::Engine::strict() const noexcept {
	// Выводим строгость сервера без состояния переноса
	return this->_flight.strict();
}
/**
 * @brief Метод установки обязательности расширенного главного секрета издания 1.2
 *
 * @param mandatory отвергается ли собеседник без расширения RFC 7627
 *
 */
void nts::internal::Engine::master(const bool mandatory) noexcept {
	// Запоминаем обязательность расширенного главного секрета
	this->_mandatory = mandatory;
}
/**
 * @brief Метод проверки обязательности расширенного главного секрета издания 1.2
 *
 * @return признак того, что собеседник без расширения RFC 7627 отвергается
 *
 */
bool nts::internal::Engine::master() const noexcept {
	// Выводим обязательность расширенного главного секрета
	return this->_mandatory;
}
/**
 * @brief Метод получения срока ожидания повторной передачи
 *
 * @return срок в миллисекундах, ноль, когда повторять нечего
 *
 */
uint32_t nts::internal::Engine::timeout() const noexcept {
	// Выводим срок ожидания переноса
	return this->_flight.timeout();
}
/**
 * @brief Метод извещения связи об истечении срока ожидания
 *
 * @return отказ повторной передачи: TIMEOUT по исчерпании попыток
 *
 */
context::error_t nts::internal::Engine::elapsed() noexcept {
	// Если связь ещё не заведена либо уже оборвана
	if((this->_state == context::state_t::NONE) || (this->_state == context::state_t::FAILED))
		// Выводим отказ негодного состояния связи
		return context::error_t::STATE;
	// Часы идут лишь у переноса дейтаграммами
	if(this->_transport != context::transport_t::DATAGRAMS)
		// Выводим успешность: ждать нечего
		return context::error_t::NONE;
	// Выводим итог повторной передачи залпа
	return this->resent(this->_flight.retransmit());
}
/**
 * @brief Метод учёта итога повторной передачи залпа
 *
 * @param outcome отказ, которым ответил перенос
 * @return        отказ повторной передачи: TIMEOUT по исчерпании попыток
 *
 */
context::error_t nts::internal::Engine::resent(const context::error_t outcome) noexcept {
	/**
	 * Раздел 5.8.2 RFC 9147: по исчерпании попыток связь обрывается; извещение
	 * собеседнику, который не отвечает, слать некому
	 */
	if(outcome == context::error_t::TIMEOUT){
		// Запоминаем отказ исчерпания попыток
		this->_error = context::error_t::TIMEOUT;
		// Переводим связь в состояние обрыва
		this->_state = context::state_t::FAILED;
		// Выполняем затирание ключевого материала оборванной связи
		this->shred();
		// Выводим отказ исчерпания попыток
		return context::error_t::TIMEOUT;
	}
	// Если залп разложить не удалось
	if(outcome != context::error_t::NONE)
		// Выводим отказ раскладки залпа
		return this->abort(outcome, alert::description_t::INTERNAL);
	// Выводим успешность повторной передачи
	return context::error_t::NONE;
}
/**
 * @brief Метод проверки ожидания подтверждения своей смены ключей
 *
 * @return признак того, что смена ключей поверх дейтаграмм ждёт подтверждения
 *
 */
bool nts::internal::Engine::rotating() const noexcept {
	// Выводим признак ожидающей смены ключей переноса дейтаграммами
	return ((this->_transport == context::transport_t::DATAGRAMS) && this->_flight.rotating());
}
/**
 * @brief Метод испрашивания смены ключей у собеседника по счёту его записей
 *
 * @return отказ смены ключевого материала своего направления
 *
 */
context::error_t nts::internal::Engine::soliciting() noexcept {
	/**
	 * Смена у собеседника испрашивается просьбою в собственном KeyUpdate, и просьба
	 * повторяется лишь после того, как собеседник ключи сменил; своя смена, ждущая
	 * подтверждения поверх дейтаграмм, просьбы не будит
	 */
	if(!this->_automatic || this->_asked || this->rotating() || (this->_state != context::state_t::ESTABLISHED))
		// Выводим успешность: смена ключей не испрашивается
		return context::error_t::NONE;
	// Определяем число записей, по которому сменяются ключи
	const uint64_t threshold = ((this->_renewal > 0) ? this->_renewal : (protect::limit(this->_suite) / 2));
	// Если счётчик записей собеседника до смены ключей не дошёл
	if(this->sequence(true) < threshold)
		// Выводим успешность: ключи менять рано
		return context::error_t::NONE;
	// Запоминаем, что смена ключей у собеседника испрошена
	this->_asked = true;
	// Выводим итог смены своих ключей с просьбою о встречной смене
	return this->update(true);
}
/**
 * @brief Метод получения числа молча отброшенных записей и дейтаграмм
 *
 * @return число отброшенных записей и дейтаграмм
 *
 */
uint64_t nts::internal::Engine::discarded() const noexcept {
	// Выводим число отброшенного по всем причинам
	return this->_flight.discarded();
}
/**
 * @brief Метод получения числа отброшенного по причине
 *
 * @param reason причина отброса
 * @return       число отброшенного по причине
 *
 */
uint64_t nts::internal::Engine::discarded(const datagram::reason_t reason) const noexcept {
	// Выводим число отброшенного по причине
	return this->_flight.discarded(reason);
}
/**
 * @brief Метод установки адреса собеседника для метки возврата состояния
 *
 * @param address адрес либо иной опознаватель собеседника
 * @return        признак того, что адрес принят
 *
 */
bool nts::internal::Engine::address(const view_t & address) noexcept {
	// Выводим итог установки адреса переносу
	return this->_flight.address(address);
}
/**
 * @brief Метод установки секрета метки возврата состояния
 *
 * @param secret устанавливаемый секрет
 *
 */
void nts::internal::Engine::stamp(const vector <uint8_t> & secret) noexcept {
	// Устанавливаем секрет метки переносу
	this->_flight.stamp(secret);
}
/**
 * @brief Метод смены поколения секрета метки возврата состояния
 *
 */
void nts::internal::Engine::restamp() noexcept {
	// Сменяем поколение секрета метки переносу
	this->_flight.restamp();
}
/**
 * @brief Конструктор
 *
 * @param server признак того, что связь ведётся стороной сервера
 *
 */
nts::internal::Engine::Engine(const bool server) noexcept :
	_server(server), _request(false), _mandatory(false), _extending(false), _requested(false), _retried(false),
	_state(context::state_t::NONE), _error(context::error_t::NONE),
	_suite(protect::suite_t::NONE), _group(extension::group_t::NONE),
	_moment(0), _limit(0), _passed(0),
	_codepoint(static_cast <uint16_t> (extension::type_t::SETTINGS)), _settled(false), _stated(false), _bequeathed(false),
	_shared(false), _chosen(0), _advance(false), _earlying(false), _accepted(false),
	_automatic(true), _asked(false), _owed(false), _misaged(false), _granted(0), _renewal(0),
	_closed(false), _drained(false), _lifetime(TERM), _ticket(protect::suite_t::NONE), _skipped(0), _starved(false),
	_certtype(extension::cert_t::X509), _owncert(extension::cert_t::X509), _clientraw(false), _srtp(0),
	_transport(context::transport_t::RECORDS), _acquired(false), _pushed(context::level_t::NONE), _width(0), _ventured(false), _judged(false),	_inflation(INFLATION), _squeezed(0), _inflated(0),
	_inquiring(false), _inquired(false), _verifying(false), _leeway(0), _certified(ocsp::status_t::NONE), _stamping(false), _stamped(false), _outgoing(record::RECORD_PLAINTEXT), _incoming(record::RECORD_PLAINTEXT), _sizing(0), _bounded(0), _fragmented(0), _bounding(0), _fragmenting(0), _sized{0, 0}, _heartbeating(false), _permitted(false), _answering(false), _beating(false), _pulses(0), _negotiating(false), _negotiated(false), _announced(false), _reshare(true), _greasing(false), _profiled(false), _ech(ech_t::NONE), _shroud(0), _echaccepted(false), _echrejected(false), _unshrouding(false),
	_queries(0), _confirmed(false), _delivered(0), _switched(false),
	_lowest(LEGACY), _highest(MODERN), _version(0), _legacy(false), _ancient(false), _proposed(false), _own(true), _phase(phase_t::NONE), _sealing(false), _opening(false), _stapling(false),
	_claimed(0), _etm(false), _strict(false), _ticketing(false), _presented(false), _resumed(false), _authenticated(0), _scrubbing(true), _cleansing(false) {
	// Сбрасываем ключевой материал связи до заведения участка
	this->_keys = nullptr;
	/**
	 * Заводим участок укрытой памяти под ключевой материал связи (решение 17 шапки); без
	 * участка связь негодна с рождения: ключам лежать в обычной куче нельзя
	 */
	if(this->_shelter.reserve(sizeof(keys_t)))
		// Запоминаем ключевой материал связи
		this->_keys = reinterpret_cast <keys_t *> (this->_shelter.data());
	// Если хранилище участка не дало
	else {
		// Отмечаем связь негодной
		this->_state = context::state_t::FAILED;
		// Запоминаем отказ памяти
		this->_error = context::error_t::MEMORY;
	}
	// Выполняем сброс поры ключей записей клиента
	this->_epoch[0] = flow::epoch_t::PLAIN;
	// Выполняем сброс поры ключей записей сервера
	this->_epoch[1] = flow::epoch_t::PLAIN;
	// Выполняем обнуление случайного значения своего приветствия
	::memset(this->_random, 0, sizeof(this->_random));
	// Выполняем обнуление зерна значений GREASE связи
	::memset(this->_seed, 0, sizeof(this->_seed));
	// Выполняем обнуление случайного значения внутреннего приветствия ECH
	::memset(this->_innerandom, 0, sizeof(this->_innerandom));
	// Выполняем обнуление случайного значения собеседника
	::memset(this->_foreign, 0, sizeof(this->_foreign));
	// Выполняем обнуление признаков готовности значений направлений
	::memset(this->_ready, 0, sizeof(this->_ready));
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		/**
		 * Наборы шифрования по умолчанию - классика, понятная любому собеседнику: от
		 * стойкого к быстрому, ChaCha20-Poly1305 идёт за AES-256, издание 1.2 следом за
		 * 1.3. Наборов ГОСТ («Кузнечик» и «Магма» в MGM) в умолчании нет - их потребитель
		 * объявляет сам перечнем suites() (намеренное решение 19). Порядок этот лишь
		 * умолчание, а перечень потребителя не пересортировывается
		 */
		// Классы затирания памяти связи по умолчанию - только секреты (намеренное решение 20)
		this->_wiping = {context::wiping_t::SECRETS};
		// Наборы шифрования по умолчанию: AEAD впереди, за ними CBC классики
		this->_suites = {
			// Наборы TLS 1.3 по умолчанию: AES-256-GCM и ChaCha20-Poly1305
			protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256,
			protect::suite_t::AES_128_GCM_SHA256,
			protect::suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384, protect::suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
			protect::suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256, protect::suite_t::ECDHE_RSA_AES_256_GCM_SHA384,
			protect::suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_RSA_AES_128_GCM_SHA256,
			protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256, protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA256,
			protect::suite_t::ECDHE_ECDSA_AES_256_CBC_SHA, protect::suite_t::ECDHE_ECDSA_AES_128_CBC_SHA,
			protect::suite_t::ECDHE_RSA_AES_256_CBC_SHA, protect::suite_t::ECDHE_RSA_AES_128_CBC_SHA,
			protect::suite_t::RSA_AES_256_GCM_SHA384, protect::suite_t::RSA_AES_128_GCM_SHA256,
			protect::suite_t::RSA_AES_256_CBC_SHA256, protect::suite_t::RSA_AES_128_CBC_SHA256,
			protect::suite_t::RSA_AES_256_CBC_SHA, protect::suite_t::RSA_AES_128_CBC_SHA,
			protect::suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256, protect::suite_t::ECDHE_PSK_AES_256_CBC_SHA,
			protect::suite_t::ECDHE_PSK_AES_128_CBC_SHA, protect::suite_t::PSK_AES_256_CBC_SHA, protect::suite_t::PSK_AES_128_CBC_SHA
		};
		// Настройка наборов: заведение связи берёт наборы отсюда
		this->_catalog = this->_suites;
		/**
		 * Кривые обмена ключами по умолчанию - те, что предлагают браузеры и OpenSSL 3.5:
		 * гибрид X25519MLKEM768 впереди, за ним X25519 и кривые NIST раздела 4.2.7
		 * RFC 8446. Кривых ГОСТ (GC256A…GC512C) в умолчании нет - их потребитель
		 * объявляет сам перечнем groups() (намеренное решение 19); порядок этот лишь
		 * умолчание, и потребитель заменяет его целиком своим перечнем
		 */
		this->_groups = {
			// Группы по умолчанию: гибрид впереди, за ним X25519 и кривые NIST
			extension::group_t::X25519MLKEM768, extension::group_t::X25519,
			extension::group_t::SECP256R1, extension::group_t::SECP384R1
		};
		// Схемы подписи по умолчанию: лишь классические, схемы ГОСТ объявляет потребитель
		this->_signatures.assign(SCHEMES, SCHEMES + (sizeof(SCHEMES) / sizeof(extension::scheme_t)));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выполняем сброс наборов шифрования связи
		this->_suites.clear();
		// Выполняем сброс кривых обмена ключами связи
		this->_groups.clear();
		// Выполняем сброс схем подписи связи
		this->_signatures.clear();
		// Запоминаем, что настройкам связи памяти не хватило
		this->_starved = true;
	}
}
/**
 * @brief Деструктор
 *
 */
nts::internal::Engine::~Engine() noexcept {
	// Выполняем сброс состояния связи
	this->clear();
	// Если подлинность несёт секретный ключ
	if(!this->_credential.secret.empty())
		// Выполняем затирание секретного ключа своей подлинности
		this->purge(this->_credential.secret.data(), this->_credential.secret.size());
	// Ключи билетов сеансов затирает их хранитель; если заранее разделённый ключ задан
	if(!this->_psk.key.empty())
		// Выполняем затирание заранее разделённого ключа
		this->purge(this->_psk.key.data(), this->_psk.key.size());
}
