/**
 * @file ocsp.cpp
 * @date 2026-09-04
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
 * @brief Проверки состояния сертификата OCSP по RFC 6960 и сшивки ответа по разделу
 *        4.4.2.1 RFC 8446: разбор ответов, составленных настоящим openssl, их проверка,
 *        составление запроса байт в байт с openssl, ответ ГОСТ своей выработки, петлевые
 *        рукопожатия со сшивкой по записям и по уровням, отказы, обмен с настоящим
 *        openssl и нехватка памяти
 *
 * @note Ответы и запросы набора tests/corpus/ocsp выработаны openssl 3.6.3: команды
 *       записаны в tests/corpus/README.md
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <functional>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <openssl.hpp>
#include <identity.hpp>
#include <pem/pem.hpp>
#include <ocsp/ocsp.hpp>
#include <x509/x509.hpp>
#include <trust/trust.hpp>
#include <digest/hash.hpp>
#include <handshake/handshake.hpp>
#include <message/message.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору ключей для сличения
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Миг проверки: 21 сентября 2026 года, внутри десятилетнего срока ответов набора
	 */
	static constexpr int64_t MOMENT = 1790000000;
	/**
	 * Миг до составления ответов набора: июнь 2026 года
	 */
	static constexpr int64_t EARLIER = 1780000000;
	/**
	 * Миг верности состояния ответа leaf-ec.good.der: 4 сентября 2026 года 12:37:49
	 */
	static constexpr int64_t UPDATED = 1788525469;
	/**
	 * Миг окончания обещания ответа leaf-ec.good.der: 1 сентября 2036 года 12:37:49
	 */
	static constexpr int64_t PROMISED = 2103885469;
	/**
	 * Миг отзыва в ответе leaf-ec.revoked.der: 1 сентября 2026 года 00:00:00
	 */
	static constexpr int64_t REVOKED = 1788220800;
	/**
	 * Миг окончания обещания ответа leaf-ec.short.der: 5 сентября 2026 года 12:39:15
	 */
	static constexpr int64_t SHORT = 1788611955;
	/**
	 * Неповторимое значение запроса leaf-ec.nonce.req.der, отвеченное leaf-ec.nonce.der
	 */
	static const uint8_t NONCE[16] = {0x87, 0x7D, 0x8E, 0xA1, 0x97, 0x62, 0x89, 0xF0, 0x8D, 0xDE, 0x91, 0x09, 0xE4, 0x79, 0xCC, 0x21};
	/**
	 * Ответ ответчика отказом unauthorized (6): раздел 4.2.1 RFC 6960
	 */
	static const uint8_t UNAUTHORIZED[5] = {0x30, 0x03, 0x0A, 0x01, 0x06};
	/**
	 * Классические наборы шифрования
	 */
	static const protect::suite_t SUITES[] = {protect::suite_t::AES_128_GCM_SHA256, protect::suite_t::AES_256_GCM_SHA384, protect::suite_t::CHACHA20_POLY1305_SHA256};
	/**
	 * Уровни защиты, несущие сообщения рукопожатия, в порядке подачи
	 */
	static const context::level_t LEVELS[] = {context::level_t::INITIAL, context::level_t::HANDSHAKE, context::level_t::APPLICATION};
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к файлу
	 *
	 * @return     содержимое файла либо пустой накопитель
	 *
	 */
	vector <uint8_t> slurp(const std::string & path) noexcept {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое файла
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Метод записи файла целиком
	 *
	 * @param path путь к файлу
	 * @param data записываемое содержимое
	 *
	 * @return     признак успешности записи
	 *
	 */
	bool spill(const std::string & path, const vector <uint8_t> & data) noexcept {
		// Открываем файл на запись
		std::ofstream file(path, std::ios::binary);
		// Если файл не открыт
		if(!file.is_open())
			// Выводим отказ записи
			return false;
		// Записываем содержимое
		file.write(reinterpret_cast <const char *> (data.data()), static_cast <std::streamsize> (data.size()));
		// Выводим успешность записи
		return file.good();
	}
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла набора
	 *
	 * @return     содержимое файла набора
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Выводим содержимое файла набора
		return slurp(std::string(CORPUS) + "/" + name);
	}
	/**
	 * @brief Метод чтения ответа либо запроса OCSP из набора
	 *
	 * @param name имя файла в каталоге ocsp набора
	 *
	 * @return     содержимое файла
	 *
	 */
	vector <uint8_t> vectored(const char * name) noexcept {
		// Выводим содержимое файла каталога ocsp набора
		return slurp(std::string(CORPUS) + "/ocsp/" + name);
	}
	/**
	 * @brief Метод чтения сертификата набора записью DER
	 *
	 * @param name имя файла сертификата набора в записи PEM
	 *
	 * @return     запись DER сертификата либо пустой накопитель
	 *
	 */
	vector <uint8_t> certified(const char * name) noexcept {
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus(name);
		// Разобранные сертификаты записи PEM
		vector <vector <uint8_t>> chain;
		// Если сертификат разобрать не удалось
		if(text.empty() || (pem::certificates(std::string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Выводим пустой накопитель
			return vector <uint8_t> ();
		// Выводим запись DER сертификата
		return chain[0];
	}
	/**
	 * @brief Метод составления подлинности стороны из ключей набора
	 *
	 * @param name   имя ключа набора: rsa2048, ec256, ec384 либо ed25519
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyed(const char * name, context::credential_t & result) noexcept {
		// Читаем секретный ключ набора в записи PEM
		result.secret = corpus((std::string(name) + ".pem").c_str());
		// Читаем сертификат набора в записи PEM
		const vector <uint8_t> text = corpus((std::string(name) + ".crt").c_str());
		// Если ключ либо сертификат не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Метод составления подлинности стороны из цепочки набора
	 *
	 * @param kind   вид ключа цепочки: ec либо rsa
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool chained(const char * kind, context::credential_t & result) noexcept {
		// Читаем секретный ключ листа цепочки в записи PEM
		result.secret = corpus((std::string("leaf-") + kind + ".key").c_str());
		// Читаем цепочку набора в записи PEM
		const vector <uint8_t> text = corpus((std::string("chain-") + kind + ".pem").c_str());
		// Если ключ либо цепочка не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return ((pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE) && (result.chain.size() == 3));
	}
	/**
	 * @brief Метод разбора и проверки ответа набора одним вызовом
	 *
	 * @param name        имя ответа в каталоге ocsp набора
	 * @param certificate имя файла проверяемого сертификата набора
	 * @param issuer      имя файла сертификата издателя набора
	 * @param moment      миг проверки
	 * @param leeway      люфт сроков
	 * @param nonce       ожидаемое неповторимое значение
	 * @param status      место, в которое помещается состояние сертификата
	 *
	 * @return            отказ разбора либо проверки
	 *
	 */
	ocsp::error_t judge(const char * name, const char * certificate, const char * issuer, const int64_t moment, const int64_t leeway, const view_t & nonce, ocsp::status_t & status) noexcept {
		// Запись ответа
		const vector <uint8_t> data = vectored(name);
		// Запись проверяемого сертификата
		const vector <uint8_t> subject = certified(certificate);
		// Запись сертификата издателя
		const vector <uint8_t> authority = certified(issuer);
		// Если что-то из набора не прочитано
		if(data.empty() || subject.empty() || authority.empty())
			// Выводим отказ разбора сертификата
			return ocsp::error_t::KEY;
		// Объект разбора ответа
		ocsp::response_t response;
		// Отказ разбора ответа
		const ocsp::error_t failure = response.parse(view_t(data.data(), data.size()));
		// Если ответ разобрать не удалось
		if(failure != ocsp::error_t::NONE)
			// Выводим отказ разбора ответа
			return failure;
		// Выводим итог проверки ответа
		return ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), moment, leeway, nonce, status);
	}
	/**
	 * @brief Метод выработки ответа OCSP на алгоритмах ГОСТ своими средствами
	 *
	 * @details Ответчик - сам издатель самоподписанного сертификата ГОСТ: подпись по
	 *          ГОСТ Р 34.10-2012 с хешем «Стрибог»-256, опознаватель сертификата по
	 *          «Стрибогу»-256 (RFC 9215), ответчик назван именем
	 *
	 * @param credential подлинность ГОСТ с самоподписанным сертификатом
	 * @param status     записываемое состояние сертификата
	 * @param result     накопитель, в который помещается запись ответа
	 *
	 * @return           признак успешности выработки ответа
	 *
	 */
	bool gosted(const context::credential_t & credential, const ocsp::status_t status, vector <uint8_t> & result) noexcept {
		// Объект разбора сертификата стороны
		x509::certificate_t certificate;
		// Если сертификат стороны разобрать не удалось
		if(credential.chain.empty() || (certificate.parse(view_t(credential.chain[0].data(), credential.chain[0].size())) != x509::error_t::NONE))
			// Выводим отказ выработки
			return false;
		// Места, в которые помещаются хеши имени и ключа издателя
		uint8_t name[32], key[32];
		// Если хеш имени издателя вычислить не удалось
		if(!digest::hash(digest::hash_t::STREEBOG256, certificate.subjects().element, name, sizeof(name)))
			// Выводим отказ выработки
			return false;
		// Если хеш ключа издателя вычислить не удалось
		if(!digest::hash(digest::hash_t::STREEBOG256, certificate.key().key, key, sizeof(key)))
			// Выводим отказ выработки
			return false;
		// Составитель подписываемой части ответа
		asn1::writer_t body;
		// Открываем подписываемую часть ответа
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Разборщик записи имени владельца
		asn1::reader_t owner(certificate.subjects().element);
		// Элемент записи имени владельца
		asn1::element_t title;
		// Если запись имени владельца перечитать не удалось
		if(!owner.next(asn1::tag_t::SEQUENCE, title))
			// Выводим отказ выработки
			return false;
		// Открываем обёртку имени ответчика
		if(!body.open(asn1::cls_t::CONTEXT, 1))
			// Выводим отказ выработки
			return false;
		// Записываем имя ответчика именем владельца сертификата
		if(!body.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), title.content))
			// Выводим отказ выработки
			return false;
		// Закрываем обёртку имени ответчика
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Записываем миг составления ответа
		if(!body.time(asn1::tag_t::GENERALIZED_TIME, UPDATED))
			// Выводим отказ выработки
			return false;
		// Открываем перечень ответов по сертификатам
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Открываем ответ по сертификату
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Открываем опознаватель сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Открываем опознаватель алгоритма хеша
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Записываем опознаватель «Стрибога»-256
		if(!body.oid("1.2.643.7.1.1.2.2"))
			// Выводим отказ выработки
			return false;
		// Закрываем опознаватель алгоритма хеша
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Записываем хеш имени издателя
		if(!body.octets(view_t(name, sizeof(name))))
			// Выводим отказ выработки
			return false;
		// Записываем хеш ключа издателя
		if(!body.octets(view_t(key, sizeof(key))))
			// Выводим отказ выработки
			return false;
		// Записываем порядковый номер сертификата
		if(!body.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), certificate.number()))
			// Выводим отказ выработки
			return false;
		// Закрываем опознаватель сертификата
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Если сертификат отозван
		if(status == ocsp::status_t::REVOKED){
			// Открываем сведения об отзыве
			if(!body.open(asn1::cls_t::CONTEXT, 1))
				// Выводим отказ выработки
				return false;
			// Записываем миг отзыва
			if(!body.time(asn1::tag_t::GENERALIZED_TIME, REVOKED))
				// Выводим отказ выработки
				return false;
			// Закрываем сведения об отзыве
			if(!body.close())
				// Выводим отказ выработки
				return false;
		// Если сертификат не отозван либо неведом
		} else if(!body.element(asn1::cls_t::CONTEXT, false, static_cast <uint32_t> (status), view_t(nullptr, 0)))
			// Выводим отказ выработки
			return false;
		// Записываем миг верности состояния
		if(!body.time(asn1::tag_t::GENERALIZED_TIME, UPDATED))
			// Выводим отказ выработки
			return false;
		// Открываем обёртку мига окончания обещания
		if(!body.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ выработки
			return false;
		// Записываем миг окончания обещания
		if(!body.time(asn1::tag_t::GENERALIZED_TIME, PROMISED))
			// Выводим отказ выработки
			return false;
		// Закрываем обёртку мига окончания обещания
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Закрываем ответ по сертификату
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Закрываем перечень ответов по сертификатам
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Закрываем подписываемую часть ответа
		if(!body.close())
			// Выводим отказ выработки
			return false;
		// Получаем подписываемую часть ответа
		const view_t tbs = body.data();
		// Эллиптическая кривая ключа стороны
		curve::curve_t curve;
		// Если кривую ключа стороны завести не удалось
		if(!curve::parameters("1.2.643.2.2.35.1", curve))
			// Выводим отказ выработки
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если кривую подписи установить не удалось
		if(!gost.start(curve))
			// Выводим отказ выработки
			return false;
		// Если секретный ключ подписи установить не удалось
		if(!gost.secret(view_t(credential.secret.data(), credential.secret.size())))
			// Выводим отказ выработки
			return false;
		// Место, в которое помещается хеш подписываемой части
		uint8_t hash[32];
		// Если хеш подписываемой части выработать не удалось
		if(!digest::streebog(digest::type_t::SHORT, tbs, hash, sizeof(hash), digest::order_t::VECTOR))
			// Выводим отказ выработки
			return false;
		// Место, в которое помещается выработанная подпись
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Если подпись выработать не удалось
		if(!gost.make(view_t(hash, sizeof(hash)), signature))
			// Выводим отказ выработки
			return false;
		// Место, в которое помещается подпись в записи RFC 9215
		uint8_t reversed[64];
		// Переносим число s вперёд: раздел 2 RFC 9215
		::memcpy(reversed, signature + curve.size(), curve.size());
		// Переносим число r следом
		::memcpy(reversed + curve.size(), signature, curve.size());
		// Составитель основного ответа
		asn1::writer_t basic;
		// Открываем основной ответ
		if(!basic.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Разборщик подписываемой части
		asn1::reader_t reader(tbs);
		// Элемент подписываемой части
		asn1::element_t item;
		// Если подписываемую часть перечитать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим отказ выработки
			return false;
		// Записываем подписываемую часть как есть
		if(!basic.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), item.content))
			// Выводим отказ выработки
			return false;
		// Открываем опознаватель алгоритма подписи
		if(!basic.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Записываем опознаватель подписи ГОСТ Р 34.10-2012 с «Стрибогом»-256
		if(!basic.oid("1.2.643.7.1.1.3.2"))
			// Выводим отказ выработки
			return false;
		// Закрываем опознаватель алгоритма подписи
		if(!basic.close())
			// Выводим отказ выработки
			return false;
		// Записываем подпись
		if(!basic.bits(view_t(reversed, curve.size() * 2)))
			// Выводим отказ выработки
			return false;
		// Закрываем основной ответ
		if(!basic.close())
			// Выводим отказ выработки
			return false;
		// Составитель записи ответа
		asn1::writer_t writer;
		// Открываем запись ответа
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Значение исхода обращения: успех
		const uint8_t successful = 0x00;
		// Записываем исход обращения перечислением
		if(!writer.element(asn1::cls_t::UNIVERSAL, false, 0x0A, view_t(&successful, 1)))
			// Выводим отказ выработки
			return false;
		// Открываем обёртку тела ответа
		if(!writer.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ выработки
			return false;
		// Открываем тело ответа
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки
			return false;
		// Записываем опознаватель вида основного ответа
		if(!writer.oid("1.3.6.1.5.5.7.48.1.1"))
			// Выводим отказ выработки
			return false;
		// Записываем основной ответ строкой байтов
		if(!writer.octets(basic.data()))
			// Выводим отказ выработки
			return false;
		// Закрываем тело ответа
		if(!writer.close())
			// Выводим отказ выработки
			return false;
		// Закрываем обёртку тела ответа
		if(!writer.close())
			// Выводим отказ выработки
			return false;
		// Закрываем запись ответа
		if(!writer.close())
			// Выводим отказ выработки
			return false;
		// Получаем составленную запись ответа
		const view_t data = writer.data();
		// Переносим запись ответа в накопитель
		result.assign(data.data, data.data + data.size);
		// Выводим успешность выработки
		return true;
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи по записям
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		/**
		 * Выполняем перехват ошибок работы с памятью
		 */
		try {
			// Получаем байты, отправляемые клиентом
			view_t data = client.output();
			// Если клиенту есть что отправить серверу
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу
				server.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
			// Получаем байты, отправляемые сервером
			data = server.output();
			// Если серверу есть что отправить клиенту
			if(data.size > 0){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя сервера
				server.consume(buffer.size());
				// Выполняем подачу отправленных байтов клиенту
				client.push(view_t(buffer.data(), buffer.size()));
				// Запоминаем, что байты между сторонами передавались
				moved = true;
			}
		/**
		 * Если памяти под перенос байтов не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим признак того, что байты между сторонами не передавались
			return false;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи по записям
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 */
	void converse(client::context_t & client, server::context_t & server) noexcept {
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	}
	/**
	 * @brief Метод обмена прикладными данными в обе стороны
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что данные дошли в обе стороны без искажения
	 *
	 */
	bool barter(client::context_t & client, server::context_t & server) noexcept {
		// Прикладные данные, отправляемые клиентом
		const string request = "Запрос по связи со сшитым ответом о состоянии сертификата";
		// Если отправить прикладные данные клиентом не удалось
		if(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Накопитель, в который помещаются принятые прикладные данные
		vector <uint8_t> received;
		// Если получить принятые сервером прикладные данные не удалось
		if((server.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != request))
			// Выводим отказ обмена
			return false;
		// Прикладные данные, отправляемые сервером
		const string answer = "Ответ по связи со сшитым ответом о состоянии сертификата";
		// Если отправить прикладные данные сервером не удалось
		if(server.write(view_t(reinterpret_cast <const uint8_t *> (answer.data()), answer.size())) != context::error_t::NONE)
			// Выводим отказ обмена
			return false;
		// Выполняем передачу байтов между сторонами связи
		converse(client, server);
		// Выполняем сброс накопителя принятых данных
		received.clear();
		// Если получить принятые клиентом прикладные данные не удалось
		if((client.read(received) != context::error_t::NONE) || (string(received.begin(), received.end()) != answer))
			// Выводим отказ обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Метод настройки сторон связи
	 *
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param suite      набор шифрования обеих сторон
	 * @param group      группа обмена обеих сторон
	 * @param credential подлинность сервера и клиента
	 * @param mutual     запрашивается ли подлинность клиента
	 * @param levels     ведётся ли перенос по уровням QUIC
	 *
	 */
	void arrange(client::context_t & client, server::context_t & server, const protect::suite_t suite, const extension::group_t group, const context::credential_t & credential, const bool mutual, const bool levels) noexcept {
		// Устанавливаем набор шифрования клиенту
		client.suites(vector <protect::suite_t> {suite});
		// Устанавливаем набор шифрования серверу
		server.suites(vector <protect::suite_t> {suite});
		// Устанавливаем группу обмена клиенту
		client.groups(vector <extension::group_t> {group});
		// Устанавливаем группу обмена серверу
		server.groups(vector <extension::group_t> {group});
		// Устанавливаем подлинность сервера
		server.credential(credential);
		// Устанавливаем миг проверки клиенту
		client.moment(MOMENT);
		// Устанавливаем миг проверки серверу
		server.moment(MOMENT);
		// Если запрашивается подлинность клиента
		if(mutual){
			// Запрашиваем подлинность клиента
			server.request(true);
			// Устанавливаем подлинность клиента
			client.credential(credential);
		}
		// Если ведётся перенос по уровням
		if(levels){
			// Устанавливаем перенос по уровням клиенту
			client.transport(context::transport_t::LEVELS);
			// Устанавливаем перенос по уровням серверу
			server.transport(context::transport_t::LEVELS);
			// Устанавливаем прикладной протокол клиенту
			client.protocols(vector <string> {"h3"});
			// Устанавливаем прикладной протокол серверу
			server.protocols(vector <string> {"h3"});
			// Устанавливаем параметры переноса клиенту
			client.parameters(vector <uint8_t> {0x01, 0x04, 0x80, 0x00, 0xFF, 0xFF});
			// Устанавливаем параметры переноса серверу
			server.parameters(vector <uint8_t> {0x03, 0x02, 0x45, 0xAC});
		}
	}
	/**
	 * @brief Искажение сообщения рукопожатия на пути между сторонами по уровням
	 *
	 */
	typedef struct Mutation {
		// Искажается ли сообщение, идущее от сервера к клиенту
		bool downstream;
		// Вид искажаемого сообщения рукопожатия
		handshake::type_t type;
		// Преобразование тела сообщения; выводимый вид заменяет прежний
		std::function <handshake::type_t (vector <uint8_t> &)> apply;
		/**
		 * @brief Конструктор
		 *
		 */
		Mutation() noexcept : downstream(true), type(handshake::type_t::NONE) {}
	} mutation_t;
	/**
	 * @brief Метод искажения сообщения нужного вида в потоке сообщений уровня
	 *
	 * @param buffer   поток сообщений уровня с обвязкой
	 * @param mutation описание искажения
	 *
	 * @return         признак того, что сообщение найдено и искажено
	 *
	 */
	bool mutate(vector <uint8_t> & buffer, const mutation_t & mutation) {
		// Пересобираемый поток сообщений
		vector <uint8_t> rebuilt;
		// Признак того, что сообщение искажено
		bool applied = false;
		// Смещение разбора
		size_t offset = 0;
		/**
		 * Выполняем перебор сообщений потока
		 */
		while(offset < buffer.size()){
			// Обвязка очередного сообщения
			handshake::header_t header;
			// Если обвязку разобрать не удалось
			if(handshake::parse(view_t(buffer.data() + offset, buffer.size() - offset), header) != handshake::error_t::NONE)
				// Выводим отказ искажения
				return false;
			// Если тело сообщения не вмещается
			if((offset + handshake::HANDSHAKE_HEADER + header.size) > buffer.size())
				// Выводим отказ искажения
				return false;
			// Тело очередного сообщения
			vector <uint8_t> body(buffer.begin() + static_cast <std::ptrdiff_t> (offset + handshake::HANDSHAKE_HEADER), buffer.begin() + static_cast <std::ptrdiff_t> (offset + handshake::HANDSHAKE_HEADER + header.size));
			// Вид сообщения после искажения
			handshake::type_t type = header.type;
			// Если это искажаемое сообщение
			if(!applied && (header.type == mutation.type)){
				// Применяем искажение к телу
				type = mutation.apply(body);
				// Запоминаем, что сообщение искажено
				applied = true;
			}
			// Составитель сообщения с обвязкой
			handshake::writer_t writer;
			// Если сообщение составить не удалось
			if(writer.push(type, view_t(body.data(), body.size())) != handshake::error_t::NONE)
				// Выводим отказ искажения
				return false;
			// Получаем составленное сообщение
			const view_t data = writer.data();
			// Дописываем сообщение в пересобираемый поток
			rebuilt.insert(rebuilt.end(), data.data, data.data + data.size);
			// Сдвигаем смещение за сообщение
			offset += (handshake::HANDSHAKE_HEADER + header.size);
		}
		// Заменяем поток пересобранным
		buffer = rebuilt;
		// Выводим признак искажения
		return applied;
	}
	/**
	 * @brief Метод переноса сообщений одного уровня от одной стороны к другой с искажением
	 *
	 * @param from     связь стороны, отдающей сообщения
	 * @param to       связь стороны, принимающей сообщения
	 * @param level    уровень защиты переносимых сообщений
	 * @param mutation описание искажения либо nullptr
	 * @param applied  место, куда помещается признак применённого искажения
	 *
	 * @return         признак того, что сообщения переносились
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const context::level_t level, const mutation_t * mutation, bool & applied) {
		// Получаем сообщения, отправляемые на уровне
		const view_t data = from.output(level);
		// Если отправлять на уровне нечего
		if(data.size == 0)
			// Выводим признак того, что сообщения не переносились
			return false;
		// Выполняем перенос отправляемых сообщений
		vector <uint8_t> buffer(data.data, data.data + data.size);
		// Снимаем отправленные сообщения с накопителя уровня
		from.consume(level, buffer.size());
		// Если искажение задано и ещё не применено
		if((mutation != nullptr) && !applied)
			// Применяем искажение к потоку сообщений уровня
			applied = mutate(buffer, *mutation);
		// Выполняем подачу сообщений принимающей стороне на том же уровне
		to.push(level, view_t(buffer.data(), buffer.size()));
		// Выводим признак того, что сообщения переносились
		return true;
	}
	/**
	 * @brief Метод проведения рукопожатия сторон связи по уровням с искажением
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param mutation описание искажения либо nullptr
	 *
	 * @return         признак применённого искажения
	 *
	 */
	bool converse(client::context_t & client, server::context_t & server, const mutation_t * mutation) {
		// Признак применённого искажения
		bool applied = false;
		/**
		 * Выполняем передачу сообщений между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; i < 16; i++){
			// Признак того, что сообщения передавались
			bool moved = false;
			/**
			 * Выполняем перебор уровней защиты от клиента к серверу
			 */
			for(size_t j = 0; j < (sizeof(LEVELS) / sizeof(LEVELS[0])); j++)
				// Переносим сообщения уровня от клиента к серверу
				moved = (carry(client, server, LEVELS[j], (((mutation != nullptr) && !mutation->downstream) ? mutation : nullptr), applied) || moved);
			/**
			 * Выполняем перебор уровней защиты от сервера к клиенту
			 */
			for(size_t j = 0; j < (sizeof(LEVELS) / sizeof(LEVELS[0])); j++)
				// Переносим сообщения уровня от сервера к клиенту
				moved = (carry(server, client, LEVELS[j], (((mutation != nullptr) && mutation->downstream) ? mutation : nullptr), applied) || moved);
			// Если сторонам сказать больше нечего
			if(!moved)
				// Прекращаем передачу
				break;
		}
		// Выводим признак применённого искажения
		return applied;
	}
	/**
	 * @brief Метод искажения расширения состояния в теле сообщения цепочки сертификатов
	 *
	 * @param body      тело сообщения цепочки сертификатов
	 * @param transform преобразование тела расширения состояния первой записи
	 *
	 * @return          признак успешности искажения
	 *
	 */
	bool retouch(vector <uint8_t> & body, const std::function <void (vector <uint8_t> &)> & transform) noexcept {
		// Разбираемое сообщение цепочки сертификатов
		message::certificate_t certificate;
		// Если сообщение цепочки разобрать не удалось либо цепочка пуста
		if((message::parse(view_t(body.data(), body.size()), certificate) != message::error_t::NONE) || certificate.entries.empty())
			// Выводим отказ искажения
			return false;
		// Тело расширения состояния после преобразования
		vector <uint8_t> status;
		// Признак того, что расширение состояния найдено
		bool found = false;
		/**
		 * Выполняем перебор расширений первой записи цепочки
		 */
		for(size_t i = 0; i < certificate.entries[0].extensions.size(); i++){
			// Если это расширение состояния сертификата
			if(certificate.entries[0].extensions[i].type == static_cast <uint16_t> (extension::type_t::STATUS)){
				// Переносим тело расширения
				status.assign(certificate.entries[0].extensions[i].data.data, certificate.entries[0].extensions[i].data.data + certificate.entries[0].extensions[i].data.size);
				// Применяем преобразование к телу расширения
				transform(status);
				// Заменяем тело расширения преобразованным
				certificate.entries[0].extensions[i].data = view_t(status.data(), status.size());
				// Запоминаем, что расширение найдено
				found = true;
			}
		}
		// Если расширения состояния нет
		if(!found){
			// Составляем тело расширения преобразованием пустого
			transform(status);
			// Добавляем расширение состояния в первую запись
			certificate.entries[0].extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::STATUS), view_t(status.data(), status.size())));
		}
		// Накопитель пересобранного тела
		vector <uint8_t> rebuilt;
		// Если тело сообщения пересобрать не удалось
		if(message::build(certificate, rebuilt) != message::error_t::NONE)
			// Выводим отказ искажения
			return false;
		// Заменяем тело пересобранным
		body = rebuilt;
		// Выводим успешность искажения
		return true;
	}
};

/**
 * Проверка разбора ответов, составленных настоящим openssl: исход, ответчик, состояния
 * good/revoked/unknown, сроки, отсутствие nextUpdate, неповторимое значение, приложенный
 * сертификат делегированного ответчика, ответчик по хешу ключа, отказ ответчика без
 * тела и порченые записи
 */
TEST(OcspTest, Parse){
	{
		// Запись ответа good
		const vector <uint8_t> data = vectored("leaf-ec.good.der");
		// Проверяем чтение набора
		ASSERT_FALSE(data.empty());
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем исход обращения
		ASSERT_EQ(response.outcome(), ocsp::outcome_t::SUCCESSFUL);
		// Проверяем число ответов по сертификатам
		ASSERT_EQ(response.responses().size(), static_cast <size_t> (1));
		// Проверяем состояние сертификата
		ASSERT_EQ(response.responses()[0].status, ocsp::status_t::GOOD);
		// Проверяем алгоритм хеша опознавателя: sha1
		ASSERT_EQ(response.responses()[0].identifier.algorithm, "1.3.14.3.2.26");
		// Проверяем длину хеша имени издателя
		ASSERT_EQ(response.responses()[0].identifier.name.size, static_cast <size_t> (20));
		// Проверяем длину хеша ключа издателя
		ASSERT_EQ(response.responses()[0].identifier.key.size, static_cast <size_t> (20));
		// Проверяем порядковый номер сертификата
		ASSERT_EQ(response.responses()[0].identifier.serial.size, static_cast <size_t> (1));
		// Проверяем значение порядкового номера
		ASSERT_EQ(response.responses()[0].identifier.serial.data[0], 0x03);
		// Проверяем миг верности состояния
		ASSERT_EQ(response.responses()[0].updated, UPDATED);
		// Проверяем миг окончания обещания
		ASSERT_EQ(response.responses()[0].next, PROMISED);
		// Проверяем отсутствие мига отзыва
		ASSERT_EQ(response.responses()[0].revocation, static_cast <int64_t> (0));
		// Проверяем миг составления ответа
		ASSERT_EQ(response.produced(), UPDATED);
		// Проверяем отсутствие расширений ответа
		ASSERT_TRUE(response.extension().empty());
		// Проверяем приложенный сертификат ответчика
		ASSERT_EQ(response.certificates().size(), static_cast <size_t> (1));
		// Признак именования ответчика хешем
		bool hashed = true;
		// Опознаватель ответчика
		const view_t & responder = response.responder(hashed);
		// Проверяем, что ответчик назван именем
		ASSERT_FALSE(hashed);
		// Объект разбора сертификата издателя
		x509::certificate_t issuer;
		// Запись сертификата издателя
		const vector <uint8_t> authority = certified("mid-ec.crt");
		// Проверяем разбор сертификата издателя
		ASSERT_EQ(issuer.parse(view_t(authority.data(), authority.size())), x509::error_t::NONE);
		// Проверяем совпадение имени ответчика с именем издателя
		ASSERT_EQ(responder.size, issuer.subjects().element.size);
		// Проверяем совпадение имени ответчика с именем издателя байт в байт
		ASSERT_EQ(::memcmp(responder.data, issuer.subjects().element.data, responder.size), 0);
		// Проверяем алгоритм подписи: ecdsa-with-SHA256
		ASSERT_EQ(response.algorithms(), "1.2.840.10045.4.3.2");
		// Проверяем, что подписываемая часть найдена
		ASSERT_GT(response.body().size, static_cast <size_t> (0));
		// Число неиспользуемых разрядов подписи
		uint8_t unused = 1;
		// Проверяем, что подпись найдена
		ASSERT_GT(response.sign(unused).size, static_cast <size_t> (0));
		// Проверяем число неиспользуемых разрядов подписи
		ASSERT_EQ(unused, 0);
		// Проверяем сброс
		response.clear();
		// Проверяем, что ответы сброшены
		ASSERT_TRUE(response.responses().empty());
	}
	{
		// Запись ответа revoked
		const vector <uint8_t> data = vectored("leaf-ec.revoked.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем состояние сертификата
		ASSERT_EQ(response.responses()[0].status, ocsp::status_t::REVOKED);
		// Проверяем миг отзыва
		ASSERT_EQ(response.responses()[0].revocation, REVOKED);
	}
	{
		// Запись ответа unknown
		const vector <uint8_t> data = vectored("leaf-ec.unknown.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем состояние сертификата
		ASSERT_EQ(response.responses()[0].status, ocsp::status_t::UNKNOWN);
	}
	{
		// Запись ответа без nextUpdate
		const vector <uint8_t> data = vectored("leaf-ec.open.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем отсутствие мига окончания обещания
		ASSERT_EQ(response.responses()[0].next, static_cast <int64_t> (0));
	}
	{
		// Запись ответа с неповторимым значением
		const vector <uint8_t> data = vectored("leaf-ec.nonce.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем наличие расширения ответа
		ASSERT_EQ(response.extension().size(), static_cast <size_t> (1));
		// Проверяем опознаватель расширения
		ASSERT_EQ(response.extension()[0].oid, "1.3.6.1.5.5.7.48.1.2");
		// Неповторимое значение ответа
		view_t nonce;
		// Проверяем извлечение неповторимого значения
		ASSERT_EQ(ocsp::nonce(response.extension(), nonce), ocsp::error_t::NONE);
		// Проверяем длину неповторимого значения
		ASSERT_EQ(nonce.size, sizeof(NONCE));
		// Проверяем совпадение неповторимого значения с запрошенным
		ASSERT_EQ(::memcmp(nonce.data, NONCE, sizeof(NONCE)), 0);
		// Проверяем отсутствие значения в пустом наборе
		ASSERT_EQ(ocsp::nonce(response.responses()[0].extensions, nonce), ocsp::error_t::NONE);
		// Проверяем, что значение пусто
		ASSERT_EQ(nonce.size, static_cast <size_t> (0));
	}
	{
		// Запись ответа делегированного ответчика, названного хешем ключа
		const vector <uint8_t> data = vectored("leaf-ec.delegated.rid.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Признак именования ответчика хешем
		bool hashed = false;
		// Проверяем длину хеша ключа ответчика
		ASSERT_EQ(response.responder(hashed).size, static_cast <size_t> (20));
		// Проверяем, что ответчик назван хешем ключа
		ASSERT_TRUE(hashed);
		// Проверяем приложенный сертификат ответчика
		ASSERT_EQ(response.certificates().size(), static_cast <size_t> (1));
	}
	{
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор отказа ответчика
		ASSERT_EQ(response.parse(view_t(UNAUTHORIZED, sizeof(UNAUTHORIZED))), ocsp::error_t::NONE);
		// Проверяем исход обращения
		ASSERT_EQ(response.outcome(), ocsp::outcome_t::UNAUTHORIZED);
		// Проверяем отсутствие ответов по сертификатам
		ASSERT_TRUE(response.responses().empty());
		// Отказ ответчика с неизвестным исходом
		const uint8_t strange[5] = {0x30, 0x03, 0x0A, 0x01, 0x04};
		// Проверяем отказ разбора неизвестного исхода
		ASSERT_EQ(response.parse(view_t(strange, sizeof(strange))), ocsp::error_t::STRUCTURE);
		// Успешный исход без тела
		const uint8_t hollow[5] = {0x30, 0x03, 0x0A, 0x01, 0x00};
		// Проверяем отказ разбора успеха без тела
		ASSERT_EQ(response.parse(view_t(hollow, sizeof(hollow))), ocsp::error_t::STRUCTURE);
		// Проверяем отказ разбора пустой записи
		ASSERT_EQ(response.parse(view_t(nullptr, 0)), ocsp::error_t::ENCODING);
	}
	{
		// Запись ответа good
		vector <uint8_t> data = vectored("leaf-ec.good.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Дописываем лишний байт за записью
		data.push_back(0x00);
		// Проверяем отказ разбора лишнего хвоста
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::STRUCTURE);
		// Снимаем лишний байт
		data.pop_back();
		/**
		 * Выполняем перебор усечений записи
		 */
		for(size_t size = 1; size < data.size(); size += 7)
			// Проверяем отказ разбора усечённой записи
			ASSERT_NE(response.parse(view_t(data.data(), size)), ocsp::error_t::NONE) << "усечение " << size;
		// Портим опознаватель вида ответа: последний байт OID basic
		data[10] = 0x02;
		// Проверяем отказ разбора чужого вида ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::STRUCTURE);
	}
}

/**
 * Проверка ответов против сертификата и издателя: состояния good/revoked/unknown,
 * делегированный ответчик по имени и по хешу ключа, ответчик без назначения ключа,
 * чужой ответчик, sha256 в опознавателе, RSA, самоподписанные ключи набора, чужой
 * опознаватель, отказ ответчика, сроки с люфтом, неповторимое значение, битая подпись
 */
TEST(OcspTest, Verify){
	// Состояние сертификата
	ocsp::status_t status = ocsp::status_t::NONE;
	// Пустое неповторимое значение
	const view_t none(nullptr, 0);
	// Проверяем ответ good
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ revoked
	ASSERT_EQ(judge("leaf-ec.revoked.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::REVOKED);
	// Проверяем ответ unknown
	ASSERT_EQ(judge("leaf-ec.unknown.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::UNKNOWN);
	// Проверяем ответ делегированного ответчика по имени
	ASSERT_EQ(judge("leaf-ec.delegated.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ делегированного ответчика по хешу ключа
	ASSERT_EQ(judge("leaf-ec.delegated.rid.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ делегированного ответчика вне срока его сертификата: сертификат издан 2026 годом
	ASSERT_EQ(judge("leaf-ec.delegated.der", "leaf-ec.crt", "mid-ec.crt", 1600000000, 0, none, status), ocsp::error_t::RESPONDER);
	// Проверяем ответ ответчика без назначения id-kp-OCSPSigning
	ASSERT_EQ(judge("leaf-ec.unauthorized.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::RESPONDER);
	// Проверяем состояние: не установлено
	ASSERT_EQ(status, ocsp::status_t::NONE);
	// Проверяем ответ чужого ответчика, издателем не изданного
	ASSERT_EQ(judge("leaf-ec.foreign.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::RESPONDER);
	// Проверяем ответ с опознавателем по sha256
	ASSERT_EQ(judge("leaf-ec.sha256.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ RSA
	ASSERT_EQ(judge("leaf-rsa.good.der", "leaf-rsa.crt", "mid-rsa.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ по самоподписанному ключу ec256
	ASSERT_EQ(judge("ec256.good.der", "ec256.crt", "ec256.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ revoked по самоподписанному ключу ec256
	ASSERT_EQ(judge("ec256.revoked.der", "ec256.crt", "ec256.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::REVOKED);
	// Проверяем ответ по самоподписанному ключу ec384
	ASSERT_EQ(judge("ec384.good.der", "ec384.crt", "ec384.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем ответ по самоподписанному ключу rsa2048
	ASSERT_EQ(judge("rsa2048.good.der", "rsa2048.crt", "rsa2048.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Проверяем ответ revoked по самоподписанному ключу rsa2048
	ASSERT_EQ(judge("rsa2048.revoked.der", "rsa2048.crt", "rsa2048.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::REVOKED);
	// Проверяем чужой опознаватель: ответ по листу ec против листа rsa
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-rsa.crt", "mid-rsa.crt", MOMENT, 0, none, status), ocsp::error_t::IDENTITY);
	// Проверяем чужой издатель: хеши имени и ключа издателя не сходятся
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-ec.crt", "ca-ec.crt", MOMENT, 0, none, status), ocsp::error_t::IDENTITY);
	// Проверяем чужой лист того же издателя: порядковый номер не сходится
	ASSERT_EQ(judge("leaf-ec.good.der", "ocsp/aia-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::IDENTITY);
	// Проверяем срок: обещание короткого ответа вышло
	ASSERT_EQ(judge("leaf-ec.short.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::EXPIRED);
	// Проверяем срок с люфтом: сто секунд за обещанием при люфте двести
	ASSERT_EQ(judge("leaf-ec.short.der", "leaf-ec.crt", "mid-ec.crt", SHORT + 100, 200, none, status), ocsp::error_t::NONE);
	// Проверяем срок без люфта: сто секунд за обещанием
	ASSERT_EQ(judge("leaf-ec.short.der", "leaf-ec.crt", "mid-ec.crt", SHORT + 100, 0, none, status), ocsp::error_t::EXPIRED);
	// Проверяем срок: миг верности в будущем
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-ec.crt", "mid-ec.crt", EARLIER, 0, none, status), ocsp::error_t::EXPIRED);
	// Проверяем срок: миг верности в будущем в пределах люфта
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-ec.crt", "mid-ec.crt", UPDATED - 30, 60, none, status), ocsp::error_t::NONE);
	// Проверяем срок без нулевого мига: сроки не судятся
	ASSERT_EQ(judge("leaf-ec.short.der", "leaf-ec.crt", "mid-ec.crt", 0, 0, none, status), ocsp::error_t::NONE);
	// Проверяем ответ без обещания на далёкий миг: обещания нет, срок не вышел
	ASSERT_EQ(judge("leaf-ec.open.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	// Проверяем неповторимое значение: ответ с запрошенным значением
	ASSERT_EQ(judge("leaf-ec.nonce.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, view_t(NONCE, sizeof(NONCE)), status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Чужое неповторимое значение
	uint8_t alien[16];
	// Переносим запрошенное значение
	::memcpy(alien, NONCE, sizeof(alien));
	// Портим один байт
	alien[7] = static_cast <uint8_t> (alien[7] ^ 0x01);
	// Проверяем неповторимое значение: чужое
	ASSERT_EQ(judge("leaf-ec.nonce.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, view_t(alien, sizeof(alien)), status), ocsp::error_t::NONCE);
	// Проверяем неповторимое значение: ответ без значения при запрошенном
	ASSERT_EQ(judge("leaf-ec.good.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, view_t(NONCE, sizeof(NONCE)), status), ocsp::error_t::NONCE);
	// Проверяем ответ с неповторимым значением без ожидания: значение не судится
	ASSERT_EQ(judge("leaf-ec.nonce.der", "leaf-ec.crt", "mid-ec.crt", MOMENT, 0, none, status), ocsp::error_t::NONE);
	{
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем отказ ответчика
		ASSERT_EQ(response.parse(view_t(UNAUTHORIZED, sizeof(UNAUTHORIZED))), ocsp::error_t::NONE);
		// Записи сертификатов
		const vector <uint8_t> subject = certified("leaf-ec.crt"), authority = certified("mid-ec.crt");
		// Проверяем, что отказ ответчика проверку не проходит
		ASSERT_EQ(ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), MOMENT, 0, none, status), ocsp::error_t::STATUS);
		// Проверяем состояние: не установлено
		ASSERT_EQ(status, ocsp::status_t::NONE);
		// Порченый сертификат
		const vector <uint8_t> broken(subject.begin(), subject.begin() + 40);
		// Запись ответа good
		const vector <uint8_t> data = vectored("leaf-ec.good.der");
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем отказ разбора порченого сертификата
		ASSERT_EQ(ocsp::verify(response, view_t(broken.data(), broken.size()), view_t(authority.data(), authority.size()), MOMENT, 0, none, status), ocsp::error_t::KEY);
		// Проверяем отказ разбора порченого издателя
		ASSERT_EQ(ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(broken.data(), broken.size()), MOMENT, 0, none, status), ocsp::error_t::KEY);
	}
	{
		// Записи сертификатов
		const vector <uint8_t> subject = certified("leaf-ec.crt"), authority = certified("mid-ec.crt");
		// Запись ответа good
		vector <uint8_t> data = vectored("leaf-ec.good.der");
		// Объект разбора ответа
		ocsp::response_t response;
		// Проверяем разбор ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Число неиспользуемых разрядов подписи
		uint8_t unused = 0;
		// Смещение подписи внутри записи
		const size_t offset = static_cast <size_t> (response.sign(unused).data - data.data());
		// Портим последний байт подписи
		data[offset + response.sign(unused).size - 1] = static_cast <uint8_t> (data[offset + response.sign(unused).size - 1] ^ 0x01);
		// Проверяем разбор порченого ответа
		ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
		// Проверяем, что битая подпись не сходится
		ASSERT_EQ(ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), MOMENT, 0, none, status), ocsp::error_t::SIGNATURE);
		// Восстанавливаем подпись
		data[offset + response.sign(unused).size - 1] = static_cast <uint8_t> (data[offset + response.sign(unused).size - 1] ^ 0x01);
		// Смещение подписываемой части
		const size_t body = static_cast <size_t> (response.body().data - data.data());
		// Портим байт внутри подписываемой части: секунды мига составления
		data[body + 40] = static_cast <uint8_t> (data[body + 40] ^ 0x01);
		// Проверяем, что подпись под подменённой частью не сходится либо запись отвергнута
		if(response.parse(view_t(data.data(), data.size())) == ocsp::error_t::NONE){
			// Проверяем отказ подписи
			ASSERT_EQ(ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), MOMENT, 0, none, status), ocsp::error_t::SIGNATURE);
		}
	}
}

/**
 * Проверка составления запроса байт в байт с openssl: sha1 без значения, sha256, с
 * неповторимым значением, самоподписанный ключ; неподдерживаемый хеш и порченый вход;
 * при наличии openssl запрос составляется им живьём и сличается, а ответ на наш запрос
 * вырабатывается им и проверяется нами
 */
TEST(OcspTest, Request){
	// Записи сертификатов
	const vector <uint8_t> subject = certified("leaf-ec.crt"), authority = certified("mid-ec.crt");
	// Проверяем чтение набора
	ASSERT_FALSE(subject.empty() || authority.empty());
	// Накопитель запроса
	vector <uint8_t> request;
	// Проверяем составление запроса по sha1
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA1, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем совпадение с запросом openssl байт в байт
	ASSERT_EQ(request, vectored("leaf-ec.req.der"));
	// Проверяем составление запроса по sha256
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA256, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем совпадение с запросом openssl байт в байт
	ASSERT_EQ(request, vectored("leaf-ec.sha256.req.der"));
	// Проверяем составление запроса с неповторимым значением
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA1, view_t(NONCE, sizeof(NONCE)), request), ocsp::error_t::NONE);
	// Проверяем совпадение с запросом openssl байт в байт
	ASSERT_EQ(request, vectored("leaf-ec.nonce.req.der"));
	// Запись самоподписанного сертификата
	const vector <uint8_t> self = certified("ec256.crt");
	// Проверяем составление запроса по самоподписанному ключу
	ASSERT_EQ(ocsp::request(view_t(self.data(), self.size()), view_t(self.data(), self.size()), digest::hash_t::SHA1, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем совпадение с запросом openssl байт в байт
	ASSERT_EQ(request, vectored("ec256.req.der"));
	// Проверяем составление запроса по «Стрибогу»: параметры хеша опущены по RFC 9215
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::STREEBOG256, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем длину запроса: хеши по 32 байта, опознаватель на байт короче sha256 и без NULL в два байта
	ASSERT_EQ(request.size(), vectored("leaf-ec.sha256.req.der").size() - 3);
	// Проверяем отказ неподдерживаемого хеша
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::MD5, view_t(nullptr, 0), request), ocsp::error_t::HASH);
	// Слишком длинное неповторимое значение
	const uint8_t longish[33] = {0};
	// Проверяем отказ длинного значения
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA1, view_t(longish, sizeof(longish)), request), ocsp::error_t::STRUCTURE);
	// Проверяем отказ порченого сертификата
	ASSERT_EQ(ocsp::request(view_t(subject.data(), 30), view_t(authority.data(), authority.size()), digest::hash_t::SHA1, view_t(nullptr, 0), request), ocsp::error_t::KEY);
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0){
		// Пропускаем живое сличение вслух
		GTEST_SKIP() << "openssl недоступен: запросы сличены лишь с записанными";
	}
	// Пути к файлам обмена
	const std::string base = "/tmp/ants-ocsp-" + std::to_string(::getpid());
	// Пути к сертификатам
	const std::string crt = std::string(CORPUS) + "/leaf-ec.crt", issuer = std::string(CORPUS) + "/mid-ec.crt", key = std::string(CORPUS) + "/mid-ec.key";
	// Составляем запрос openssl живьём
	ASSERT_EQ(shell("openssl ocsp -issuer " + issuer + " -cert " + crt + " -no_nonce -reqout " + base + ".req >/dev/null 2>&1"), 0);
	// Проверяем составление нашего запроса
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA1, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем совпадение с живым запросом openssl
	ASSERT_EQ(request, slurp(base + ".req"));
	// Записываем наш запрос с неповторимым значением
	ASSERT_EQ(ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA256, view_t(NONCE, sizeof(NONCE)), request), ocsp::error_t::NONE);
	// Сохраняем наш запрос
	ASSERT_TRUE(spill(base + ".ours", request));
	// Проверяем, что openssl разбирает наш запрос и видит порядковый номер
	ASSERT_EQ(shell("(openssl ocsp -reqin " + base + ".ours -req_text -noverify 2>/dev/null | grep -q 'Serial Number: 03')"), 0);
	// Проверяем, что openssl видит наше неповторимое значение
	ASSERT_EQ(shell("(openssl ocsp -reqin " + base + ".ours -req_text -noverify 2>/dev/null | grep -qi 'nonce')"), 0);
	// Если ответчик openssl не умеет задавать хеш подписи (LibreSSL без -rmd), ответ уйдёт под SHA-1, который библиотека отвергает по замыслу
	if(shell("openssl ocsp -help 2>&1 | grep -q rmd") != 0)
		// Пропускаем обмен ответом: чужой ответчик негоден, а не наш разбор
		GTEST_SKIP() << "openssl ocsp без -rmd подписывает ответ SHA-1";
	// Вырабатываем ответ openssl на наш запрос
	ASSERT_EQ(shell("openssl ocsp -index " + std::string(CORPUS) + "/ocsp/index-good.txt -rmd sha256 -rsigner " + issuer + " -rkey " + key + " -CA " + issuer + " -reqin " + base + ".ours -respout " + base + ".resp -ndays 30 >/dev/null 2>&1"), 0);
	// Читаем ответ openssl
	const vector <uint8_t> answer = slurp(base + ".resp");
	// Проверяем чтение ответа
	ASSERT_FALSE(answer.empty());
	// Объект разбора ответа
	ocsp::response_t response;
	// Проверяем разбор ответа openssl
	ASSERT_EQ(response.parse(view_t(answer.data(), answer.size())), ocsp::error_t::NONE);
	// Состояние сертификата
	ocsp::status_t status = ocsp::status_t::NONE;
	// Проверяем ответ на наш запрос: sha256 в опознавателе, неповторимое значение возвращено, срок судится мигом верности
	ASSERT_EQ(ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), response.responses().empty() ? 0 : response.responses()[0].updated + 60, 0, view_t(NONCE, sizeof(NONCE)), status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Удаляем файлы обмена
	::remove((base + ".req").c_str());
	// Удаляем наш запрос
	::remove((base + ".ours").c_str());
	// Удаляем ответ
	::remove((base + ".resp").c_str());
}

/**
 * Проверка извлечения адреса ответчика из расширения сведений о доступе к издателю
 */
TEST(OcspTest, Responder){
	// Запись сертификата с адресом ответчика
	const vector <uint8_t> aia = certified("ocsp/aia-ec.crt");
	// Проверяем чтение набора
	ASSERT_FALSE(aia.empty());
	// Адрес ответчика
	string address;
	// Проверяем извлечение адреса
	ASSERT_EQ(ocsp::responder(view_t(aia.data(), aia.size()), address), ocsp::error_t::NONE);
	// Проверяем адрес
	ASSERT_EQ(address, "http://ocsp.anyks.com/ec");
	// Запись сертификата без адреса
	const vector <uint8_t> plain = certified("leaf-ec.crt");
	// Проверяем извлечение адреса из сертификата без него
	ASSERT_EQ(ocsp::responder(view_t(plain.data(), plain.size()), address), ocsp::error_t::NONE);
	// Проверяем, что адрес пуст
	ASSERT_TRUE(address.empty());
	// Проверяем отказ порченого сертификата
	ASSERT_EQ(ocsp::responder(view_t(aia.data(), 25), address), ocsp::error_t::KEY);
}

/**
 * Проверка ответа на алгоритмах ГОСТ, выработанного своими средствами: подпись
 * ГОСТ Р 34.10-2012 со «Стрибогом»-256, опознаватель по «Стрибогу»-256, состояния
 * good и revoked, чужой ключ
 */
TEST(OcspTest, Gost){
	// Подлинность стороны ГОСТ
	context::credential_t credential;
	// Вырабатываем подлинность ГОСТ
	ASSERT_TRUE(identity("anyks.com", credential));
	// Запись ответа
	vector <uint8_t> data;
	// Вырабатываем ответ good
	ASSERT_TRUE(gosted(credential, ocsp::status_t::GOOD, data));
	// Объект разбора ответа
	ocsp::response_t response;
	// Проверяем разбор ответа
	ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
	// Проверяем алгоритм подписи
	ASSERT_EQ(response.algorithms(), "1.2.643.7.1.1.3.2");
	// Проверяем алгоритм хеша опознавателя
	ASSERT_EQ(response.responses()[0].identifier.algorithm, "1.2.643.7.1.1.2.2");
	// Состояние сертификата
	ocsp::status_t status = ocsp::status_t::NONE;
	// Просмотр сертификата
	const view_t certificate(credential.chain[0].data(), credential.chain[0].size());
	// Проверяем ответ ГОСТ
	ASSERT_EQ(ocsp::verify(response, certificate, certificate, MOMENT, 0, view_t(nullptr, 0), status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::GOOD);
	// Вырабатываем ответ revoked
	ASSERT_TRUE(gosted(credential, ocsp::status_t::REVOKED, data));
	// Проверяем разбор ответа
	ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
	// Проверяем миг отзыва
	ASSERT_EQ(response.responses()[0].revocation, REVOKED);
	// Проверяем ответ ГОСТ
	ASSERT_EQ(ocsp::verify(response, certificate, certificate, MOMENT, 0, view_t(nullptr, 0), status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::REVOKED);
	// Чужая подлинность ГОСТ с тем же именем
	context::credential_t other;
	// Вырабатываем чужую подлинность
	ASSERT_TRUE(identity("anyks.com", other));
	// Просмотр чужого сертификата
	const view_t alien(other.chain[0].data(), other.chain[0].size());
	// Проверяем, что ответ к чужому сертификату не относится: хеш ключа издателя иной
	ASSERT_EQ(ocsp::verify(response, alien, alien, MOMENT, 0, view_t(nullptr, 0), status), ocsp::error_t::IDENTITY);
	// Вырабатываем ответ unknown
	ASSERT_TRUE(gosted(credential, ocsp::status_t::UNKNOWN, data));
	// Проверяем разбор ответа
	ASSERT_EQ(response.parse(view_t(data.data(), data.size())), ocsp::error_t::NONE);
	// Проверяем ответ ГОСТ
	ASSERT_EQ(ocsp::verify(response, certificate, certificate, MOMENT, 0, view_t(nullptr, 0), status), ocsp::error_t::NONE);
	// Проверяем состояние
	ASSERT_EQ(status, ocsp::status_t::UNKNOWN);
	// Запрос по «Стрибогу» к сертификату ГОСТ
	vector <uint8_t> request;
	// Проверяем составление запроса
	ASSERT_EQ(ocsp::request(certificate, certificate, digest::hash_t::STREEBOG256, view_t(nullptr, 0), request), ocsp::error_t::NONE);
	// Проверяем, что запрос не пуст
	ASSERT_FALSE(request.empty());
}

/**
 * Проверка петлевых рукопожатий со сшивкой по записям и по уровням: сервер отдаёт
 * ответ, клиент запрашивает, получает и проверяет; при подлинности клиента ответ идёт и
 * от клиента к серверу по запросу подлинности; самоподписанные ключи набора, цепочка из
 * трёх звеньев с издателем во втором и ветвь ГОСТ; обмен данными и возобновление
 */
TEST(OcspTest, Loopback){
	/**
	 * Выполняем перебор способов переноса: записи и уровни
	 */
	for(size_t t = 0; t < 2; t++){
		/**
		 * Выполняем перебор ключей набора
		 */
		for(size_t k = 0; k < 3; k++){
			// Имена ключей набора с ответами
			static const char * ENTRIES[] = {"ec256", "ec384", "rsa2048"};
			// Подлинность стороны
			context::credential_t credential;
			// Составляем подлинность
			ASSERT_TRUE(keyed(ENTRIES[k], credential)) << ENTRIES[k];
			// Ответ о состоянии
			const vector <uint8_t> answer = vectored((std::string(ENTRIES[k]) + ".good.der").c_str());
			// Проверяем чтение ответа
			ASSERT_FALSE(answer.empty());
			/**
			 * Выполняем перебор наборов шифрования
			 */
			for(size_t s = 0; s < (sizeof(SUITES) / sizeof(SUITES[0])); s++){
				// Связь стороны клиента
				client::context_t client;
				// Связь стороны сервера
				server::context_t server;
				// Настраиваем стороны с подлинностью клиента
				arrange(client, server, SUITES[s], extension::group_t::X25519, credential, true, (t == 1));
				// Пустой запас доверия: издатель самоподписанного сертификата - он сам
				const trust::store_t store;
				// Сервер отдаёт ответ
				server.status(answer);
				// Сервер запрашивает состояние клиента
				server.status(true);
				// Сервер проверяет ответ клиента
				server.verification(true, 0, store);
				// Клиент отдаёт ответ
				client.status(answer);
				// Клиент запрашивает состояние сервера
				client.status(true);
				// Клиент проверяет ответ сервера
				client.verification(true, 0, store);
				// Заводим сервер
				ASSERT_EQ(server.start(), context::error_t::NONE);
				// Заводим клиента
				ASSERT_EQ(client.start(), context::error_t::NONE);
				// Если перенос идёт записями
				if(t == 0)
					// Проводим рукопожатие по записям
					converse(client, server);
				// Если перенос идёт по уровням
				else
					// Проводим рукопожатие по уровням
					(void) converse(client, server, nullptr);
				// Проверяем установленность связи клиентом
				ASSERT_TRUE(client.established()) << ENTRIES[k] << " " << s << " " << t << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
				// Проверяем установленность связи сервером
				ASSERT_TRUE(server.established()) << ENTRIES[k] << " " << s << " " << t;
				// Проверяем, что ответ сервера дошёл до клиента байт в байт
				ASSERT_EQ(client.status(), answer);
				// Проверяем состояние сертификата сервера у клиента
				ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
				// Проверяем, что ответ клиента дошёл до сервера байт в байт
				ASSERT_EQ(server.status(), answer);
				// Проверяем состояние сертификата клиента у сервера
				ASSERT_EQ(server.certified(), ocsp::status_t::GOOD);
				// Если перенос идёт записями
				if(t == 0){
					// Проверяем обмен данными
					ASSERT_TRUE(barter(client, server));
					// Выдаём билет
					ASSERT_EQ(server.issue(), context::error_t::NONE);
					// Доставляем билет
					converse(client, server);
					// Проверяем получение билета
					ASSERT_EQ(client.tickets().size(), static_cast <size_t> (1));
					// Связь возобновляющего клиента
					client::context_t resuming;
					// Связь возобновляющего сервера
					server::context_t resumed;
					// Настраиваем стороны без подлинности клиента
					arrange(resuming, resumed, SUITES[s], extension::group_t::X25519, credential, false, false);
					// Сервер отдаёт ответ
					resumed.status(answer);
					// Клиент запрашивает состояние
					resuming.status(true);
					// Клиент проверяет ответ
					resuming.verification(true, 0, store);
					// Предъявляем билет
					resuming.resume(client.tickets()[0]);
					// Признаём билеты
					resumed.resume(server.tickets());
					// Заводим сервер
					ASSERT_EQ(resumed.start(), context::error_t::NONE);
					// Заводим клиента
					ASSERT_EQ(resuming.start(), context::error_t::NONE);
					// Проводим рукопожатие
					converse(resuming, resumed);
					// Проверяем установленность связи
					ASSERT_TRUE(resuming.established() && resumed.established()) << ENTRIES[k] << " " << s;
					// Проверяем возобновление билетом
					ASSERT_TRUE(resuming.shared() && resumed.shared());
					// Цепочки при возобновлении нет: ответа нет
					ASSERT_TRUE(resuming.status().empty());
					// Состояние не установлено
					ASSERT_EQ(resuming.certified(), ocsp::status_t::NONE);
					// Проверяем обмен данными по возобновлённой связи
					ASSERT_TRUE(barter(resuming, resumed));
				}
			}
		}
		{
			// Подлинность стороны из цепочки трёх звеньев
			context::credential_t credential;
			// Составляем подлинность
			ASSERT_TRUE(chained("ec", credential));
			// Ответ о состоянии листа цепочки, подписанный издателем
			const vector <uint8_t> answer = vectored("leaf-ec.delegated.der");
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны без подлинности клиента
			arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, false, (t == 1));
			// Пустой запас доверия: издатель берётся вторым звеном цепочки
			const trust::store_t store;
			// Сервер отдаёт ответ по листу
			server.status(answer, 0);
			// Сервер отдаёт ответ и по промежуточному звену: любая запись, лишь бы дошла
			server.status(vectored("leaf-ec.good.der"), 1);
			// Клиент запрашивает состояние
			client.status(true);
			// Клиент проверяет ответ
			client.verification(true, 0, store);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Если перенос идёт записями
			if(t == 0)
				// Проводим рукопожатие по записям
				converse(client, server);
			// Если перенос идёт по уровням
			else
				// Проводим рукопожатие по уровням
				(void) converse(client, server, nullptr);
			// Проверяем установленность связи
			ASSERT_TRUE(client.established() && server.established()) << t << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Проверяем цепочку у клиента
			ASSERT_EQ(client.peer().size(), static_cast <size_t> (3));
			// Проверяем ответ листа у клиента
			ASSERT_EQ(client.status(), answer);
			// Проверяем состояние: делегированный ответчик признан
			ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
		}
		{
			// Подлинность стороны из одного листа цепочки: издатель разыскивается в запасе
			context::credential_t credential;
			// Составляем подлинность
			ASSERT_TRUE(chained("ec", credential));
			// Оставляем один лист
			credential.chain.resize(1);
			// Ответ о состоянии листа
			const vector <uint8_t> answer = vectored("leaf-ec.good.der");
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны без подлинности клиента
			arrange(client, server, protect::suite_t::AES_256_GCM_SHA384, extension::group_t::X25519, credential, false, (t == 1));
			// Запас доверия с издателем листа
			trust::store_t store;
			// Запись издателя
			const vector <uint8_t> issuer = certified("mid-ec.crt");
			// Добавляем издателя в запас
			ASSERT_TRUE(store.add(view_t(issuer.data(), issuer.size())));
			// Сервер отдаёт ответ
			server.status(answer);
			// Клиент запрашивает состояние
			client.status(true);
			// Клиент проверяет ответ по запасу
			client.verification(true, 0, store);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Если перенос идёт записями
			if(t == 0)
				// Проводим рукопожатие по записям
				converse(client, server);
			// Если перенос идёт по уровням
			else
				// Проводим рукопожатие по уровням
				(void) converse(client, server, nullptr);
			// Проверяем установленность связи
			ASSERT_TRUE(client.established() && server.established()) << t << " " << static_cast <int> (client.error());
			// Проверяем состояние: издатель найден в запасе
			ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
		}
		{
			// Подлинность стороны ГОСТ
			context::credential_t credential;
			// Вырабатываем подлинность ГОСТ
			ASSERT_TRUE(identity("anyks.com", credential));
			// Ответ ГОСТ
			vector <uint8_t> answer;
			// Вырабатываем ответ good
			ASSERT_TRUE(gosted(credential, ocsp::status_t::GOOD, answer));
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны с подлинностью клиента на наборе ГОСТ
			arrange(client, server, protect::suite_t::KUZNYECHIK_MGM_L, extension::group_t::GC256B, credential, true, (t == 1));
			// Пустой запас доверия
			const trust::store_t store;
			// Сервер отдаёт ответ
			server.status(answer);
			// Сервер запрашивает состояние клиента
			server.status(true);
			// Сервер проверяет ответ клиента
			server.verification(true, 0, store);
			// Клиент отдаёт ответ
			client.status(answer);
			// Клиент запрашивает состояние
			client.status(true);
			// Клиент проверяет ответ
			client.verification(true, 0, store);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Если перенос идёт записями
			if(t == 0)
				// Проводим рукопожатие по записям
				converse(client, server);
			// Если перенос идёт по уровням
			else
				// Проводим рукопожатие по уровням
				(void) converse(client, server, nullptr);
			// Проверяем установленность связи
			ASSERT_TRUE(client.established() && server.established()) << t << " " << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
			// Проверяем ответ у клиента
			ASSERT_EQ(client.status(), answer);
			// Проверяем состояние у клиента
			ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
			// Проверяем ответ у сервера
			ASSERT_EQ(server.status(), answer);
			// Проверяем состояние у сервера
			ASSERT_EQ(server.certified(), ocsp::status_t::GOOD);
		}
	}
}

/**
 * Проверка политики отсутствия ответа: запрос без ответа связь не рвёт, ответ без
 * запроса не посылается, проверка без ответа состояния не даёт; ответ без проверки
 * хранится как есть, даже revoked
 */
TEST(OcspTest, Absent){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(keyed("ec256", credential));
	// Пустой запас доверия
	const trust::store_t store;
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true, false);
		// Клиент запрашивает состояние, сервер ответа не имеет
		client.status(true);
		// Клиент проверяет ответ
		client.verification(true, 0, store);
		// Сервер запрашивает состояние, клиент ответа не имеет
		server.status(true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи: отсутствие ответа - не отказ
		ASSERT_TRUE(client.established() && server.established()) << static_cast <int> (client.error()) << " " << static_cast <int> (server.error());
		// Проверяем, что ответа у клиента нет
		ASSERT_TRUE(client.status().empty());
		// Проверяем, что состояние не установлено
		ASSERT_EQ(client.certified(), ocsp::status_t::NONE);
		// Проверяем, что ответа у сервера нет
		ASSERT_TRUE(server.status().empty());
		// Проверяем обмен данными
		ASSERT_TRUE(barter(client, server));
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true, false);
		// Сервер имеет ответ, клиент его не запрашивает
		server.status(vectored("ec256.good.der"));
		// Клиент имеет ответ, сервер его не запрашивает
		client.status(vectored("ec256.good.der"));
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что ответ без запроса не послан клиенту
		ASSERT_TRUE(client.status().empty());
		// Проверяем, что ответ без запроса не послан серверу
		ASSERT_TRUE(server.status().empty());
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны без подлинности клиента
		arrange(client, server, protect::suite_t::CHACHA20_POLY1305_SHA256, extension::group_t::X25519, credential, false, false);
		// Ответ revoked
		const vector <uint8_t> answer = vectored("ec256.revoked.der");
		// Сервер отдаёт ответ revoked
		server.status(answer);
		// Клиент запрашивает состояние без проверки
		client.status(true);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем установленность связи: без проверки ответ лишь хранится
		ASSERT_TRUE(client.established() && server.established());
		// Проверяем, что ответ дошёл как есть
		ASSERT_EQ(client.status(), answer);
		// Проверяем, что состояние не установлено
		ASSERT_EQ(client.certified(), ocsp::status_t::NONE);
		// Объект разбора ответа потребителем
		ocsp::response_t response;
		// Проверяем разбор ответа потребителем
		ASSERT_EQ(response.parse(view_t(client.status().data(), client.status().size())), ocsp::error_t::NONE);
		// Проверяем состояние по разбору
		ASSERT_EQ(response.responses()[0].status, ocsp::status_t::REVOKED);
		// Проверяем, что клиент сброшен без остатка
		client.clear();
		// Проверяем, что ответ сброшен
		ASSERT_TRUE(client.status().empty());
	}
}

/**
 * Проверка отказов: отозванный сертификат, чужой ответ, вышедший срок, неведомый
 * ответчику сертификат (не отказ), порченый ответ - извещение 113 в обе стороны, по
 * записям и по уровням; искажения на пути: вид состояния не ocsp, лишний хвост,
 * непрошенное расширение, status_request в защищённых расширениях
 */
TEST(OcspTest, Refusals){
	// Подлинность стороны
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(keyed("ec256", credential));
	// Пустой запас доверия
	const trust::store_t store;
	/**
	 * Выполняем перебор способов переноса: записи и уровни
	 */
	for(size_t t = 0; t < 2; t++){
		/**
		 * @brief Описание случая отказа
		 *
		 */
		typedef struct Refusal {
			// Название случая
			const char * name;
			// Ответ, отдаваемый сервером
			const char * answer;
			// Ожидаемое извещение у сервера от клиента
			alert::description_t description;
			// Устанавливается ли связь
			bool established;
			// Ожидаемое состояние у клиента: отозванный сертификат проверен, состояние его известно
			ocsp::status_t status;
		} refusal_t;
		// Случаи отказов
		static const refusal_t CASES[] = {
			{"revoked", "ec256.revoked.der", alert::description_t::STATUS, false, ocsp::status_t::REVOKED},
			{"foreign", "leaf-ec.good.der", alert::description_t::STATUS, false, ocsp::status_t::NONE},
			{"expired", "leaf-ec.short.der", alert::description_t::STATUS, false, ocsp::status_t::NONE},
			{"unauthorized", "leaf-ec.unauthorized.der", alert::description_t::STATUS, false, ocsp::status_t::NONE},
			{"good", "ec256.good.der", alert::description_t::CLOSE, true, ocsp::status_t::GOOD}
		};
		/**
		 * Выполняем перебор случаев отказов
		 */
		for(size_t c = 0; c < (sizeof(CASES) / sizeof(CASES[0])); c++){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны без подлинности клиента
			arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false, (t == 1));
			// Сервер отдаёт ответ случая
			server.status(vectored(CASES[c].answer));
			// Клиент запрашивает состояние
			client.status(true);
			// Клиент проверяет ответ
			client.verification(true, 0, store);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Если перенос идёт записями
			if(t == 0)
				// Проводим рукопожатие по записям
				converse(client, server);
			// Если перенос идёт по уровням
			else
				// Проводим рукопожатие по уровням
				(void) converse(client, server, nullptr);
			// Проверяем установленность связи по случаю
			ASSERT_EQ(client.established(), CASES[c].established) << CASES[c].name << " " << t << " " << static_cast <int> (client.error());
			// Проверяем состояние у клиента
			ASSERT_EQ(client.certified(), CASES[c].status) << CASES[c].name;
			// Если связь по случаю обрывается
			if(!CASES[c].established){
				// Проверяем отказ клиента
				ASSERT_EQ(client.error(), context::error_t::STATUS) << CASES[c].name;
				// Проверяем извещение клиента: bad_certificate_status_response
				ASSERT_EQ(client.alert().description, alert::description_t::STATUS) << CASES[c].name;
				// Проверяем, что ответ всё же доступен потребителю
				ASSERT_EQ(client.status(), vectored(CASES[c].answer)) << CASES[c].name;
				// Проверяем число извещения
				ASSERT_EQ(static_cast <uint8_t> (client.alert().description), 113);
				/**
				 * По уровням извещение собеседнику несёт QUIC своим сообщением закрытия, а не
				 * связь: сервер узнаёт о нём лишь по записям
				 */
				if(t == 0){
					// Проверяем, что сервер получил извещение 113
					ASSERT_EQ(server.error(), context::error_t::ALERT) << CASES[c].name;
					// Проверяем описание извещения у сервера
					ASSERT_EQ(server.alert().description, CASES[c].description) << CASES[c].name;
				}
			}
		}
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны с подлинностью клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, true, false);
		// Клиент отдаёт ответ revoked
		client.status(vectored("ec256.revoked.der"));
		// Сервер запрашивает состояние клиента
		server.status(true);
		// Сервер проверяет ответ клиента
		server.verification(true, 0, store);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем, что сервер отверг клиента
		ASSERT_EQ(server.error(), context::error_t::STATUS);
		// Проверяем извещение сервера
		ASSERT_EQ(server.alert().description, alert::description_t::STATUS);
		// Проверяем, что клиент получил извещение 113
		ASSERT_EQ(client.error(), context::error_t::ALERT);
		// Проверяем описание извещения у клиента
		ASSERT_EQ(client.alert().description, alert::description_t::STATUS);
	}
	{
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны без подлинности клиента
		arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false, false);
		// Сервер отдаёт ответ по чужому сертификату с состоянием unknown: опознаватель не сходится
		server.status(vectored("leaf-ec.unknown.der"));
		// Клиент запрашивает состояние
		client.status(true);
		// Клиент проверяет ответ
		client.verification(true, 0, store);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Проводим рукопожатие
		converse(client, server);
		// Проверяем обрыв: чужой опознаватель
		ASSERT_EQ(client.error(), context::error_t::STATUS);
	}
	{
		/**
		 * Искажения на пути по уровням
		 */
		typedef struct Twist {
			// Название искажения
			const char * name;
			// Запрашивает ли клиент состояние
			bool inquiring;
			// Искажаемое сообщение
			handshake::type_t type;
			// Ожидаемое извещение клиента
			alert::description_t description;
			// Преобразование тела сообщения
			std::function <handshake::type_t (vector <uint8_t> &)> apply;
		} twist_t;
		// Ответ good
		const vector <uint8_t> answer = vectored("ec256.good.der");
		// Искажения
		const twist_t TWISTS[] = {
			{"вид состояния не ocsp", true, handshake::type_t::CERTIFICATE, alert::description_t::STATUS, [](vector <uint8_t> & body) -> handshake::type_t {
				// Меняем вид состояния на 2
				retouch(body, [](vector <uint8_t> & status){ status[0] = 0x02; });
				// Вид сообщения прежний
				return handshake::type_t::CERTIFICATE;
			}},
			{"лишний хвост", true, handshake::type_t::CERTIFICATE, alert::description_t::STATUS, [](vector <uint8_t> & body) -> handshake::type_t {
				// Дописываем байт за записью ответа
				retouch(body, [](vector <uint8_t> & status){ status.push_back(0x00); });
				// Вид сообщения прежний
				return handshake::type_t::CERTIFICATE;
			}},
			{"пустая запись ответа", true, handshake::type_t::CERTIFICATE, alert::description_t::STATUS, [](vector <uint8_t> & body) -> handshake::type_t {
				// Оставляем вид ocsp и нулевую длину
				retouch(body, [](vector <uint8_t> & status){ status.assign({0x01, 0x00, 0x00, 0x00}); });
				// Вид сообщения прежний
				return handshake::type_t::CERTIFICATE;
			}},
			{"порченый ответ", true, handshake::type_t::CERTIFICATE, alert::description_t::STATUS, [](vector <uint8_t> & body) -> handshake::type_t {
				// Портим исход обращения внутри записи ответа: седьмой байт DER за четырьмя байтами обвязки
				retouch(body, [](vector <uint8_t> & status){ status[10] = 0x01; });
				// Вид сообщения прежний
				return handshake::type_t::CERTIFICATE;
			}},
			{"непрошенное расширение", false, handshake::type_t::CERTIFICATE, alert::description_t::EXTENSION, [answer](vector <uint8_t> & body) -> handshake::type_t {
				// Добавляем расширение состояния, которого клиент не просил
				retouch(body, [answer](vector <uint8_t> & status){
					// Вид ocsp
					status.assign({0x01, static_cast <uint8_t> (answer.size() >> 16), static_cast <uint8_t> (answer.size() >> 8), static_cast <uint8_t> (answer.size())});
					// Запись ответа
					status.insert(status.end(), answer.begin(), answer.end());
				});
				// Вид сообщения прежний
				return handshake::type_t::CERTIFICATE;
			}},
			{"status_request в защищённых расширениях", true, handshake::type_t::EXTENSIONS, alert::description_t::PARAMETER, [](vector <uint8_t> & body) -> handshake::type_t {
				// Длина перечня расширений
				const size_t length = (((static_cast <size_t> (body[0]) << 8) | body[1]) + 4);
				// Правим длину перечня
				body[0] = static_cast <uint8_t> (length >> 8);
				// Младший байт длины
				body[1] = static_cast <uint8_t> (length);
				// Дописываем пустое расширение status_request
				body.insert(body.end(), {0x00, 0x05, 0x00, 0x00});
				// Вид сообщения прежний
				return handshake::type_t::EXTENSIONS;
			}}
		};
		/**
		 * Выполняем перебор искажений
		 */
		for(size_t i = 0; i < (sizeof(TWISTS) / sizeof(TWISTS[0])); i++){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны без подлинности клиента по уровням
			arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::X25519, credential, false, true);
			// Сервер отдаёт ответ
			server.status(answer);
			// Клиент запрашивает состояние по искажению
			client.status(TWISTS[i].inquiring);
			// Клиент проверяет ответ
			client.verification(true, 0, store);
			// Заводим сервер
			ASSERT_EQ(server.start(), context::error_t::NONE);
			// Заводим клиента
			ASSERT_EQ(client.start(), context::error_t::NONE);
			// Описание искажения
			mutation_t mutation;
			// Искажается сообщение сервера
			mutation.downstream = true;
			// Вид искажаемого сообщения
			mutation.type = TWISTS[i].type;
			// Преобразование
			mutation.apply = TWISTS[i].apply;
			// Проводим рукопожатие с искажением
			ASSERT_TRUE(converse(client, server, &mutation)) << TWISTS[i].name;
			// Проверяем, что связь не установилась
			ASSERT_FALSE(client.established()) << TWISTS[i].name;
			// Проверяем извещение клиента
			ASSERT_EQ(client.alert().description, TWISTS[i].description) << TWISTS[i].name << " " << static_cast <int> (client.error());
		}
	}
}

/**
 * Проверка обмена с настоящим openssl: s_server -status_file против нашего клиента с
 * запросом состояния и проверкой; s_client -status против нашего сервера со сшивкой -
 * в выводе клиента «OCSP Response Data» и состояние good
 */
TEST(OcspTest, Openssl){
	// Способности системного openssl, снятые щупами
	const toolkit_t toolkit = inspect();
	// Если openssl недоступен
	if(!toolkit.present){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	}
	// Если openssl не умеет TLS 1.3
	if(!toolkit.tls13){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl без TLS 1.3";
	}
	// Если openssl собран без OCSP
	if(shell("(openssl list -disabled 2>/dev/null | grep -qi '^OCSP$')") == 0){
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl собран без OCSP";
	}
	/**
	 * Подлинность стороны берётся цепочкой из трёх звеньев: s_server 3.x сличает ответ из
	 * файла с сертификатом по издателю из цепочки и самоподписанному листу ответа не шлёт
	 */
	context::credential_t credential;
	// Составляем подлинность
	ASSERT_TRUE(chained("ec", credential));
	// Пути к сертификату, ключу, цепочке, корню и ответу
	const std::string crt = std::string(CORPUS) + "/leaf-ec.crt", key = std::string(CORPUS) + "/leaf-ec.key", chain = std::string(CORPUS) + "/chain-ec.pem", root = std::string(CORPUS) + "/ca-ec.crt", resp = std::string(CORPUS) + "/ocsp/leaf-ec.good.der";
	// Ответ good по листу цепочки
	const vector <uint8_t> answer = vectored("leaf-ec.good.der");
	// Пустой запас доверия: издатель берётся вторым звеном цепочки
	const trust::store_t store;
	/**
	 * Ключ сшивки у s_server: с 3.2 ответы из файлов сличаются с цепочкой ключом -status_all,
	 * а -status у него шлёт ответ лишь по своему устройству; у старых сборок есть один -status
	 */
	const std::string stapling = (listed("s_server", "status_all") ? "-status_all" : "-status");
	{
		// Свободный порт
		const uint16_t number = vacant(false);
		// Проверяем наличие порта
		ASSERT_NE(number, 0);
		// Журнал сервера openssl
		const std::string log = "/tmp/ants-ocsp-server-" + std::to_string(number) + ".log";
		// Запускаем сервер openssl со сшивкой ответа из файла
		ASSERT_TRUE(launch("openssl s_server" + accepting(toolkit, number) + " -tls1_3 -cert " + crt + " -key " + key + " -cert_chain " + chain + " " + stapling + " -status_file " + resp + " -www" + once(toolkit) + " </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож сервера openssl: снимается по номеру и при отказе посреди проверки
		sentinel_t sentinel(log + ".pid");
		// Подключаемся к серверу openssl
		const int fd = dial(number);
		// Проверяем подключение
		ASSERT_GE(fd, 0) << "порт " << number;
		// Связь стороны клиента
		client::context_t client;
		// Наборы клиента
		client.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группы клиента
		client.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Имя узла
		client.name("localhost");
		// Миг проверки
		client.moment(MOMENT);
		// Клиент запрашивает состояние
		client.status(true);
		// Клиент проверяет ответ
		client.verification(true, 0, store);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		/**
		 * Выполняем передачу байтов до установления связи
		 */
		for(size_t i = 0; (i < 8) && !client.established() && (client.state() != context::state_t::FAILED); i++)
			// Передаём байты
			relay(client, fd);
		// Проверяем установленность связи
		ASSERT_TRUE(client.established()) << "отказ " << static_cast <int> (client.error()) << " извещение " << static_cast <int> (client.alert().description);
		// Проверяем цепочку сервера у клиента: s_server шлёт лист и следом цепочку с листом ещё раз
		ASSERT_GE(client.peer().size(), static_cast <size_t> (3));
		// Проверяем, что сшитый ответ openssl дошёл байт в байт
		ASSERT_EQ(client.status(), answer);
		// Проверяем состояние по проверке
		ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
		// Запрос HTTP серверу openssl
		const string request = "GET / HTTP/1.0\r\n\r\n";
		// Отправляем запрос
		ASSERT_EQ(client.write(view_t(reinterpret_cast <const uint8_t *> (request.data()), request.size())), context::error_t::NONE);
		// Накопитель ответа
		vector <uint8_t> reply;
		/**
		 * Выполняем передачу байтов до получения ответа
		 */
		for(size_t i = 0; (i < 16) && reply.empty(); i++){
			// Передаём байты
			relay(client, fd);
			// Читаем принятые данные
			ASSERT_EQ(client.read(reply), context::error_t::NONE);
		}
		// Проверяем, что ответ HTTP получен
		ASSERT_NE(string(reply.begin(), reply.end()).find("HTTP/1.0 200"), string::npos);
		// Закрываем сокет
		::close(fd);
		// Снимаем сервер до удаления журнала: иначе отметка завершения воссоздаст файл
		sentinel.halt();
		// Журнал сервера
		std::string journal;
		// Дожидаемся отметки завершения снятого сервера
		(void) settle(log, journal);
		// Удаляем журнал
		::remove(log.c_str());
	}
	{
		// Порт сервера
		uint16_t number = 0;
		// Слушающий сокет
		const int listener = harbour(number);
		// Проверяем сокет
		ASSERT_GE(listener, 0);
		// Журнал клиента openssl
		const std::string log = "/tmp/ants-ocsp-client-" + std::to_string(number) + ".log";
		// Запускаем клиента openssl с запросом состояния
		ASSERT_TRUE(launch("openssl s_client -connect 127.0.0.1:" + std::to_string(number) + " -tls1_3 -status -CAfile " + root + " -servername test.anyks.com </dev/null >" + log + " 2>&1", log, log + ".pid"));
		// Сторож клиента openssl
		sentinel_t sentinel(log + ".pid");
		// Принимаем подключение
		const int fd = greeted(listener);
		// Проверяем подключение
		ASSERT_GE(fd, 0);
		// Связь стороны сервера
		server::context_t server;
		// Наборы сервера
		server.suites(vector <protect::suite_t> {protect::suite_t::AES_128_GCM_SHA256});
		// Группы сервера
		server.groups(vector <extension::group_t> {extension::group_t::X25519});
		// Подлинность сервера
		server.credential(credential);
		// Сервер отдаёт ответ
		server.status(answer);
		// Заводим сервер
		ASSERT_EQ(server.start(), context::error_t::NONE);
		// Ведём связь до конца рукопожатия
		const bool complete = serve(server, fd);
		// Проверяем, что рукопожатие дошло до конца
		ASSERT_TRUE(complete) << "отказ " << static_cast <int> (server.error());
		// Проверяем, что отказа не было
		ASSERT_EQ(server.error(), context::error_t::NONE);
		// Закрываем связь, коли она ещё открыта
		ASSERT_TRUE(farewell(server, fd));
		// Закрываем сокет
		::close(fd);
		// Закрываем слушающий сокет
		::close(listener);
		// Содержимое журнала
		std::string text;
		// Клиент обязан завершиться
		ASSERT_TRUE(settle(log, text)) << text;
		// Проверяем, что клиент openssl получил сшитый ответ
		ASSERT_NE(text.find("OCSP Response Data"), std::string::npos) << text;
		// Проверяем состояние в выводе клиента openssl
		ASSERT_NE(text.find("Cert Status: good"), std::string::npos) << text;
		// Проверяем проверку сертификата сервера клиентом openssl
		ASSERT_NE(text.find("Verify return code: 0 (ok)"), std::string::npos) << text;
		// Удаляем журнал
		::remove(log.c_str());
	}
}

/**
 * Проверка самодостаточности запроса состояния: расширение уходит без иных настроек
 */
TEST(OcspTest, Alone){
	// Байты расширения status_request: тип 0x0005, длина 5, вид ответчика OCSP, пустые перечни
	static const uint8_t EXTENSION[] = {0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00};
	{
		// Связь стороны клиента с одним лишь запросом состояния
		client::context_t client;
		// Запрашиваем состояние сертификата собеседника
		client.status(true);
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента
		const view_t greeting = client.output();
		// Проверяем, что приветствие составлено
		ASSERT_GT(greeting.size, sizeof(EXTENSION));
		// Ищем расширение в приветствии
		ASSERT_NE(std::search(greeting.data, greeting.data + greeting.size, EXTENSION, EXTENSION + sizeof(EXTENSION)), greeting.data + greeting.size);
	}{
		// Связь стороны клиента без запроса состояния
		client::context_t client;
		// Заводим клиента
		ASSERT_EQ(client.start(), context::error_t::NONE);
		// Приветствие клиента
		const view_t greeting = client.output();
		// Проверяем, что приветствие составлено
		ASSERT_GT(greeting.size, sizeof(EXTENSION));
		// Проверяем, что расширения в приветствии нет
		ASSERT_EQ(std::search(greeting.data, greeting.data + greeting.size, EXTENSION, EXTENSION + sizeof(EXTENSION)), greeting.data + greeting.size);
	}
}

/**
 * Проверка поведения при нехватке памяти: разбор, проверка и составление запроса, а
 * также рукопожатие со сшивкой в обе стороны - всякий отказ либо NONE, либо MEMORY,
 * либо обрыв внутренним извещением
 */
TEST(OcspTest, Starved){
	// Запись ответа good
	const vector <uint8_t> data = vectored("leaf-ec.delegated.der");
	// Записи сертификатов
	const vector <uint8_t> subject = certified("leaf-ec.crt"), authority = certified("mid-ec.crt");
	// Проверяем чтение набора
	ASSERT_FALSE(data.empty() || subject.empty() || authority.empty());
	{
		// Признак того, что нехватка памяти встретилась
		bool starved = false;
		// Признак того, что на щедром запасе всё удалось
		bool complete = false;
		/**
		 * Выполняем перебор запасов выделений
		 */
		for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 200) ? 1 : 37)){
			// Отказы разбора, проверки и составления
			ocsp::error_t first = ocsp::error_t::NONE, second = ocsp::error_t::NONE, third = ocsp::error_t::NONE;
			// Состояние сертификата
			ocsp::status_t status = ocsp::status_t::NONE;
			{
				// Ограничиваем запас выделений
				starve::ration_t ration(budget);
				// Объект разбора ответа
				ocsp::response_t response;
				// Разбираем ответ
				first = response.parse(view_t(data.data(), data.size()));
				// Если ответ разобран
				if(first == ocsp::error_t::NONE)
					// Проверяем ответ
					second = ocsp::verify(response, view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), MOMENT, 0, view_t(nullptr, 0), status);
				// Накопитель запроса
				vector <uint8_t> request;
				// Составляем запрос
				third = ocsp::request(view_t(subject.data(), subject.size()), view_t(authority.data(), authority.size()), digest::hash_t::SHA256, view_t(NONCE, sizeof(NONCE)), request);
			}
			// Запоминаем нехватку памяти
			starved = (starved || (first == ocsp::error_t::MEMORY) || (second == ocsp::error_t::MEMORY) || (third == ocsp::error_t::MEMORY));
			// Проверяем законность исходов
			ASSERT_TRUE((first == ocsp::error_t::NONE) || (first == ocsp::error_t::MEMORY)) << "запас " << budget << " разбор " << static_cast <int> (first);
			// Проверяем законность проверки
			ASSERT_TRUE((second == ocsp::error_t::NONE) || (second == ocsp::error_t::MEMORY)) << "запас " << budget << " проверка " << static_cast <int> (second);
			// Проверяем законность составления
			ASSERT_TRUE((third == ocsp::error_t::NONE) || (third == ocsp::error_t::MEMORY)) << "запас " << budget << " запрос " << static_cast <int> (third);
			// Запоминаем полный успех
			complete = ((first == ocsp::error_t::NONE) && (second == ocsp::error_t::NONE) && (third == ocsp::error_t::NONE) && (status == ocsp::status_t::GOOD));
		}
		// Проверяем, что нехватка памяти встретилась
		ASSERT_TRUE(starved);
		// Проверяем, что на щедром запасе всё удалось
		ASSERT_TRUE(complete);
	}
	{
		// Подлинность стороны
		context::credential_t credential;
		// Составляем подлинность
		ASSERT_TRUE(keyed("ec256", credential));
		// Ответ good
		const vector <uint8_t> answer = vectored("ec256.good.der");
		// Пустой запас доверия
		const trust::store_t store;
		// Признак того, что нехватка памяти встретилась
		bool starved = false;
		// Признак того, что связь на щедром запасе установилась
		bool complete = false;
		/**
		 * Выполняем перебор запасов выделений
		 */
		for(size_t budget = 0; (budget < 6000) && !complete; budget += ((budget < 200) ? 1 : 37)){
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Настраиваем стороны с подлинностью клиента
			arrange(client, server, protect::suite_t::AES_128_GCM_SHA256, extension::group_t::SECP256R1, credential, true, false);
			// Сервер отдаёт ответ
			server.status(answer);
			// Сервер запрашивает состояние
			server.status(true);
			// Сервер проверяет ответ
			server.verification(true, 0, store);
			// Клиент отдаёт ответ
			client.status(answer);
			// Клиент запрашивает состояние
			client.status(true);
			// Клиент проверяет ответ
			client.verification(true, 0, store);
			// Ошибки сторон
			context::error_t first = context::error_t::NONE, second = context::error_t::NONE;
			{
				// Ограничиваем запас выделений
				starve::ration_t ration(budget);
				// Заводим сервер
				first = server.start();
				// Заводим клиента
				second = client.start();
				// Если стороны заведены
				if((first == context::error_t::NONE) && (second == context::error_t::NONE)){
					// Проводим рукопожатие
					converse(client, server);
					// Ошибка сервера после рукопожатия
					first = server.error();
					// Ошибка клиента
					second = client.error();
				}
			}
			// Запоминаем нехватку памяти
			starved = (starved || (first == context::error_t::MEMORY) || (second == context::error_t::MEMORY));
			/**
			 * Дозволенные исходы: успех, нехватка памяти либо обрыв собеседником с внутренним
			 * извещением о его нехватке памяти
			 */
			const bool lawful = ((first == context::error_t::NONE) || (first == context::error_t::MEMORY) || ((first == context::error_t::ALERT) && (server.alert().description == alert::description_t::INTERNAL))) &&
				((second == context::error_t::NONE) || (second == context::error_t::MEMORY) || ((second == context::error_t::ALERT) && (client.alert().description == alert::description_t::INTERNAL)));
			// Проверяем законность исхода
			ASSERT_TRUE(lawful) << "запас " << budget << " отказы " << static_cast <int> (first) << " " << static_cast <int> (second);
			// Запоминаем установление связи
			complete = (client.established() && server.established());
			// Если связь установилась
			if(complete){
				// Проверяем состояние у клиента
				ASSERT_EQ(client.certified(), ocsp::status_t::GOOD);
				// Проверяем состояние у сервера
				ASSERT_EQ(server.certified(), ocsp::status_t::GOOD);
			}
		}
		// Проверяем, что нехватка памяти встретилась
		ASSERT_TRUE(starved);
		// Проверяем, что на щедром запасе связь установилась
		ASSERT_TRUE(complete);
	}
}
