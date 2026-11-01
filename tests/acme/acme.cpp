/**
 * @file acme.cpp
 * @date 2026-10-06
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
 * @brief Исходный файл проверок модуля протокола ACME
 *
 * @note Эталоном служат записи разделов 7.1.1, 7.1.3, 7.1.4 и 6.7 RFC 8555
 *       (ответы directory, заказа, записи полномочий и отказа), а также
 *       круговая сборка запросов ключами набора tests/corpus
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
#include <fstream>
#include <sstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <posix.hpp>
#include <starve.hpp>
#include <jws/jws.hpp>
#include <acme/acme.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок протокола ACME
 */
namespace {
	/**
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 * @return     содержимое файла
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в поток
		std::stringstream stream;
		// Переливаем содержимое файла
		stream << file.rdbuf();
		// Выводим содержимое файла
		return stream.str();
	}
	/**
	 * @brief Функция получения просмотра строки
	 *
	 * @param text строка, на которую заводится просмотр
	 * @return     просмотр строки
	 *
	 */
	static view_t view(const std::string & text) {
		// Выводим просмотр строки
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Функция разбора ключа из записи PEM
	 *
	 * @param path   путь к файлу записи
	 * @param result ключ, в который помещается итог разбора
	 *
	 */
	static void load(const std::string & path, keys::key_t & result) {
		// Читаем запись ключа
		const std::string text = slurp(path);
		// Разбираем запись ключа
		ASSERT_EQ(keys::decode(text, view_t(), result), keys::error_t::NONE);
	}
}

/**
 * @brief Проверка разбора ответа ресурса directory
 *
 */
TEST(AcmeTest, Directory) {
	// Ответ ресурса directory раздела 7.1.1 RFC 8555
	static const char * ANSWER =
		"{"
		"\"newNonce\": \"https://example.com/acme/new-nonce\","
		"\"newAccount\": \"https://example.com/acme/new-account\","
		"\"newOrder\": \"https://example.com/acme/new-order\","
		"\"newAuthz\": \"https://example.com/acme/new-authz\","
		"\"revokeCert\": \"https://example.com/acme/revoke-cert\","
		"\"keyChange\": \"https://example.com/acme/key-change\","
		"\"meta\": {"
		"\"termsOfService\": \"https://example.com/acme/terms/2017-5-30\","
		"\"website\": \"https://www.example.com/\","
		"\"caaIdentities\": [\"example.com\"],"
		"\"externalAccountRequired\": false"
		"}"
		"}";
	// Разбираем ответ
	acme::directory_t directory;
	// Разбор обязан удаться
	ASSERT_EQ(directory.parse(view(std::string(ANSWER))), acme::error_t::NONE);
	// Сверяем адреса ресурсов
	ASSERT_EQ(directory.newNonce, "https://example.com/acme/new-nonce");
	ASSERT_EQ(directory.newAccount, "https://example.com/acme/new-account");
	ASSERT_EQ(directory.newOrder, "https://example.com/acme/new-order");
	ASSERT_EQ(directory.newAuthz, "https://example.com/acme/new-authz");
	ASSERT_EQ(directory.revokeCert, "https://example.com/acme/revoke-cert");
	ASSERT_EQ(directory.keyChange, "https://example.com/acme/key-change");
	// Адреса renewalInfo ответ не несёт
	ASSERT_TRUE(directory.renewalInfo.empty());
	// Отказы разбора
	{
		// Пустой ответ
		ASSERT_EQ(directory.parse(view(std::string(""))), acme::error_t::EMPTY);
		// Ответ не объект
		ASSERT_EQ(directory.parse(view(std::string("[1,2]"))), acme::error_t::STRUCTURE);
		// Ответ без адреса newNonce
		ASSERT_EQ(directory.parse(view(std::string("{\"newAccount\":\"https://a/\",\"newOrder\":\"https://b/\",\"revokeCert\":\"https://c/\"}"))), acme::error_t::STRUCTURE);
		// Порченый ответ
		ASSERT_EQ(directory.parse(view(std::string("{\"newNonce\":"))), acme::error_t::STRUCTURE);
	}
}

/**
 * @brief Проверка разбора ответа ресурса заказа
 *
 */
TEST(AcmeTest, Order) {
	// Ответ ресурса заказа раздела 7.1.3 RFC 8555
	static const char * ANSWER =
		"{"
		"\"status\": \"pending\","
		"\"expires\": \"2016-01-20T14:09:07.99Z\","
		"\"identifiers\": ["
		"{\"type\": \"dns\", \"value\": \"www.example.org\"},"
		"{\"type\": \"dns\", \"value\": \"example.org\"}"
		"],"
		"\"notBefore\": \"2016-01-01T00:00:00Z\","
		"\"notAfter\": \"2016-01-08T00:00:00Z\","
		"\"authorizations\": ["
		"\"https://example.com/acme/authz/PAniVnsZcis\","
		"\"https://example.com/acme/authz/r4HqLzrSrpI\""
		"],"
		"\"finalize\": \"https://example.com/acme/order/TOlocE8rfgo/finalize\""
		"}";
	// Разбираем ответ
	acme::order_t order;
	// Разбор обязан удаться
	ASSERT_EQ(order.parse(view(std::string(ANSWER))), acme::error_t::NONE);
	// Сверяем поля заказа
	ASSERT_EQ(order.status, "pending");
	ASSERT_EQ(order.expires, "2016-01-20T14:09:07.99Z");
	// Сверяем идентификаторы заказа
	ASSERT_EQ(order.identifiers.size(), 2);
	ASSERT_EQ(order.identifiers[0].first, acme::identifier_t::DNS);
	ASSERT_EQ(order.identifiers[0].second, "www.example.org");
	ASSERT_EQ(order.identifiers[1].second, "example.org");
	// Сверяем адреса записей полномочий
	ASSERT_EQ(order.authorizations.size(), 2);
	ASSERT_EQ(order.authorizations[0], "https://example.com/acme/authz/PAniVnsZcis");
	// Сверяем адрес завершения заказа
	ASSERT_EQ(order.finalize, "https://example.com/acme/order/TOlocE8rfgo/finalize");
	// Адрес сертификата до выдачи пуст
	ASSERT_TRUE(order.certificate.empty());
	// Отказы разбора
	{
		// Ответ без состояния
		ASSERT_EQ(order.parse(view(std::string("{\"identifiers\":[{\"type\":\"dns\",\"value\":\"a\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Ответ без идентификаторов
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pending\",\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Идентификатор чужого вида
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pending\",\"identifiers\":[{\"type\":\"email\",\"value\":\"a@b\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
	}
}

/**
 * @brief Проверка разбора ответа ресурса записи полномочий
 *
 */
TEST(AcmeTest, Authorization) {
	// Ответ ресурса записи полномочий раздела 7.1.4 RFC 8555
	static const char * ANSWER =
		"{"
		"\"status\": \"valid\","
		"\"expires\": \"2018-09-09T14:09:00.0Z\","
		"\"identifier\": {"
		"\"type\": \"dns\","
		"\"value\": \"example.org\""
		"},"
		"\"challenges\": ["
		"{"
		"\"type\": \"http-01\","
		"\"url\": \"https://example.com/acme/chall/prV_B7yEyA4\","
		"\"status\": \"valid\","
		"\"validated\": \"2017-09-08T14:09:05.1Z\","
		"\"token\": \"DGyRejmCefe7v4NfDGDKfA\""
		"},"
		"{"
		"\"type\": \"dns-01\","
		"\"url\": \"https://example.com/acme/chall/Rg5dV14Gh1Q\","
		"\"status\": \"pending\","
		"\"token\": \"DGyRejmCefe7v4NfDGDKfA\""
		"}"
		"],"
		"\"wildcard\": false"
		"}";
	// Разбираем ответ
	acme::authorization_t authorization;
	// Разбор обязан удаться
	ASSERT_EQ(authorization.parse(view(std::string(ANSWER))), acme::error_t::NONE);
	// Сверяем поля записи
	ASSERT_EQ(authorization.status, "valid");
	ASSERT_EQ(authorization.expires, "2018-09-09T14:09:00.0Z");
	// Сверяем идентификатор записи
	ASSERT_EQ(authorization.identifier.first, acme::identifier_t::DNS);
	ASSERT_EQ(authorization.identifier.second, "example.org");
	// Признак маски сброшен
	ASSERT_FALSE(authorization.wildcard);
	// Сверяем испытания записи
	ASSERT_EQ(authorization.challenges.size(), 2);
	ASSERT_EQ(authorization.challenges[0].type, "http-01");
	ASSERT_EQ(authorization.challenges[0].url, "https://example.com/acme/chall/prV_B7yEyA4");
	ASSERT_EQ(authorization.challenges[0].status, "valid");
	ASSERT_EQ(authorization.challenges[0].token, "DGyRejmCefe7v4NfDGDKfA");
	ASSERT_EQ(authorization.challenges[0].validated, "2017-09-08T14:09:05.1Z");
	ASSERT_EQ(authorization.challenges[1].type, "dns-01");
	// Метка подтверждения второго испытания пуста
	ASSERT_TRUE(authorization.challenges[1].validated.empty());
	// Отказы разбора
	{
		// Ответ без испытаний
		ASSERT_EQ(authorization.parse(view(std::string("{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a\"}}"))), acme::error_t::STRUCTURE);
		// Испытание без адреса
		ASSERT_EQ(authorization.parse(view(std::string("{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a\"},\"challenges\":[{\"type\":\"http-01\",\"status\":\"pending\"}]}"))), acme::error_t::STRUCTURE);
		// Испытание без метки разбирается: новые виды испытаний её не несут
		ASSERT_EQ(authorization.parse(view(std::string("{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"a\"},\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://u/\",\"status\":\"pending\"}]}"))), acme::error_t::NONE);
	}
}

/**
 * @brief Проверка разбора ответа об отказе
 *
 */
TEST(AcmeTest, Problem) {
	// Ответ об отказе раздела 6.7 RFC 8555
	static const char * ANSWER =
		"{"
		"\"type\": \"urn:ietf:params:acme:error:malformed\","
		"\"detail\": \"Some of the identifiers requested were rejected\","
		"\"status\": 400"
		"}";
	// Разбираем ответ
	acme::problem_t problem;
	// Разбор обязан удаться
	ASSERT_EQ(problem.parse(view(std::string(ANSWER))), acme::error_t::NONE);
	// Сверяем поля отказа
	ASSERT_EQ(problem.type, "urn:ietf:params:acme:error:malformed");
	ASSERT_EQ(problem.detail, "Some of the identifiers requested were rejected");
	ASSERT_EQ(problem.status, 400);
	// Отказ без состояния
	{
		// Разбираем ответ без состояния
		ASSERT_EQ(problem.parse(view(std::string("{\"type\":\"urn:ietf:params:acme:error:unauthorized\"}"))), acme::error_t::NONE);
		// Состояние нулевое
		ASSERT_EQ(problem.status, 0);
	}
	// Отказы разбора
	{
		// Ответ без вида отказа
		ASSERT_EQ(problem.parse(view(std::string("{\"detail\":\"oops\"}"))), acme::error_t::STRUCTURE);
		// Пустой ответ
		ASSERT_EQ(problem.parse(view(std::string(""))), acme::error_t::EMPTY);
	}
}

/**
 * @brief Проверка сборки полезных нагрузок запросов
 *
 */
TEST(AcmeTest, Payloads) {
	// Полезная нагрузка заведения учётной записи
	{
		// Итог сборки
		std::string payload;
		// Собираем полезную нагрузку
		acme::newAccount({"mailto:cert-admin@example.org", "mailto:admin@example.org"}, true, false, payload);
		// Нагрузка заведения учётной записи сошлась с эталоном
		ASSERT_EQ(payload, "{\"contact\":[\"mailto:cert-admin@example.org\",\"mailto:admin@example.org\"],\"termsOfServiceAgreed\":true}");
		// Собираем запрос лишь существующей записи
		acme::newAccount({}, false, true, payload);
		// Нагрузка запроса лишь существующей записи сошлась с эталоном
		ASSERT_EQ(payload, "{\"onlyReturnExisting\":true}");
	}
	// Полезная нагрузка заведения заказа
	{
		// Итог сборки
		std::string payload;
		// Собираем полезную нагрузку
		ASSERT_EQ(acme::newOrder({{acme::identifier_t::DNS, "example.org"}, {acme::identifier_t::DNS, "www.example.org"}}, payload), acme::error_t::NONE);
		// Нагрузка заведения заказа сошлась с эталоном
		ASSERT_EQ(payload, "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.org\"},{\"type\":\"dns\",\"value\":\"www.example.org\"}]}");
		// Пустой набор идентификаторов отвергается
		ASSERT_EQ(acme::newOrder({}, payload), acme::error_t::EMPTY);
		// Идентификатор неустановленного вида отвергается
		ASSERT_EQ(acme::newOrder({{acme::identifier_t::NONE, "a"}}, payload), acme::error_t::STRUCTURE);
	}
	// Полезная нагрузка завершения заказа
	{
		// Итог сборки
		std::string payload;
		// Запись запроса
		const uint8_t csr[] = {0x30, 0x03, 0x02, 0x01, 0x00};
		// Собираем полезную нагрузку
		acme::finalize(view_t(csr, sizeof(csr)), payload);
		// Нагрузка завершения заказа с запросом подписи сошлась с эталоном
		ASSERT_EQ(payload, "{\"csr\":\"MAMCAQA\"}");
	}
	// Полезная нагрузка отзыва сертификата
	{
		// Итог сборки
		std::string payload;
		// Запись сертификата
		const uint8_t certificate[] = {0x30, 0x03, 0x02, 0x01, 0x00};
		// Собираем полезную нагрузку
		acme::revokeCert(view_t(certificate, sizeof(certificate)), 1, payload);
		// Нагрузка отзыва сертификата сошлась с эталоном
		ASSERT_EQ(payload, "{\"certificate\":\"MAMCAQA\",\"reason\":1}");
	}
	// Полезная нагрузка ответа на испытание
	{
		// Итог сборки
		std::string payload;
		// Собираем полезную нагрузку
		acme::answer(payload);
		// Нагрузка ответа на испытание сошлась с эталоном
		ASSERT_EQ(payload, "{}");
	}
}

/**
 * @brief Проверка выработки полномочного ключа испытания
 *
 */
TEST(AcmeTest, KeyAuthorization) {
	// Ключ RSA раздела 3.1 RFC 7638: отпечаток его известен
	static const char * JWK =
		"{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
		"\"e\":\"AQAB\"}";
	// Разбираем ключ
	keys::key_t key;
	// Запись ключа разбирается без ошибок
	ASSERT_EQ(jws::unjwk(view(std::string(JWK)), key), jws::error_t::NONE);
	// Вырабатываем владение ключом
	std::string possession;
	// Выработка обязана удаться
	ASSERT_EQ(acme::keyPossession("DGyRejmCefe7v4NfDGDKfA", key, possession), acme::error_t::NONE);
	// Владение: метка ‖ '.' ‖ отпечаток RFC 7638
	ASSERT_EQ(possession, "DGyRejmCefe7v4NfDGDKfA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
	// Вырабатываем полномочный ключ
	std::string authorization;
	// Выработка обязана удаться
	ASSERT_EQ(acme::keyAuthorization("DGyRejmCefe7v4NfDGDKfA", key, authorization), acme::error_t::NONE);
	// Полномочный ключ: base64url(SHA-256(владение)) по разделу 8.1 RFC 8555
	ASSERT_EQ(authorization, "Bs72Q7B-BSSQo4oDjA2qBR07GB6sc3hiG9zqaqvHx7U");
	// Пустая метка отвергается
	ASSERT_EQ(acme::keyPossession("", key, possession), acme::error_t::EMPTY);
}

/**
 * @brief Проверка круговой сборки запроса ACME
 *
 */
TEST(AcmeTest, Request) {
	// Разбираем ключ набора
	keys::key_t key;
	// Ключ набора читается из файла набора
	load(std::string(CORPUS) + "/ca-ec.key", key);
	// Готовим ключ подписи
	keys::signer_t signer;
	// Подготовка ключа подписи удаётся
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-ec.key"))), keys::error_t::NONE);
	// Полезная нагрузка запроса
	std::string payload;
	// Собираем полезную нагрузку новой учётной записи
	acme::newAccount({"mailto:admin@example.org"}, false, false, payload);
	// Собираем запрос с записью ключа JWK
	std::string body;
	ASSERT_EQ(acme::request("https://example.com/acme/new-account", "6S8IqOGY7eL2lsGoTZYifg", "", key, view(payload), signer, body), acme::error_t::NONE);
	// Тело запроса несёт три члена
	ASSERT_NE(body.find("\"protected\":\""), 0);
	ASSERT_NE(body.find("\",\"payload\":\""), std::string::npos);
	ASSERT_NE(body.find("\",\"signature\":\""), std::string::npos);
	// Извлекаем запись JWS из тела запроса и проверяем подпись
	{
		// Позиции членов тела
		const size_t head = body.find("\"protected\":\"") + 13;
		// Позиция начала полезной нагрузки
		const size_t middle = body.find("\",\"payload\":\"", head);
		// Позиция начала подписи
		const size_t tail = body.find("\",\"signature\":\"", middle);
		// Собираем компактную запись JWS
		std::string compact = body.substr(head, middle - head) + "." + body.substr(middle + 13, tail - middle - 13) + "." + body.substr(tail + 15, body.size() - tail - 17);
		// Разбираем компактную запись подписи из тела запроса
		jws::signature_t signature;
		// Компактная запись JWS разбирается
		ASSERT_EQ(signature.parse(view(compact)), jws::error_t::NONE);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
		// Заголовок несёт jwk, nonce и url
		ASSERT_NE(signature.header().find("\"jwk\":"), std::string::npos);
		ASSERT_NE(signature.header().find("\"nonce\":\"6S8IqOGY7eL2lsGoTZYifg\""), std::string::npos);
		ASSERT_NE(signature.header().find("\"url\":\"https://example.com/acme/new-account\""), std::string::npos);
		// Полезная нагрузка совпадает с собранной
		std::vector <uint8_t> extracted;
		// Полезная нагрузка извлекается из записи
		ASSERT_EQ(signature.payload(extracted), jws::error_t::NONE);
		ASSERT_EQ(std::string(reinterpret_cast <const char *> (extracted.data()), extracted.size()), payload);
	}
	// Собираем запрос с адресом учётной записи
	{
		// Итог сборки
		std::string other;
		// Сборка обязана удаться
		ASSERT_EQ(acme::request("https://example.com/acme/order/1/finalize", "Ab8IqOGY7eL2lsGoTZYifg", "https://example.com/acme/acct/1", key, view(std::string("{\"csr\":\"AA\"}")), signer, other), acme::error_t::NONE);
		// Извлекаем заголовок записи
		const size_t head = other.find("\"protected\":\"") + 13;
		// Конец защищённого заголовка в теле
		const size_t middle = other.find("\",\"payload\":\"", head);
		// Декодируем заголовок
		std::vector <uint8_t> header;
		// Защищённый заголовок декодируется из base64url
		ASSERT_TRUE(jws::unbase64url(view(other.substr(head, middle - head)), header));
		// Заголовок несёт kid, а не jwk
		const std::string text(reinterpret_cast <const char *> (header.data()), header.size());
		ASSERT_NE(text.find("\"kid\":\"https://example.com/acme/acct/1\""), std::string::npos);
		// Поля jwk в заголовке нет
		ASSERT_EQ(text.find("\"jwk\":"), std::string::npos);
	}
	// Запрос POST-as-GET несёт пустую полезную нагрузку
	{
		// Итог сборки
		std::string other;
		// Сборка обязана удаться
		ASSERT_EQ(acme::request("https://example.com/acme/order/1", "Ab8IqOGY7eL2lsGoTZYifg", "https://example.com/acme/acct/1", key, view_t(), signer, other), acme::error_t::NONE);
		// Полезная нагрузка пуста
		ASSERT_NE(other.find("\"payload\":\"\""), std::string::npos);
	}
	// Отказы сборки
	{
		// Итог сборки
		std::string other;
		// Пустой адрес
		ASSERT_EQ(acme::request("", "nonce", "kid", key, view_t(), signer, other), acme::error_t::EMPTY);
		// Пустая метка
		ASSERT_EQ(acme::request("https://example.com/", "", "kid", key, view_t(), signer, other), acme::error_t::EMPTY);
		// Неподготовленный ключ
		keys::signer_t unprepared;
		ASSERT_EQ(acme::request("https://example.com/", "nonce", "kid", key, view_t(), unprepared, other), acme::error_t::EMPTY);
	}
}

/**
 * @brief Проверка разбора строк JSON с экранировками
 *
 * @note Строки несут все экранировки раздела 7 RFC 8259: кавычку, черты,
 *       управляющие знаки и коды Unicode одно-, двух- и трёхбайтовые; отказы -
 *       оборванная экранировка, чужая экранировка, чужой разряд кода
 *
 */
TEST(AcmeTest, Escapes) {
	// Ответ ресурса заказа со всеми экранировками в строках
	static const char * ANSWER =
		"{"
		"\"status\": \"pend\\\"ing\","
		"\"expires\": \"2016-01-20T14:09:07Z\","
		"\"identifiers\": ["
		"{\"type\": \"dns\", \"value\": \"www.example.org\"}"
		"],"
		"\"authorizations\": [\"https:\\/\\/example.com\\/acme\\/authz\\\\1\"],"
		"\"finalize\": \"https://example.com/acme/order/1/finalize\""
		"}";
	// Разбираем ответ
	acme::order_t order;
	// Разбор обязан удаться
	ASSERT_EQ(order.parse(view(std::string(ANSWER))), acme::error_t::NONE);
	// Сверяем состояние с экранированной кавычкой
	ASSERT_EQ(order.status, "pend\"ing");
	// Сверяем адрес записи полномочий с экранированными чертами и обратной чертой
	ASSERT_EQ(order.authorizations.size(), 1);
	ASSERT_EQ(order.authorizations[0], "https://example.com/acme/authz\\1");
	// Ответ с управляющими знаками и кодами Unicode в строке состояния
	static const char * CONTROLS =
		"{"
		"\"status\": \"a\\b\\f\\n\\r\\tA\\u0041\\u00DF\\u6C34\","
		"\"identifiers\": [{\"type\": \"dns\", \"value\": \"a\"}],"
		"\"authorizations\": [],"
		"\"finalize\": \"https://f/\""
		"}";
	// Разбор обязан удаться
	ASSERT_EQ(order.parse(view(std::string(CONTROLS))), acme::error_t::NONE);
	// Сверяем состояние: управляющие знаки и коды A (U+0041), ß (U+00DF), U+6C34
	ASSERT_EQ(order.status, std::string("a\b\f\n\r\t" "A" "A" "\xC3\x9F" "\xE6\xB0\xB4"));
	// Отказы разбора
	{
		// Оборванная экранировка в конце строки
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pending\\\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"a\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Чужая экранировка
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pend\\xing\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"a\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Чужой разряд кода Unicode
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pend\\u00zz\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"a\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Оборванная запись кода Unicode
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pend\\u00\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"a\"}],\"authorizations\":[],\"finalize\":\"https://f/\"}"))), acme::error_t::STRUCTURE);
		// Строка без закрывающей кавычки
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pending,\"identifiers\":[]}"))), acme::error_t::STRUCTURE);
		// Экранировка в самом конце записи
		ASSERT_EQ(order.parse(view(std::string("{\"status\":\"pending\\"))), acme::error_t::STRUCTURE);
	}
	// Код Unicode заглавными разрядами
	static const char * CAPITAL =
		"{"
		"\"status\": \"\\u0041\\u00DF\\u00e9\","
		"\"identifiers\": [{\"type\": \"dns\", \"value\": \"a\"}],"
		"\"authorizations\": [],"
		"\"finalize\": \"https://f/\""
		"}";
	// Разбор обязан удаться
	ASSERT_EQ(order.parse(view(std::string(CAPITAL))), acme::error_t::NONE);
	// Сверяем состояние: коды A, ß и é
	ASSERT_EQ(order.status, std::string("A\xC3\x9F\xC3\xA9"));
}

/**
 * @brief Проверка устойчивости сборки и разбора запросов к нехватке памяти
 *
 */
TEST(AcmeTest, Starved){
	// Ответ ресурса заказа раздела 7.1.3 RFC 8555
	static const char * ANSWER =
		"{"
		"\"status\": \"pending\","
		"\"expires\": \"2016-01-20T14:09:07.99Z\","
		"\"identifiers\": ["
		"{\"type\": \"dns\", \"value\": \"www.example.org\"},"
		"{\"type\": \"dns\", \"value\": \"example.org\"}"
		"],"
		"\"authorizations\": ["
		"\"https://example.com/acme/authz/PAniVnsZcis\""
		"],"
		"\"finalize\": \"https://example.com/acme/order/TOlocE8rfgo/finalize\""
		"}";
	// Разбираемый ключ набора: разбирается заранее, чтобы разбор не попал под подмену выделений
	keys::key_t key;
	// Ключ набора читается из файла набора
	load(std::string(CORPUS) + "/ca-ec.key", key);
	// Текст записи ключа набора: читается заранее, чтобы чтение не попало под подмену выделений
	const std::string pem = slurp(std::string(CORPUS) + "/ca-ec.key");
	// Подготовленный ключ подписи: готовится заранее, чтобы подготовка не попала под подмену выделений
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(pem)), keys::error_t::NONE);
	// Полезная нагрузка запроса: собирается заранее, чтобы сборка не попала под подмену выделений
	std::string payload;
	// Полезная нагрузка новой учётной записи собирается заранее
	acme::newAccount({"mailto:admin@example.org"}, false, false, payload);
	// Просмотр полезной нагрузки: заводится заранее, чтобы его сборка не попала под подмену выделений
	const view_t bodyView(reinterpret_cast <const uint8_t *> (payload.data()), payload.size());
	// Просмотр ответа заказа: заводится заранее, чтобы его сборка не попала под подмену выделений
	const view_t answer(reinterpret_cast <const uint8_t *> (ANSWER), std::strlen(ANSWER));
	// Адрес запроса: заводится заранее, чтобы его сборка не попала под подмену выделений
	const std::string url("https://example.com/acme/new-account");
	// Одноразовый номер запроса: заводится заранее, чтобы его сборка не попала под подмену выделений
	const std::string nonce("6S8IqOGY7eL2lsGoTZYifg");
	// Пустой адрес учётной записи: заводится заранее, чтобы его сборка не попала под подмену выделений
	const std::string kid;
	// Метка испытания: заводится заранее, чтобы её сборка не попала под подмену выделений
	const std::string token("DGyRejmCefe7v4NfDGDKfA");
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе сборка и разбор обязаны
	 * ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог сборки запроса при отмеренном запасе
		acme::error_t requested = acme::error_t::NONE;
		{
			// Отмеряем запас выделений на время сборки
			starve::ration_t ration(budget);
			// Собранное тело запроса
			std::string body;
			// Выполняем сборку запроса при отмеренном запасе
			requested = acme::request(url, nonce, kid, key, bodyView, signer, body);
		}
		// Проверяем, что сборка ответила успехом либо отказом памяти
		ASSERT_TRUE((requested == acme::error_t::NONE) || (requested == acme::error_t::MEMORY)) << "запас " << budget << ", отказ сборки " << static_cast <int> (requested);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (requested == acme::error_t::MEMORY));
		// Итог выработки владения ключом при отмеренном запасе
		acme::error_t possessed = acme::error_t::NONE;
		{
			// Отмеряем запас выделений на время выработки
			starve::ration_t ration(budget);
			// Выработанное владение ключом
			std::string possession;
			// Выполняем выработку владения ключом при отмеренном запасе
			possessed = acme::keyPossession(token, key, possession);
		}
		// Проверяем, что выработка ответила успехом либо отказом памяти
		ASSERT_TRUE((possessed == acme::error_t::NONE) || (possessed == acme::error_t::MEMORY)) << "запас " << budget << ", отказ выработки " << static_cast <int> (possessed);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (possessed == acme::error_t::MEMORY));
		// Итог разбора ответа заказа при отмеренном запасе
		acme::error_t parsed = acme::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Разбираемый заказ
			acme::order_t order;
			// Выполняем разбор ответа заказа при отмеренном запасе
			parsed = order.parse(answer);
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((parsed == acme::error_t::NONE) || (parsed == acme::error_t::MEMORY)) << "запас " << budget << ", отказ разбора " << static_cast <int> (parsed);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (parsed == acme::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
