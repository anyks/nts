/**
 * @file jws.cpp
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
 * @brief Исходный файл проверок модуля подписей JWS
 *
 * @note Эталоном служат векторы приложения A.3 RFC 7515 (подпись RS256 над
 *       записью «{"iss":"joe",…}» ключом RSA приложения A.2) и раздела 3.1
 *       RFC 7638 (отпечаток ключа RSA), а также круговая запись ключами
 *       набора tests/corpus
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
#include <pem/pem.hpp>
#include <jws/jws.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок подписей JWS
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
	 * @brief Функция разбора шестнадцатеричной записи
	 *
	 * @param hex шестнадцатеричная запись
	 * @return    байты записи
	 *
	 */
	static std::vector <uint8_t> bytes(const std::string & hex) {
		// Байты записи
		std::vector <uint8_t> result;
		/**
		 * Выполняем обход записи
		 */
		for(size_t i = 0; i + 1 < hex.size(); i += 2)
			// Разбираем байт записи
			result.push_back(static_cast <uint8_t> (std::stoul(hex.substr(i, 2), nullptr, 16)));
		// Выводим байты записи
		return result;
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
 * @brief Проверка кодировки base64url
 *
 */
TEST(JwsTest, Base64url) {
	// Пустая запись кодируется пустой
	{
		// Итог кодирования
		std::string encoded;
		// Кодируем пустую запись
		jws::base64url(view_t(), encoded);
		// Запись обязана быть пустой
		ASSERT_TRUE(encoded.empty());
	}
	// Векторы раздела 10 RFC 4648 в записи base64url без заполнителей
	{
		// Итог кодирования
		std::string encoded;
		// Кодируем запись «f»
		jws::base64url(view(std::string("f")), encoded);
		// Кодировка «f» обязана дать «Zg»
		ASSERT_EQ(encoded, "Zg");
		// Кодируем запись «fo»
		jws::base64url(view(std::string("fo")), encoded);
		// Кодировка «fo» обязана дать «Zm8»
		ASSERT_EQ(encoded, "Zm8");
		// Кодируем запись «foo»
		jws::base64url(view(std::string("foo")), encoded);
		// Кодировка «foo» обязана дать «Zm9v»
		ASSERT_EQ(encoded, "Zm9v");
		// Кодируем запись «foob»
		jws::base64url(view(std::string("foob")), encoded);
		// Кодировка «foob» обязана дать «Zm9vYg»
		ASSERT_EQ(encoded, "Zm9vYg");
		// Кодируем запись «fooba»
		jws::base64url(view(std::string("fooba")), encoded);
		// Кодировка «fooba» обязана дать «Zm9vYmE»
		ASSERT_EQ(encoded, "Zm9vYmE");
		// Кодируем запись «foobar»
		jws::base64url(view(std::string("foobar")), encoded);
		// Кодировка «foobar» обязана дать «Zm9vYmFy»
		ASSERT_EQ(encoded, "Zm9vYmFy");
	}
	// Алфавит base64url: байты 0xFB 0xFF дают «-_», а не «+/»
	{
		// Итог кодирования
		std::string encoded;
		// Байты записи
		const uint8_t data[] = {0xFB, 0xFF};
		// Кодируем байты
		jws::base64url(view_t(data, sizeof(data)), encoded);
		// Байты 0xFB 0xFF обязаны кодироваться в «-_8»
		ASSERT_EQ(encoded, "-_8");
	}
	// Круговое декодирование
	{
		// Исходные данные
		const std::string source = "The quick brown fox jumps over the lazy dog";
		// Итог кодирования
		std::string encoded;
		// Кодируем исходную строку в base64url
		jws::base64url(view(source), encoded);
		// Итог декодирования
		std::vector <uint8_t> decoded;
		// Декодирование записи обратно в исходные байты обязано удаться
		ASSERT_TRUE(jws::unbase64url(view(encoded), decoded));
		// Сверяем итог с исходными данными
		ASSERT_EQ(std::string(reinterpret_cast <const char *> (decoded.data()), decoded.size()), source);
	}
	// Отказы декодирования
	{
		// Итог декодирования
		std::vector <uint8_t> decoded;
		// Заполнитель отвергается
		ASSERT_FALSE(jws::unbase64url(view(std::string("Zg==")), decoded));
		// Символ '+' чужого алфавита отвергается
		ASSERT_FALSE(jws::unbase64url(view(std::string("Zg+8")), decoded));
		// Символ '/' чужого алфавита отвергается
		ASSERT_FALSE(jws::unbase64url(view(std::string("Zg/8")), decoded));
		// Длина 1 по модулю 4 отвергается
		ASSERT_FALSE(jws::unbase64url(view(std::string("Z")), decoded));
		// Ненулевые хвостовые разряды отвергаются
		ASSERT_FALSE(jws::unbase64url(view(std::string("Zh")), decoded));
	}
}

/**
 * @brief Проверка разбора и проверки записи вектора A.3 RFC 7515
 *
 */
TEST(JwsTest, Rfc7515A3) {
	// Запись JWS приложения A.3.1 RFC 7515
	static const char * RECORD =
		"eyJhbGciOiJSUzI1NiJ9"
		"."
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
		"."
		"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
	// Ключ RSA приложения A.2 RFC 7515: модуль
	static const char * N =
		"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
		"HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
		"D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
		"SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
		"MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
		"NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
	// Заводим ключ из записи JWK
	keys::key_t key;
	// Разбор записи ключа обязан удаться
	{
		// Запись ключа JWK
		std::string jwk = std::string("{\"kty\":\"RSA\",\"n\":\"") + N + "\",\"e\":\"AQAB\"}";
		// Разбираем запись ключа
		ASSERT_EQ(jws::unjwk(view(jwk), key), jws::error_t::NONE);
	}
	// Объект разбора вектора подписи приложения A.3
	jws::signature_t signature;
	// Разбор обязан удаться
	const std::string record = RECORD;
	// Разбор записи обязан удаться
	ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
	// Алгоритм записи - RS256
	ASSERT_EQ(signature.algorithm(), jws::algorithm_t::RS256);
	// Заголовок записи
	ASSERT_EQ(signature.header(), "{\"alg\":\"RS256\"}");
	// Полезная нагрузка записи
	std::vector <uint8_t> payload;
	// Извлечение полезной нагрузки обязано удаться
	ASSERT_EQ(signature.payload(payload), jws::error_t::NONE);
	// Сверяем полезную нагрузку с записью приложения A.3.2
	static const char * PAYLOAD = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
	ASSERT_EQ(std::string(reinterpret_cast <const char *> (payload.data()), payload.size()), PAYLOAD);
	// Подпись записи обязана сойтись ключом приложения A.2
	ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
	// Портим подпись записи
	std::string damaged = RECORD;
	// Переворачиваем разряд последнего символа подписи
	damaged.back() = ((damaged.back() == 'A') ? 'B' : 'A');
	// Разбираем порченую запись
	jws::signature_t broken;
	// Разбор обязан удаться
	ASSERT_EQ(broken.parse(view(damaged)), jws::error_t::NONE);
	// Подпись порченой записи сойтись не обязана
	ASSERT_EQ(broken.verify(key), jws::error_t::SIGNATURE);
}

/**
 * @brief Проверка отпечатка ключа раздела 3.1 RFC 7638
 *
 */
TEST(JwsTest, Rfc7638) {
	// Ключ RSA раздела 3.1 RFC 7638
	keys::key_t key;
	// Заводим вид ключа
	key.kind = keys::kind_t::RSA;
	// Модуль ключа из записи RFC в base64url
	static const char * N =
		"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"
		"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6"
		"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD"
		"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"
		"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH"
		"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
	// Декодируем модуль ключа
	ASSERT_TRUE(jws::unbase64url(view(std::string(N)), key.n));
	// Показатель ключа
	key.e = bytes("010001");
	// Собираем запись JWK ключа
	std::string jwk;
	// Сборка обязана удаться
	ASSERT_EQ(jws::jwk(key, jwk), jws::error_t::NONE);
	// Каноническая запись ключа обязана совпасть с записью раздела 3.1 RFC 7638
	ASSERT_EQ(jwk,
		"{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
		"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9y"
		"BXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qM"
		"QvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0"
		"Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}");
	// Вырабатываем отпечаток ключа
	std::string thumbprint;
	// Выработка обязана удаться
	ASSERT_EQ(jws::thumbprint(key, thumbprint), jws::error_t::NONE);
	// Отпечаток обязан совпасть с отпечатком раздела 3.1 RFC 7638
	ASSERT_EQ(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

/**
 * @brief Проверка разбора записи ключа JWK
 *
 */
TEST(JwsTest, Unjwk) {
	// Ключ RSA раздела 3.1 RFC 7638
	static const char * JWK =
		"{\"kty\":\"RSA\","
		"\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\","
		"\"e\":\"AQAB\"}";
	// Разбираем запись ключа
	keys::key_t key;
	// Разбор обязан удаться
	const std::string jwk = JWK;
	// Разбор записи ключа обязан удаться
	ASSERT_EQ(jws::unjwk(view(jwk), key), jws::error_t::NONE);
	// Вид ключа - RSA
	ASSERT_EQ(key.kind, keys::kind_t::RSA);
	// Показатель ключа - 65537
	ASSERT_EQ(key.e, bytes("010001"));
	// Отпечаток разобранного ключа обязан совпасть с отпечатком RFC 7638
	std::string thumbprint;
	// Построение отпечатка обязано удаться
	ASSERT_EQ(jws::thumbprint(key, thumbprint), jws::error_t::NONE);
	ASSERT_EQ(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
	// Круговая запись ключа EC набора
	{
		// Разбираем ключ набора
		keys::key_t ec;
		// Читаем ключ EC из набора
		load(std::string(CORPUS) + "/ca-ec.key", ec);
		// Собираем запись ключа
		std::string record;
		// Сборка записи ключа обязана удаться
		ASSERT_EQ(jws::jwk(ec, record), jws::error_t::NONE);
		// Разбираем запись обратно
		keys::key_t back;
		// Обратный разбор записи обязан удаться
		ASSERT_EQ(jws::unjwk(view(record), back), jws::error_t::NONE);
		// Сверяем вид и составляющие ключа
		ASSERT_EQ(back.kind, ec.kind);
		ASSERT_EQ(back.oid, ec.oid);
		ASSERT_EQ(back.x, ec.x);
		ASSERT_EQ(back.y, ec.y);
	}
	// Отказы разбора
	{
		// Ключ без члена kty
		keys::key_t broken;
		// Без члена kty разбор обязан отказать устройством записи
		ASSERT_EQ(jws::unjwk(view(std::string("{\"n\":\"AA\",\"e\":\"AQAB\"}")), broken), jws::error_t::STRUCTURE);
		// Ключ чужого вида
		ASSERT_EQ(jws::unjwk(view(std::string("{\"kty\":\"oct\",\"k\":\"AA\"}")), broken), jws::error_t::ALGORITHM);
		// Ключ на чужой кривой
		ASSERT_EQ(jws::unjwk(view(std::string("{\"kty\":\"EC\",\"crv\":\"P-192\",\"x\":\"AA\",\"y\":\"AA\"}")), broken), jws::error_t::ALGORITHM);
		// Пустая запись
		ASSERT_EQ(jws::unjwk(view(std::string("")), broken), jws::error_t::EMPTY);
	}
}

/**
 * @brief Проверка круговой записи и проверки подписи ключами набора
 *
 */
TEST(JwsTest, Roundtrip) {
	// Полезная нагрузка записи
	static const char * PAYLOAD = "The quick brown fox jumps over the lazy dog";
	// Круговая запись ключом RSA
	{
		// Разбираем ключ набора
		keys::key_t key;
		// Читаем ключ RSA из набора
		load(std::string(CORPUS) + "/ca-rsa.key", key);
		// Готовим ключ подписи
		keys::signer_t signer;
		// Подготовка подписи обязана удаться
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-rsa.key"))), keys::error_t::NONE);
		// Алгоритм ключа - RS256
		ASSERT_EQ(jws::algorithm(key), jws::algorithm_t::RS256);
		ASSERT_EQ(jws::algorithm(signer), jws::algorithm_t::RS256);
		// Собираем запись
		std::string record;
		// Сборка записи обязана удаться
		ASSERT_EQ(jws::encode(jws::algorithm_t::RS256, "", view(std::string(PAYLOAD)), signer, record), jws::error_t::NONE);
		// Объект разбора собранной записи подписи RSA
		jws::signature_t signature;
		// Разбор записи обязан удаться
		ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
		// Алгоритм записи - RS256
		ASSERT_EQ(signature.algorithm(), jws::algorithm_t::RS256);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
		// Полезная нагрузка обязана совпасть
		std::vector <uint8_t> payload;
		// Извлечение полезной нагрузки обязано удаться
		ASSERT_EQ(signature.payload(payload), jws::error_t::NONE);
		ASSERT_EQ(std::string(reinterpret_cast <const char *> (payload.data()), payload.size()), PAYLOAD);
	}
	// Круговая запись ключом EC
	{
		// Разбираем ключ набора
		keys::key_t key;
		// Читаем ключ EC из набора
		load(std::string(CORPUS) + "/ca-ec.key", key);
		// Готовим ключ подписи
		keys::signer_t signer;
		// Подготовка подписи обязана удаться
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-ec.key"))), keys::error_t::NONE);
		// Алгоритм ключа - ES256
		ASSERT_EQ(jws::algorithm(key), jws::algorithm_t::ES256);
		ASSERT_EQ(jws::algorithm(signer), jws::algorithm_t::ES256);
		// Собираем запись с заголовком
		std::string record;
		// Сборка записи с заголовком kid обязана удаться
		ASSERT_EQ(jws::encode(jws::algorithm_t::ES256, "{\"kid\":\"https://example.com/acct/1\"}", view(std::string(PAYLOAD)), signer, record), jws::error_t::NONE);
		// Объект разбора собранной записи подписи EC
		jws::signature_t signature;
		// Разбор записи обязан удаться
		ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
		// Алгоритм записи - ES256
		ASSERT_EQ(signature.algorithm(), jws::algorithm_t::ES256);
		// Заголовок несёт и kid, и alg
		ASSERT_NE(signature.header().find("\"kid\":\"https://example.com/acct/1\""), std::string::npos);
		// Заголовок обязан носить и alg
		ASSERT_NE(signature.header().find("\"alg\":\"ES256\""), std::string::npos);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
		// Подпись чужим ключом сойтись не обязана
		keys::key_t foreign;
		// Читаем чужой ключ EC из набора
		load(std::string(CORPUS) + "/leaf-ec.key", foreign);
		// Подпись чужим ключом обязана отказать имитовставкой
		ASSERT_EQ(signature.verify(foreign), jws::error_t::SIGNATURE);
		// Подпись ключом RSA отвергается по алгоритму
		keys::key_t rsa;
		// Читаем ключ RSA из набора
		load(std::string(CORPUS) + "/ca-rsa.key", rsa);
		// Подпись ключом RSA обязана отказать алгоритмом
		ASSERT_EQ(signature.verify(rsa), jws::error_t::ALGORITHM);
	}
	// Отказы разбора записи
	{
		// Разбираемая запись
		jws::signature_t signature;
		// Пустая запись
		ASSERT_EQ(signature.parse(view(std::string(""))), jws::error_t::EMPTY);
		// Запись без разделителей
		{ const std::string text = "abcdef"; ASSERT_EQ(signature.parse(view(text)), jws::error_t::STRUCTURE); }
		// Запись с одним разделителем
		{ const std::string text = "abc.def"; ASSERT_EQ(signature.parse(view(text)), jws::error_t::STRUCTURE); }
		// Запись с тремя разделителями
		{ const std::string text = "ab.cd.ef.gh"; ASSERT_EQ(signature.parse(view(text)), jws::error_t::STRUCTURE); }
		// Запись с чужим алгоритмом
		{ const std::string text = "eyJhbGciOiJIUzI1NiJ9.ab.AA"; ASSERT_EQ(signature.parse(view(text)), jws::error_t::ALGORITHM); }
		// Запись с порченой кодировкой заголовка
		{ const std::string text = "+.ab.cde"; ASSERT_EQ(signature.parse(view(text)), jws::error_t::STRUCTURE); }
	}
}

/**
 * @brief Проверка имён алгоритмов подписи
 *
 */
TEST(JwsTest, Names) {
	// Имя алгоритма RS256
	ASSERT_STREQ(jws::name(jws::algorithm_t::RS256), "RS256");
	// Имя алгоритма RS384
	ASSERT_STREQ(jws::name(jws::algorithm_t::RS384), "RS384");
	// Имя алгоритма RS512
	ASSERT_STREQ(jws::name(jws::algorithm_t::RS512), "RS512");
	// Имя алгоритма ES256
	ASSERT_STREQ(jws::name(jws::algorithm_t::ES256), "ES256");
	// Имя алгоритма ES384
	ASSERT_STREQ(jws::name(jws::algorithm_t::ES384), "ES384");
	// Имя алгоритма ES512
	ASSERT_STREQ(jws::name(jws::algorithm_t::ES512), "ES512");
	// Имя алгоритма EdDSA
	ASSERT_STREQ(jws::name(jws::algorithm_t::EDDSA), "EdDSA");
	// Имя неустановленного алгоритма пусто
	ASSERT_STREQ(jws::name(jws::algorithm_t::NONE), "");
	// Круговой разбор имени обязан дать тот же алгоритм
	ASSERT_EQ(jws::algorithm(view(std::string("ES256"))), jws::algorithm_t::ES256);
	// Имя неустановленного алгоритма разбирается в NONE
	ASSERT_EQ(jws::algorithm(view(std::string(jws::name(jws::algorithm_t::NONE)))), jws::algorithm_t::NONE);
}

/**
 * @brief Проверка круговой записи и проверки подписи ключами P-384, P-521 и Ed25519
 *
 */
TEST(JwsTest, RoundtripEc384Ec521Ed25519) {
	// Полезная нагрузка записи
	static const char * PAYLOAD = "The quick brown fox jumps over the lazy dog";
	// Круговая запись ключом EC P-384
	{
		// Разбираем ключ набора
		keys::key_t key;
		// Читаем ключ P-384 из набора
		load(std::string(CORPUS) + "/ec384.pem", key);
		// Готовим ключ подписи
		keys::signer_t signer;
		// Подготовка подписи обязана удаться
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ec384.pem"))), keys::error_t::NONE);
		// Алгоритм ключа - ES384
		ASSERT_EQ(jws::algorithm(key), jws::algorithm_t::ES384);
		ASSERT_EQ(jws::algorithm(signer), jws::algorithm_t::ES384);
		// Собираем запись
		std::string record;
		// Сборка записи обязана удаться
		ASSERT_EQ(jws::encode(jws::algorithm_t::ES384, "", view(std::string(PAYLOAD)), signer, record), jws::error_t::NONE);
		// Объект разбора собранной записи подписи P-384
		jws::signature_t signature;
		// Разбор записи обязан удаться
		ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
		// Алгоритм записи - ES384
		ASSERT_EQ(signature.algorithm(), jws::algorithm_t::ES384);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
	}
	// Круговая запись ключом EC P-521
	{
		// Разбираем ключ набора
		keys::key_t key;
		// Читаем ключ P-521 из набора
		load(std::string(CORPUS) + "/ec521.pem", key);
		// Готовим ключ подписи
		keys::signer_t signer;
		// Подготовка подписи обязана удаться
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ec521.pem"))), keys::error_t::NONE);
		// Алгоритм ключа - ES512
		ASSERT_EQ(jws::algorithm(key), jws::algorithm_t::ES512);
		ASSERT_EQ(jws::algorithm(signer), jws::algorithm_t::ES512);
		// Собираем запись
		std::string record;
		// Сборка записи обязана удаться
		ASSERT_EQ(jws::encode(jws::algorithm_t::ES512, "", view(std::string(PAYLOAD)), signer, record), jws::error_t::NONE);
		// Объект разбора собранной записи подписи P-521
		jws::signature_t signature;
		// Разбор записи обязан удаться
		ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
		// Алгоритм записи - ES512
		ASSERT_EQ(signature.algorithm(), jws::algorithm_t::ES512);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
	}
	// Круговая запись ключом Ed25519
	{
		// Разбираем ключ набора
		keys::key_t key;
		// Читаем ключ Ed25519 из набора
		load(std::string(CORPUS) + "/ed25519.pem", key);
		// Готовим ключ подписи
		keys::signer_t signer;
		// Подготовка подписи обязана удаться
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ed25519.pem"))), keys::error_t::NONE);
		// Алгоритм ключа - EdDSA
		ASSERT_EQ(jws::algorithm(key), jws::algorithm_t::EDDSA);
		ASSERT_EQ(jws::algorithm(signer), jws::algorithm_t::EDDSA);
		// Собираем запись
		std::string record;
		// Сборка записи обязана удаться
		ASSERT_EQ(jws::encode(jws::algorithm_t::EDDSA, "", view(std::string(PAYLOAD)), signer, record), jws::error_t::NONE);
		// Объект разбора собранной записи подписи Ed25519
		jws::signature_t signature;
		// Разбор записи обязан удаться
		ASSERT_EQ(signature.parse(view(record)), jws::error_t::NONE);
		// Алгоритм записи - EdDSA
		ASSERT_EQ(signature.algorithm(), jws::algorithm_t::EDDSA);
		// Подпись обязана сойтись
		ASSERT_EQ(signature.verify(key), jws::error_t::NONE);
	}
}

/**
 * @brief Проверка устойчивости записи и разбора подписи к нехватке памяти
 *
 */
TEST(JwsTest, Starved){
	// Полезная нагрузка записи
	static const char * PAYLOAD = "The quick brown fox jumps over the lazy dog";
	// Текст записи ключа набора: читается заранее, чтобы чтение не попало под подмену выделений
	const std::string pem = slurp(std::string(CORPUS) + "/ca-rsa.key");
	// Подготовленный ключ подписи: готовится заранее, чтобы подготовка не попала под подмену выделений
	keys::signer_t signer;
	// Проверяем подготовку ключа из записи набора
	ASSERT_EQ(signer.prepare(view(pem)), keys::error_t::NONE);
	// Просмотр полезной нагрузки: заводится заранее, чтобы его сборка не попала под подмену выделений
	const view_t payload(reinterpret_cast <const uint8_t *> (PAYLOAD), std::strlen(PAYLOAD));
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе запись и разбор обязаны
	 * ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог записи при отмеренном запасе
		jws::error_t encodedResult = jws::error_t::NONE;
		// Записанная подпись
		std::string record;
		{
			// Отмеряем запас выделений на время записи
			starve::ration_t ration(budget);
			// Выполняем запись подписи при отмеренном запасе
			encodedResult = jws::encode(jws::algorithm_t::RS256, "", payload, signer, record);
		}
		// Проверяем, что запись ответила успехом либо отказом памяти
		ASSERT_TRUE((encodedResult == jws::error_t::NONE) || (encodedResult == jws::error_t::MEMORY)) << "запас " << budget << ", отказ записи " << static_cast <int> (encodedResult);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (encodedResult == jws::error_t::MEMORY));
		// Если запись собрана
		if(encodedResult == jws::error_t::NONE){
			// Итог разбора при отмеренном запасе
			jws::error_t parsed = jws::error_t::NONE;
			{
				// Отмеряем запас выделений на время разбора
				starve::ration_t ration(budget);
				// Разбираемая запись
				jws::signature_t signature;
				// Выполняем разбор записи при отмеренном запасе
				parsed = signature.parse(view(record));
			}
			// Проверяем, что разбор ответил успехом либо отказом памяти
			ASSERT_TRUE((parsed == jws::error_t::NONE) || (parsed == jws::error_t::MEMORY)) << "запас " << budget << ", отказ разбора " << static_cast <int> (parsed);
			// Запоминаем объявленный отказ памяти
			starved = (starved || (parsed == jws::error_t::MEMORY));
		}
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
