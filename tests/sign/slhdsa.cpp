/**
 * @file slhdsa.cpp
 * @date 2026-10-03
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
 * @brief Исходный файл проверок модуля электронной подписи SLH-DSA
 *
 * @note Контрольные примеры переложены сценарием tools/sign/slhdsa.py из записей
 *       ACVP (keyGen, sigGen, sigVer) подмодуля OpenSSL в набор tests/corpus/slhdsa:
 *       выработка ключа из зерна сверяется побайтно, подписи детерминированная и
 *       с тестовой энтропией сверяются побайтно, хеджированная сличается своей
 *       проверкой, гнилые подписи отвергаются. Сценарии message-encoding:0
 *       (расширение OpenSSL вне чистого FIPS 205) в набор не идут
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <fstream>
#include <main.hpp>
#include <sign/slhdsa.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Каталог набора контрольных примеров
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Функция разбора записи из шестнадцатеричного текста
 *
 * @param text запись в шестнадцатеричном виде
 * @return     запись в байтах
 *
 */
static std::vector <uint8_t> unhex(const std::string & text) noexcept {
	// Результат разбора записи
	std::vector <uint8_t> result;
	// Разбор полубайта записи
	auto nib = [](const char c) -> uint8_t {
		// Если полубайт цифровой
		if((c >= '0') && (c <= '9')){
			// Значение цифрового полубайта 0..9
			return static_cast <uint8_t> (c - '0');
		}
		// Если полубайт строчный
		if((c >= 'a') && (c <= 'f')){
			// Строчная буква a..f даёт значение 10..15
			return static_cast <uint8_t> ((c - 'a') + 10);
		}
		// Если полубайт заглавный
		if((c >= 'A') && (c <= 'F')){
			// Заглавная буква A..F даёт значение 10..15
			return static_cast <uint8_t> ((c - 'A') + 10);
		}
		// Выводим пустой полубайт
		return 0;
	};
	/**
	 * Выполняем перебор пар полубайтов записи
	 */
	for(size_t i = 0; i + 1 < text.size(); i += 2)
		// Собираем байт записи из пары полубайтов
		result.push_back(static_cast <uint8_t> ((nib(text[i]) << 4) | nib(text[i + 1])));
	// Выводим запись в байтах
	return result;
}

/**
 * @brief Функция чтения строки набора контрольных примеров на поля
 *
 * @param line строка набора
 * @return     поля строки набора
 *
 */
static std::vector <std::string> fields(const std::string & line) noexcept {
	// Результат разбора строки
	std::vector <std::string> result;
	// Текущее поле разбора
	std::string field;
	/**
	 * Выполняем перебор знаков строки набора
	 */
	for(const char c : line){
		// Если знак разделяет поля
		if(c == ' '){
			// Если поле набрано
			if(!field.empty()){
				// Запоминаем поле разбора
				result.push_back(field);
				// Сбрасываем текущее поле разбора
				field.clear();
			}
		// Иначе копим знак поля
		} else
			field += c;
	}
	// Если поле набрано
	if(!field.empty())
		// Запоминаем поле разбора
		result.push_back(field);
	// Выводим поля строки набора
	return result;
}

/**
 * @brief Функция получения набора параметров по записи
 *
 * @param name запись набора
 * @return     набор параметров
 *
 */
static sign::Slhdsa::set_t layout(const std::string & name) noexcept {
	// Запись набора sha2-128s
	if(name == "sha2-128s"){
		// Краткие подписи SHA2 на 128 бит стойкости
		return sign::Slhdsa::set_t::SHA2_128S;
	}
	// Запись набора shake-128s
	if(name == "shake-128s"){
		// Краткие подписи SHAKE на 128 бит стойкости
		return sign::Slhdsa::set_t::SHAKE_128S;
	}
	// Запись набора sha2-128f
	if(name == "sha2-128f"){
		// Быстрые подписи SHA2 на 128 бит стойкости
		return sign::Slhdsa::set_t::SHA2_128F;
	}
	// Запись набора shake-128f
	if(name == "shake-128f"){
		// Быстрые подписи SHAKE на 128 бит стойкости
		return sign::Slhdsa::set_t::SHAKE_128F;
	}
	// Запись набора sha2-192s
	if(name == "sha2-192s"){
		// Краткие подписи SHA2 на 192 бита стойкости
		return sign::Slhdsa::set_t::SHA2_192S;
	}
	// Запись набора shake-192s
	if(name == "shake-192s"){
		// Краткие подписи SHAKE на 192 бита стойкости
		return sign::Slhdsa::set_t::SHAKE_192S;
	}
	// Запись набора sha2-192f
	if(name == "sha2-192f"){
		// Быстрые подписи SHA2 на 192 бита стойкости
		return sign::Slhdsa::set_t::SHA2_192F;
	}
	// Запись набора shake-192f
	if(name == "shake-192f"){
		// Быстрые подписи SHAKE на 192 бита стойкости
		return sign::Slhdsa::set_t::SHAKE_192F;
	}
	// Запись набора sha2-256s
	if(name == "sha2-256s"){
		// Краткие подписи SHA2 на 256 бит стойкости
		return sign::Slhdsa::set_t::SHA2_256S;
	}
	// Запись набора shake-256s
	if(name == "shake-256s"){
		// Краткие подписи SHAKE на 256 бит стойкости
		return sign::Slhdsa::set_t::SHAKE_256S;
	}
	// Запись набора sha2-256f
	if(name == "sha2-256f"){
		// Быстрые подписи SHA2 на 256 бит стойкости
		return sign::Slhdsa::set_t::SHA2_256F;
	}
	// Выводим набор SHAKE-256f
	return sign::Slhdsa::set_t::SHAKE_256F;
}

/**
 * @brief Функция получения поля записи в байтах
 *
 * @param field поле записи, прочерк означает пустое поле
 * @return      поле записи в байтах
 *
 */
static std::vector <uint8_t> bytes(const std::string & field) noexcept {
	// Если поле пустое
	if(field == "-")
		// Выводим пустое поле
		return {};
	// Выводим поле записи в байтах
	return unhex(field);
}

/**
 * @brief Проверка примеров выработки ключа из зерна ACVP keyGen
 *
 */
TEST(SlhdsaTest, Keygen) {
	// Читаем набор примеров выработки ключа
	std::ifstream input(std::string(CORPUS) + "/slhdsa/keygen.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	/**
	 * Выполняем перебор строк набора примеров
	 */
	while(std::getline(input, line)){
		// Если строка помечена примечанием либо пуста
		if(line.empty() || (line[0] == '#'))
			// Переходим к следующей строке набора
			continue;
		// Поля строки набора
		const std::vector <std::string> parts = fields(line);
		// Разбираем поля строки набора
		ASSERT_EQ(parts.size(), 4u);
		// Набор параметров строки
		const sign::Slhdsa::set_t set = layout(parts[0]);
		// Зерно, ключ проверки и ключ подписи примера
		const std::vector <uint8_t> seed = bytes(parts[1]), pub = bytes(parts[2]), priv = bytes(parts[3]);
		// Места выработанных ключей
		std::vector <uint8_t> key(pub.size()), secret(priv.size());
		// Модуль подписи
		sign::Slhdsa slhdsa;
		// Выполняем выработку ключа из зерна примера
		ASSERT_TRUE(slhdsa.generate(set, view_t(seed.data(), seed.size()), key.data(), secret.data()));
		// Сверяем ключи с примером побайтно
		EXPECT_EQ(key, pub);
		EXPECT_EQ(secret, priv);
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 120u);
}

/**
 * @brief Проверка примеров подписи ACVP sigGen
 *
 */
TEST(SlhdsaTest, Siggen) {
	// Читаем набор примеров подписи
	std::ifstream input(std::string(CORPUS) + "/slhdsa/siggen.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	/**
	 * Выполняем перебор строк набора примеров
	 */
	while(std::getline(input, line)){
		// Если строка помечена примечанием либо пуста
		if(line.empty() || (line[0] == '#'))
			// Переходим к следующей строке набора
			continue;
		// Поля строки набора
		const std::vector <std::string> parts = fields(line);
		// Разбираем поля строки набора
		ASSERT_GE(parts.size(), 6u);
		// Набор параметров строки
		const sign::Slhdsa::set_t set = layout(parts[0]);
		// Ключ подписи, сообщение, контекст и подпись примера
		const std::vector <uint8_t> priv = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), want = bytes(parts[5]);
		// Модули подписи и проверки
		sign::Slhdsa signer, verifier;
		// Выполняем установку ключа подписи примера
		ASSERT_TRUE(signer.secret(set, view_t(priv.data(), priv.size())));
		// Ключ проверки из установленного ключа подписи
		std::vector <uint8_t> pub(sign::Slhdsa::publicSize(set));
		// Выполняем получение и установку ключа проверки
		ASSERT_TRUE(signer.key(pub.data(), pub.size()));
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Место выработанной подписи
		std::vector <uint8_t> signature(sign::Slhdsa::signatureSize(set));
		// Случайность сценария: нули у детерминированной, энтропия у помеченной e
		uint8_t rnd[32] = {};
		// Если сценарий с тестовой энтропией
		if(parts[1] == "e"){
			// Разбираем энтропию сценария
			const std::vector <uint8_t> entropy = bytes(parts[6]);
			// Переносим энтропию в случайность
			::memcpy(rnd, entropy.data(), ((entropy.size() < sizeof(rnd)) ? entropy.size() : sizeof(rnd)));
		}
		// Выполняем выработку подписи и сверяем с примером побайтно
		ASSERT_TRUE(signer.make(view_t(rnd, sizeof(rnd)), view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), signature.data()));
		// Выработанная подпись обязана совпасть с примером побайтно
		EXPECT_EQ(signature, want);
		// Выполняем сличение выработанной подписи
		EXPECT_TRUE(verifier.check(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), view_t(signature.data(), signature.size())));
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 174u);
}

/**
 * @brief Проверка примеров сличения ACVP sigVer
 *
 */
TEST(SlhdsaTest, Sigver) {
	// Читаем набор примеров сличения
	std::ifstream input(std::string(CORPUS) + "/slhdsa/sigver.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	/**
	 * Выполняем перебор строк набора примеров
	 */
	while(std::getline(input, line)){
		// Если строка помечена примечанием либо пуста
		if(line.empty() || (line[0] == '#'))
			// Переходим к следующей строке набора
			continue;
		// Поля строки набора
		const std::vector <std::string> parts = fields(line);
		// Разбираем поля строки набора
		ASSERT_EQ(parts.size(), 6u);
		// Набор параметров строки
		const sign::Slhdsa::set_t set = layout(parts[0]);
		// Ключ проверки, сообщение, контекст и подпись примера
		const std::vector <uint8_t> pub = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), sig = bytes(parts[5]);
		// Модуль проверки
		sign::Slhdsa verifier;
		// Выполняем установку ключа проверки примера
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Выполняем сличение подписи примера с ожидаемым ответом
		EXPECT_EQ(verifier.check(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), view_t(sig.data(), sig.size())), (parts[1] == "ok"));
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 168u);
}

/**
 * @brief Проверка круга подписи на своих ключах всех наборов
 *
 */
TEST(SlhdsaTest, Round) {
	// Сообщение круга подписи
	const std::string text = "сообщение круга подписи SLH-DSA";
	// Наборы параметров круга
	static const sign::Slhdsa::set_t SUITS[] = {
		sign::Slhdsa::set_t::SHA2_128S, sign::Slhdsa::set_t::SHAKE_128S,
		sign::Slhdsa::set_t::SHA2_128F, sign::Slhdsa::set_t::SHAKE_128F,
		sign::Slhdsa::set_t::SHA2_192S, sign::Slhdsa::set_t::SHAKE_192S,
		sign::Slhdsa::set_t::SHA2_192F, sign::Slhdsa::set_t::SHAKE_192F,
		sign::Slhdsa::set_t::SHA2_256S, sign::Slhdsa::set_t::SHAKE_256S,
		sign::Slhdsa::set_t::SHA2_256F, sign::Slhdsa::set_t::SHAKE_256F
	};
	/**
	 * Выполняем перебор наборов параметров
	 */
	for(auto set : SUITS){
		// Модули подписи и проверки
		sign::Slhdsa signer, verifier;
		// Места записей ключей
		std::vector <uint8_t> pub(sign::Slhdsa::publicSize(set)), priv(sign::Slhdsa::secretSize(set));
		// Выполняем порождение ключа из источника случайности
		ASSERT_TRUE(signer.generate(set, pub.data(), priv.data()));
		// Выполняем установку ключа подписи и ключа проверки
		ASSERT_TRUE(signer.secret(set, view_t(priv.data(), priv.size())));
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Набор, размер и предел подписи после установки
		EXPECT_EQ(signer.set(), set);
		EXPECT_EQ(signer.size(), sign::Slhdsa::signatureSize(set));
		EXPECT_EQ(signer.limit(), sign::Slhdsa::signatureSize(set));
		// Место подписи
		std::vector <uint8_t> signature(sign::Slhdsa::signatureSize(set));
		// Выполняем выработку подписи от источника случайности
		ASSERT_TRUE(signer.make(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), signature.data()));
		// Выполняем сличение подписи
		EXPECT_TRUE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Порченый байт подписи отвергается
		signature[100] ^= 1;
		// Сверка порченой подписи обязана завершиться отказом
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Возвращаем байт подписи обратно
		signature[100] ^= 1;
		// Иное сообщение отвергается
		const std::string other = "иное сообщение";
		// Сверка подписи иного сообщения обязана завершиться отказом
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (other.data()), other.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Иной контекст отвергается
		const uint8_t context[1] = {1};
		// Сверка подписи с иным контекстом обязана завершиться отказом
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(context, sizeof(context)), view_t(signature.data(), signature.size())));
		// Сброс модуля снимает ключи
		signer.clear();
		// Набор после сброса обязан стать пустым
		EXPECT_EQ(signer.set(), sign::Slhdsa::set_t::NONE);
		EXPECT_EQ(signer.size(), 0u);
	}
}
