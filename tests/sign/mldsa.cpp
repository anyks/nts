/**
 * @file mldsa.cpp
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
 * @brief Исходный файл проверок модуля электронной подписи ML-DSA
 *
 * @note Контрольные примеры переложены сценарием tools/sign/mldsa.py из записей
 *       ACVP (keyGen, sigGen, sigVer) и Wycheproof подмодуля OpenSSL в набор
 *       tests/corpus/mldsa: выработка ключа из зерна сверяется побайтно,
 *       детерминированная подпись сверяется побайтно, хеджированная сличается своей
 *       проверкой, гнилые ключи и подписи отвергаются. Сценарии с внешним μ в набор
 *       не идут: модулю нужен чистый ML-DSA с сообщением целиком
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
#include <sign/mldsa.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Каталог набора контрольных примеров
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Метод разбора записи из шестнадцатеричного текста
 *
 * @param text запись в шестнадцатеричном виде
 *
 * @return     запись в байтах
 *
 */
static std::vector <uint8_t> unhex(const std::string & text) noexcept {
	// Результат разбора записи
	std::vector <uint8_t> result;
	// Разбор полубайта записи
	auto nib = [](const char c) -> uint8_t {
		// Если полубайт цифровой
		if((c >= '0') && (c <= '9'))
			return static_cast <uint8_t> (c - '0');
		// Если полубайт строчный
		if((c >= 'a') && (c <= 'f'))
			return static_cast <uint8_t> ((c - 'a') + 10);
		// Если полубайт заглавный
		if((c >= 'A') && (c <= 'F'))
			return static_cast <uint8_t> ((c - 'A') + 10);
		// Выводим пустой полубайт
		return 0;
	};
	// Выполняем перебор пар полубайтов записи
	for(size_t i = 0; i + 1 < text.size(); i += 2)
		// Собираем байт записи из пары полубайтов
		result.push_back(static_cast <uint8_t> ((nib(text[i]) << 4) | nib(text[i + 1])));
	// Выводим запись в байтах
	return result;
}

/**
 * @brief Метод чтения строки набора контрольных примеров на поля
 *
 * @param line строка набора
 *
 * @return     поля строки набора
 *
 */
static std::vector <std::string> fields(const std::string & line) noexcept {
	// Результат разбора строки
	std::vector <std::string> result;
	// Текущее поле разбора
	std::string field;
	// Выполняем перебор знаков строки набора
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
 * @brief Метод получения набора параметров по записи
 *
 * @param name запись набора
 *
 * @return     набор параметров
 *
 */
static sign::mldsa_t::set_t layout(const std::string & name) noexcept {
	// Если набор ML-DSA-44
	if(name == "44")
		// Выводим набор ML-DSA-44
		return sign::mldsa_t::set_t::DSA44;
	// Если набор ML-DSA-65
	if(name == "65")
		// Выводим набор ML-DSA-65
		return sign::mldsa_t::set_t::DSA65;
	// Выводим набор ML-DSA-87
	return sign::mldsa_t::set_t::DSA87;
}

/**
 * @brief Метод получения поля записи в байтах
 *
 * @param field поле записи, прочерк означает пустое поле
 *
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
TEST(MldsaTest, Keygen) {
	// Читаем набор примеров выработки ключа
	std::ifstream input(std::string(CORPUS) + "/mldsa/keygen.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	// Выполняем перебор строк набора примеров
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
		const sign::mldsa_t::set_t set = layout(parts[0]);
		// Зерно, ключ проверки и ключ подписи примера
		const std::vector <uint8_t> seed = bytes(parts[1]), pub = bytes(parts[2]), priv = bytes(parts[3]);
		// Места выработанных ключей
		std::vector <uint8_t> key(pub.size()), secret(priv.size());
		// Модуль подписи
		sign::mldsa_t mldsa;
		// Выполняем выработку ключа из зерна примера
		ASSERT_TRUE(mldsa.generate(set, view_t(seed.data(), seed.size()), key.data(), secret.data()));
		// Сверяем ключи с примером побайтно
		EXPECT_EQ(key, pub);
		EXPECT_EQ(secret, priv);
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 78u);
}

/**
 * @brief Проверка примеров подписи ACVP sigGen
 *
 */
TEST(MldsaTest, Siggen) {
	// Читаем набор примеров подписи
	std::ifstream input(std::string(CORPUS) + "/mldsa/siggen.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	// Выполняем перебор строк набора примеров
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
		const sign::mldsa_t::set_t set = layout(parts[0]);
		// Ключ подписи, сообщение, контекст и подпись примера
		const std::vector <uint8_t> priv = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), want = bytes(parts[5]);
		// Модули подписи и проверки
		sign::mldsa_t signer, verifier;
		// Выполняем установку ключа подписи примера
		ASSERT_TRUE(signer.secret(set, view_t(priv.data(), priv.size())));
		// Ключ проверки из установленного ключа подписи
		std::vector <uint8_t> pub(sign::mldsa_t::publicSize(set));
		// Выполняем получение и установку ключа проверки
		ASSERT_TRUE(signer.key(pub.data(), pub.size()));
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Место выработанной подписи
		std::vector <uint8_t> signature(sign::mldsa_t::signatureSize(set));
		// Если сценарий детерминированный
		if(parts[1] == "d"){
			// Случайность из тридцати двух нулевых байтов
			const uint8_t zeros[32] = {};
			// Выполняем выработку подписи и сверяем с примером побайтно
			ASSERT_TRUE(signer.make(view_t(zeros, sizeof(zeros)), view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), signature.data()));
			EXPECT_EQ(signature, want);
		// Иначе сценарий хеджированный
		} else {
			// Выполняем выработку подписи от источника случайности
			ASSERT_TRUE(signer.make(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), signature.data()));
		}
		// Выполняем сличение выработанной подписи
		EXPECT_TRUE(verifier.check(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), view_t(signature.data(), signature.size())));
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 93u);
}

/**
 * @brief Проверка примеров сличения ACVP sigVer
 *
 */
TEST(MldsaTest, Sigver) {
	// Читаем набор примеров сличения
	std::ifstream input(std::string(CORPUS) + "/mldsa/sigver.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	// Выполняем перебор строк набора примеров
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
		const sign::mldsa_t::set_t set = layout(parts[0]);
		// Ключ проверки, сообщение, контекст и подпись примера
		const std::vector <uint8_t> pub = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), sig = bytes(parts[5]);
		// Модуль проверки
		sign::mldsa_t verifier;
		// Выполняем установку ключа проверки примера
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Выполняем сличение подписи примера с ожидаемым ответом
		EXPECT_EQ(verifier.check(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), view_t(sig.data(), sig.size())), (parts[1] == "ok"));
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, 45u);
}

/**
 * @brief Метод проверки примеров подписи Wycheproof набора
 *
 * @param name запись набора
 * @param want число сценариев набора
 *
 */
static void wycheproofSign(const char * name, const size_t want) {
	// Читаем набор примеров подписи
	std::ifstream input(std::string(CORPUS) + "/mldsa/wycheproof" + name + "-sign.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	// Выполняем перебор строк набора примеров
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
		const sign::mldsa_t::set_t set = layout(parts[0]);
		// Ключ подписи, сообщение, контекст и подпись примера
		const std::vector <uint8_t> priv = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), wantSig = bytes(parts[5]);
		// Модуль подписи
		sign::mldsa_t signer;
		// Выполняем установку ключа подписи примера
		const bool accepted = signer.secret(set, view_t(priv.data(), priv.size()));
		// Если сценарий с гнилым ключом
		if(parts[1] == "keyerr"){
			// Гнилая запись ключа отвергается
			EXPECT_FALSE(accepted);
		// Если сценарий с длинным контекстом
		} else if(parts[1] == "ctxerr"){
			// Ключ годный
			ASSERT_TRUE(accepted);
			// Место подписи
			std::vector <uint8_t> signature(sign::mldsa_t::signatureSize(set));
			// Случайность из тридцати двух нулевых байтов
			const uint8_t zeros[32] = {};
			// Выработка с контекстом длиннее двухсот пятидесяти пяти байтов отвергается
			EXPECT_FALSE(signer.make(view_t(zeros, sizeof(zeros)), view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), signature.data()));
		// Иначе сценарий сверки подписи
		} else {
			// Ключ годный
			ASSERT_TRUE(accepted);
			// Место подписи
			std::vector <uint8_t> signature(sign::mldsa_t::signatureSize(set));
			// Случайность из тридцати двух нулевых байтов
			const uint8_t zeros[32] = {};
			// Выполняем выработку подписи и сверяем с примером побайтно
			ASSERT_TRUE(signer.make(view_t(zeros, sizeof(zeros)), view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), signature.data()));
			EXPECT_EQ(signature, wantSig);
		}
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, want);
}

/**
 * @brief Метод проверки примеров сличения Wycheproof набора
 *
 * @param name запись набора
 * @param want число сценариев набора
 *
 */
static void wycheproofVerify(const char * name, const size_t want) {
	// Читаем набор примеров сличения
	std::ifstream input(std::string(CORPUS) + "/mldsa/wycheproof" + name + "-verify.txt");
	// Строка набора примеров
	std::string line;
	// Число сценариев набора
	size_t done = 0;
	// Выполняем перебор строк набора примеров
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
		const sign::mldsa_t::set_t set = layout(parts[0]);
		// Ключ проверки, сообщение, контекст и подпись примера
		const std::vector <uint8_t> pub = bytes(parts[2]), msg = bytes(parts[3]), ctx = bytes(parts[4]), sig = bytes(parts[5]);
		// Модуль проверки
		sign::mldsa_t verifier;
		// Выполняем установку ключа проверки примера
		const bool accepted = verifier.key(set, view_t(pub.data(), pub.size()));
		// Если сценарий с гнилым ключом
		if(parts[1] == "keyerr"){
			// Гнилая запись ключа отвергается
			EXPECT_FALSE(accepted);
		// Иначе сценарий сличения подписи
		} else {
			// Ключ годный
			ASSERT_TRUE(accepted);
			// Выполняем сличение подписи примера с ожидаемым ответом
			EXPECT_EQ(verifier.check(view_t(msg.data(), msg.size()), view_t(ctx.data(), ctx.size()), view_t(sig.data(), sig.size())), (parts[1] == "ok"));
		}
		// Считаем сценарий набора
		done++;
	}
	// Набор прочитан целиком
	EXPECT_EQ(done, want);
}

/**
 * @brief Проверка примеров подписи Wycheproof ML-DSA-44
 *
 */
TEST(MldsaTest, Wycheproof44Sign) {
	// Выполняем проверку примеров набора
	wycheproofSign("44", 61u);
}

/**
 * @brief Проверка примеров сличения Wycheproof ML-DSA-44
 *
 */
TEST(MldsaTest, Wycheproof44Verify) {
	// Выполняем проверку примеров набора
	wycheproofVerify("44", 78u);
}

/**
 * @brief Проверка примеров подписи Wycheproof ML-DSA-65
 *
 */
TEST(MldsaTest, Wycheproof65Sign) {
	// Выполняем проверку примеров набора
	wycheproofSign("65", 63u);
}

/**
 * @brief Проверка примеров сличения Wycheproof ML-DSA-65
 *
 */
TEST(MldsaTest, Wycheproof65Verify) {
	// Выполняем проверку примеров набора
	wycheproofVerify("65", 81u);
}

/**
 * @brief Проверка примеров подписи Wycheproof ML-DSA-87
 *
 */
TEST(MldsaTest, Wycheproof87Sign) {
	// Выполняем проверку примеров набора
	wycheproofSign("87", 54u);
}

/**
 * @brief Проверка примеров сличения Wycheproof ML-DSA-87
 *
 */
TEST(MldsaTest, Wycheproof87Verify) {
	// Выполняем проверку примеров набора
	wycheproofVerify("87", 74u);
}

/**
 * @brief Проверка круга подписи на своих ключах всех наборов
 *
 */
TEST(MldsaTest, Round) {
	// Сообщение круга подписи
	const std::string text = "сообщение круга подписи ML-DSA";
	// Выполняем перебор наборов параметров
	for(auto set : {sign::mldsa_t::set_t::DSA44, sign::mldsa_t::set_t::DSA65, sign::mldsa_t::set_t::DSA87}){
		// Модули подписи и проверки
		sign::mldsa_t signer, verifier;
		// Места записей ключей
		std::vector <uint8_t> pub(sign::mldsa_t::publicSize(set)), priv(sign::mldsa_t::secretSize(set));
		// Выполняем порождение ключа из источника случайности
		ASSERT_TRUE(signer.generate(set, pub.data(), priv.data()));
		// Выполняем установку ключа проверки
		ASSERT_TRUE(verifier.key(set, view_t(pub.data(), pub.size())));
		// Набор, размер и предел подписи после установки
		EXPECT_EQ(signer.set(), set);
		EXPECT_EQ(signer.size(), sign::mldsa_t::signatureSize(set));
		EXPECT_EQ(signer.limit(), sign::mldsa_t::signatureSize(set));
		// Место подписи
		std::vector <uint8_t> signature(sign::mldsa_t::signatureSize(set));
		// Выполняем выработку подписи от источника случайности
		ASSERT_TRUE(signer.make(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), signature.data()));
		// Выполняем сличение подписи
		EXPECT_TRUE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Порченый байт подписи отвергается
		signature[100] ^= 1;
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Возвращаем байт подписи обратно
		signature[100] ^= 1;
		// Иное сообщение отвергается
		const std::string other = "иное сообщение";
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (other.data()), other.size()), view_t(nullptr, 0), view_t(signature.data(), signature.size())));
		// Иной контекст отвергается
		const uint8_t context[1] = {1};
		EXPECT_FALSE(verifier.check(view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), view_t(context, sizeof(context)), view_t(signature.data(), signature.size())));
		// Сброс модуля снимает ключи
		signer.clear();
		EXPECT_EQ(signer.set(), sign::mldsa_t::set_t::NONE);
		EXPECT_EQ(signer.size(), 0u);
	}
}
