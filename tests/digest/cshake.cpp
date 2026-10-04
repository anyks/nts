/**
 * @file cshake.cpp
 * @date 2026-10-05
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Проверки модуля настраиваемых функций переменного выхода cSHAKE и
 *        имитовставок KMAC по SP 800-185 на контрольных примерах NIST
 *
 * @details Контрольные примеры - официальные образцы NIST «Examples of the SHA-3
 *          Derived Functions» (cSHAKE_samples.pdf, KMAC_samples.pdf): cSHAKE128
 *          образцы 1-2, cSHAKE256 образцы 3-4, KMAC128 образцы 1-3, KMAC256
 *          образцы 4-5, KMACXOF256 образец 6
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/cshake.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 *
 * @return     запись строчными шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		// Записываем младший полубайт
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Выводим запись
	return result;
}
/**
 * @brief Метод вычисления cSHAKE за один вызов
 *
 * @param type    разновидность функции
 * @param message сообщение
 * @param name    имя функции N
 * @param custom  настройка S
 * @param size    длина итога
 *
 * @return        запись итога шестнадцатеричной строкой либо пустая при отказе
 *
 */
static std::string cshaking(const digest::sha3_t type, const std::vector <uint8_t> & message, const std::string & name, const std::string & custom, const size_t size) {
	// Место, в которое записывается итог
	std::vector <uint8_t> result(size, 0);
	// Просмотр сообщения
	const view_t data(message.data(), message.size());
	// Просмотр имени функции
	const view_t naming(reinterpret_cast <const uint8_t *> (name.data()), name.size());
	// Просмотр настройки
	const view_t tuning(reinterpret_cast <const uint8_t *> (custom.data()), custom.size());
	// Если итог вычислить не удалось
	if(!digest::cshake(type, data, naming, tuning, result.data(), size))
		// Выводим пустую запись
		return std::string();
	// Выводим запись итога
	return text(result.data(), size);
}
/**
 * @brief Метод вычисления имитовставки KMAC за один вызов
 *
 * @param type    разновидность функции
 * @param key     ключ имитовставки
 * @param message сообщение
 * @param custom  настройка S
 * @param size    длина имитовставки
 * @param xof     признак переменной длины итога (KMACXOF)
 *
 * @return        запись имитовставки шестнадцатеричной строкой либо пустая при отказе
 *
 */
static std::string kmacing(const digest::sha3_t type, const std::vector <uint8_t> & key, const std::vector <uint8_t> & message, const std::string & custom, const size_t size, const bool xof) {
	// Место, в которое записывается имитовставка
	std::vector <uint8_t> result(size, 0);
	// Просмотр ключа
	const view_t secret(key.data(), key.size());
	// Просмотр сообщения
	const view_t data(message.data(), message.size());
	// Просмотр настройки
	const view_t tuning(reinterpret_cast <const uint8_t *> (custom.data()), custom.size());
	// Вычисляем имитовставку по виду итога
	const bool ok = (xof ? digest::kmacxof(type, secret, data, tuning, result.data(), size) : digest::kmac(type, secret, data, tuning, result.data(), size));
	// Если имитовставку вычислить не удалось
	if(!ok)
		// Выводим пустую запись
		return std::string();
	// Выводим запись имитовставки
	return text(result.data(), size);
}
/**
 * @brief Метод составления сообщения из байтов 00..C7
 *
 * @param size длина сообщения в байтах
 *
 * @return     сообщение из байтов 00..C7
 *
 */
static std::vector <uint8_t> pattern(const size_t size) {
	// Составляемое сообщение
	std::vector <uint8_t> result(size, 0);
	/**
	 * Выполняем перебор байтов сообщения
	 */
	for(size_t i = 0; i < size; i++)
		// Записываем очередной байт образца
		result[i] = static_cast <uint8_t> (i);
	// Выводим сообщение
	return result;
}
/**
 * @brief Метод составления ключа из байтов 40..5F
 *
 * @return ключ из тридцати двух байтов 40..5F
 *
 */
static std::vector <uint8_t> keying() {
	// Составляемый ключ
	std::vector <uint8_t> result(32, 0);
	/**
	 * Выполняем перебор байтов ключа
	 */
	for(size_t i = 0; i < result.size(); i++)
		// Записываем очередной байт ключа
		result[i] = static_cast <uint8_t> (0x40 + i);
	// Выводим ключ
	return result;
}

/**
 * Проверка cSHAKE128 на контрольных примерах NIST
 */
TEST(CshakeTest, Cshake128){
	// Сообщение примеров: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Образец 1: X из 4 байтов, N = "", S = "Email Signature", итог 256 разрядов
	EXPECT_EQ(cshaking(digest::sha3_t::SHAKE128, message, "", "Email Signature", 32),
		"c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
	// Образец 2: X из 200 байтов 00..C7, N = "", S = "Email Signature", итог 256 разрядов
	EXPECT_EQ(cshaking(digest::sha3_t::SHAKE128, pattern(200), "", "Email Signature", 32),
		"c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b");
}

/**
 * Проверка cSHAKE256 на контрольных примерах NIST
 */
TEST(CshakeTest, Cshake256){
	// Сообщение примеров: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Образец 3: X из 4 байтов, N = "", S = "Email Signature", итог 512 разрядов
	EXPECT_EQ(cshaking(digest::sha3_t::SHAKE256, message, "", "Email Signature", 64),
		"d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c");
	// Образец 4: X из 200 байтов 00..C7, N = "", S = "Email Signature", итог 512 разрядов
	EXPECT_EQ(cshaking(digest::sha3_t::SHAKE256, pattern(200), "", "Email Signature", 64),
		"07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb");
}

/**
 * Проверка тождества cSHAKE с пустыми именем и настройкой функции SHAKE
 */
TEST(CshakeTest, ShakeIdentity){
	// Сообщение проверки: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Место итогов cSHAKE и SHAKE
	std::vector <uint8_t> customized(32, 0), plain(32, 0);
	// Просмотр сообщения
	const view_t data(message.data(), message.size());
	// Вычисляем cSHAKE с пустыми именем и настройкой
	ASSERT_TRUE(digest::cshake(digest::sha3_t::SHAKE128, data, view_t(nullptr, 0), view_t(nullptr, 0), customized.data(), customized.size()));
	// Вычисляем SHAKE128 того же сообщения
	ASSERT_TRUE(digest::sha3(digest::sha3_t::SHAKE128, data, plain.data(), plain.size()));
	// Раздел 3.1 SP 800-185: при пустых N и S функция есть ровно SHAKE
	EXPECT_EQ(text(customized.data(), customized.size()), text(plain.data(), plain.size()));
}

/**
 * Проверка KMAC128 на контрольных примерах NIST
 */
TEST(CshakeTest, Kmac128){
	// Ключ примеров: байты 40..5F
	const std::vector <uint8_t> key = keying();
	// Сообщение примеров: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Образец 1: X из 4 байтов, S = "", итог 256 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE128, key, message, "", 32, false),
		"e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
	// Образец 2: X из 4 байтов, S = "My Tagged Application", итог 256 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE128, key, message, "My Tagged Application", 32, false),
		"3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");
	// Образец 3: X из 200 байтов 00..C7, S = "My Tagged Application", итог 256 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE128, key, pattern(200), "My Tagged Application", 32, false),
		"1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230");
}

/**
 * Проверка KMAC256 на контрольных примерах NIST
 */
TEST(CshakeTest, Kmac256){
	// Ключ примеров: байты 40..5F
	const std::vector <uint8_t> key = keying();
	// Сообщение примеров: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Образец 4: X из 4 байтов, S = "My Tagged Application", итог 512 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE256, key, message, "My Tagged Application", 64, false),
		"20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");
	// Образец 5: X из 200 байтов 00..C7, S = "", итог 512 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE256, key, pattern(200), "", 64, false),
		"75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69");
}

/**
 * Проверка KMACXOF256 на контрольном примере NIST и свойства префикса
 */
TEST(CshakeTest, KmacXof){
	// Ключ примеров: байты 40..5F
	const std::vector <uint8_t> key = keying();
	// Образец 6: X из 200 байтов 00..C7, S = "My Tagged Application", итог 512 разрядов
	EXPECT_EQ(kmacing(digest::sha3_t::SHAKE256, key, pattern(200), "My Tagged Application", 64, false),
		"b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965");
	// Сообщение проверки: байты 00..03
	const std::vector <uint8_t> message = {0x00, 0x01, 0x02, 0x03};
	// Итоги переменной длины: 32 и 64 байта
	const std::string shorter = kmacing(digest::sha3_t::SHAKE128, key, message, "", 32, true);
	const std::string longer = kmacing(digest::sha3_t::SHAKE128, key, message, "", 64, true);
	// Начало длинного итога совпадает с коротким: right_encode(0) не несёт длины
	ASSERT_FALSE(shorter.empty());
	ASSERT_FALSE(longer.empty());
	EXPECT_EQ(longer.substr(0, shorter.size()), shorter);
	// KMAC и KMACXOF при той же длине различаются записью длины итога
	EXPECT_NE(kmacing(digest::sha3_t::SHAKE128, key, message, "", 32, false), shorter);
}
