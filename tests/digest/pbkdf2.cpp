/**
 * @file: pbkdf2.cpp
 * @date: 2026-09-04
 * @license: GPL-3.0
 *
 * @telegram: @forman
 * @author: Yuriy Lobarev
 * @phone: +7 (910) 983-95-90
 * @email: forman@anyks.com
 * @site: https://anyks.com
 *
 * @copyright: Copyright © 2026
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/pbkdf2.hpp>

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
 * @brief Метод вывода ключа строкой
 *
 * @param algorithm  алгоритм хеширования
 * @param password   пароль
 * @param salt       соль
 * @param iterations число оборотов
 * @param size       длина ключа
 *
 * @return           запись ключа шестнадцатеричной строкой
 *
 */
static std::string derive(const digest::hash_t algorithm, const std::string & password, const std::string & salt, const uint32_t iterations, const size_t size) {
	// Место, в которое записывается ключ
	uint8_t result[64];
	// Если ключ вывести не удалось
	if(!digest::pbkdf2(algorithm, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(reinterpret_cast <const uint8_t *> (salt.data()), salt.size()), iterations, result, size))
		// Выводим пустую запись
		return "";
	// Выводим запись ключа
	return text(result, size);
}

/**
 * Проверка векторов RFC 6070 на SHA-1
 */
TEST(Pbkdf2Test, Sha1){
	// Один оборот
	ASSERT_EQ(derive(digest::hash_t::SHA1, "password", "salt", 1, 20), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
	// Четыре тысячи девяносто шесть оборотов
	ASSERT_EQ(derive(digest::hash_t::SHA1, "password", "salt", 4096, 20), "4b007901b765489abead49d926f721d065a429c1");
	// Ключ в два блока с хвостом
	ASSERT_EQ(derive(digest::hash_t::SHA1, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25), "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
}

/**
 * Проверка векторов на SHA-256: тот же вход, что у RFC 6070, числа по OpenSSL
 */
TEST(Pbkdf2Test, Sha256){
	// Четыре тысячи девяносто шесть оборотов, ключ в 32 байта
	ASSERT_EQ(derive(digest::hash_t::SHA256, "password", "salt", 4096, 32), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
	// Ключ в 40 байтов: два блока
	ASSERT_EQ(derive(digest::hash_t::SHA256, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40), "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");
	// Ключи AWH: 16, 24 и 32 байта - каждый начало предыдущего
	const std::string longest = derive(digest::hash_t::SHA256, "password", "salt", 100, 32);
	// Проверяем ключ в 24 байта
	ASSERT_EQ(derive(digest::hash_t::SHA256, "password", "salt", 100, 24), longest.substr(0, 48));
	// Проверяем ключ в 16 байтов
	ASSERT_EQ(derive(digest::hash_t::SHA256, "password", "salt", 100, 16), longest.substr(0, 32));
}

/**
 * Проверка отказов договора
 */
TEST(Pbkdf2Test, Refusals){
	// Место под ключ
	uint8_t result[32];
	// Проверяем отказ без оборотов
	ASSERT_FALSE(digest::pbkdf2(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> ("p"), 1), view_t(), 0, result, sizeof(result)));
	// Проверяем отказ неустановленного алгоритма
	ASSERT_FALSE(digest::pbkdf2(digest::hash_t::NONE, view_t(reinterpret_cast <const uint8_t *> ("p"), 1), view_t(), 1, result, sizeof(result)));
	// Проверяем отказ нулевой длины ключа
	ASSERT_FALSE(digest::pbkdf2(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> ("p"), 1), view_t(), 1, result, 0));
	// Проверяем вывод с пустыми паролем и солью
	ASSERT_TRUE(digest::pbkdf2(digest::hash_t::SHA256, view_t(), view_t(), 1, result, sizeof(result)));
}
