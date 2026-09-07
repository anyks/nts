/**
 * @file siphash.cpp
 * @date 2026-09-07
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
 * @brief Проверки модуля SipHash-2-4
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
#include <digest/siphash.hpp>

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
 * @return     запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	std::string result;
	static const char * DIGITS = "0123456789abcdef";
	for(size_t i = 0; i < size; i++){
		result.push_back(DIGITS[data[i] >> 4]);
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	return result;
}
/**
 * @brief Метод вычисления по векторам статьи: ключ 00..0f, сообщение 00..n-1
 *
 * @param length длина сообщения
 * @param size   длина итога
 *
 * @return       запись итога либо пустая при отказе
 *
 */
static std::string paper(const size_t length, const size_t size) {
	uint8_t key[16];
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	std::vector <uint8_t> message(length, 0);
	for(size_t i = 0; i < length; i++) message[i] = static_cast <uint8_t> (i);
	uint8_t result[16];
	if(!digest::siphash(view_t(key, sizeof(key)), view_t(message.data(), message.size()), result, size))
		return std::string();
	return text(result, size);
}

/**
 * Векторы статьи Аумассона и Бернштейна (приложение A): ключ 00..0f, сообщения 00..n-1
 */
TEST(SiphashTest, Paper){
	ASSERT_EQ(paper(0, 8), "310e0edd47db6f72");
	ASSERT_EQ(paper(1, 8), "fd67dc93c539f874");
	ASSERT_EQ(paper(2, 8), "5a4fa9d909806c0d");
	ASSERT_EQ(paper(8, 8), "6224939a79f5f593");
	ASSERT_EQ(paper(15, 8), "e545be4961ca29a1");
	ASSERT_EQ(paper(63, 8), "724506eb4c328a95");
	// SipHash-2-4-128 на пустом сообщении (референсные vectors_128)
	ASSERT_EQ(paper(0, 16), "a3817f04ba25a8e66df67214c7550293");
}

/**
 * Итог числом сходится с байтами от младшего
 */
TEST(SiphashTest, Number){
	uint8_t key[16];
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	uint64_t number = 0;
	ASSERT_TRUE(digest::siphash(view_t(key, sizeof(key)), view_t(), number));
	EXPECT_EQ(number, 0x726fdb47dd0e0e31ULL);
}

/**
 * Отказы и зависимость от ключа
 */
TEST(SiphashTest, Refusals){
	uint8_t key[16] = {0}, result[16];
	uint64_t number = 0;
	EXPECT_FALSE(digest::siphash(view_t(key, 15), view_t(), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(nullptr, 16), view_t(), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(), nullptr, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(), result, 12));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(nullptr, 3), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 15), view_t(), number));
	// Один разряд ключа меняет итог
	const std::string message = "wireguard";
	ASSERT_TRUE(digest::siphash(view_t(key, 16), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, 8));
	const std::string first = text(result, 8);
	key[0] ^= 0x01;
	ASSERT_TRUE(digest::siphash(view_t(key, 16), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, 8));
	EXPECT_NE(first, text(result, 8));
}
