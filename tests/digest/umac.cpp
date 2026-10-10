/**
 * @file umac.cpp
 * @date 2026-10-10
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
 * @brief Проверки модуля имитовставки UMAC (RFC 4418)
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
#include <digest/umac.hpp>

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
 * @brief Метод вычисления по векторам RFC 4418: ключ «abcdefghijklmnop», одноразовое число «bcdefghi»
 *
 * @param message сообщение
 * @param size    длина итога: 8 (UMAC-64) или 16 (UMAC-128)
 *
 * @return        запись итога либо пустая при отказе
 *
 */
static std::string rfc(const std::vector <uint8_t> & message, const size_t size) {
	// Ключ и одноразовое число векторов RFC 4418
	static const uint8_t KEY[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
	static const uint8_t NONCE[8] = {'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'};
	uint8_t result[16];
	if(!digest::umac(view_t(KEY, sizeof(KEY)), view_t(NONCE, sizeof(NONCE)), view_t(message.data(), message.size()), result, size))
		return std::string();
	return text(result, size);
}
/**
 * @brief Метод составления сообщения из повторов строки
 *
 * @param piece повторяемая строка
 * @param count число повторов
 *
 * @return      сообщение
 *
 */
static std::vector <uint8_t> repeat(const std::string & piece, const size_t count) {
	std::vector <uint8_t> result;
	result.reserve(piece.size() * count);
	for(size_t i = 0; i < count; i++)
		result.insert(result.end(), piece.begin(), piece.end());
	return result;
}

/**
 * Векторы приложения RFC 4418 для UMAC-64: пустое сообщение, «a» и «abc» в разных длинах,
 * в том числе через слой POLY (длиннее 1024 байтов)
 */
TEST(UmacTest, Rfc64){
	// Пустое сообщение
	ASSERT_EQ(rfc(std::vector <uint8_t> (), 8), "6e155fad26900be1");
	// «a» трижды
	ASSERT_EQ(rfc(repeat("a", 3), 8), "44b5cb542f220104");
	// «a» 2^10 раз (ровно блок слоя L1)
	ASSERT_EQ(rfc(repeat("a", 1024), 8), "26bf2f5d60118bd9");
	// «a» 2^15 раз (через слой POLY)
	ASSERT_EQ(rfc(repeat("a", 32768), 8), "27f8ef643b0d118d");
	// «a» 2^20 раз (через слой POLY)
	ASSERT_EQ(rfc(repeat("a", 1048576), 8), "a4477e87e9f55853");
	// «abc» один раз
	ASSERT_EQ(rfc(repeat("abc", 1), 8), "d4d7b9f6bd4fbfcf");
	// «abc» пятьсот раз (через слой POLY)
	ASSERT_EQ(rfc(repeat("abc", 500), 8), "d4cf26ddefd5c01a");
}

/**
 * UMAC-128 на тех же сообщениях: эталонные значения сверены с независимой реализацией
 * RFC 4418 на python (собственный AES), которая на UMAC-64 сходится с векторами RFC
 */
TEST(UmacTest, Rfc128){
	// Пустое сообщение
	ASSERT_EQ(rfc(std::vector <uint8_t> (), 16), "32fedb100c79ad58f07ff7643cc60465");
	// «a» трижды
	ASSERT_EQ(rfc(repeat("a", 3), 16), "185e4fe905cba7bd85e4c2dc3d117d8d");
	// «abc» пятьсот раз (через слой POLY)
	ASSERT_EQ(rfc(repeat("abc", 500), 16), "8824a260c53c66a36c9260a62cb83aa1");
}

/**
 * Отказы и зависимость от ключа и одноразового числа
 */
TEST(UmacTest, Refusals){
	uint8_t key[16] = {0}, result[16];
	const uint8_t nonce[8] = {'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'};
	const std::string message = "message";
	const view_t data(reinterpret_cast <const uint8_t *> (message.data()), message.size());
	// Ключ не в шестнадцать байтов, пустой ключ, пустое место итога, иная длина итога
	EXPECT_FALSE(digest::umac(view_t(key, 15), view_t(nonce, sizeof(nonce)), data, result, 8));
	EXPECT_FALSE(digest::umac(view_t(nullptr, 16), view_t(nonce, sizeof(nonce)), data, result, 8));
	EXPECT_FALSE(digest::umac(view_t(key, 16), view_t(nonce, sizeof(nonce)), data, nullptr, 8));
	EXPECT_FALSE(digest::umac(view_t(key, 16), view_t(nonce, sizeof(nonce)), data, result, 12));
	// Пустое одноразовое число отвергается
	EXPECT_FALSE(digest::umac(view_t(key, 16), view_t(nonce, 0), data, result, 8));
	// Одноразовое число длиннее блока отвергается
	const uint8_t longest[17] = {0};
	EXPECT_FALSE(digest::umac(view_t(key, 16), view_t(longest, sizeof(longest)), data, result, 8));
	// Один разряд ключа меняет итог
	ASSERT_TRUE(digest::umac(view_t(key, 16), view_t(nonce, sizeof(nonce)), data, result, 8));
	const std::string first = text(result, 8);
	key[0] ^= 0x01;
	ASSERT_TRUE(digest::umac(view_t(key, 16), view_t(nonce, sizeof(nonce)), data, result, 8));
	EXPECT_NE(first, text(result, 8));
	key[0] ^= 0x01;
	// Иное одноразовое число меняет итог
	const uint8_t other[8] = {'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j'};
	ASSERT_TRUE(digest::umac(view_t(key, 16), view_t(other, sizeof(other)), data, result, 8));
	EXPECT_NE(first, text(result, 8));
}
