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
 * @brief Функция записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 * @return     запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Буфер собираемой шестнадцатеричной записи
	std::string result;
	// Цифры шестнадцатеричной записи по возрастанию
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Перебираем байты, добавляя в запись пару шестнадцатеричных цифр
	 */
	for(size_t i = 0; i < size; i++){
		// В старшей позиции — цифра старшего полубайта
		result.push_back(DIGITS[data[i] >> 4]);
		// В младшей позиции — цифра младшего полубайта
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Отдаём собранную шестнадцатеричную запись
	return result;
}
/**
 * @brief Функция вычисления по векторам статьи: ключ 00..0f, сообщение 00..n-1
 *
 * @param length длина сообщения
 * @param size   длина итога
 * @return       запись итога либо пустая при отказе
 *
 */
static std::string paper(const size_t length, const size_t size) {
	// Буфер ключа из 16 байтов
	uint8_t key[16];
	/**
	 * Заполняем ключ байтами 00..0f по возрастанию
	 */
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	// Сообщение заданной длины, нули заменим байтами ниже
	std::vector <uint8_t> message(length, 0);
	/**
	 * Заменяем нули сообщения байтами 00..n-1 по возрастанию
	 */
	for(size_t i = 0; i < length; i++) message[i] = static_cast <uint8_t> (i);
	// Буфер итога заданной длины
	uint8_t result[16];
	// Вычисляем итог заданной длины над сообщением
	if(!digest::siphash(view_t(key, sizeof(key)), view_t(message.data(), message.size()), result, size)){
		// При отказе возвращаем пустую запись
		return std::string();
	}
	// Отдаём итог в виде шестнадцатеричной записи
	return text(result, size);
}

/**
 * Векторы статьи Аумассона и Бернштейна (приложение A): ключ 00..0f, сообщения 00..n-1
 */
TEST(SiphashTest, Paper){
	// Итоги SipHash-2-4-64 из приложения A статьи для длин 0, 1, 2, 8, 15 и 63
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
	// Буфер ключа из 16 байтов
	uint8_t key[16];
	/**
	 * Заполняем ключ байтами 00..0f по возрастанию
	 */
	for(size_t i = 0; i < 16; i++) key[i] = static_cast <uint8_t> (i);
	// Итог в виде числа
	uint64_t number = 0;
	// Вычисляем итог пустого сообщения в число
	ASSERT_TRUE(digest::siphash(view_t(key, sizeof(key)), view_t(), number));
	// Число сходится с итогом пустого сообщения, прочитанным от младшего байта
	EXPECT_EQ(number, 0x726fdb47dd0e0e31ULL);
}

/**
 * Отказы и зависимость от ключа
 */
TEST(SiphashTest, Refusals){
	// Нулевой ключ и буферы итога
	uint8_t key[16] = {0}, result[16];
	// Итог в виде числа
	uint64_t number = 0;
	// Ключ короче 16 байтов отвергается
	EXPECT_FALSE(digest::siphash(view_t(key, 15), view_t(), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(nullptr, 16), view_t(), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(), nullptr, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(), result, 12));
	EXPECT_FALSE(digest::siphash(view_t(key, 16), view_t(nullptr, 3), result, 8));
	EXPECT_FALSE(digest::siphash(view_t(key, 15), view_t(), number));
	// Один разряд ключа меняет итог
	const std::string message = "wireguard";
	// Вычисляем итог с исходным ключом
	ASSERT_TRUE(digest::siphash(view_t(key, 16), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, 8));
	// Запоминаем итог исходного ключа
	const std::string first = text(result, 8);
	// Меняем младший разряд ключа
	key[0] ^= 0x01;
	// Вычисляем итог с изменённым ключом
	ASSERT_TRUE(digest::siphash(view_t(key, 16), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, 8));
	// Итоги исходного и изменённого ключей обязаны различаться
	EXPECT_NE(first, text(result, 8));
}
