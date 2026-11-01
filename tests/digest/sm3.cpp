/**
 * @file sm3.cpp
 * @date 2026-10-04
 *
 * @license{GPL-3.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля дайджеста SM3: контрольные примеры,
 *        куски, хешер и отказы
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
#include <digest/sm3.hpp>
#include <digest/hash.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция записи хеша шестнадцатеричной строкой
 *
 * @param data байты хеша
 * @param size число байтов хеша
 * @return     запись хеша строчными шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись хеша
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов хеша
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		// Записываем младший полубайт
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Выводим запись хеша
	return result;
}

/**
 * @brief Функция выработки хеша целого сообщения строкой
 *
 * @param message хешируемое сообщение
 * @return        запись хеша шестнадцатеричной строкой
 *
 */
static std::string whole(const std::string & message) {
	// Место, в которое записывается хеш
	uint8_t result[32];
	// Если хеш выработать не удалось
	if(!digest::sm3(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)))
		// Выводим пустую запись
		return "";
	// Выводим запись хеша
	return text(result, sizeof(result));
}

/**
 * Проверка векторов GB/T 32905-2016
 */
TEST(Sm3Test, Vectors){
	// Хеш сообщения «abc» (пример 1 стандарта)
	ASSERT_EQ(whole("abc"), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
	// Хеш сообщения «abcd», повторённого шестнадцать раз (пример 2 стандарта, 64 байта)
	ASSERT_EQ(whole("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
	// Хеш пустого сообщения, закреплённый по эталонным реализациям
	ASSERT_EQ(whole(""), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
}

/**
 * Проверка независимости хеша от нарезки на куски
 */
TEST(Sm3Test, Chunks){
	// Сообщение в миллион знаков «a»
	const std::string message(1000000, 'a');
	// Хеш миллиона знаков «a» целиком, закреплённый по эталонным реализациям
	ASSERT_EQ(whole(message), "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3");
	// Размеры кусков, которыми подаётся сообщение
	const size_t chunks[] = {1, 3, 7, 63, 64, 65, 1000, 4097};
	/**
	 * Выполняем перебор размеров кусков
	 */
	for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++){
		// Объект хеширования
		digest::sm3_t hasher;
		/**
		 * Выполняем подачу сообщения кусками
		 */
		for(size_t offset = 0; offset < message.size(); offset += chunks[c]){
			// Размер очередного куска
			const size_t size = (((message.size() - offset) < chunks[c]) ? (message.size() - offset) : chunks[c]);
			// Выполняем подачу очередного куска
			hasher.update(view_t(reinterpret_cast <const uint8_t *> (message.data()) + offset, size));
		}
		// Место, в которое записывается хеш
		uint8_t result[32];
		// Проверяем снятие хеша
		ASSERT_TRUE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
		// Проверяем схождение хеша с выработанным целиком
		ASSERT_EQ(text(result, sizeof(result)), "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3") << "кусок " << chunks[c];
		// Проверяем отказ повторного снятия хеша без сброса
		ASSERT_FALSE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
	}
}

/**
 * Проверка общего договора хеширования
 */
TEST(Sm3Test, Hasher){
	// Место, в которое записывается хеш
	uint8_t result[32];
	// Проверяем длину хеша SM3
	ASSERT_EQ(digest::length(digest::hash_t::SM3), 32);
	// Проверяем размер блока SM3
	ASSERT_EQ(digest::block(digest::hash_t::SM3), 64);
	// Проверяем выработку хеша общим методом
	ASSERT_TRUE(digest::hash(digest::hash_t::SM3, view_t(reinterpret_cast <const uint8_t *> ("abc"), 3), result, sizeof(result)));
	// Проверяем хеш сообщения «abc» общим методом
	ASSERT_EQ(text(result, sizeof(result)), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
	// Объект общего хеширования
	digest::hasher_t hasher(digest::hash_t::SM3);
	// Проверяем выбранный алгоритм
	ASSERT_EQ(hasher.type(), digest::hash_t::SM3);
	// Выполняем подачу сообщения «abc»
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3));
	// Проверяем снятие хеша
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш сообщения «abc»
	ASSERT_EQ(text(result, sizeof(result)), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
}

/**
 * Проверка отказов договора
 */
TEST(Sm3Test, Refusals){
	// Место, в которое записывается хеш
	uint8_t result[32];
	// Объект хеширования
	digest::sm3_t hasher;
	// Проверяем отказ снятия хеша в место короче хеша
	ASSERT_FALSE(hasher.finish(result, 31));
	// Проверяем отказ снятия хеша в пустое место
	ASSERT_FALSE(hasher.finish(nullptr, sizeof(result)));
	// Проверяем снятие хеша в место ровно по длине
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш пустого сообщения после отказов
	ASSERT_EQ(text(result, sizeof(result)), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b");
	// Выполняем сброс состояния
	hasher.reset();
	// Выполняем подачу сообщения «abc»
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3));
	// Проверяем снятие хеша после сброса
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш сообщения «abc»
	ASSERT_EQ(text(result, sizeof(result)), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
}
