/**
 * @file: sha1.cpp
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
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/sha1.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод записи хеша шестнадцатеричной строкой
 *
 * @param data байты хеша
 * @param size число байтов хеша
 *
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
 * @brief Метод выработки хеша целого сообщения строкой
 *
 * @param message хешируемое сообщение
 *
 * @return        запись хеша шестнадцатеричной строкой
 *
 */
static std::string whole(const std::string & message) {
	// Место, в которое записывается хеш
	uint8_t result[20];
	// Если хеш выработать не удалось
	if(!digest::sha1(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)))
		// Выводим пустую запись
		return "";
	// Выводим запись хеша
	return text(result, sizeof(result));
}

/**
 * Проверка векторов FIPS 180-4
 */
TEST(Sha1Test, Vectors){
	// Хеш сообщения «abc»
	ASSERT_EQ(whole("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
	// Хеш пустого сообщения
	ASSERT_EQ(whole(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	// Хеш сообщения в два блока: дополнение переходит через границу блока
	ASSERT_EQ(whole("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

/**
 * Проверка миллиона знаков «a» и независимости хеша от нарезки на куски
 */
TEST(Sha1Test, Million){
	// Сообщение в миллион знаков «a»
	const std::string message(1000000, 'a');
	// Хеш миллиона знаков «a» целиком
	ASSERT_EQ(whole(message), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
	// Размеры кусков, которыми подаётся сообщение
	const size_t chunks[] = {1, 3, 7, 63, 64, 65, 1000, 4097};
	/**
	 * Выполняем перебор размеров кусков
	 */
	for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++){
		// Объект хеширования
		digest::sha1_t hasher;
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
		uint8_t result[20];
		// Проверяем снятие хеша
		ASSERT_TRUE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
		// Проверяем схождение хеша с выработанным целиком
		ASSERT_EQ(text(result, sizeof(result)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f") << "кусок " << chunks[c];
		// Проверяем отказ повторного снятия хеша без сброса
		ASSERT_FALSE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
	}
}

/**
 * Проверка вектора AWH, закреплённого по BoringSSL
 */
TEST(Sha1Test, Foreign){
	// Хеш входа векторов AWH
	ASSERT_EQ(whole("Hello World, Hello World, Hello World, Hello World, Hello World, Hello World!!!!!!!!!!!!!!!!?"), "adaccf563788bc09516f3b13c5fb969dee97ed41");
}

/**
 * Проверка отказов договора
 */
TEST(Sha1Test, Refusals){
	// Место, в которое записывается хеш
	uint8_t result[20];
	// Объект хеширования
	digest::sha1_t hasher;
	// Проверяем отказ снятия хеша в место короче хеша
	ASSERT_FALSE(hasher.finish(result, 19));
	// Проверяем отказ снятия хеша в пустое место
	ASSERT_FALSE(hasher.finish(nullptr, sizeof(result)));
	// Проверяем снятие хеша в место ровно по длине
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш пустого сообщения после отказов
	ASSERT_EQ(text(result, sizeof(result)), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
	// Выполняем сброс состояния
	hasher.reset();
	// Выполняем подачу сообщения «abc»
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3));
	// Проверяем снятие хеша после сброса
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш сообщения «abc»
	ASSERT_EQ(text(result, sizeof(result)), "a9993e364706816aba3e25717850c26c9cd0d89d");
}
