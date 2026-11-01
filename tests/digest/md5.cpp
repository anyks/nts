/**
 * @file md5.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля дайджеста MD5: контрольные примеры,
 *        миллион символов, чужие хеши и отказы
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
#include <digest/md5.hpp>

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
	uint8_t result[16];
	// Если хеш выработать не удалось
	if(!digest::md5(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)))
		// Выводим пустую запись
		return "";
	// Выводим запись хеша
	return text(result, sizeof(result));
}

/**
 * Проверка векторов приложения A.5 RFC 1321
 */
TEST(Md5Test, Vectors){
	// Хеш пустого сообщения
	ASSERT_EQ(whole(""), "d41d8cd98f00b204e9800998ecf8427e");
	// Хеш сообщения «a»
	ASSERT_EQ(whole("a"), "0cc175b9c0f1b6a831c399e269772661");
	// Хеш сообщения «abc»
	ASSERT_EQ(whole("abc"), "900150983cd24fb0d6963f7d28e17f72");
	// Хеш сообщения «message digest»
	ASSERT_EQ(whole("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
	// Хеш строчных букв
	ASSERT_EQ(whole("abcdefghijklmnopqrstuvwxyz"), "c3fcd3d76192e4007dfb496cca67e13b");
	// Хеш букв обоих регистров и цифр
	ASSERT_EQ(whole("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "d174ab98d277d9f5a5611c2c9f419d9f");
	// Хеш восьмидесяти цифр: дополнение переходит через границу блока
	ASSERT_EQ(whole("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57edf4a22be3c955ac49da2e2107b67a");
}

/**
 * Проверка миллиона знаков «a» и независимости хеша от нарезки на куски
 */
TEST(Md5Test, Million){
	// Сообщение в миллион знаков «a»
	const std::string message(1000000, 'a');
	// Хеш миллиона знаков «a» целиком
	ASSERT_EQ(whole(message), "7707d6ae4e027c70eea2a935c2296f21");
	// Размеры кусков, которыми подаётся сообщение
	const size_t chunks[] = {1, 3, 7, 63, 64, 65, 1000, 4097};
	/**
	 * Выполняем перебор размеров кусков
	 */
	for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++){
		// Объект хеширования
		digest::md5_t hasher;
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
		uint8_t result[16];
		// Проверяем снятие хеша
		ASSERT_TRUE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
		// Проверяем схождение хеша с выработанным целиком
		ASSERT_EQ(text(result, sizeof(result)), "7707d6ae4e027c70eea2a935c2296f21") << "кусок " << chunks[c];
		// Проверяем отказ повторного снятия хеша без сброса
		ASSERT_FALSE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
	}
}

/**
 * Проверка вектора AWH, закреплённого по BoringSSL
 */
TEST(Md5Test, Foreign){
	// Хеш входа векторов AWH
	ASSERT_EQ(whole("Hello World, Hello World, Hello World, Hello World, Hello World, Hello World!!!!!!!!!!!!!!!!?"), "7039bdd0df3e5cec78934c32ab931c91");
}

/**
 * Проверка отказов договора
 */
TEST(Md5Test, Refusals){
	// Место, в которое записывается хеш
	uint8_t result[16];
	// Объект хеширования
	digest::md5_t hasher;
	// Проверяем отказ снятия хеша в место короче хеша
	ASSERT_FALSE(hasher.finish(result, 15));
	// Проверяем отказ снятия хеша в пустое место
	ASSERT_FALSE(hasher.finish(nullptr, sizeof(result)));
	// Проверяем снятие хеша в место ровно по длине
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш пустого сообщения после отказов
	ASSERT_EQ(text(result, sizeof(result)), "d41d8cd98f00b204e9800998ecf8427e");
	// Выполняем сброс состояния
	hasher.reset();
	// Выполняем подачу сообщения «abc»
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3));
	// Проверяем снятие хеша после сброса
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш сообщения «abc»
	ASSERT_EQ(text(result, sizeof(result)), "900150983cd24fb0d6963f7d28e17f72");
}
