/**
 * @file ripemd.cpp
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
 * @brief Проверки модуля хеш-функции RIPEMD-160
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
#include <digest/ripemd.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
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
	// Выводим собранную запись
	return result;
}
/**
 * @brief Функция вычисления хеша сообщения
 *
 * @param message хешируемое сообщение
 * @return        запись хеша либо пустая при отказе
 *
 */
static std::string hashed(const std::vector <uint8_t> & message) {
	// Место под хеш
	uint8_t result[digest::RIPEMD160];
	// Вычисляем хеш сообщения
	if(!digest::ripemd160(view_t(message.data(), message.size()), result, sizeof(result))){
		// Отказ хеширования: возвращаем пустую запись
		return std::string();
	}
	// Выводим запись хеша
	return text(result, sizeof(result));
}
/**
 * @brief Функция составления сообщения из повторов символа
 *
 * @param piece повторяемый символ
 * @param count число повторов
 * @return      сообщение
 *
 */
static std::vector <uint8_t> repeat(const char piece, const size_t count) {
	// Собираемое сообщение
	return std::vector <uint8_t> (count, static_cast <uint8_t> (piece));
}

/**
 * Векторы спецификации RIPEMD-160 (Доббертин, Босселарс, Пренел)
 */
TEST(RipemdTest, Vectors){
	// Пустое сообщение
	ASSERT_EQ(hashed(std::vector <uint8_t> ()), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
	// «a»
	ASSERT_EQ(hashed(std::vector <uint8_t> {'a'}), "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
	// «abc»
	ASSERT_EQ(hashed(std::vector <uint8_t> {'a', 'b', 'c'}), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
	// «message digest»
	{
		// Сообщение из спецификации
		const std::string message = "message digest";
		// Хеш «message digest» совпадает со значением спецификации
		ASSERT_EQ(hashed(std::vector <uint8_t> (message.begin(), message.end())), "5d0689ef49d2fae572b881b123a85ffa21595f36");
	}
	// Алфавит
	{
		// Алфавит в нижнем регистре
		const std::string message = "abcdefghijklmnopqrstuvwxyz";
		// Хеш алфавита совпадает со значением спецификации
		ASSERT_EQ(hashed(std::vector <uint8_t> (message.begin(), message.end())), "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
	}
	// «abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq»
	{
		// Сообщение из повторяющихся пар знаков по спецификации
		const std::string message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		// Хеш этого сообщения совпадает со значением спецификации
		ASSERT_EQ(hashed(std::vector <uint8_t> (message.begin(), message.end())), "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
	}
	// «a» миллион раз
	ASSERT_EQ(hashed(repeat('a', 1000000)), "52783243c1697bdbe16d37f97f68f08325dc1528");
}

/**
 * Подача кусками сходится с подачей разом
 */
TEST(RipemdTest, Chunks){
	// Хешируемое сообщение
	const std::vector <uint8_t> message = repeat('a', 1000);
	// Хеш целого сообщения
	const std::string whole = hashed(message);
	// Хеш по кускам
	digest::ripemd_t hasher;
	/**
	 * Подаём сообщение кусками по семь байтов
	 */
	for(size_t i = 0; i < message.size(); i += 7){
		// Длина очередного куска
		const size_t chunk = ((message.size() - i < 7) ? (message.size() - i) : 7);
		// Подаём очередной кусок
		hasher.update(view_t(message.data() + i, chunk));
	}
	// Место под хеш
	uint8_t result[digest::RIPEMD160];
	// Снимаем хеш
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем сходимость с целым
	ASSERT_EQ(text(result, sizeof(result)), whole);
}

/**
 * Отказы и сброс состояния
 */
TEST(RipemdTest, Refusals){
	// Место под хеш
	uint8_t result[digest::RIPEMD160];
	// Пустое место итога и малое место отвергаются
	EXPECT_FALSE(digest::ripemd160(view_t(), nullptr, digest::RIPEMD160));
	EXPECT_FALSE(digest::ripemd160(view_t(), result, digest::RIPEMD160 - 1));
	// Хешируемое по кускам
	digest::ripemd_t hasher;
	// Подача длиной без места порчена: снятие отказывает
	hasher.update(view_t(nullptr, 3));
	// Снятие хеша после порчи подачи отвергается
	EXPECT_FALSE(hasher.finish(result, sizeof(result)));
	// После сброса хеширование идёт заново
	hasher.reset();
	// Хешируемое сообщение
	const std::string message = "abc";
	// Подаём «abc» сброшенному накопителю
	hasher.update(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()));
	// Снятие хеша после сброса проходит
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Итог совпадает с хешем «abc»
	ASSERT_EQ(text(result, sizeof(result)), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
	// Повторное снятие без сброса отвергается
	EXPECT_FALSE(hasher.finish(result, sizeof(result)));
}
