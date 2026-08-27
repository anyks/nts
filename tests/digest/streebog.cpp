/**
 * @file streebog.cpp
 * @date 2026-08-27
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл проверок модуля хеширования «Стрибог»
 *
 * @note Контрольные примеры взяты из раздела 10 ГОСТ Р 34.11-2012 (перепечатан
 *       RFC 6986). Сообщения записаны там двоичным вектором, то есть от старшего
 *       байта к младшему, - здесь же они записаны потоком байтов, в котором первым
 *       идёт младший байт вектора
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cstring>
#include <string>
#include <vector>
#include <main.hpp>
#include <digest/streebog.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace anyks;

/**
 * @brief Первое сообщение контрольного примера
 *
 */
static const char * MESSAGE_FIRST = "012345678901234567890123456789012345678901234567890123456789012";

/**
 * @brief Второе сообщение контрольного примера
 *
 */
static const uint8_t MESSAGE_SECOND[] = {
		0xD1, 0xE5, 0x20, 0xE2, 0xE5, 0xF2, 0xF0, 0xE8, 0x2C, 0x20, 0xD1, 0xF2,
		0xF0, 0xE8, 0xE1, 0xEE, 0xE6, 0xE8, 0x20, 0xE2, 0xED, 0xF3, 0xF6, 0xE8,
		0x2C, 0x20, 0xE2, 0xE5, 0xFE, 0xF2, 0xFA, 0x20, 0xF1, 0x20, 0xEC, 0xEE,
		0xF0, 0xFF, 0x20, 0xF1, 0xF2, 0xF0, 0xE5, 0xEB, 0xE0, 0xEC, 0xE8, 0x20,
		0xED, 0xE0, 0x20, 0xF5, 0xF0, 0xE0, 0xE1, 0xF0, 0xFB, 0xFF, 0x20, 0xEF,
		0xEB, 0xFA, 0xEA, 0xFB, 0x20, 0xC8, 0xE3, 0xEE, 0xF0, 0xE5, 0xE2, 0xFB};

/**
 * @brief Метод сборки записи хеша в виде строки
 *
 * @param data выработанный хеш
 * @param size длина выработанного хеша
 *
 * @return     запись хеша шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись хеша
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов выработанного хеша
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись хеша
	return result;
}
/**
 * @brief Метод выработки хеша сообщения
 *
 * @param type длина вырабатываемого хеша
 * @param data хешируемое сообщение
 * @param size длина хешируемого сообщения
 *
 * @return     запись выработанного хеша шестнадцатеричными знаками
 *
 */
static std::string hashing(const digest::type_t type, const uint8_t * data, const size_t size) {
	// Место под выработанный хеш
	uint8_t result[64];
	// Если выработка хеша не удалась
	if(!digest::streebog(type, view_t(data, size), result, sizeof(result)))
		// Выводим пустую запись хеша
		return std::string();
	// Выводим запись выработанного хеша
	return text(result, static_cast <size_t> (type));
}
/**
 * @brief Проверка выработки хеша первого контрольного примера
 *
 */
TEST(StreebogTest, First) {
	// Получаем указатель на первое сообщение контрольного примера
	const uint8_t * data = reinterpret_cast <const uint8_t *> (MESSAGE_FIRST);
	// Проверяем длину первого сообщения контрольного примера
	ASSERT_EQ(::strlen(MESSAGE_FIRST), size_t(63));
	// Проверяем хеш длиной 512 разрядов
	ASSERT_STREQ(hashing(digest::type_t::LONG, data, 63).c_str(),
		"486f64c1917879417fef082b3381a4e2"
		"11c324f074654c38823a7b76f830ad00"
		"fa1fbae42b1285c0352f227524bc9ab1"
		"6254288dd6863dccd5b9f54a1ad0541b");
	// Проверяем хеш длиной 256 разрядов
	ASSERT_STREQ(hashing(digest::type_t::SHORT, data, 63).c_str(),
		"00557be5e584fd52a449b16b0251d05d"
		"27f94ab76cbaa6da890b59d8ef1e159d");
}
/**
 * @brief Проверка выработки хеша второго контрольного примера
 *
 */
TEST(StreebogTest, Second) {
	// Проверяем длину второго сообщения контрольного примера
	ASSERT_EQ(sizeof(MESSAGE_SECOND), size_t(72));
	// Проверяем хеш длиной 512 разрядов
	ASSERT_STREQ(hashing(digest::type_t::LONG, MESSAGE_SECOND, sizeof(MESSAGE_SECOND)).c_str(),
		"28fbc9bada033b1460642bdcddb90c3f"
		"b3e56c497ccd0f62b8a2ad4935e85f03"
		"7613966de4ee00531ae60f3b5a47f8da"
		"e06915d5f2f194996fcabf2622e6881e");
	// Проверяем хеш длиной 256 разрядов
	ASSERT_STREQ(hashing(digest::type_t::SHORT, MESSAGE_SECOND, sizeof(MESSAGE_SECOND)).c_str(),
		"508f7e553c06501d749a66fc28c6cac0"
		"b005746d97537fa85d9e40904efed29d");
}
/**
 * @brief Проверка независимости хеша от нарезки сообщения на куски
 *
 */
TEST(StreebogTest, Chunks) {
	// Собираемое сообщение произвольной длины
	std::vector <uint8_t> message;
	/**
	 * Выполняем сборку сообщения, покрывающего несколько блоков хеширования
	 */
	for(size_t i = 0; i < 1000; i++)
		// Дополняем сообщение очередным байтом
		message.push_back(static_cast <uint8_t> ((i * 37) & 0xFF));
	// Набор длин вырабатываемого хеша
	const digest::type_t types[] = {digest::type_t::SHORT, digest::type_t::LONG};
	/**
	 * Выполняем перебор длин вырабатываемого хеша
	 */
	for(size_t t = 0; t < 2; t++){
		// Вырабатываем хеш сообщения, поданного целиком
		const std::string expected = hashing(types[t], message.data(), message.size());
		// Проверяем успешность выработки хеша
		ASSERT_FALSE(expected.empty());
		/**
		 * Выполняем перебор размеров куска подачи сообщения
		 */
		for(size_t size = 1; size <= 130; size++){
			// Создаём объект хеширования
			digest::streebog_t hash(types[t]);
			/**
			 * Выполняем подачу сообщения кусками выбранного размера
			 */
			for(size_t offset = 0; offset < message.size(); offset += size){
				// Определяем размер очередного куска сообщения
				const size_t count = (((message.size() - offset) < size) ? (message.size() - offset) : size);
				// Выполняем подачу очередного куска сообщения
				hash.update(view_t(message.data() + offset, count));
			}
			// Место под выработанный хеш
			uint8_t result[64];
			// Проверяем успешность снятия хеша
			ASSERT_TRUE(hash.finish(result, sizeof(result))) << "кусок " << size;
			// Проверяем совпадение хеша с выработанным при подаче целиком
			ASSERT_STREQ(text(result, static_cast <size_t> (types[t])).c_str(), expected.c_str()) << "кусок " << size;
		}
	}
}
/**
 * @brief Проверка выработки хеша сообщений длиной вокруг размера блока
 *
 */
TEST(StreebogTest, Boundary) {
	// Собираемое сообщение
	std::vector <uint8_t> message;
	// Запись хеша предыдущего сообщения
	std::string previous;
	/**
	 * Выполняем перебор длин сообщения вокруг размера блока хеширования
	 */
	for(size_t size = 0; size <= 130; size++){
		// Вырабатываем хеш сообщения выбранной длины
		const std::string result = hashing(digest::type_t::LONG, message.data(), message.size());
		// Проверяем успешность выработки хеша
		ASSERT_FALSE(result.empty()) << "длина " << size;
		// Проверяем длину записи выработанного хеша
		ASSERT_EQ(result.size(), size_t(128)) << "длина " << size;
		/**
		 * Хеши сообщений разной длины обязаны различаться: дополнение блока для того
		 * и введено, чтобы сообщение и оно же с нулевым хвостом давали разные хеши
		 */
		ASSERT_STRNE(result.c_str(), previous.c_str()) << "длина " << size;
		// Запоминаем запись хеша сообщения
		previous = result;
		// Дополняем сообщение нулевым байтом
		message.push_back(0x00);
	}
}
/**
 * @brief Проверка отказов снятия выработанного хеша
 *
 */
TEST(StreebogTest, Refusal) {
	// Место под выработанный хеш
	uint8_t result[64];
	// Создаём объект хеширования
	digest::streebog_t hash(digest::type_t::LONG);
	// Проверяем отказ снятия хеша в недостаточное место
	ASSERT_FALSE(hash.finish(result, 63));
	// Проверяем отказ снятия хеша в отсутствующее место
	ASSERT_FALSE(hash.finish(nullptr, sizeof(result)));
	// Проверяем успешность снятия хеша
	ASSERT_TRUE(hash.finish(result, sizeof(result)));
	// Проверяем отказ повторного снятия хеша
	ASSERT_FALSE(hash.finish(result, sizeof(result)));
	// Приводим объект к началу хеширования
	hash.reset(digest::type_t::NONE);
	// Проверяем отказ снятия хеша с неустановленной длиной
	ASSERT_FALSE(hash.finish(result, sizeof(result)));
	// Проверяем длину вырабатываемого хеша
	ASSERT_EQ(hash.type(), digest::type_t::NONE);
}
/**
 * @brief Проверка повторного применения объекта хеширования
 *
 */
TEST(StreebogTest, Reset) {
	// Получаем указатель на первое сообщение контрольного примера
	const uint8_t * data = reinterpret_cast <const uint8_t *> (MESSAGE_FIRST);
	// Место под выработанный хеш
	uint8_t result[64];
	// Создаём объект хеширования
	digest::streebog_t hash(digest::type_t::SHORT);
	// Выполняем подачу второго сообщения контрольного примера
	hash.update(view_t(MESSAGE_SECOND, sizeof(MESSAGE_SECOND)));
	// Проверяем успешность снятия хеша
	ASSERT_TRUE(hash.finish(result, sizeof(result)));
	// Приводим объект к началу хеширования с иной длиной хеша
	hash.reset(digest::type_t::LONG);
	// Выполняем подачу первого сообщения контрольного примера
	hash.update(view_t(data, 63));
	// Проверяем успешность снятия хеша
	ASSERT_TRUE(hash.finish(result, sizeof(result)));
	// Проверяем совпадение хеша с контрольным примером
	ASSERT_STREQ(text(result, 64).c_str(),
		"486f64c1917879417fef082b3381a4e2"
		"11c324f074654c38823a7b76f830ad00"
		"fa1fbae42b1285c0352f227524bc9ab1"
		"6254288dd6863dccd5b9f54a1ad0541b");
}
