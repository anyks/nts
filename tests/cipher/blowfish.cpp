/**
 * @file blowfish.cpp
 * @date 2026-10-11
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
 * @brief Проверки модуля блочного шифра Blowfish (Шнайер)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <cipher/blowfish.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод разбора шестнадцатеричной строки в байты
 *
 * @param text разбираемая строка
 *
 * @return     разобранные байты
 *
 */
static std::vector <uint8_t> bytes(const std::string & text) {
	// Разобранные байты
	std::vector <uint8_t> result;
	/**
	 * Выполняем перебор пар знаков
	 */
	for(size_t i = 0; (i + 1) < text.size(); i += 2)
		// Добавляем очередной байт
		result.push_back(static_cast <uint8_t> (std::stoul(text.substr(i, 2), nullptr, 16)));
	// Выводим разобранные байты
	return result;
}
/**
 * @brief Метод чтения слова из байтов от старшего к младшему
 *
 * @param data читаемые байты
 *
 * @return     прочитанное слово
 *
 */
static uint32_t fetch(const uint8_t * data) noexcept {
	// Выводим прочитанное слово
	return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) | (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
}
/**
 * @brief Метод записи слова в байты от старшего к младшему
 *
 * @param value записываемое слово
 * @param data  место записи
 *
 */
static void store(const uint32_t value, uint8_t * data) noexcept {
	// Записываем очередной байт слова
	data[0] = static_cast <uint8_t> (value >> 24);
	data[1] = static_cast <uint8_t> (value >> 16);
	data[2] = static_cast <uint8_t> (value >> 8);
	data[3] = static_cast <uint8_t> (value);
}

/**
 * Проверка шифрования блока по контрольным примерам Шнайера
 */
TEST(BlowfishTest, Vectors) {
	// Контрольные примеры Шнайера: ключ, открытый текст, шифртекст
	static const struct {
		// Ключ, открытый текст и шифртекст шестнадцатеричной записью
		const char * key, * plain, * cipher;
	} VECTORS[] = {
		{"0000000000000000", "0000000000000000", "4ef997456198dd78"},
		{"FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866fd5b85ecb8a"},
		{"3000000000000000", "1000000000000001", "7d856f9a613063f2"},
		{"0123456789ABCDEFF0E1D2C3B4A59687", "FEDCBA9876543210", "d0042196b11308ea"}
	};
	/**
	 * Выполняем перебор контрольных примеров
	 */
	for(const auto & item : VECTORS){
		// Контекст шифра
		cipher::blowfish_t context;
		// Выполняем инициализацию контекста константами числа π
		cipher::init(&context);
		// Разбираем ключ контрольного примера
		const std::vector <uint8_t> key = bytes(item.key);
		// Выполняем расширение ключа без соли
		cipher::expand0(&context, key.data(), key.size());
		// Разбираем открытый текст контрольного примера
		const std::vector <uint8_t> plain = bytes(item.plain);
		// Преобразуемый блок: две половины словами от старшего байта
		uint32_t block[2] = {::fetch(plain.data()), ::fetch(plain.data() + 4)};
		// Выполняем зашифрование блока
		cipher::encrypt(&context, block, 1);
		// Место шифртекста байтами
		uint8_t result[8];
		// Записываем половины шифртекста от старшего байта
		::store(block[0], result);
		::store(block[1], result + 4);
		// Сверяем шифртекст с контрольным примером
		EXPECT_EQ(std::vector <uint8_t> (result, result + sizeof(result)), bytes(item.cipher)) << "ключ " << item.key;
	}
}

/**
 * Проверка извлечения слова из потока байтов с зацикливанием
 */
TEST(BlowfishTest, Stream2word) {
	// Поток из трёх байтов
	const uint8_t data[3] = {0x01, 0x02, 0x03};
	// Текущая позиция в потоке
	size_t current = 0;
	// Первое слово: четыре байта с зацикливанием 01 02 03 01
	EXPECT_EQ(cipher::stream2word(data, sizeof(data), &current), 0x01020301u);
	EXPECT_EQ(current, 1u);
	// Второе слово: четыре байта с зацикливанием 02 03 01 02
	EXPECT_EQ(cipher::stream2word(data, sizeof(data), &current), 0x02030102u);
	EXPECT_EQ(current, 2u);
	// Третье слово: четыре байта с зацикливанием 03 01 02 03
	EXPECT_EQ(cipher::stream2word(data, sizeof(data), &current), 0x03010203u);
	EXPECT_EQ(current, 3u);
}
