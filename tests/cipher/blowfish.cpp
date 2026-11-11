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
#include <cipher/mode.hpp>
#include <cipher/mgm.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Функция разбора шестнадцатеричной строки в байты
 *
 * @param text разбираемая строка
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
 * @brief Функция чтения слова из байтов от старшего к младшему
 *
 * @param data читаемые байты
 * @return     прочитанное слово
 *
 */
static uint32_t fetch(const uint8_t * data) noexcept {
	// Выводим прочитанное слово
	return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) | (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
}
/**
 * @brief Функция записи слова в байты от старшего к младшему
 *
 * @param value записываемое слово
 * @param data  место записи
 *
 */
static void store(const uint32_t value, uint8_t * data) noexcept {
	// Записываем старший байт слова
	data[0] = static_cast <uint8_t> (value >> 24);
	// Записываем второй байт слова
	data[1] = static_cast <uint8_t> (value >> 16);
	// Записываем третий байт слова
	data[2] = static_cast <uint8_t> (value >> 8);
	// Записываем младший байт слова
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

/**
 * Проверка расшифрования блока и обращения к шифру через описатель режимов работы
 *
 * @note Сеть Фейстеля обращается переменой порядка подмешиваемых элементов P-array,
 *       оттого расшифрование ведётся теми же раундами, что и зашифрование, но
 *       элементы накладываются от последнего к первому
 *
 */
TEST(BlowfishTest, Block) {
	// Ключ контрольного примера Шнайера
	const std::vector <uint8_t> key = bytes("0123456789ABCDEFF0E1D2C3B4A59687");
	// Контекст шифра
	cipher::blowfish_t context;
	// Выполняем инициализацию контекста константами числа π
	cipher::init(&context);
	// Выполняем расширение ключа без соли
	cipher::expand0(&context, key.data(), key.size());
	// Описатель базового алгоритма блочного шифрования
	const cipher::block_t block(context);
	// Проверяем размер блока описателя
	EXPECT_EQ(block.size, cipher::BLOWFISH_BLOCK);
	// Проверяем заполненность обращения к зашифрованию блока
	EXPECT_NE(block.encrypt, nullptr);
	// Проверяем заполненность обращения к расшифрованию блока
	EXPECT_NE(block.decrypt, nullptr);
	// Открытый текст контрольного примера Шнайера
	const std::vector <uint8_t> plain = bytes("FEDCBA9876543210");
	// Место шифртекста и место расшифрованного блока
	uint8_t sealed[8], back[8];
	// Выполняем зашифрование блока через описатель
	ASSERT_TRUE(block.encrypt(block.cipher, plain.data(), sealed));
	// Сверяем шифртекст с контрольным примером Шнайера
	EXPECT_EQ(std::vector <uint8_t> (sealed, sealed + sizeof(sealed)), bytes("d0042196b11308ea"));
	// Выполняем расшифрование блока через описатель
	ASSERT_TRUE(block.decrypt(block.cipher, sealed, back));
	// Сверяем расшифрованный блок с исходным
	EXPECT_EQ(::memcmp(back, plain.data(), sizeof(back)), 0);
	/**
	 * Расшифрование нескольких блоков обязано обращаться к их зашифрованию: обе
	 * функции ведут один и тот же массив слов на месте
	 */
	// Массив слов из четырёх блоков и его нетронутая копия
	uint32_t direct[8], sample[8];
	/**
	 * Выполняем заполнение обеих копий массива слов
	 */
	for(size_t i = 0; i < 8; i++){
		// Записываем очередное слово массива
		direct[i] = static_cast <uint32_t> ((i * 2654435761u) + 1);
		// Записываем очередное слово нетронутой копии
		sample[i] = direct[i];
	}
	// Выполняем зашифрование четырёх блоков
	cipher::encrypt(&context, direct, 4);
	// Проверяем, что зашифрованные блоки разошлись с исходными
	EXPECT_NE(::memcmp(direct, sample, sizeof(direct)), 0);
	// Выполняем расшифрование четырёх зашифрованных блоков
	cipher::decrypt(&context, direct, 4);
	// Сверяем расшифрованные блоки с исходными
	EXPECT_EQ(::memcmp(direct, sample, sizeof(direct)), 0);
	// Начальное заполнение счётчика режимов работы
	uint8_t iv[cipher::BLOWFISH_BLOCK];
	// Выполняем заполнение начального значения счётчика
	::memset(iv, 0x5A, sizeof(iv));
	// Сообщение, шифртекст и расшифрованный текст
	uint8_t source[37], gamma[37], opened[37];
	/**
	 * Выполняем заполнение сообщения
	 */
	for(size_t i = 0; i < sizeof(source); i++)
		// Записываем очередной байт сообщения
		source[i] = static_cast <uint8_t> ((i * 29) + 3);
	/**
	 * Синхропосылка режима счётчика занимает половину блока шифра: такова процедура
	 * инициализации In раздела 5.2 ГОСТ Р 34.13-2015
	 */
	const view_t sync(iv, cipher::BLOWFISH_BLOCK / 2);
	// Объект режима счётчика
	cipher::counter_t counter;
	// Выполняем запуск режима счётчика на описателе Blowfish
	ASSERT_TRUE(counter.start(block, sync));
	// Выполняем зашифрование сообщения режимом счётчика
	ASSERT_TRUE(counter.encrypt(view_t(source, sizeof(source)), gamma));
	// Проверяем, что шифртекст разошёлся с открытым текстом
	EXPECT_NE(::memcmp(gamma, source, sizeof(source)), 0);
	// Выполняем повторный запуск режима счётчика на той же синхропосылке
	ASSERT_TRUE(counter.start(block, sync));
	// Выполняем расшифрование сообщения режимом счётчика
	ASSERT_TRUE(counter.decrypt(view_t(gamma, sizeof(gamma)), opened));
	// Сверяем расшифрованное сообщение с исходным
	EXPECT_EQ(::memcmp(opened, source, sizeof(source)), 0);
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Метка целостности длиной в блок шифра
	uint8_t tag[cipher::BLOWFISH_BLOCK];
	// Выполняем запуск режима MGM на описателе Blowfish
	ASSERT_TRUE(galois.start(block, view_t(iv, sizeof(iv))));
	// Выполняем зашифрование сообщения режимом MGM с выработкой метки целостности
	ASSERT_TRUE(galois.encrypt(view_t(source, 16), view_t(source + 16, sizeof(source) - 16), gamma, tag));
	// Выполняем запуск режима MGM на стороне расшифрования
	ASSERT_TRUE(galois.start(block, view_t(iv, sizeof(iv))));
	// Выполняем расшифрование сообщения режимом MGM с проверкой метки целостности
	ASSERT_TRUE(galois.decrypt(view_t(source, 16), view_t(gamma, sizeof(source) - 16), opened, view_t(tag, sizeof(tag))));
	// Сверяем расшифрованное сообщение с исходным
	EXPECT_EQ(::memcmp(opened, source + 16, sizeof(source) - 16), 0);
	// Выполняем порчу младшего байта метки целостности
	tag[sizeof(tag) - 1] = static_cast <uint8_t> (tag[sizeof(tag) - 1] ^ 0x01);
	// Выполняем запуск режима MGM на стороне проверки порченой метки
	ASSERT_TRUE(galois.start(block, view_t(iv, sizeof(iv))));
	// Проверяем отказ расшифрования при порченой метке целостности
	EXPECT_FALSE(galois.decrypt(view_t(source, 16), view_t(gamma, sizeof(source) - 16), opened, view_t(tag, sizeof(tag))));
}
