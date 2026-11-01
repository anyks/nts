/**
 * @file ccm.cpp
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
 * @brief Исходный файл проверок модуля режима CCM
 *
 * @note Контрольные примеры взяты из раздела 8 RFC 3610 (AES-CCM) целиком, а
 *       пример SM4-CCM выработан эталонной реализацией и сверен с OpenSSL 3.6
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
#include <cipher/ccm.hpp>
#include <cipher/aes.hpp>
#include <cipher/sm4.hpp>

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
	// Выводим запись
	return result;
}

/**
 * @brief Функция проверки одного примера RFC 3610
 *
 * @param key        ключ шифрования
 * @param nonce      одноразовое значение
 * @param associated связанные данные
 * @param plain      открытый текст
 * @param size       длина метки целостности
 * @param expected   ожидаемый шифртекст с меткой подряд
 *
 */
static void sample(const std::string & key, const std::string & nonce, const std::string & associated, const std::string & plain, const size_t size, const std::string & expected) {
	// Разобранные доводы примера
	const std::vector <uint8_t> secret = bytes(key), once = bytes(nonce), data = bytes(associated), message = bytes(plain);
	// Объект шифра AES
	cipher::aes_t aes;
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(secret.data(), secret.size())));
	// Объект режима CCM
	cipher::ccm_t ccm;
	// Проверяем запуск режима
	ASSERT_TRUE(ccm.start(cipher::block_t(aes), view_t(once.data(), once.size()), size));
	// Проверяем готовность режима
	ASSERT_TRUE(ccm.ready());
	// Зашифрованное сообщение
	std::vector <uint8_t> sealed(message.size());
	// Выработанная метка целостности
	std::vector <uint8_t> tag(size);
	// Проверяем зашифрование
	ASSERT_TRUE(ccm.encrypt(view_t(data.data(), data.size()), view_t(message.data(), message.size()), sealed.data(), tag.data()));
	// Собранный шифртекст с меткой подряд
	std::string gathered = (text(sealed.data(), sealed.size()) + text(tag.data(), tag.size()));
	// Проверяем шифртекст с меткой примера
	ASSERT_EQ(gathered, expected) << "пример " << expected;
	// Расшифрованное сообщение
	std::vector <uint8_t> opened(message.size());
	// Проверяем расшифрование со сходящейся меткой
	ASSERT_TRUE(ccm.decrypt(view_t(data.data(), data.size()), view_t(sealed.data(), sealed.size()), view_t(tag.data(), tag.size()), opened.data()));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened.data(), message.data(), message.size()), 0) << "пример " << expected;
	// Портим метку целостности
	tag[0] = static_cast <uint8_t> (tag[0] ^ 0x01);
	// Проверяем отказ расшифрования с порченой меткой
	ASSERT_FALSE(ccm.decrypt(view_t(data.data(), data.size()), view_t(sealed.data(), sealed.size()), view_t(tag.data(), tag.size()), opened.data()));
}

/**
 * Проверка примеров раздела 8 RFC 3610
 */
TEST(CcmTest, Vectors){
	// Пример 1: метка в 8 байтов, связанные данные в 8 байтов, сообщение в 23 байта
	sample("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000003020100a0a1a2a3a4a5", "0001020304050607", "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", 8, "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
	// Пример 2: метка в 8 байтов, связанные данные в 8 байтов, сообщение в 24 байта
	sample("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000004030201a0a1a2a3a4a5", "0001020304050607", "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8, "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916");
	// Пример 3: метка в 8 байтов, связанные данные в 8 байтов, сообщение в 25 байтов
	sample("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", "00000005040302a0a1a2a3a4a5", "0001020304050607", "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 8, "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5");
}

/**
 * Проверка примера SM4-CCM, сверенного с OpenSSL 3.6
 */
TEST(CcmTest, Sm4){
	// Ключ примера
	const std::vector <uint8_t> secret = bytes("0123456789abcdeffedcba9876543210");
	// Одноразовое значение примера: двенадцать байтов, как у защиты записей TLS
	const std::vector <uint8_t> once = bytes("000102030405060708090a0b");
	// Связанные данные примера: заголовок записи TLS
	const std::vector <uint8_t> data = bytes("17030300100000000000000000");
	// Открытый текст примера
	const std::vector <uint8_t> message = bytes("48656c6c6f2c20534d342d43434d21");
	// Объект шифра SM4
	cipher::sm4_t sm4;
	// Проверяем установку ключа
	ASSERT_TRUE(sm4.key(view_t(secret.data(), secret.size())));
	// Объект режима CCM
	cipher::ccm_t ccm;
	// Проверяем запуск режима с меткой в 16 байтов
	ASSERT_TRUE(ccm.start(cipher::block_t(sm4), view_t(once.data(), once.size()), 16));
	// Зашифрованное сообщение
	std::vector <uint8_t> sealed(message.size());
	// Выработанная метка целостности
	uint8_t tag[16];
	// Проверяем зашифрование
	ASSERT_TRUE(ccm.encrypt(view_t(data.data(), data.size()), view_t(message.data(), message.size()), sealed.data(), tag));
	// Проверяем шифртекст примера OpenSSL
	ASSERT_EQ(text(sealed.data(), sealed.size()), "5f0fb4a60eba8a34e7cb2d632c64af");
	// Проверяем метку целостности примера OpenSSL
	ASSERT_EQ(text(tag, sizeof(tag)), "a9ad04053f4c34f1aa780269660a2896");
	// Расшифрованное сообщение
	std::vector <uint8_t> opened(message.size());
	// Проверяем расшифрование со сходящейся меткой
	ASSERT_TRUE(ccm.decrypt(view_t(data.data(), data.size()), view_t(sealed.data(), sealed.size()), view_t(tag, sizeof(tag)), opened.data()));
	// Проверяем схождение с открытым текстом
	ASSERT_EQ(::memcmp(opened.data(), message.data(), message.size()), 0);
	// Проверяем зашифрование на своём месте
	std::vector <uint8_t> inplace(message);
	// Проверяем зашифрование на своём месте
	ASSERT_TRUE(ccm.encrypt(view_t(data.data(), data.size()), view_t(inplace.data(), inplace.size()), inplace.data(), tag));
	// Проверяем схождение с зашифрованным врозь
	ASSERT_EQ(::memcmp(inplace.data(), sealed.data(), sealed.size()), 0);
}

/**
 * Проверка отказов договора
 */
TEST(CcmTest, Refusals){
	// Ключ примера
	const std::vector <uint8_t> secret = bytes("404142434445464748494a4b4c4d4e4f");
	// Одноразовое значение примера
	const std::vector <uint8_t> once = bytes("10111213141516");
	// Открытый текст примера
	const std::vector <uint8_t> message = bytes("20212223");
	// Объект шифра AES
	cipher::aes_t aes;
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(secret.data(), secret.size())));
	// Объект режима CCM
	cipher::ccm_t ccm;
	// Проверяем неготовность режима без запуска
	ASSERT_FALSE(ccm.ready());
	// Проверяем отказ запуска с пустым одноразовым значением
	ASSERT_FALSE(ccm.start(cipher::block_t(aes), view_t(), 8));
	// Проверяем отказ запуска с одноразовым значением короче семи байтов
	ASSERT_FALSE(ccm.start(cipher::block_t(aes), view_t(once.data(), 6), 8));
	// Проверяем отказ запуска с нечётной длиной метки
	ASSERT_FALSE(ccm.start(cipher::block_t(aes), view_t(once.data(), once.size()), 7));
	// Проверяем отказ запуска с меткой короче четырёх байтов
	ASSERT_FALSE(ccm.start(cipher::block_t(aes), view_t(once.data(), once.size()), 2));
	// Проверяем запуск режима
	ASSERT_TRUE(ccm.start(cipher::block_t(aes), view_t(once.data(), once.size()), 8));
	// Зашифрованное сообщение
	std::vector <uint8_t> sealed(message.size());
	// Выработанная метка целостности
	uint8_t tag[8];
	// Проверяем отказ зашифрования в пустое место
	ASSERT_FALSE(ccm.encrypt(view_t(), view_t(message.data(), message.size()), nullptr, tag));
	// Проверяем отказ зашифрования с пустым местом метки
	ASSERT_FALSE(ccm.encrypt(view_t(), view_t(message.data(), message.size()), sealed.data(), nullptr));
	// Проверяем зашифрование пустого сообщения
	ASSERT_TRUE(ccm.encrypt(view_t(), view_t(), sealed.data(), tag));
	// Проверяем отказ расшифрования с меткой неверной длины
	ASSERT_FALSE(ccm.decrypt(view_t(), view_t(sealed.data(), 0), view_t(tag, 7), sealed.data()));
	// Выполняем сброс состояния режима
	ccm.clear();
	// Проверяем неготовность режима после сброса
	ASSERT_FALSE(ccm.ready());
}
