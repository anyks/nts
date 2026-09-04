/**
 * @file: hkdf.cpp
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
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/hkdf.hpp>

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
 * @brief Метод заполнения области байтами подряд
 *
 * @param from первый байт
 * @param to   байт за последним
 *
 * @return     заполненная область
 *
 */
static std::vector <uint8_t> range(const int from, const int to) {
	// Заполняемая область
	std::vector <uint8_t> result;
	/**
	 * Выполняем перебор байтов
	 */
	for(int i = from; i < to; i++)
		// Добавляем очередной байт
		result.push_back(static_cast <uint8_t> (i));
	// Выводим область
	return result;
}

/**
 * Проверка первого случая приложения A RFC 5869
 */
TEST(HkdfTest, First){
	// Исходный материал: 22 байта 0x0b
	const std::vector <uint8_t> material(22, 0x0B);
	// Соль
	const std::vector <uint8_t> salt = range(0x00, 0x0D);
	// Привязка
	const std::vector <uint8_t> info = range(0xF0, 0xFA);
	// Псевдослучайный ключ
	uint8_t key[32];
	// Проверяем извлечение ключа
	ASSERT_TRUE(digest::extract(digest::hash_t::SHA256, view_t(salt.data(), salt.size()), view_t(material.data(), material.size()), key, sizeof(key)));
	// Проверяем псевдослучайный ключ
	ASSERT_EQ(text(key, sizeof(key)), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
	// Выведенный материал
	uint8_t output[42];
	// Проверяем развёртывание ключа
	ASSERT_TRUE(digest::expand(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(info.data(), info.size()), output, sizeof(output)));
	// Проверяем выведенный материал
	ASSERT_EQ(text(output, sizeof(output)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
	// Проверяем вывод за один вызов
	ASSERT_TRUE(digest::hkdf(digest::hash_t::SHA256, view_t(salt.data(), salt.size()), view_t(material.data(), material.size()), view_t(info.data(), info.size()), output, sizeof(output)));
	// Проверяем выведенный материал
	ASSERT_EQ(text(output, sizeof(output)), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

/**
 * Проверка второго случая RFC 5869: длинные вход, соль и привязка, 82 байта материала
 */
TEST(HkdfTest, Second){
	// Исходный материал: байты от 0x00 до 0x4f
	const std::vector <uint8_t> material = range(0x00, 0x50);
	// Соль: байты от 0x60 до 0xaf
	const std::vector <uint8_t> salt = range(0x60, 0xB0);
	// Привязка: байты от 0xb0 до 0xff - длиннее блока, чем и ценна
	const std::vector <uint8_t> info = range(0xB0, 0x100);
	// Выведенный материал
	uint8_t output[82];
	// Проверяем вывод за один вызов
	ASSERT_TRUE(digest::hkdf(digest::hash_t::SHA256, view_t(salt.data(), salt.size()), view_t(material.data(), material.size()), view_t(info.data(), info.size()), output, sizeof(output)));
	// Проверяем выведенный материал
	ASSERT_EQ(text(output, sizeof(output)), "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
}

/**
 * Проверка третьего случая RFC 5869: пустые соль и привязка
 */
TEST(HkdfTest, Third){
	// Исходный материал: 22 байта 0x0b
	const std::vector <uint8_t> material(22, 0x0B);
	// Выведенный материал
	uint8_t output[42];
	// Проверяем вывод с пустыми солью и привязкой
	ASSERT_TRUE(digest::hkdf(digest::hash_t::SHA256, view_t(), view_t(material.data(), material.size()), view_t(), output, sizeof(output)));
	// Проверяем выведенный материал
	ASSERT_EQ(text(output, sizeof(output)), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

/**
 * Проверка четвёртого случая RFC 5869: SHA-1
 */
TEST(HkdfTest, Fourth){
	// Исходный материал: 11 байтов 0x0b
	const std::vector <uint8_t> material(11, 0x0B);
	// Соль
	const std::vector <uint8_t> salt = range(0x00, 0x0D);
	// Привязка
	const std::vector <uint8_t> info = range(0xF0, 0xFA);
	// Выведенный материал
	uint8_t output[42];
	// Проверяем вывод на SHA-1
	ASSERT_TRUE(digest::hkdf(digest::hash_t::SHA1, view_t(salt.data(), salt.size()), view_t(material.data(), material.size()), view_t(info.data(), info.size()), output, sizeof(output)));
	// Проверяем выведенный материал
	ASSERT_EQ(text(output, sizeof(output)), "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896");
}

/**
 * Проверка отказов договора
 */
TEST(HkdfTest, Refusals){
	// Исходный материал
	const std::vector <uint8_t> material(22, 0x0B);
	// Псевдослучайный ключ
	uint8_t key[32];
	// Выведенный материал
	uint8_t output[64];
	// Проверяем отказ извлечения неустановленным алгоритмом
	ASSERT_FALSE(digest::extract(digest::hash_t::NONE, view_t(), view_t(material.data(), material.size()), key, sizeof(key)));
	// Проверяем отказ извлечения в место короче хеша
	ASSERT_FALSE(digest::extract(digest::hash_t::SHA256, view_t(), view_t(material.data(), material.size()), key, 31));
	// Проверяем извлечение ключа
	ASSERT_TRUE(digest::extract(digest::hash_t::SHA256, view_t(), view_t(material.data(), material.size()), key, sizeof(key)));
	// Проверяем отказ развёртывания ключа короче хеша
	ASSERT_FALSE(digest::expand(digest::hash_t::SHA256, view_t(key, 31), view_t(), output, sizeof(output)));
	// Проверяем отказ развёртывания в нулевую длину
	ASSERT_FALSE(digest::expand(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(), output, 0));
	// Проверяем отказ развёртывания в пустое место
	ASSERT_FALSE(digest::expand(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(), nullptr, 16));
	// Проверяем отказ развёртывания в длину свыше 255 хешей
	ASSERT_FALSE(digest::expand(digest::hash_t::MD5, view_t(key, 16), view_t(), output, (255 * 16) + 1));
	// Проверяем развёртывание в длину короче хеша
	ASSERT_TRUE(digest::expand(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(), output, 5));
}

/**
 * Проверка развёртывания с меткой по приложению A.1 RFC 9001: начальные секреты QUIC v1
 */
TEST(HkdfTest, Label){
	// Соль начальных секретов QUIC v1
	const std::vector <uint8_t> salt = {0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB, 0x7F, 0x0A};
	// Опознаватель связи назначения
	const std::vector <uint8_t> connection = {0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08};
	// Начальный секрет
	uint8_t initial[32];
	// Проверяем извлечение начального секрета
	ASSERT_TRUE(digest::extract(digest::hash_t::SHA256, view_t(salt.data(), salt.size()), view_t(connection.data(), connection.size()), initial, sizeof(initial)));
	// Начальный секрет клиента
	uint8_t client[32];
	// Проверяем развёртывание секрета клиента с меткой «client in»
	ASSERT_TRUE(digest::label(digest::hash_t::SHA256, view_t(initial, sizeof(initial)), view_t(reinterpret_cast <const uint8_t *> ("client in"), 9), view_t(), client, sizeof(client)));
	// Проверяем секрет клиента
	ASSERT_EQ(text(client, sizeof(client)), "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
	// Ключ, вектор и защита заголовка клиента
	uint8_t key[16], iv[12], hp[16];
	// Проверяем развёртывание ключа
	ASSERT_TRUE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(reinterpret_cast <const uint8_t *> ("quic key"), 8), view_t(), key, sizeof(key)));
	// Проверяем ключ клиента
	ASSERT_EQ(text(key, sizeof(key)), "1f369613dd76d5467730efcbe3b1a22d");
	// Проверяем развёртывание вектора
	ASSERT_TRUE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(reinterpret_cast <const uint8_t *> ("quic iv"), 7), view_t(), iv, sizeof(iv)));
	// Проверяем вектор клиента
	ASSERT_EQ(text(iv, sizeof(iv)), "fa044b2f42a3fd3b46fb255c");
	// Проверяем развёртывание защиты заголовка
	ASSERT_TRUE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(reinterpret_cast <const uint8_t *> ("quic hp"), 7), view_t(), hp, sizeof(hp)));
	// Проверяем защиту заголовка клиента
	ASSERT_EQ(text(hp, sizeof(hp)), "9f50449e04a0e810283a1e9933adedd2");
	// Проверяем отказ пустой метки
	ASSERT_FALSE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(), view_t(), key, sizeof(key)));
	// Метка длиннее дозволенного
	const std::vector <uint8_t> lengthy(250, 'x');
	// Проверяем отказ метки в 250 байтов
	ASSERT_FALSE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(lengthy.data(), lengthy.size()), view_t(), key, sizeof(key)));
	// Метка в 249 байтов и привязка в 255: наибольшая запись HkdfLabel
	const std::vector <uint8_t> widest(255, 'y');
	// Проверяем развёртывание с наибольшей записью
	ASSERT_TRUE(digest::label(digest::hash_t::SHA256, view_t(client, sizeof(client)), view_t(lengthy.data(), 249), view_t(widest.data(), widest.size()), key, sizeof(key)));
}
