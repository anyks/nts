/**
 * @file hash.cpp
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
 * @brief Исходный файл проверок модуля дайджестов: размеры, диспетчеризация,
 *        имитовставка HMAC и чужие хеши
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>

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
	// Выводим запись
	return result;
}

/**
 * @brief Функция выработки имитовставки строкой
 *
 * @param algorithm алгоритм хеширования
 * @param key       ключ имитовставки
 * @param message   сообщение
 * @return          запись имитовставки шестнадцатеричной строкой
 *
 */
static std::string mac(const digest::hash_t algorithm, const std::string & key, const std::string & message) {
	// Место, в которое записывается имитовставка
	uint8_t result[64];
	// Длина имитовставки
	const size_t size = digest::length(algorithm);
	// Если имитовставку выработать не удалось
	if(!digest::hmac(algorithm, view_t(reinterpret_cast <const uint8_t *> (key.data()), key.size()), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, size))
		// Выводим пустую запись
		return "";
	// Выводим запись имитовставки
	return text(result, size);
}

/**
 * Проверка длин хешей и блоков сжатия по алгоритмам
 */
TEST(HashTest, Sizes){
	// Алгоритмы хеширования по порядку перечисления
	const digest::hash_t algorithms[] = {digest::hash_t::MD5, digest::hash_t::SHA1, digest::hash_t::SHA224, digest::hash_t::SHA256, digest::hash_t::SHA384, digest::hash_t::SHA512, digest::hash_t::STREEBOG256, digest::hash_t::STREEBOG512};
	// Длины хешей по алгоритмам
	const size_t lengths[] = {16, 20, 28, 32, 48, 64, 32, 64};
	// Размеры блоков по алгоритмам
	const size_t blocks[] = {64, 64, 64, 64, 128, 128, 64, 64};
	/**
	 * Выполняем перебор алгоритмов
	 */
	for(size_t i = 0; i < 8; i++){
		// Проверяем длину хеша алгоритма
		ASSERT_EQ(digest::length(algorithms[i]), lengths[i]) << "алгоритм " << i;
		// Проверяем размер блока алгоритма
		ASSERT_EQ(digest::block(algorithms[i]), blocks[i]) << "алгоритм " << i;
	}
	// Проверяем длину хеша неустановленного алгоритма
	ASSERT_EQ(digest::length(digest::hash_t::NONE), 0u);
	// Проверяем размер блока неустановленного алгоритма
	ASSERT_EQ(digest::block(digest::hash_t::NONE), 0u);
}

/**
 * Проверка схождения общего хеширования с хешами модулей
 */
TEST(HashTest, Dispatch){
	// Хешируемое сообщение
	const std::string message = "abc";
	// Место, в которое записывается хеш
	uint8_t result[64];
	// Хеш MD5 сообщения «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::MD5, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Проверяем хеш MD5
	ASSERT_EQ(text(result, 16), "900150983cd24fb0d6963f7d28e17f72");
	// Хеш SHA-1 сообщения «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::SHA1, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Проверяем хеш SHA-1
	ASSERT_EQ(text(result, 20), "a9993e364706816aba3e25717850c26c9cd0d89d");
	// Хеш SHA-256 сообщения «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Проверяем хеш SHA-256
	ASSERT_EQ(text(result, 32), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	// Хеш SHA-512 сообщения «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::SHA512, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Проверяем хеш SHA-512
	ASSERT_EQ(text(result, 64), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
	// Хеш «Стрибог» длиной 256 разрядов сообщения «abc» в место шире хеша
	ASSERT_TRUE(digest::hash(digest::hash_t::STREEBOG256, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Хеш «Стрибог» того же сообщения самим модулем
	uint8_t direct[32];
	// Выполняем выработку хеша модулем
	ASSERT_TRUE(digest::streebog(digest::type_t::SHORT, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), direct, sizeof(direct)));
	// Проверяем схождение общего хеширования с модулем
	ASSERT_EQ(::memcmp(result, direct, sizeof(direct)), 0);
	// Проверяем отказ хеширования неустановленным алгоритмом
	ASSERT_FALSE(digest::hash(digest::hash_t::NONE, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)));
	// Проверяем отказ хеширования в место короче хеша
	ASSERT_FALSE(digest::hash(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, 31));
	// Объект общего хеширования
	digest::hasher_t hasher(digest::hash_t::SHA224);
	// Проверяем выбранный алгоритм
	ASSERT_EQ(hasher.type(), digest::hash_t::SHA224);
	// Выполняем подачу сообщения по одному знаку
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("a"), 1));
	// Выполняем подачу сообщения по одному знаку
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("b"), 1));
	// Выполняем подачу сообщения по одному знаку
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("c"), 1));
	// Проверяем снятие хеша
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш SHA-224
	ASSERT_EQ(text(result, 28), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
	// Проверяем отказ повторного снятия
	ASSERT_FALSE(hasher.finish(result, sizeof(result)));
}

/**
 * Проверка имитовставок по RFC 2202 и RFC 4231
 */
TEST(HashTest, Hmac){
	// Ключ первого случая: двадцать байтов 0x0b
	const std::string key20(20, static_cast <char> (0x0B));
	// Ключ первого случая MD5: шестнадцать байтов 0x0b
	const std::string key16(16, static_cast <char> (0x0B));
	// Ключ шестого случая: сто тридцать один байт 0xaa - длиннее любого блока
	const std::string key131(131, static_cast <char> (0xAA));
	// Первый случай: имитовставка MD5
	ASSERT_EQ(mac(digest::hash_t::MD5, key16, "Hi There"), "9294727a3638bb1c13f48ef8158bfc9d");
	// Первый случай: имитовставка SHA-1
	ASSERT_EQ(mac(digest::hash_t::SHA1, key20, "Hi There"), "b617318655057264e28bc0b6fb378c8ef146be00");
	// Первый случай: имитовставка SHA-224
	ASSERT_EQ(mac(digest::hash_t::SHA224, key20, "Hi There"), "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
	// Первый случай: имитовставка SHA-256
	ASSERT_EQ(mac(digest::hash_t::SHA256, key20, "Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	// Первый случай: имитовставка SHA-384
	ASSERT_EQ(mac(digest::hash_t::SHA384, key20, "Hi There"), "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
	// Первый случай: имитовставка SHA-512
	ASSERT_EQ(mac(digest::hash_t::SHA512, key20, "Hi There"), "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
	// Второй случай: ключ «Jefe», имитовставка MD5
	ASSERT_EQ(mac(digest::hash_t::MD5, "Jefe", "what do ya want for nothing?"), "750c783e6ab0b503eaa86e310a5db738");
	// Второй случай: имитовставка SHA-1
	ASSERT_EQ(mac(digest::hash_t::SHA1, "Jefe", "what do ya want for nothing?"), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
	// Второй случай: имитовставка SHA-256
	ASSERT_EQ(mac(digest::hash_t::SHA256, "Jefe", "what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	// Второй случай: имитовставка SHA-512
	ASSERT_EQ(mac(digest::hash_t::SHA512, "Jefe", "what do ya want for nothing?"), "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
	// Шестой случай: ключ длиннее блока хешируется, SHA-256
	ASSERT_EQ(mac(digest::hash_t::SHA256, key131, "Test Using Larger Than Block-Size Key - Hash Key First"), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
	// Шестой случай: ключ длиннее блока в 128 байтов хешируется, SHA-512
	ASSERT_EQ(mac(digest::hash_t::SHA512, key131, "Test Using Larger Than Block-Size Key - Hash Key First"), "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
	// Шестой случай: SHA-1
	ASSERT_EQ(mac(digest::hash_t::SHA1, key131, "Test Using Larger Than Block-Size Key - Hash Key First"), "90d0dace1c1bdc957339307803160335bde6df2b");
	// Шестой случай: MD5
	ASSERT_EQ(mac(digest::hash_t::MD5, key131, "Test Using Larger Than Block-Size Key - Hash Key First"), "bfecaf4efff90a3a668f3922fec3762d");
}

/**
 * Проверка имитовставок AWH, закреплённых по BoringSSL: ключом идёт запись хеша строкой
 */
TEST(HashTest, Foreign){
	// Вход векторов AWH
	const std::string message = "Hello World, Hello World, Hello World, Hello World, Hello World, Hello World!!!!!!!!!!!!!!!!?";
	// Имитовставка MD5 с ключом-записью хеша MD5
	ASSERT_EQ(mac(digest::hash_t::MD5, "7039bdd0df3e5cec78934c32ab931c91", message), "9f10e6df14d6e2c3776a03b465663a0c");
	// Имитовставка SHA-1 с ключом-записью хеша SHA-1
	ASSERT_EQ(mac(digest::hash_t::SHA1, "adaccf563788bc09516f3b13c5fb969dee97ed41", message), "d5db41118255ea7a4db2b941b321d75bf3acbd88");
	// Имитовставка SHA-224 с ключом-записью хеша SHA-224
	ASSERT_EQ(mac(digest::hash_t::SHA224, "e919819b0c7386e38e040c7bbd876bcbe35de8c4364179b28f4ebb95", message), "c6cfa6a7ca15f589fcae4a213a8998b581fe3a2759cfa51cf36ba102");
	// Имитовставка SHA-256 с ключом-записью хеша SHA-256
	ASSERT_EQ(mac(digest::hash_t::SHA256, "3a4f9cfad7df5274dc724737d9176cc57787aaa930e0b4e7d82398fd4a82facf", message), "17d253ace96030f0f6d7325cc69a80a0cbf47a6a6421c69f1f78d1c5dc5cbff5");
	// Имитовставка SHA-384 с ключом-записью хеша SHA-384: ключ в 96 знаков короче блока в 128
	ASSERT_EQ(mac(digest::hash_t::SHA384, "b996ff91f7ef04fe8ea7ee01dd1015d31882daee84054a54ad1e517175ff0c9adab2ce958deac16828268b2f599a96c0", message), "a9700ad0692bca6760d206a1ef8c5c6be6626de37817655b22e02893587ba367558c8d8a69ea20926ac31facbb9a4c72");
	// Имитовставка SHA-512 с ключом-записью хеша SHA-512: ключ в 128 знаков ровно в блок
	ASSERT_EQ(mac(digest::hash_t::SHA512, "4eb68fe9cda573be3ef1183b34a776fbc62bbb6e0571632afbbcb292e95e655160d984ded4b8fe9b1a221d9d5250c5c6587fc18556194b95c7159ba8e19c1779", message), "a4eaf14ba267f1af48e3ceda03b9ae2addfcd8fd57b1ed35dd0bca4ecb15836d4beab59902fefc56f5c2054529196fe2e287891e4e18f902812a002090413ede");
	// Проверяем усечение имитовставки до восьми байтов
	uint8_t truncated[8];
	// Выполняем выработку усечённой имитовставки
	ASSERT_TRUE(digest::hmac(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> ("Jefe"), 4), view_t(reinterpret_cast <const uint8_t *> ("what do ya want for nothing?"), 28), truncated, sizeof(truncated)));
	// Проверяем старшие байты имитовставки
	ASSERT_EQ(text(truncated, sizeof(truncated)), "5bdcc146bf60754e");
	// Проверяем отказ имитовставки длиннее хеша
	ASSERT_FALSE(digest::hmac(digest::hash_t::MD5, view_t(reinterpret_cast <const uint8_t *> ("Jefe"), 4), view_t(reinterpret_cast <const uint8_t *> ("x"), 1), truncated, 17));
	// Проверяем отказ имитовставки неустановленным алгоритмом
	ASSERT_FALSE(digest::hmac(digest::hash_t::NONE, view_t(reinterpret_cast <const uint8_t *> ("Jefe"), 4), view_t(reinterpret_cast <const uint8_t *> ("x"), 1), truncated, 8));
}

/**
 * BLAKE2 в общем перечне: хеш, длины и блоки, HMAC-BLAKE2s/BLAKE2b по openssl mac HMAC
 */
TEST(HashTest, Blake2){
	// Место итога и ключ HMAC
	uint8_t result[64], key[32];
	/**
	 * Заполняем ключ байтами 00..1f
	 */
	for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (i);
	// Сообщение из трёх знаков «abc»
	const view_t abc(reinterpret_cast <const uint8_t *> ("abc"), 3);
	// Длина итога BLAKE2s256 — 32 байта
	EXPECT_EQ(digest::length(digest::hash_t::BLAKE2S256), 32u);
	EXPECT_EQ(digest::length(digest::hash_t::BLAKE2B512), 64u);
	EXPECT_EQ(digest::block(digest::hash_t::BLAKE2S256), 64u);
	EXPECT_EQ(digest::block(digest::hash_t::BLAKE2B512), 128u);
	// Считаем BLAKE2s256 от «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::BLAKE2S256, abc, result, 32));
	// Итог BLAKE2s256 совпадает с контрольным значением openssl
	EXPECT_EQ(text(result, 32), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
	// Считаем BLAKE2b512 от «abc»
	ASSERT_TRUE(digest::hash(digest::hash_t::BLAKE2B512, abc, result, 64));
	// Итог BLAKE2b512 совпадает с контрольным значением openssl
	EXPECT_EQ(text(result, 64), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
	// HMAC поверх BLAKE2: значения openssl mac -digest BLAKE2s256/BLAKE2b512 HMAC с ключом 00..1f
	ASSERT_TRUE(digest::hmac(digest::hash_t::BLAKE2S256, view_t(key, 32), abc, result, 32));
	// Итог HMAC-BLAKE2s256 совпадает со значением openssl mac
	EXPECT_EQ(text(result, 32), "82623be5bc0a391b24dce53e67d028eff92d586de0485ac37822e597d049c74f");
	// Считаем HMAC-BLAKE2b512 с тем же ключом
	ASSERT_TRUE(digest::hmac(digest::hash_t::BLAKE2B512, view_t(key, 32), abc, result, 64));
	// Итог HMAC-BLAKE2b512 совпадает со значением openssl mac
	EXPECT_EQ(text(result, 64), "af6aef48e9a5a5e6a63b9f4703f032b5e42905477afec4d14f45d2d85e43dd193e96ba6432d7f7be1186083a09e71894f83dcf65fcf5a88b585529ef4928833d");
	// Короткое место отвергается
	digest::hasher_t hasher(digest::hash_t::BLAKE2S256);
	// Поглощаем «abc» накопителем
	hasher.update(abc);
	// Итог в 31 байт отвергается: место короче итога BLAKE2s256
	EXPECT_FALSE(hasher.finish(result, 31));
}
