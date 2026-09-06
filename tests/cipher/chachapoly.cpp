/**
 * @file: chachapoly.cpp
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
#include <random>
#include <cstring>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <sys/machine.hpp>
#include <cipher/chachapoly.hpp>

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
 * @brief Размеры куска приёмки потока: 1…40 и 63, 64, 65, 333, 8192
 *
 */
static const size_t CHUNKS[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	63, 64, 65, 333, 8192
};

/**
 * Ключ раздела 2.8.2 RFC 8439: от 0x80 до 0x9f
 */
static const char * KEY_282 = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

/**
 * Заполнение раздела 2.8.2 RFC 8439: постоянная 7 и вектор 0x40…0x47
 */
static const char * NONCE_282 = "070000004041424344454647";

/**
 * Связанные данные раздела 2.8.2 RFC 8439
 */
static const char * AAD_282 = "50515253c0c1c2c3c4c5c6c7";

/**
 * Открытый текст раздела 2.8.2 RFC 8439: 114 байтов
 */
static const char * PLAIN_282 = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

/**
 * Шифртекст раздела 2.8.2 RFC 8439
 */
static const char * SEALED_282 = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";

/**
 * Метка раздела 2.8.2 RFC 8439
 */
static const char * TAG_282 = "1ae10b594f09e26a7e902ecbd0600691";

/**
 * Ключ приложения A.5 RFC 8439
 */
static const char * KEY_A5 = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";

/**
 * Заполнение приложения A.5 RFC 8439
 */
static const char * NONCE_A5 = "000000000102030405060708";

/**
 * Связанные данные приложения A.5 RFC 8439
 */
static const char * AAD_A5 = "f33388860000000000004e91";

/**
 * Шифртекст приложения A.5 RFC 8439: 265 байтов
 */
static const char * SEALED_A5 = "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b";

/**
 * Метка приложения A.5 RFC 8439
 */
static const char * TAG_A5 = "eead9d67890cbb22392336fea1851f38";

/**
 * Открытый текст приложения A.5 RFC 8439: 265 байтов с кавычками UTF-8
 */
static const char * PLAIN_A5 = "496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d";

/**
 * @brief Метод поточной проверки случая кусками заданного размера
 *
 * @param key        ключ
 * @param nonce      начальное заполнение
 * @param associated связанные данные
 * @param plain      открытый текст
 * @param sealed     ожидаемый шифртекст
 * @param tag        ожидаемая метка
 * @param chunk      размер куска
 *
 */
static void slice(const std::vector <uint8_t> & key, const std::vector <uint8_t> & nonce, const std::vector <uint8_t> & associated, const std::vector <uint8_t> & plain, const std::vector <uint8_t> & sealed, const std::vector <uint8_t> & tag, const size_t chunk) {
	// Объект режима
	cipher::chachapoly_t aead;
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()))) << "кусок " << chunk;
	/**
	 * Выполняем подачу связанных данных кусками
	 */
	for(size_t offset = 0; offset < associated.size(); offset += chunk)
		// Проверяем подачу куска связанных данных
		ASSERT_TRUE(aead.associate(view_t(associated.data() + offset, (((associated.size() - offset) < chunk) ? (associated.size() - offset) : chunk)))) << "кусок " << chunk;
	// Проверяем подачу пустого куска связанных данных
	ASSERT_TRUE(aead.associate(view_t())) << "кусок " << chunk;
	// Шифртекст потока
	std::vector <uint8_t> output(plain.size() + 1);
	// Проверяем пустой кусок данных
	ASSERT_TRUE(aead.encrypt(view_t(), nullptr)) << "кусок " << chunk;
	/**
	 * Выполняем подачу открытого текста кусками
	 */
	for(size_t offset = 0; offset < plain.size(); offset += chunk)
		// Проверяем зашифрование куска
		ASSERT_TRUE(aead.encrypt(view_t(plain.data() + offset, (((plain.size() - offset) < chunk) ? (plain.size() - offset) : chunk)), output.data() + offset)) << "кусок " << chunk;
	// Метка потока
	uint8_t t[cipher::CHACHAPOLY_TAG];
	// Проверяем снятие метки
	ASSERT_TRUE(aead.finish(t)) << "кусок " << chunk;
	// Проверяем схождение шифртекста с ожидаемым
	ASSERT_EQ(::memcmp(output.data(), sealed.data(), plain.size()), 0) << "кусок " << chunk;
	// Проверяем схождение метки с ожидаемой
	ASSERT_EQ(::memcmp(t, tag.data(), sizeof(t)), 0) << "кусок " << chunk;
	// Проверяем отказ куска после закрытия потока
	ASSERT_FALSE(aead.encrypt(view_t(), nullptr)) << "кусок " << chunk;
	// Проверяем повторный запуск: заслон сброшен
	ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()))) << "кусок " << chunk;
	// Проверяем подачу связанных данных разом
	ASSERT_TRUE(aead.associate(view_t(associated.data(), associated.size()))) << "кусок " << chunk;
	// Открытый текст потока
	std::vector <uint8_t> opened(plain.size() + 1);
	/**
	 * Выполняем подачу шифртекста кусками
	 */
	for(size_t offset = 0; offset < sealed.size(); offset += chunk)
		// Проверяем расшифрование куска
		ASSERT_TRUE(aead.decrypt(view_t(sealed.data() + offset, (((sealed.size() - offset) < chunk) ? (sealed.size() - offset) : chunk)), opened.data() + offset)) << "кусок " << chunk;
	// Проверяем отказ связанных данных после данных
	ASSERT_FALSE(aead.associate(view_t(associated.data(), 1))) << "кусок " << chunk;
	// Проверяем сличение метки
	ASSERT_TRUE(aead.verify(view_t(tag.data(), tag.size()))) << "кусок " << chunk;
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened.data(), plain.data(), plain.size()), 0) << "кусок " << chunk;
}

/**
 * @brief Метод проверки одного случая AEAD разом и потоком
 *
 * @param key        ключ
 * @param nonce      начальное заполнение
 * @param associated связанные данные
 * @param plain      открытый текст
 * @param sealed     ожидаемый шифртекст
 * @param tag        ожидаемая метка
 *
 */
static void check(const std::string & key, const std::string & nonce, const std::string & associated, const std::string & plain, const std::string & sealed, const std::string & tag) {
	// Разобранные байты случая
	const std::vector <uint8_t> k = bytes(key), n = bytes(nonce), a = bytes(associated), p = bytes(plain), s = bytes(sealed), e = bytes(tag);
	// Проверяем длины открытого текста и шифртекста
	ASSERT_EQ(p.size(), s.size());
	// Объект режима
	cipher::chachapoly_t aead;
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()))) << "случай " << tag;
	// Проверяем длину метки
	ASSERT_EQ(aead.size(), 16u);
	// Шифртекст
	std::vector <uint8_t> c(p.size() + 1);
	// Метка
	uint8_t t[cipher::CHACHAPOLY_TAG];
	// Проверяем зашифрование
	ASSERT_TRUE(aead.encrypt(view_t(a.data(), a.size()), view_t(p.data(), p.size()), c.data(), t)) << "случай " << tag;
	// Проверяем шифртекст
	ASSERT_EQ(text(c.data(), p.size()), sealed) << "случай " << tag;
	// Проверяем метку
	ASSERT_EQ(text(t, sizeof(t)), tag) << "случай " << tag;
	// Проверяем отказ повторного зашифрования на том же заполнении
	ASSERT_FALSE(aead.encrypt(view_t(a.data(), a.size()), view_t(p.data(), p.size()), c.data(), t)) << "случай " << tag;
	// Открытый текст после расшифрования
	std::vector <uint8_t> o(p.size() + 1, 0xA5);
	// Проверяем расшифрование с верной меткой
	ASSERT_TRUE(aead.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(o.data(), p.data(), p.size()), 0) << "случай " << tag;
	// Заполняем выход образцом, чтобы увидеть, тронут ли он при отказе
	std::fill(o.begin(), o.end(), 0xA5);
	// Портим метку
	t[0] ^= 0x01;
	// Проверяем отказ расшифрования с испорченной меткой
	ASSERT_FALSE(aead.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	// Проверяем, что выход при отказе не тронут
	ASSERT_EQ(o, std::vector <uint8_t> (p.size() + 1, 0xA5)) << "случай " << tag;
	// Восстанавливаем метку
	t[0] ^= 0x01;
	// Если открытый текст непуст
	if(!p.empty()){
		// Портим шифртекст
		c[p.size() / 2] ^= 0x80;
		// Проверяем отказ расшифрования с испорченным шифртекстом
		ASSERT_FALSE(aead.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
		// Проверяем, что выход при отказе не тронут
		ASSERT_EQ(o, std::vector <uint8_t> (p.size() + 1, 0xA5)) << "случай " << tag;
		// Восстанавливаем шифртекст
		c[p.size() / 2] ^= 0x80;
	}
	// Проверяем отказ расшифрования с чужими связанными данными
	ASSERT_FALSE(aead.decrypt(view_t(reinterpret_cast <const uint8_t *> ("x"), 1), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	// Заполнение с испорченным байтом
	std::vector <uint8_t> wrong = n;
	// Портим заполнение
	wrong[11] ^= 0x01;
	// Проверяем перезапуск на испорченном заполнении
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(wrong.data(), wrong.size()))) << "случай " << tag;
	// Проверяем отказ расшифрования на чужом заполнении
	ASSERT_FALSE(aead.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	/**
	 * Выполняем поточную проверку по всем размерам куска
	 */
	for(const size_t chunk : CHUNKS)
		// Проверяем поток кусками заданного размера
		slice(k, n, a, p, s, e, chunk);
}

/**
 * Проверка вектора раздела 2.8.2 RFC 8439
 */
TEST(ChachapolyTest, Rfc){
	// Раздел 2.8.2: текст про солнцезащитный крем со связанными данными
	check(KEY_282, NONCE_282, AAD_282, PLAIN_282, SEALED_282, TAG_282);
}

/**
 * Проверка вектора приложения A.5 RFC 8439: длинное сообщение в 265 байтов
 */
TEST(ChachapolyTest, Appendix){
	// A.5: расшифрование длинного сообщения
	check(KEY_A5, NONCE_A5, AAD_A5, PLAIN_A5, SEALED_A5, TAG_A5);
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_A5), n = bytes(NONCE_A5), a = bytes(AAD_A5), s = bytes(SEALED_A5), t = bytes(TAG_A5), p = bytes(PLAIN_A5);
	// Объект режима
	cipher::chachapoly_t aead;
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Открытый текст
	std::vector <uint8_t> opened(s.size());
	// Проверяем расшифрование в том виде, в котором его даёт приложение: без предварительного зашифрования
	ASSERT_TRUE(aead.decrypt(view_t(a.data(), a.size()), view_t(s.data(), s.size()), opened.data(), view_t(t.data(), t.size())));
	// Проверяем открытый текст
	ASSERT_EQ(opened, p);
}

/**
 * Проверка пустых текста и связанных данных: метка на одних длинах
 */
TEST(ChachapolyTest, Empty){
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_282), n = bytes(NONCE_282);
	// Объект режима
	cipher::chachapoly_t aead;
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Метка
	uint8_t tag[cipher::CHACHAPOLY_TAG];
	// Проверяем зашифрование пустого текста без связанных данных
	ASSERT_TRUE(aead.encrypt(view_t(), view_t(), nullptr, tag));
	// Проверяем расшифрование пустого текста
	ASSERT_TRUE(aead.decrypt(view_t(), view_t(), nullptr, view_t(tag, sizeof(tag))));
	// Портим метку
	tag[15] ^= 0x01;
	// Проверяем отказ на испорченной метке
	ASSERT_FALSE(aead.decrypt(view_t(), view_t(), nullptr, view_t(tag, sizeof(tag))));
	// Восстанавливаем метку
	tag[15] ^= 0x01;
	// Проверяем перезапуск
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем снятие метки потоком без единого куска
	uint8_t stream[cipher::CHACHAPOLY_TAG];
	// Проверяем снятие метки
	ASSERT_TRUE(aead.finish(stream));
	// Проверяем схождение с разовой
	ASSERT_EQ(::memcmp(stream, tag, sizeof(tag)), 0);
}

/**
 * Проверка отказов договора
 */
TEST(ChachapolyTest, Refusals){
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_282), n = bytes(NONCE_282), p = bytes(PLAIN_282);
	// Объект режима
	cipher::chachapoly_t aead;
	// Шифртекст
	std::vector <uint8_t> sealed(p.size());
	// Метка
	uint8_t tag[cipher::CHACHAPOLY_TAG];
	// Проверяем неготовность до запуска
	ASSERT_FALSE(aead.ready());
	// Проверяем отказ зашифрования до запуска
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(p.data(), p.size()), sealed.data(), tag));
	// Проверяем отказ запуска без ключа
	ASSERT_FALSE(aead.start(view_t(), view_t(n.data(), n.size())));
	// Проверяем отказ запуска с коротким ключом
	ASSERT_FALSE(aead.start(view_t(k.data(), 16), view_t(n.data(), n.size())));
	// Проверяем отказ запуска без заполнения
	ASSERT_FALSE(aead.start(view_t(k.data(), k.size()), view_t()));
	// Проверяем отказ запуска с заполнением в 8 байтов
	ASSERT_FALSE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), 8)));
	// Проверяем отказ запуска с заполнением в 16 байтов
	ASSERT_FALSE(aead.start(view_t(k.data(), k.size()), view_t(k.data(), 16)));
	// Проверяем неготовность после отказов
	ASSERT_FALSE(aead.ready());
	// Проверяем запуск
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем готовность
	ASSERT_TRUE(aead.ready());
	// Проверяем отказ зашифрования без места под метку
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(p.data(), p.size()), sealed.data(), nullptr));
	// Проверяем отказ зашифрования текста, объявленного непустым, но не переданного
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(nullptr, 4), sealed.data(), tag));
	// Проверяем отказ зашифрования без места под шифртекст
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(p.data(), p.size()), nullptr, tag));
	// Проверяем отказ зашифрования со связанными данными, объявленными непустыми, но не переданными
	ASSERT_FALSE(aead.encrypt(view_t(nullptr, 4), view_t(p.data(), p.size()), sealed.data(), tag));
	// Проверяем зашифрование: отказы выше заполнения не расходуют
	ASSERT_TRUE(aead.encrypt(view_t(), view_t(p.data(), p.size()), sealed.data(), tag));
	// Открытый текст
	std::vector <uint8_t> opened(p.size());
	// Проверяем отказ расшифрования с меткой в 12 байтов
	ASSERT_FALSE(aead.decrypt(view_t(), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, 12)));
	// Проверяем отказ расшифрования без метки
	ASSERT_FALSE(aead.decrypt(view_t(), view_t(sealed.data(), sealed.size()), opened.data(), view_t()));
	// Проверяем отказ расшифрования без места под открытый текст
	ASSERT_FALSE(aead.decrypt(view_t(), view_t(sealed.data(), sealed.size()), nullptr, view_t(tag, sizeof(tag))));
	// Проверяем расшифрование
	ASSERT_TRUE(aead.decrypt(view_t(), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, sizeof(tag))));
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, p);
	// Выполняем сброс режима
	aead.clear();
	// Проверяем неготовность после сброса
	ASSERT_FALSE(aead.ready());
	// Проверяем отказ расшифрования после сброса
	ASSERT_FALSE(aead.decrypt(view_t(), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, sizeof(tag))));
}

/**
 * Проверка заслонов потока: направление, порядок, заслон заполнения, длина метки
 */
TEST(ChachapolyTest, Stream){
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_282), n = bytes(NONCE_282);
	// Открытый текст в 100 байтов
	std::vector <uint8_t> plain(100);
	/**
	 * Выполняем заполнение открытого текста
	 */
	for(size_t i = 0; i < plain.size(); i++)
		// Записываем очередной байт
		plain[i] = static_cast <uint8_t> (i * 5 + 1);
	// Объект режима
	cipher::chachapoly_t aead;
	// Шифртекст и метка
	uint8_t sealed[100], tag[cipher::CHACHAPOLY_TAG];
	// Проверяем отказ потока до запуска
	ASSERT_FALSE(aead.associate(view_t(plain.data(), 4)));
	// Проверяем отказ куска до запуска
	ASSERT_FALSE(aead.encrypt(view_t(plain.data(), 4), sealed));
	// Проверяем отказ завершения до запуска
	ASSERT_FALSE(aead.finish(tag));
	// Проверяем отказ сличения до запуска
	ASSERT_FALSE(aead.verify(view_t(tag, sizeof(tag))));
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем отказ завершения без места под метку
	ASSERT_FALSE(aead.finish(nullptr));
	// Проверяем отказ объявленного непустым, но не переданного куска
	ASSERT_FALSE(aead.encrypt(view_t(nullptr, 4), sealed));
	// Проверяем отказ куска без места под итог
	ASSERT_FALSE(aead.encrypt(view_t(plain.data(), 4), nullptr));
	// Проверяем отказ связанных данных, объявленных непустыми, но не переданных
	ASSERT_FALSE(aead.associate(view_t(nullptr, 4)));
	// Проверяем подачу связанных данных
	ASSERT_TRUE(aead.associate(view_t(plain.data(), 7)));
	// Проверяем зашифрование первого куска в один байт
	ASSERT_TRUE(aead.encrypt(view_t(plain.data(), 1), sealed));
	// Проверяем отказ смены направления посреди потока
	ASSERT_FALSE(aead.decrypt(view_t(plain.data() + 1, 1), sealed + 1));
	// Проверяем отказ связанных данных после данных
	ASSERT_FALSE(aead.associate(view_t(plain.data(), 1)));
	// Проверяем отказ сличения посреди зашифрования
	ASSERT_FALSE(aead.verify(view_t(tag, sizeof(tag))));
	// Проверяем зашифрование остатка
	ASSERT_TRUE(aead.encrypt(view_t(plain.data() + 1, plain.size() - 1), sealed + 1));
	// Проверяем снятие метки
	ASSERT_TRUE(aead.finish(tag));
	// Проверяем отказ повторного снятия метки: поток закрыт
	ASSERT_FALSE(aead.finish(tag));
	// Проверяем отказ куска после закрытия
	ASSERT_FALSE(aead.decrypt(view_t(sealed, 1), sealed));
	// Проверяем отказ разового зашифрования: заполнение израсходовано потоком
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(plain.data(), plain.size()), sealed, tag));
	// Открытый текст
	uint8_t opened[100];
	// Проверяем разовое расшифрование того, что зашифровано потоком
	ASSERT_TRUE(aead.decrypt(view_t(plain.data(), 7), view_t(sealed, sizeof(sealed)), opened, view_t(tag, sizeof(tag))));
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
	// Проверяем перезапуск: заслон заполнения сброшен
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем отказ сличения метки не той длины
	ASSERT_FALSE(aead.verify(view_t(tag, 12)));
	// Проверяем подачу связанных данных разом
	ASSERT_TRUE(aead.associate(view_t(plain.data(), 7)));
	// Проверяем поточное расшифрование разом
	ASSERT_TRUE(aead.decrypt(view_t(sealed, sizeof(sealed)), opened));
	// Проверяем отказ снятия метки посреди расшифрования
	ASSERT_FALSE(aead.finish(tag));
	// Портим метку
	tag[15] ^= 0x01;
	// Проверяем отказ сличения порченой метки
	ASSERT_FALSE(aead.verify(view_t(tag, sizeof(tag))));
	// Восстанавливаем метку
	tag[15] ^= 0x01;
	// Проверяем перезапуск и пустой поток: метка пустого текста снимается на завершении
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем снятие метки без единого куска
	ASSERT_TRUE(aead.finish(tag));
	// Проверяем отказ повторного потока без перезапуска: заполнение израсходовано
	ASSERT_FALSE(aead.encrypt(view_t(), nullptr));
	// Проверяем перезапуск и сличение метки пустого текста потоком
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем сличение метки без единого куска
	ASSERT_TRUE(aead.verify(view_t(tag, sizeof(tag))));
	// Проверяем перезапуск: расшифрование под заслон не подпадает
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Проверяем первое расшифрование пустого потока
	ASSERT_TRUE(aead.verify(view_t(tag, sizeof(tag))));
	// Проверяем повторное разовое расшифрование без перезапуска
	ASSERT_TRUE(aead.decrypt(view_t(), view_t(), nullptr, view_t(tag, sizeof(tag))));
	// Проверяем разовое зашифрование: расшифрования заполнение не расходуют, первое зашифрование допустимо
	ASSERT_TRUE(aead.encrypt(view_t(), view_t(), nullptr, tag));
	// Проверяем отказ второго разового зашифрования: заполнение израсходовано
	ASSERT_FALSE(aead.encrypt(view_t(), view_t(), nullptr, tag));
	// Проверяем, что расшифрование после израсходованного заполнения по-прежнему допустимо
	ASSERT_TRUE(aead.decrypt(view_t(), view_t(), nullptr, view_t(tag, sizeof(tag))));
	// Выполняем сброс режима
	aead.clear();
	// Проверяем отказ потока после сброса
	ASSERT_FALSE(aead.encrypt(view_t(plain.data(), 1), sealed));
}

/**
 * Проверка того, что связанные данные кусками по одному байту через границу блока сходятся с разовыми
 */
TEST(ChachapolyTest, AssociatedPadding){
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_282), n = bytes(NONCE_282), p = bytes(PLAIN_282);
	// Связанные данные в 33 байта: два блока и один байт дополнения
	std::vector <uint8_t> associated(33);
	/**
	 * Выполняем заполнение связанных данных
	 */
	for(size_t i = 0; i < associated.size(); i++)
		// Записываем очередной байт
		associated[i] = static_cast <uint8_t> (i * 3 + 7);
	// Объект режима
	cipher::chachapoly_t aead;
	// Проверяем запуск режима
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Шифртекст и метка разового зашифрования
	std::vector <uint8_t> sealed(p.size());
	// Метка
	uint8_t tag[cipher::CHACHAPOLY_TAG];
	// Проверяем разовое зашифрование
	ASSERT_TRUE(aead.encrypt(view_t(associated.data(), associated.size()), view_t(p.data(), p.size()), sealed.data(), tag));
	// Проверяем перезапуск
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	/**
	 * Выполняем подачу связанных данных по одному байту
	 */
	for(size_t i = 0; i < associated.size(); i++)
		// Проверяем подачу байта
		ASSERT_TRUE(aead.associate(view_t(associated.data() + i, 1)));
	// Шифртекст потока
	std::vector <uint8_t> output(p.size());
	// Проверяем зашифрование разом
	ASSERT_TRUE(aead.encrypt(view_t(p.data(), p.size()), output.data()));
	// Метка потока
	uint8_t stream[cipher::CHACHAPOLY_TAG];
	// Проверяем снятие метки
	ASSERT_TRUE(aead.finish(stream));
	// Проверяем схождение шифртекста
	ASSERT_EQ(output, sealed);
	// Проверяем схождение метки
	ASSERT_EQ(::memcmp(stream, tag, sizeof(tag)), 0);
	// Связанные данные без последнего байта: иная длина обязана дать иную метку
	ASSERT_TRUE(aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size())));
	// Открытый текст
	std::vector <uint8_t> opened(p.size());
	// Проверяем отказ расшифрования с укороченными связанными данными
	ASSERT_FALSE(aead.decrypt(view_t(associated.data(), associated.size() - 1), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, sizeof(tag))));
}

/**
 * Нехватка памяти: режим не выделяет памяти вовсе и обязан работать при нулевом запасе
 */
TEST(ChachapolyTest, Starved){
	// Разобранные байты
	const std::vector <uint8_t> k = bytes(KEY_A5), n = bytes(NONCE_A5), a = bytes(AAD_A5), p = bytes(PLAIN_A5), s = bytes(SEALED_A5), t = bytes(TAG_A5);
	// Шифртекст
	std::vector <uint8_t> sealed(p.size());
	// Метка
	uint8_t tag[cipher::CHACHAPOLY_TAG] = {0};
	// Открытый текст
	std::vector <uint8_t> opened(p.size());
	// Итог зашифрования
	bool outcome = false;
	// Итог расшифрования
	bool reverse = false;
	{
		// Отмеряем нулевой запас выделений: всякое выделение под noexcept прервало бы исполнение
		starve::ration_t ration(0);
		// Объект режима
		cipher::chachapoly_t aead;
		// Выполняем запуск режима
		outcome = aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()));
		// Если запуск прошёл
		if(outcome)
			// Подаём связанные данные
			outcome = aead.associate(view_t(a.data(), a.size()));
		/**
		 * Выполняем подачу текста кусками по 37 байтов
		 */
		for(size_t offset = 0; outcome && (offset < p.size()); offset += 37)
			// Подаём очередной кусок
			outcome = aead.encrypt(view_t(p.data() + offset, (((p.size() - offset) < 37) ? (p.size() - offset) : 37)), sealed.data() + offset);
		// Если подача прошла
		if(outcome)
			// Снимаем метку
			outcome = aead.finish(tag);
		// Выполняем перезапуск режима
		reverse = aead.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()));
		// Если перезапуск прошёл
		if(reverse)
			// Выполняем разовое расшифрование
			reverse = aead.decrypt(view_t(a.data(), a.size()), view_t(s.data(), s.size()), opened.data(), view_t(t.data(), t.size()));
	}
	// Проверяем успешность зашифрования без единого выделения
	ASSERT_TRUE(outcome);
	// Проверяем схождение шифртекста с приложением A.5
	ASSERT_EQ(sealed, s);
	// Проверяем схождение метки с приложением A.5
	ASSERT_EQ(text(tag, sizeof(tag)), TAG_A5);
	// Проверяем успешность расшифрования без единого выделения
	ASSERT_TRUE(reverse);
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, p);
}

/**
 * Проверка схождения векторного и переносимого путей режима: длины 0…2048 с
 * невыровненными буферами, шифртекст и метка целиком на пути машины сходятся с
 * потоком кусками случайной длины переносимым путём в обоих направлениях
 */
TEST(ChachapolyTest, Paths){
	// Разобранные байты ключа и заполнения
	const std::vector <uint8_t> key = bytes(KEY_282), nonce = bytes(NONCE_282);
	// Генератор данных и длин кусков с закреплённым зерном
	std::mt19937 generator(20260906);
	// Объект режима
	cipher::chachapoly_t aead;
	/**
	 * Выполняем перебор длин
	 */
	for(size_t length = 0; length <= 2048; length++){
		// Смещения буферов от выравнивания
		const size_t inset = (generator() % 16), outset = (generator() % 16);
		// Связанные данные случайной длины
		std::vector <uint8_t> associated(generator() % 40);
		/**
		 * Выполняем заполнение связанных данных
		 */
		for(size_t i = 0; i < associated.size(); i++)
			// Записываем очередной байт
			associated[i] = static_cast <uint8_t> (generator());
		// Открытый текст с запасом под смещение
		std::vector <uint8_t> plain(length + 16);
		/**
		 * Выполняем заполнение открытого текста
		 */
		for(size_t i = 0; i < plain.size(); i++)
			// Записываем очередной байт
			plain[i] = static_cast <uint8_t> (generator());
		// Шифртексты обоих путей и раскрытый текст
		std::vector <uint8_t> first(length + 16), second(length + 16), opened(length + 16);
		// Метки обоих путей
		uint8_t tag[cipher::CHACHAPOLY_TAG], other[cipher::CHACHAPOLY_TAG];
		// Проверяем зашифрование целиком на пути, выбранном машиной
		ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()))) << "length " << length;
		// Проверяем зашифрование целиком на пути, выбранном машиной
		ASSERT_TRUE(aead.encrypt(view_t(associated.data(), associated.size()), view_t(plain.data() + inset, length), first.data() + outset, tag)) << "length " << length;
		// Запрещаем машинные команды
		machine::allow(false);
		// Проверяем запуск потока переносимым путём
		ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()))) << "length " << length;
		// Проверяем подачу связанных данных
		ASSERT_TRUE(aead.associate(view_t(associated.data(), associated.size()))) << "length " << length;
		// Позиция внутри данных
		size_t position = 0;
		/**
		 * Выполняем расшифрование кусками случайной длины
		 */
		while(position < length){
			// Длина очередного куска
			size_t chunk = (1 + (generator() % 300));
			// Если кусок длиннее остатка
			if(chunk > (length - position))
				// Ограничиваем кусок остатком
				chunk = (length - position);
			// Проверяем расшифрование куска
			ASSERT_TRUE(aead.decrypt(view_t(first.data() + outset + position, chunk), opened.data() + inset + position)) << "length " << length;
			// Сдвигаем позицию
			position += chunk;
		}
		// Проверяем сличение метки, снятой путём машины, переносимым путём
		ASSERT_TRUE(aead.verify(view_t(tag, sizeof(tag)))) << "length " << length;
		// Проверяем возврат открытого текста
		ASSERT_EQ(::memcmp(opened.data() + inset, plain.data() + inset, length), 0) << "length " << length;
		// Проверяем запуск потока переносимым путём
		ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()))) << "length " << length;
		// Проверяем подачу связанных данных
		ASSERT_TRUE(aead.associate(view_t(associated.data(), associated.size()))) << "length " << length;
		// Сбрасываем позицию внутри данных
		position = 0;
		/**
		 * Выполняем зашифрование кусками случайной длины
		 */
		while(position < length){
			// Длина очередного куска
			size_t chunk = (1 + (generator() % 500));
			// Если кусок длиннее остатка
			if(chunk > (length - position))
				// Ограничиваем кусок остатком
				chunk = (length - position);
			// Проверяем зашифрование куска
			ASSERT_TRUE(aead.encrypt(view_t(plain.data() + inset + position, chunk), second.data() + outset + position)) << "length " << length;
			// Сдвигаем позицию
			position += chunk;
		}
		// Проверяем снятие метки переносимым путём
		ASSERT_TRUE(aead.finish(other)) << "length " << length;
		// Возвращаем машинные команды
		machine::allow(true);
		// Проверяем схождение шифртекстов обоих путей
		ASSERT_EQ(::memcmp(first.data() + outset, second.data() + outset, length), 0) << "length " << length;
		// Проверяем схождение меток обоих путей
		ASSERT_EQ(::memcmp(tag, other, sizeof(tag)), 0) << "length " << length;
	}
}
