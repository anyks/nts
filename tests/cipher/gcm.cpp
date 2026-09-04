/**
 * @file: gcm.cpp
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
#include <sys/machine.hpp>
#include <cipher/aes.hpp>
#include <cipher/gcm.hpp>

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
 * @brief Метод поточной проверки случая кусками заданного размера
 *
 * @param aes        шифр с ключом
 * @param nonce      начальное заполнение
 * @param associated связанные данные
 * @param plain      открытый текст
 * @param sealed     ожидаемый шифртекст
 * @param tag        ожидаемая метка
 * @param chunk      размер куска
 *
 */
static void slice(const cipher::aes_t & aes, const std::vector <uint8_t> & nonce, const std::vector <uint8_t> & associated, const std::vector <uint8_t> & plain, const std::vector <uint8_t> & sealed, const std::vector <uint8_t> & tag, const size_t chunk) {
	// Объект режима
	cipher::gcm_t gcm;
	// Проверяем запуск режима
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size()))) << "кусок " << chunk;
	/**
	 * Выполняем подачу связанных данных кусками
	 */
	for(size_t offset = 0; offset < associated.size(); offset += chunk)
		// Проверяем подачу куска связанных данных
		ASSERT_TRUE(gcm.associate(view_t(associated.data() + offset, (((associated.size() - offset) < chunk) ? (associated.size() - offset) : chunk)))) << "кусок " << chunk;
	// Проверяем подачу пустого куска связанных данных
	ASSERT_TRUE(gcm.associate(view_t())) << "кусок " << chunk;
	// Шифртекст потока
	std::vector <uint8_t> output(plain.size() + 1);
	// Проверяем пустой кусок данных
	ASSERT_TRUE(gcm.encrypt(view_t(), nullptr)) << "кусок " << chunk;
	/**
	 * Выполняем подачу открытого текста кусками
	 */
	for(size_t offset = 0; offset < plain.size(); offset += chunk)
		// Проверяем зашифрование куска
		ASSERT_TRUE(gcm.encrypt(view_t(plain.data() + offset, (((plain.size() - offset) < chunk) ? (plain.size() - offset) : chunk)), output.data() + offset)) << "кусок " << chunk;
	// Метка потока
	uint8_t t[16];
	// Проверяем снятие метки
	ASSERT_TRUE(gcm.finish(t)) << "кусок " << chunk;
	// Проверяем схождение шифртекста с разовым
	ASSERT_EQ(::memcmp(output.data(), sealed.data(), plain.size()), 0) << "кусок " << chunk;
	// Проверяем схождение метки с разовой
	ASSERT_EQ(::memcmp(t, tag.data(), 16), 0) << "кусок " << chunk;
	// Проверяем отказ куска после закрытия потока
	ASSERT_FALSE(gcm.encrypt(view_t(), nullptr)) << "кусок " << chunk;
	// Проверяем повторный запуск: заслон сброшен
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size()))) << "кусок " << chunk;
	// Проверяем подачу связанных данных разом
	ASSERT_TRUE(gcm.associate(view_t(associated.data(), associated.size()))) << "кусок " << chunk;
	// Открытый текст потока
	std::vector <uint8_t> opened(plain.size() + 1);
	/**
	 * Выполняем подачу шифртекста кусками
	 */
	for(size_t offset = 0; offset < sealed.size(); offset += chunk)
		// Проверяем расшифрование куска
		ASSERT_TRUE(gcm.decrypt(view_t(sealed.data() + offset, (((sealed.size() - offset) < chunk) ? (sealed.size() - offset) : chunk)), opened.data() + offset)) << "кусок " << chunk;
	// Проверяем отказ связанных данных после данных
	ASSERT_FALSE(gcm.associate(view_t(associated.data(), 1))) << "кусок " << chunk;
	// Проверяем сличение метки
	ASSERT_TRUE(gcm.verify(view_t(tag.data(), tag.size()))) << "кусок " << chunk;
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened.data(), plain.data(), plain.size()), 0) << "кусок " << chunk;
}

/**
 * @brief Метод проверки одного случая описания GCM
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
	const std::vector <uint8_t> k = bytes(key), n = bytes(nonce), a = bytes(associated), p = bytes(plain);
	// Объект шифра
	cipher::aes_t aes;
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(k.data(), k.size()))) << "случай " << tag;
	// Объект режима
	cipher::gcm_t gcm;
	// Проверяем запуск режима
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(n.data(), n.size()))) << "случай " << tag;
	// Проверяем длину метки по умолчанию
	ASSERT_EQ(gcm.size(), 16u);
	// Шифртекст
	std::vector <uint8_t> c(p.size() + 1);
	// Метка
	uint8_t t[16];
	// Проверяем зашифрование
	ASSERT_TRUE(gcm.encrypt(view_t(a.data(), a.size()), view_t(p.data(), p.size()), c.data(), t)) << "случай " << tag;
	// Проверяем шифртекст
	ASSERT_EQ(text(c.data(), p.size()), sealed) << "случай " << tag;
	// Проверяем метку
	ASSERT_EQ(text(t, sizeof(t)), tag) << "случай " << tag;
	// Проверяем отказ повторного зашифрования на том же заполнении
	ASSERT_FALSE(gcm.encrypt(view_t(a.data(), a.size()), view_t(p.data(), p.size()), c.data(), t)) << "случай " << tag;
	// Открытый текст после расшифрования
	std::vector <uint8_t> o(p.size() + 1);
	// Проверяем расшифрование с верной меткой
	ASSERT_TRUE(gcm.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(o.data(), p.data(), p.size()), 0) << "случай " << tag;
	// Портим метку
	t[0] ^= 0x01;
	// Проверяем отказ расшифрования с испорченной меткой
	ASSERT_FALSE(gcm.decrypt(view_t(a.data(), a.size()), view_t(c.data(), p.size()), o.data(), view_t(t, sizeof(t)))) << "случай " << tag;
	// Ожидаемые шифртекст и метка
	const std::vector <uint8_t> s = bytes(sealed), e = bytes(tag);
	/**
	 * Выполняем поточную проверку по всем размерам куска
	 */
	for(const size_t chunk : CHUNKS)
		// Проверяем поток кусками заданного размера
		slice(aes, n, a, p, s, e, chunk);
}

/**
 * Проверка случаев 1-6 описания GCM на AES-128
 */
TEST(GcmTest, Aes128){
	// Случай 1: пустые заполнение нулями, текст и связанные данные
	check("00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
	// Случай 2: один нулевой блок
	check("00000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf");
	// Случай 3: четыре блока без связанных данных
	check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4");
	// Случай 4: неполный последний блок и связанные данные
	check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
	// Случай 5: заполнение в 8 байтов через многочлен
	check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbad", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb");
	// Случай 6: заполнение в 60 байтов через многочлен
	check("feffe9928665731c6d6a8f9467308308", "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050");
}

/**
 * Проверка случаев 13-16 описания GCM на AES-256
 */
TEST(GcmTest, Aes256){
	// Случай 13: пустые текст и связанные данные
	check("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b");
	// Случай 14: один нулевой блок
	check("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919");
	// Случай 15: четыре блока
	check("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad", "b094dac5d93471bdec1a502270e3cc6c");
	// Случай 16: неполный блок и связанные данные
	check("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b");
}

/**
 * Проверка отказов договора и усечённой метки
 */
TEST(GcmTest, Refusals){
	// Ключ
	const std::vector <uint8_t> key = bytes("feffe9928665731c6d6a8f9467308308");
	// Заполнение
	const std::vector <uint8_t> nonce = bytes("cafebabefacedbaddecaf888");
	// Объект шифра
	cipher::aes_t aes;
	// Объект режима
	cipher::gcm_t gcm;
	// Проверяем отказ запуска без ключа
	ASSERT_FALSE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Проверяем отказ запуска без заполнения
	ASSERT_FALSE(gcm.start(cipher::block_t(aes), view_t()));
	// Проверяем отказ метки короче четырёх байтов
	ASSERT_FALSE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size()), 3));
	// Проверяем отказ метки длиннее шестнадцати байтов
	ASSERT_FALSE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size()), 17));
	// Проверяем запуск с меткой в 12 байтов
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size()), 12));
	// Проверяем длину метки
	ASSERT_EQ(gcm.size(), 12u);
	// Открытый текст
	const std::vector <uint8_t> plain = bytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72");
	// Шифртекст
	uint8_t sealed[32];
	// Метка
	uint8_t tag[16];
	// Проверяем зашифрование
	ASSERT_TRUE(gcm.encrypt(view_t(), view_t(plain.data(), plain.size()), sealed, tag));
	// Проверяем усечённую метку: старшие 12 байтов метки случая 3 на первых двух блоках
	uint8_t opened[32];
	// Проверяем расшифрование с меткой в 12 байтов
	ASSERT_TRUE(gcm.decrypt(view_t(), view_t(sealed, sizeof(sealed)), opened, view_t(tag, 12)));
	// Проверяем отказ расшифрования с меткой не той длины
	ASSERT_FALSE(gcm.decrypt(view_t(), view_t(sealed, sizeof(sealed)), opened, view_t(tag, 16)));
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
	// Проверяем отказ расшифрования с испорченными связанными данными
	ASSERT_FALSE(gcm.decrypt(view_t(reinterpret_cast <const uint8_t *> ("x"), 1), view_t(sealed, sizeof(sealed)), opened, view_t(tag, 12)));
	// Выполняем сброс режима
	gcm.clear();
	// Проверяем неготовность после сброса
	ASSERT_FALSE(gcm.ready());
	// Проверяем отказ зашифрования после сброса
	ASSERT_FALSE(gcm.encrypt(view_t(), view_t(plain.data(), plain.size()), sealed, tag));
}

/**
 * Проверка векторов на пути таблиц: разовый вызов и поток
 */
TEST(GcmTest, Tables){
	// Запрещаем машинные команды
	machine::allow(false);
	// Случай 4: неполный последний блок и связанные данные
	check("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
	// Случай 6: заполнение в 60 байтов через многочлен
	check("feffe9928665731c6d6a8f9467308308", "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050");
	// Случай 16: AES-256, неполный блок и связанные данные
	check("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b");
	// Возвращаем машинные команды
	machine::allow(true);
}

/**
 * Проверка заслонов потока: направление, порядок, заслон заполнения, длина метки
 */
TEST(GcmTest, Stream){
	// Ключ
	const std::vector <uint8_t> key = bytes("feffe9928665731c6d6a8f9467308308");
	// Заполнение
	const std::vector <uint8_t> nonce = bytes("cafebabefacedbaddecaf888");
	// Открытый текст в 100 байтов: четыре блока для сложения по четыре и остаток
	std::vector <uint8_t> plain(100);
	/**
	 * Выполняем заполнение открытого текста
	 */
	for(size_t i = 0; i < plain.size(); i++)
		// Записываем очередной байт
		plain[i] = static_cast <uint8_t> (i * 5 + 1);
	// Объект шифра
	cipher::aes_t aes;
	// Проверяем установку ключа
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Объект режима
	cipher::gcm_t gcm;
	// Шифртекст и метка
	uint8_t sealed[100], tag[16];
	// Проверяем отказ потока до запуска
	ASSERT_FALSE(gcm.associate(view_t(plain.data(), 4)));
	// Проверяем отказ куска до запуска
	ASSERT_FALSE(gcm.encrypt(view_t(plain.data(), 4), sealed));
	// Проверяем отказ завершения до запуска
	ASSERT_FALSE(gcm.finish(tag));
	// Проверяем запуск режима
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем отказ завершения без места под метку
	ASSERT_FALSE(gcm.finish(nullptr));
	// Проверяем отказ объявленного непустым, но не переданного куска
	ASSERT_FALSE(gcm.encrypt(view_t(nullptr, 4), sealed));
	// Проверяем отказ куска без места под итог
	ASSERT_FALSE(gcm.encrypt(view_t(plain.data(), 4), nullptr));
	// Проверяем зашифрование первого куска в один байт
	ASSERT_TRUE(gcm.encrypt(view_t(plain.data(), 1), sealed));
	// Проверяем отказ смены направления посреди потока
	ASSERT_FALSE(gcm.decrypt(view_t(plain.data() + 1, 1), sealed + 1));
	// Проверяем отказ связанных данных после данных
	ASSERT_FALSE(gcm.associate(view_t(plain.data(), 1)));
	// Проверяем отказ сличения посреди зашифрования
	ASSERT_FALSE(gcm.verify(view_t(tag, sizeof(tag))));
	// Проверяем зашифрование остатка
	ASSERT_TRUE(gcm.encrypt(view_t(plain.data() + 1, plain.size() - 1), sealed + 1));
	// Проверяем снятие метки
	ASSERT_TRUE(gcm.finish(tag));
	// Проверяем отказ повторного снятия метки: поток закрыт
	ASSERT_FALSE(gcm.finish(tag));
	// Проверяем отказ куска после закрытия
	ASSERT_FALSE(gcm.decrypt(view_t(sealed, 1), sealed));
	// Проверяем отказ разового зашифрования: заполнение израсходовано потоком
	ASSERT_FALSE(gcm.encrypt(view_t(), view_t(plain.data(), plain.size()), sealed, tag));
	// Открытый текст
	uint8_t opened[100];
	// Проверяем разовое расшифрование того, что зашифровано потоком
	ASSERT_TRUE(gcm.decrypt(view_t(), view_t(sealed, sizeof(sealed)), opened, view_t(tag, sizeof(tag))));
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened, plain.data(), plain.size()), 0);
	// Проверяем перезапуск: заслон заполнения сброшен
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем отказ сличения метки не той длины
	ASSERT_FALSE(gcm.verify(view_t(tag, 12)));
	// Проверяем поточное расшифрование разом
	ASSERT_TRUE(gcm.decrypt(view_t(sealed, sizeof(sealed)), opened));
	// Проверяем отказ снятия метки посреди расшифрования
	ASSERT_FALSE(gcm.finish(tag));
	// Портим метку
	tag[15] ^= 0x01;
	// Проверяем отказ сличения порченой метки
	ASSERT_FALSE(gcm.verify(view_t(tag, sizeof(tag))));
	// Восстанавливаем метку
	tag[15] ^= 0x01;
	// Проверяем перезапуск и пустой поток: метка пустого текста снимается на завершении
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем снятие метки без единого куска
	ASSERT_TRUE(gcm.finish(tag));
	// Проверяем отказ повторного потока без перезапуска: заполнение израсходовано
	ASSERT_FALSE(gcm.encrypt(view_t(), nullptr));
	// Проверяем перезапуск и сличение метки пустого текста потоком
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем сличение метки без единого куска
	ASSERT_TRUE(gcm.verify(view_t(tag, sizeof(tag))));
	// Выполняем сброс режима
	gcm.clear();
	// Проверяем отказ потока после сброса
	ASSERT_FALSE(gcm.encrypt(view_t(plain.data(), 1), sealed));
}

/**
 * Проверка схождения обоих путей: командами машины и таблицами
 */
TEST(GcmTest, Paths){
	// Ключ
	const std::vector <uint8_t> key = bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
	// Заполнение в 13 байтов: путь через многочлен
	const std::vector <uint8_t> nonce = bytes("cafebabefacedbaddecaf88801");
	// Связанные данные
	const std::vector <uint8_t> associated = bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
	// Открытый текст в 137 байтов
	std::vector <uint8_t> plain(137);
	/**
	 * Выполняем заполнение открытого текста
	 */
	for(size_t i = 0; i < plain.size(); i++)
		// Записываем очередной байт
		plain[i] = static_cast <uint8_t> (i * 7 + 3);
	// Шифртексты и метки обоих путей
	std::vector <uint8_t> first(plain.size()), second(plain.size());
	// Метки обоих путей
	uint8_t tag1[16], tag2[16];
	// Объект шифра
	cipher::aes_t aes;
	// Объект режима
	cipher::gcm_t gcm;
	// Выполняем зашифрование на пути, выбранном машиной
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Проверяем запуск режима
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем зашифрование
	ASSERT_TRUE(gcm.encrypt(view_t(associated.data(), associated.size()), view_t(plain.data(), plain.size()), first.data(), tag1));
	// Запрещаем машинные команды
	machine::allow(false);
	// Выполняем установку ключа заново: таблицы шифра строятся при установке
	ASSERT_TRUE(aes.key(view_t(key.data(), key.size())));
	// Проверяем запуск режима таблицами
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем зашифрование таблицами
	ASSERT_TRUE(gcm.encrypt(view_t(associated.data(), associated.size()), view_t(plain.data(), plain.size()), second.data(), tag2));
	// Проверяем расшифрование таблицами того, что зашифровано командами
	std::vector <uint8_t> opened(plain.size());
	// Проверяем перезапуск
	ASSERT_TRUE(gcm.start(cipher::block_t(aes), view_t(nonce.data(), nonce.size())));
	// Проверяем расшифрование
	ASSERT_TRUE(gcm.decrypt(view_t(associated.data(), associated.size()), view_t(first.data(), first.size()), opened.data(), view_t(tag1, sizeof(tag1))));
	// Возвращаем машинные команды
	machine::allow(true);
	// Проверяем схождение шифртекстов
	ASSERT_EQ(text(first.data(), first.size()), text(second.data(), second.size()));
	// Проверяем схождение меток
	ASSERT_EQ(text(tag1, sizeof(tag1)), text(tag2, sizeof(tag2)));
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened.data(), plain.data(), plain.size()), 0);
}
