/**
 * @file: chacha.cpp
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
#include <cstdlib>
#include <fstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <cipher/chacha.hpp>

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
 * @brief Метод запуска команды оболочки без консоли на входе
 *
 * @details stdin подаётся из /dev/null: у оболочки инструмента разработки он бывает
 *          сокетом, и консольный слой openssl валит работу даже там, где консоль не
 *          нужна
 *
 * @param command запускаемая команда
 *
 * @return        код возврата команды
 *
 */
static int shell(const std::string & command) {
	// Запускаем команду с пустым входом
	return ::system((command + " </dev/null").c_str());
}

/**
 * @brief Временный каталог обмена с openssl, сносимый и при отказе проверки
 *
 */
typedef struct Sandbox {
	// Путь к временному каталогу
	std::string path;
	/**
	 * @brief Конструктор
	 *
	 */
	Sandbox() {
		// Образец имени временного каталога
		char pattern[] = "/tmp/ants-chacha-XXXXXX";
		// Если временный каталог создан
		if(::mkdtemp(pattern) != nullptr)
			// Запоминаем путь к каталогу
			this->path = pattern;
	}
	/**
	 * @brief Деструктор
	 *
	 */
	~Sandbox() {
		// Если каталог создан
		if(!this->path.empty())
			// Удаляем каталог со всем содержимым
			(void) shell("rm -rf " + this->path);
	}
} sandbox_t;

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
 * Ключ в 32 байта от нуля до 31: разделы 2.3.2 и 2.4.2 RFC 8439
 */
static const char * KEY_SEQUENCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/**
 * Открытый текст раздела 2.4.2 RFC 8439: 114 байтов
 */
static const char * SUNSCREEN = "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e";

/**
 * Открытый текст случая 2 приложения A.2 RFC 8439: 375 байтов
 */
static const char * IETF = "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f";

/**
 * Открытый текст случая 3 приложения A.2 RFC 8439: 127 байтов
 */
static const char * JABBERWOCKY = "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e";

/**
 * @brief Метод проверки блочной функции
 *
 * @param key      ключ
 * @param nonce    начальное заполнение
 * @param counter  счётчик блока
 * @param expected ожидаемый блок гаммы
 *
 */
static void block(const std::string & key, const std::string & nonce, const uint32_t counter, const std::string & expected) {
	// Разобранные байты случая
	const std::vector <uint8_t> k = bytes(key), n = bytes(nonce);
	// Объект шифра
	cipher::chacha_t chacha;
	// Проверяем запуск шифра
	ASSERT_TRUE(chacha.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()), counter)) << "случай " << expected;
	// Проверяем счётчик после запуска
	ASSERT_EQ(chacha.counter(), counter);
	// Блок гаммы
	uint8_t gamma[cipher::CHACHA_BLOCK];
	// Проверяем выработку блока
	ASSERT_TRUE(chacha.block(gamma)) << "случай " << expected;
	// Проверяем блок гаммы
	ASSERT_EQ(text(gamma, sizeof(gamma)), expected);
	// Проверяем продвижение счётчика
	ASSERT_EQ(chacha.counter(), counter + 1);
	// Нулевой текст того же блока
	uint8_t zeros[cipher::CHACHA_BLOCK] = {0};
	// Шифртекст нулевого текста
	uint8_t sealed[cipher::CHACHA_BLOCK];
	// Проверяем перезапуск
	ASSERT_TRUE(chacha.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()), counter));
	// Проверяем зашифрование нулевого текста: гамма выходит как есть
	ASSERT_TRUE(chacha.encrypt(view_t(zeros, sizeof(zeros)), sealed));
	// Проверяем схождение гаммы с блоком
	ASSERT_EQ(text(sealed, sizeof(sealed)), expected);
}

/**
 * @brief Метод поточной проверки случая кусками заданного размера
 *
 * @param key     ключ
 * @param nonce   начальное заполнение
 * @param counter счётчик блока
 * @param plain   открытый текст
 * @param sealed  ожидаемый шифртекст
 * @param chunk   размер куска
 *
 */
static void slice(const std::vector <uint8_t> & key, const std::vector <uint8_t> & nonce, const uint32_t counter, const std::vector <uint8_t> & plain, const std::vector <uint8_t> & sealed, const size_t chunk) {
	// Объект шифра
	cipher::chacha_t chacha;
	// Проверяем запуск шифра
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), counter)) << "кусок " << chunk;
	// Шифртекст потока
	std::vector <uint8_t> output(plain.size() + 1);
	// Проверяем пустой кусок
	ASSERT_TRUE(chacha.encrypt(view_t(), nullptr)) << "кусок " << chunk;
	/**
	 * Выполняем подачу открытого текста кусками
	 */
	for(size_t offset = 0; offset < plain.size(); offset += chunk)
		// Проверяем зашифрование куска
		ASSERT_TRUE(chacha.encrypt(view_t(plain.data() + offset, (((plain.size() - offset) < chunk) ? (plain.size() - offset) : chunk)), output.data() + offset)) << "кусок " << chunk;
	// Проверяем схождение шифртекста с ожидаемым
	ASSERT_EQ(::memcmp(output.data(), sealed.data(), plain.size()), 0) << "кусок " << chunk;
	// Проверяем перезапуск
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), counter)) << "кусок " << chunk;
	// Открытый текст потока
	std::vector <uint8_t> opened(plain.size() + 1);
	/**
	 * Выполняем подачу шифртекста кусками
	 */
	for(size_t offset = 0; offset < sealed.size(); offset += chunk)
		// Проверяем расшифрование куска
		ASSERT_TRUE(chacha.decrypt(view_t(sealed.data() + offset, (((sealed.size() - offset) < chunk) ? (sealed.size() - offset) : chunk)), opened.data() + offset)) << "кусок " << chunk;
	// Проверяем схождение открытого текста
	ASSERT_EQ(::memcmp(opened.data(), plain.data(), plain.size()), 0) << "кусок " << chunk;
}

/**
 * @brief Метод проверки случая шифрования
 *
 * @param key     ключ
 * @param nonce   начальное заполнение
 * @param counter счётчик блока
 * @param plain   открытый текст
 * @param sealed  ожидаемый шифртекст
 *
 */
static void check(const std::string & key, const std::string & nonce, const uint32_t counter, const std::string & plain, const std::string & sealed) {
	// Разобранные байты случая
	const std::vector <uint8_t> k = bytes(key), n = bytes(nonce), p = bytes(plain), s = bytes(sealed);
	// Проверяем длины открытого текста и шифртекста
	ASSERT_EQ(p.size(), s.size());
	// Объект шифра
	cipher::chacha_t chacha;
	// Проверяем запуск шифра
	ASSERT_TRUE(chacha.start(view_t(k.data(), k.size()), view_t(n.data(), n.size()), counter));
	// Шифртекст разом
	std::vector <uint8_t> c(p.size() + 1);
	// Проверяем зашифрование разом
	ASSERT_TRUE(chacha.encrypt(view_t(p.data(), p.size()), c.data()));
	// Проверяем шифртекст
	ASSERT_EQ(text(c.data(), p.size()), sealed);
	/**
	 * Выполняем поточную проверку по всем размерам куска
	 */
	for(const size_t chunk : CHUNKS)
		// Проверяем поток кусками заданного размера
		slice(k, n, counter, p, s, chunk);
}

/**
 * Проверка четвертьраунда: разделы 2.1.1 и 2.2.1 RFC 8439
 */
TEST(ChachaTest, QuarterRound){
	// Слова раздела 2.1.1
	uint32_t a = 0x11111111, b = 0x01020304, c = 0x9B8D6F43, d = 0x01234567;
	// Выполняем четвертьраунд
	cipher::chacha_t::quarter(a, b, c, d);
	// Проверяем первое слово
	ASSERT_EQ(a, 0xEA2A92F4u);
	// Проверяем второе слово
	ASSERT_EQ(b, 0xCB1CF8CEu);
	// Проверяем третье слово
	ASSERT_EQ(c, 0x4581472Eu);
	// Проверяем четвёртое слово
	ASSERT_EQ(d, 0x5881C4BBu);
	// Состояние раздела 2.2.1
	uint32_t state[16] = {
		0x879531E0, 0xC5ECF37D, 0x516461B1, 0xC9A62F8A,
		0x44C20EF3, 0x3390AF7F, 0xD9FC690B, 0x2A5F714C,
		0x53372767, 0xB00A5631, 0x974C541A, 0x359E9963,
		0x5C971061, 0x3D631689, 0x2098D9D4, 0x91DBD320
	};
	// Ожидаемое состояние после четвертьраунда над словами 2, 7, 8, 13
	const uint32_t expected[16] = {
		0x879531E0, 0xC5ECF37D, 0xBDB886DC, 0xC9A62F8A,
		0x44C20EF3, 0x3390AF7F, 0xD9FC690B, 0xCFACAFD2,
		0xE46BEA80, 0xB00A5631, 0x974C541A, 0x359E9963,
		0x5C971061, 0xCCC07C79, 0x2098D9D4, 0x91DBD320
	};
	// Выполняем четвертьраунд над диагональю
	cipher::chacha_t::quarter(state[2], state[7], state[8], state[13]);
	/**
	 * Выполняем сличение слов состояния
	 */
	for(size_t i = 0; i < 16; i++)
		// Проверяем очередное слово
		ASSERT_EQ(state[i], expected[i]) << "слово " << i;
}

/**
 * Проверка блочной функции: раздел 2.3.2 и приложение A.1 RFC 8439
 */
TEST(ChachaTest, Block){
	// Раздел 2.3.2: ключ по порядку, заполнение с девяткой и 0x4a, счётчик один
	block(KEY_SEQUENCE, "000000090000004a00000000", 1, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
	// A.1 случай 1: всё нули
	block("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 0, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
	// A.1 случай 2: счётчик один
	block("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 1, "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
	// A.1 случай 3: единица в последнем байте ключа
	block("0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000000", 1, "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0");
	// A.1 случай 4: 0xff во втором байте ключа, счётчик два
	block("00ff000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 2, "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096");
	// A.1 случай 5: двойка в последнем байте заполнения
	block("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000002", 0, "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c78a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d");
}

/**
 * Проверка шифрования: раздел 2.4.2 и приложение A.2 RFC 8439, разом и потоком
 */
TEST(ChachaTest, Encrypt){
	// Раздел 2.4.2: текст про солнцезащитный крем
	check(KEY_SEQUENCE, "000000000000004a00000000", 1, SUNSCREEN, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
	// A.2 случай 1: нулевой блок на нулях
	check("0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", 0, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
	// A.2 случай 2: текст IETF в 375 байтов
	check("0000000000000000000000000000000000000000000000000000000000000001", "000000000000000000000002", 1, IETF, "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221");
	// A.2 случай 3: Бармаглот в 127 байтов, счётчик 42
	check("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "000000000000000000000002", 42, JABBERWOCKY, "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1");
}

/**
 * Проверка выработки ключа Poly1305: раздел 2.6.2 и приложение A.4 RFC 8439
 */
TEST(ChachaTest, PolyKey){
	// Раздел 2.6.2: ключ от 0x80, заполнение с порядком
	block("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "000000000001020304050607", 0, "8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a6468237a07d33a2839171d28a14d17367b45a87c13cf1de078686305cca87eb8570");
}

/**
 * Проверка отказов договора и переполнения счётчика
 */
TEST(ChachaTest, Refusals){
	// Ключ
	const std::vector <uint8_t> key = bytes(KEY_SEQUENCE);
	// Заполнение
	const std::vector <uint8_t> nonce = bytes("000000000000004a00000000");
	// Объект шифра
	cipher::chacha_t chacha;
	// Блок гаммы
	uint8_t gamma[cipher::CHACHA_BLOCK];
	// Проверяем неготовность до запуска
	ASSERT_FALSE(chacha.ready());
	// Проверяем отказ блока до запуска
	ASSERT_FALSE(chacha.block(gamma));
	// Проверяем отказ куска до запуска
	ASSERT_FALSE(chacha.encrypt(view_t(key.data(), 4), gamma));
	// Проверяем отказ запуска без ключа
	ASSERT_FALSE(chacha.start(view_t(), view_t(nonce.data(), nonce.size())));
	// Проверяем отказ запуска с коротким ключом
	ASSERT_FALSE(chacha.start(view_t(key.data(), 31), view_t(nonce.data(), nonce.size())));
	// Проверяем отказ запуска без заполнения
	ASSERT_FALSE(chacha.start(view_t(key.data(), key.size()), view_t()));
	// Проверяем отказ запуска с заполнением в 8 байтов
	ASSERT_FALSE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), 8)));
	// Проверяем отказ запуска с ключом, объявленным непустым, но не переданным
	ASSERT_FALSE(chacha.start(view_t(nullptr, 32), view_t(nonce.data(), nonce.size())));
	// Проверяем неготовность после отказов
	ASSERT_FALSE(chacha.ready());
	// Проверяем запуск
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size())));
	// Проверяем готовность
	ASSERT_TRUE(chacha.ready());
	// Проверяем отказ блока без места
	ASSERT_FALSE(chacha.block(nullptr));
	// Проверяем отказ куска, объявленного непустым, но не переданного
	ASSERT_FALSE(chacha.encrypt(view_t(nullptr, 4), gamma));
	// Проверяем отказ куска без места под итог
	ASSERT_FALSE(chacha.encrypt(view_t(key.data(), 4), nullptr));
	// Проверяем сброс
	chacha.clear();
	// Проверяем неготовность после сброса
	ASSERT_FALSE(chacha.ready());
	// Проверяем отказ куска после сброса
	ASSERT_FALSE(chacha.encrypt(view_t(key.data(), 4), gamma));
	// Проверяем запуск на последнем значении счётчика
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0xFFFFFFFF));
	// Проверяем выработку последнего блока
	ASSERT_TRUE(chacha.block(gamma));
	// Проверяем отказ следующего блока: счётчик переполнен
	ASSERT_FALSE(chacha.block(gamma));
	// Проверяем перезапуск на последнем значении счётчика
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0xFFFFFFFF));
	// Текст в 65 байтов: на один больше последнего блока
	uint8_t plain[65] = {0};
	// Шифртекст
	uint8_t sealed[65];
	// Проверяем зашифрование ровно последнего блока
	ASSERT_TRUE(chacha.encrypt(view_t(plain, 64), sealed));
	// Проверяем отказ куска за пределом счётчика
	ASSERT_FALSE(chacha.encrypt(view_t(plain + 64, 1), sealed + 64));
	// Проверяем перезапуск на последнем значении счётчика
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0xFFFFFFFF));
	// Проверяем отказ куска длиннее последнего блока
	ASSERT_FALSE(chacha.encrypt(view_t(plain, sizeof(plain)), sealed));
	// Проверяем перезапуск на предпоследнем значении счётчика
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0xFFFFFFFE));
	// Проверяем зашифрование через два последних блока
	ASSERT_TRUE(chacha.encrypt(view_t(plain, sizeof(plain)), sealed));
	// Проверяем отказ третьего блока
	ASSERT_FALSE(chacha.encrypt(view_t(plain, 64), sealed));
}

/**
 * Проверка того, что блок отбрасывает остаток гаммы, а поток продолжает с нового блока
 */
TEST(ChachaTest, BlockDiscardsRest){
	// Ключ
	const std::vector <uint8_t> key = bytes(KEY_SEQUENCE);
	// Заполнение
	const std::vector <uint8_t> nonce = bytes("000000000000004a00000000");
	// Открытый текст раздела 2.4.2
	const std::vector <uint8_t> plain = bytes(SUNSCREEN);
	// Ожидаемый шифртекст раздела 2.4.2 от счётчика один
	const std::vector <uint8_t> expected = bytes("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
	// Объект шифра
	cipher::chacha_t chacha;
	// Проверяем запуск на счётчике ноль
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0));
	// Шифртекст
	std::vector <uint8_t> sealed(plain.size());
	// Проверяем зашифрование одного байта: блок ноль начат
	ASSERT_TRUE(chacha.encrypt(view_t(plain.data(), 1), sealed.data()));
	// Блок гаммы
	uint8_t gamma[cipher::CHACHA_BLOCK];
	// Проверяем выработку блока один: остаток блока ноль отброшен
	ASSERT_TRUE(chacha.block(gamma));
	// Проверяем счётчик
	ASSERT_EQ(chacha.counter(), 2u);
	// Проверяем перезапуск на счётчике ноль
	ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 0));
	// Проверяем выработку блока ноль: ключ Poly1305 берётся так
	ASSERT_TRUE(chacha.block(gamma));
	// Проверяем зашифрование текста: продолжение от блока один даёт вектор раздела 2.4.2
	ASSERT_TRUE(chacha.encrypt(view_t(plain.data(), plain.size()), sealed.data()));
	// Проверяем схождение с вектором
	ASSERT_EQ(sealed, expected);
}

/**
 * Нехватка памяти: шифр не выделяет памяти вовсе и обязан работать при нулевом запасе
 */
TEST(ChachaTest, Starved){
	// Ключ
	const std::vector <uint8_t> key = bytes(KEY_SEQUENCE);
	// Заполнение
	const std::vector <uint8_t> nonce = bytes("000000000000004a00000000");
	// Открытый текст
	const std::vector <uint8_t> plain = bytes(IETF);
	// Шифртекст
	std::vector <uint8_t> sealed(plain.size());
	// Открытый текст после расшифрования
	std::vector <uint8_t> opened(plain.size());
	// Итог зашифрования
	bool outcome = false;
	// Итог расшифрования
	bool reverse = false;
	{
		// Отмеряем нулевой запас выделений: всякое выделение под noexcept прервало бы исполнение
		starve::ration_t ration(0);
		// Объект шифра
		cipher::chacha_t chacha;
		// Выполняем запуск шифра
		outcome = chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 1);
		/**
		 * Выполняем подачу текста кусками по 37 байтов
		 */
		for(size_t offset = 0; outcome && (offset < plain.size()); offset += 37)
			// Подаём очередной кусок
			outcome = chacha.encrypt(view_t(plain.data() + offset, (((plain.size() - offset) < 37) ? (plain.size() - offset) : 37)), sealed.data() + offset);
		// Выполняем перезапуск шифра
		reverse = chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 1);
		// Если перезапуск прошёл
		if(reverse)
			// Выполняем расшифрование разом
			reverse = chacha.decrypt(view_t(sealed.data(), sealed.size()), opened.data());
	}
	// Проверяем успешность зашифрования без единого выделения
	ASSERT_TRUE(outcome);
	// Проверяем успешность расшифрования без единого выделения
	ASSERT_TRUE(reverse);
	// Проверяем схождение открытого текста
	ASSERT_EQ(opened, plain);
}

/**
 * Проверка обмена с openssl: поток случайных длин, не кратных блоку, в обе стороны
 */
TEST(ChachaTest, Openssl){
	// Если openssl недоступен
	if(shell("openssl version >/dev/null 2>&1") != 0)
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl недоступен";
	// Если openssl не умеет ChaCha20
	if(shell("echo x | openssl enc -chacha20 -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 -out /dev/null >/dev/null 2>&1") != 0)
		// Пропускаем проверку вслух
		GTEST_SKIP() << "openssl не умеет chacha20";
	// Временный каталог обмена
	sandbox_t box;
	// Проверяем создание временного каталога
	ASSERT_FALSE(box.path.empty());
	// Путь к временному каталогу
	const std::string & sandbox = box.path;
	// Генератор случайных чисел с закреплённым зерном
	std::mt19937 generator(20260904u);
	// Длины, не кратные 64: случайные и обрамляющие блок
	const size_t LENGTHS[] = {1, 63, 65, 127, 129, 1000, 4097, 12345};
	/**
	 * Выполняем перебор длин
	 */
	for(const size_t length : LENGTHS){
		// Ключ, заполнение и текст случая
		std::vector <uint8_t> key(32), nonce(12), plain(length);
		/**
		 * Выполняем заполнение ключа
		 */
		for(uint8_t & byte : key)
			// Записываем очередной байт
			byte = static_cast <uint8_t> (generator());
		/**
		 * Выполняем заполнение начального заполнения
		 */
		for(uint8_t & byte : nonce)
			// Записываем очередной байт
			byte = static_cast <uint8_t> (generator());
		/**
		 * Выполняем заполнение текста
		 */
		for(uint8_t & byte : plain)
			// Записываем очередной байт
			byte = static_cast <uint8_t> (generator());
		// Счётчик блока: случайный в младшем байте, чтобы задеть и ненулевой
		const uint32_t counter = static_cast <uint32_t> (generator() & 0xFF);
		// Путь к открытому тексту
		const std::string input = (sandbox + "/plain.bin");
		// Путь к шифртексту openssl
		const std::string output = (sandbox + "/sealed.bin");
		{
			// Файл открытого текста
			std::ofstream file(input, std::ios::binary);
			// Записываем открытый текст
			file.write(reinterpret_cast <const char *> (plain.data()), static_cast <std::streamsize> (plain.size()));
		}
		// Вектор openssl: счётчик от младшего байта и заполнение
		uint8_t iv[16];
		// Записываем младший байт счётчика
		iv[0] = static_cast <uint8_t> (counter);
		// Записываем второй байт счётчика
		iv[1] = static_cast <uint8_t> (counter >> 8);
		// Записываем третий байт счётчика
		iv[2] = static_cast <uint8_t> (counter >> 16);
		// Записываем старший байт счётчика
		iv[3] = static_cast <uint8_t> (counter >> 24);
		// Переносим заполнение
		::memcpy(iv + 4, nonce.data(), 12);
		// Проверяем зашифрование openssl
		ASSERT_EQ(shell("openssl enc -chacha20 -K " + text(key.data(), key.size()) + " -iv " + text(iv, sizeof(iv)) + " -in " + input + " -out " + output + " 2>/dev/null"), 0) << "длина " << length;
		// Шифртекст openssl
		std::vector <uint8_t> reference;
		{
			// Файл шифртекста
			std::ifstream file(output, std::ios::binary);
			// Читаем шифртекст
			reference.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		}
		// Проверяем длину шифртекста openssl
		ASSERT_EQ(reference.size(), length) << "длина " << length;
		// Объект шифра
		cipher::chacha_t chacha;
		// Проверяем запуск шифра
		ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), counter));
		// Шифртекст свой
		std::vector <uint8_t> sealed(length);
		// Размер куска: случайный от 1 до 100
		const size_t chunk = (static_cast <size_t> (generator() % 100) + 1);
		/**
		 * Выполняем подачу текста кусками
		 */
		for(size_t offset = 0; offset < plain.size(); offset += chunk)
			// Проверяем зашифрование куска
			ASSERT_TRUE(chacha.encrypt(view_t(plain.data() + offset, (((plain.size() - offset) < chunk) ? (plain.size() - offset) : chunk)), sealed.data() + offset)) << "длина " << length << ", кусок " << chunk;
		// Проверяем схождение с openssl
		ASSERT_EQ(sealed, reference) << "длина " << length << ", кусок " << chunk << ", счётчик " << counter;
		// Проверяем перезапуск
		ASSERT_TRUE(chacha.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), counter));
		// Открытый текст из шифртекста openssl
		std::vector <uint8_t> opened(length);
		// Проверяем расшифрование шифртекста openssl
		ASSERT_TRUE(chacha.decrypt(view_t(reference.data(), reference.size()), opened.data()));
		// Проверяем схождение открытого текста
		ASSERT_EQ(opened, plain) << "длина " << length;
	}
}
