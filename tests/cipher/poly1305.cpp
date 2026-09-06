/**
 * @file: poly1305.cpp
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

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <cipher/poly1305.hpp>

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
 * Сообщение случаев 2 и 3 приложения A.3 RFC 8439: текст IETF в 375 байтов
 */
static const char * IETF = "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f";

/**
 * Сообщение случая 4 приложения A.3 RFC 8439: Бармаглот в 127 байтов
 */
static const char * JABBERWOCKY = "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e";

/**
 * @brief Метод проверки одного случая имитовставки разом и потоком
 *
 * @param key      ключ
 * @param message  сообщение
 * @param expected ожидаемая метка
 *
 */
static void check(const std::string & key, const std::string & message, const std::string & expected) {
	// Разобранные байты случая
	const std::vector <uint8_t> k = bytes(key), m = bytes(message);
	// Объект имитовставки
	cipher::poly1305_t poly;
	// Проверяем запуск
	ASSERT_TRUE(poly.start(view_t(k.data(), k.size()))) << "случай " << expected;
	// Проверяем подачу разом
	ASSERT_TRUE(poly.update(view_t(m.data(), m.size()))) << "случай " << expected;
	// Метка
	uint8_t tag[cipher::POLY1305_TAG];
	// Проверяем снятие метки
	ASSERT_TRUE(poly.finish(tag)) << "случай " << expected;
	// Проверяем метку
	ASSERT_EQ(text(tag, sizeof(tag)), expected);
	// Проверяем завершённость: повтор снятия отвергается
	ASSERT_FALSE(poly.finish(tag));
	// Проверяем отказ подачи после снятия
	ASSERT_FALSE(poly.update(view_t(m.data(), m.size())));
	/**
	 * Выполняем поточную проверку по всем размерам куска
	 */
	for(const size_t chunk : CHUNKS){
		// Проверяем перезапуск
		ASSERT_TRUE(poly.start(view_t(k.data(), k.size()))) << "кусок " << chunk;
		// Проверяем подачу пустого куска
		ASSERT_TRUE(poly.update(view_t())) << "кусок " << chunk;
		/**
		 * Выполняем подачу сообщения кусками
		 */
		for(size_t offset = 0; offset < m.size(); offset += chunk)
			// Проверяем подачу куска
			ASSERT_TRUE(poly.update(view_t(m.data() + offset, (((m.size() - offset) < chunk) ? (m.size() - offset) : chunk)))) << "кусок " << chunk;
		// Проверяем подачу пустого куска в конце
		ASSERT_TRUE(poly.update(view_t())) << "кусок " << chunk;
		// Проверяем снятие метки
		ASSERT_TRUE(poly.finish(tag)) << "кусок " << chunk;
		// Проверяем схождение метки с разовой
		ASSERT_EQ(text(tag, sizeof(tag)), expected) << "кусок " << chunk;
	}
}

/**
 * Проверка вектора раздела 2.5.2 RFC 8439
 */
TEST(Poly1305Test, Rfc){
	// Раздел 2.5.2: «Cryptographic Forum Research Group»
	check("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", "43727970746f6772617068696320466f72756d2052657365617263682047726f7570", "a8061dc1305136c6c22b8baf0c0127a9");
}

/**
 * Проверка векторов приложения A.3 RFC 8439
 */
TEST(Poly1305Test, Appendix){
	// Случай 1: всё нули
	check("0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000000");
	// Случай 2: r нулевой, метка равна s
	check("0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e", IETF, "36e5f6b5c5e06070f0efca96227a863e");
	// Случай 3: s нулевой
	check("36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000", IETF, "f3477e7cd95417af89a6b8794c310cf0");
	// Случай 4: Бармаглот
	check("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", JABBERWOCKY, "4541669a7eaaee61e708dc7cbcc5eb62");
	// Случай 5: r = 2, сообщение 2^128 - 1: проверка приведения
	check("0200000000000000000000000000000000000000000000000000000000000000", "ffffffffffffffffffffffffffffffff", "03000000000000000000000000000000");
	// Случай 6: r = 2, s = 2^128 - 1, сообщение 2
	check("02000000000000000000000000000000ffffffffffffffffffffffffffffffff", "02000000000000000000000000000000", "03000000000000000000000000000000");
	// Случай 7: r = 1, сумма даёт 2^130 - 5 + 5 + 1
	check("0100000000000000000000000000000000000000000000000000000000000000", "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000", "05000000000000000000000000000000");
	// Случай 8: r = 1, сумма даёт ровно 2^130 - 5: приведение в ноль
	check("0100000000000000000000000000000000000000000000000000000000000000", "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101", "00000000000000000000000000000000");
	// Случай 9: r = 2, сообщение 2^128 - 3: метка 2^128 - 6
	check("0200000000000000000000000000000000000000000000000000000000000000", "fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff");
	// Случай 10: r с двумя единицами, четыре блока: переносы конечностей
	check("0100000000000000040000000000000000000000000000000000000000000000", "e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000", "14000000000000005500000000000000");
	// Случай 11: то же на трёх блоках
	check("0100000000000000040000000000000000000000000000000000000000000000", "e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000", "13000000000000000000000000000000");
}

/**
 * Проверка отказов договора
 */
TEST(Poly1305Test, Refusals){
	// Ключ
	const std::vector <uint8_t> key = bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
	// Объект имитовставки
	cipher::poly1305_t poly;
	// Метка
	uint8_t tag[cipher::POLY1305_TAG];
	// Проверяем неготовность до запуска
	ASSERT_FALSE(poly.ready());
	// Проверяем отказ подачи до запуска
	ASSERT_FALSE(poly.update(view_t(key.data(), 4)));
	// Проверяем отказ снятия до запуска
	ASSERT_FALSE(poly.finish(tag));
	// Проверяем отказ запуска без ключа
	ASSERT_FALSE(poly.start(view_t()));
	// Проверяем отказ запуска с коротким ключом
	ASSERT_FALSE(poly.start(view_t(key.data(), 16)));
	// Проверяем отказ запуска с ключом, объявленным непустым, но не переданным
	ASSERT_FALSE(poly.start(view_t(nullptr, 32)));
	// Проверяем запуск
	ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
	// Проверяем готовность
	ASSERT_TRUE(poly.ready());
	// Проверяем отказ куска, объявленного непустым, но не переданного
	ASSERT_FALSE(poly.update(view_t(nullptr, 4)));
	// Проверяем отказ снятия без места под метку
	ASSERT_FALSE(poly.finish(nullptr));
	// Проверяем снятие метки пустого сообщения
	ASSERT_TRUE(poly.finish(tag));
	// Проверяем метку пустого сообщения: накопитель ноль, метка равна s
	ASSERT_EQ(text(tag, sizeof(tag)), "0103808afb0db2fd4abff6af4149f51b");
	// Проверяем неготовность после снятия
	ASSERT_FALSE(poly.ready());
	// Проверяем перезапуск
	ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
	// Выполняем сброс
	poly.clear();
	// Проверяем неготовность после сброса
	ASSERT_FALSE(poly.ready());
	// Проверяем отказ снятия после сброса
	ASSERT_FALSE(poly.finish(tag));
}

/**
 * Нехватка памяти: имитовставка не выделяет памяти вовсе и обязана работать при нулевом запасе
 */
TEST(Poly1305Test, Starved){
	// Ключ
	const std::vector <uint8_t> key = bytes("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
	// Сообщение
	const std::vector <uint8_t> message = bytes(IETF);
	// Метка
	uint8_t tag[cipher::POLY1305_TAG] = {0};
	// Итог работы
	bool outcome = false;
	{
		// Отмеряем нулевой запас выделений: всякое выделение под noexcept прервало бы исполнение
		starve::ration_t ration(0);
		// Объект имитовставки
		cipher::poly1305_t poly;
		// Выполняем запуск
		outcome = poly.start(view_t(key.data(), key.size()));
		/**
		 * Выполняем подачу сообщения кусками по 37 байтов
		 */
		for(size_t offset = 0; outcome && (offset < message.size()); offset += 37)
			// Подаём очередной кусок
			outcome = poly.update(view_t(message.data() + offset, (((message.size() - offset) < 37) ? (message.size() - offset) : 37)));
		// Если подача прошла
		if(outcome)
			// Снимаем метку
			outcome = poly.finish(tag);
	}
	// Проверяем успешность работы без единого выделения
	ASSERT_TRUE(outcome);
	// Объект имитовставки без ограничения
	cipher::poly1305_t poly;
	// Проверяем запуск
	ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
	// Проверяем подачу разом
	ASSERT_TRUE(poly.update(view_t(message.data(), message.size())));
	// Метка без ограничения
	uint8_t expected[cipher::POLY1305_TAG];
	// Проверяем снятие метки
	ASSERT_TRUE(poly.finish(expected));
	// Проверяем схождение меток
	ASSERT_EQ(::memcmp(tag, expected, sizeof(tag)), 0);
}

/**
 * Проверка схождения сложения блоков парами со сложением поблочно: сообщение целиком
 * идёт парами (h + m0) * r^2 + m1 * r, кусками по 16 байтов - только одиночными
 * блоками, а по одному байту - через накопитель неполного блока; метки на длинах
 * 0…1024 обязаны совпасть
 */
TEST(Poly1305Test, Pairs){
	// Генератор ключей и сообщений с закреплённым зерном
	std::mt19937 generator(20260906);
	// Объект имитовставки
	cipher::poly1305_t poly;
	/**
	 * Выполняем перебор длин
	 */
	for(size_t length = 0; length <= 1024; length++){
		// Ключ и сообщение
		std::vector <uint8_t> key(cipher::POLY1305_KEY), message(length);
		/**
		 * Выполняем заполнение ключа
		 */
		for(size_t i = 0; i < key.size(); i++)
			// Записываем очередной байт
			key[i] = static_cast <uint8_t> (generator());
		/**
		 * Выполняем заполнение сообщения
		 */
		for(size_t i = 0; i < message.size(); i++)
			// Записываем очередной байт
			message[i] = static_cast <uint8_t> (generator());
		// Метки трёх нарезок
		uint8_t whole[cipher::POLY1305_TAG], blocks[cipher::POLY1305_TAG], bytes[cipher::POLY1305_TAG];
		// Проверяем запуск имитовставки
		ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
		// Проверяем подачу сообщения целиком: парами блоков
		ASSERT_TRUE(poly.update(view_t(message.data(), message.size())));
		// Проверяем снятие метки
		ASSERT_TRUE(poly.finish(whole));
		// Проверяем перезапуск имитовставки
		ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
		/**
		 * Выполняем подачу сообщения по блокам: только одиночными
		 */
		for(size_t position = 0; position < length; position += cipher::POLY1305_TAG)
			// Проверяем подачу очередного блока
			ASSERT_TRUE(poly.update(view_t(message.data() + position, (((length - position) < cipher::POLY1305_TAG) ? (length - position) : cipher::POLY1305_TAG))));
		// Проверяем снятие метки
		ASSERT_TRUE(poly.finish(blocks));
		// Проверяем перезапуск имитовставки
		ASSERT_TRUE(poly.start(view_t(key.data(), key.size())));
		/**
		 * Выполняем подачу сообщения по одному байту: через накопитель
		 */
		for(size_t position = 0; position < length; position++)
			// Проверяем подачу очередного байта
			ASSERT_TRUE(poly.update(view_t(message.data() + position, 1)));
		// Проверяем снятие метки
		ASSERT_TRUE(poly.finish(bytes));
		// Проверяем схождение метки парами с меткой поблочно
		ASSERT_EQ(text(whole, sizeof(whole)), text(blocks, sizeof(blocks))) << "length " << length;
		// Проверяем схождение метки парами с меткой побайтно
		ASSERT_EQ(text(whole, sizeof(whole)), text(bytes, sizeof(bytes))) << "length " << length;
	}
}
