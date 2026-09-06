/**
 * @file: sha2.cpp
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

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sys/machine.hpp>
#include <digest/sha2.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод записи хеша шестнадцатеричной строкой
 *
 * @param data байты хеша
 * @param size число байтов хеша
 *
 * @return     запись хеша строчными шестнадцатеричными знаками
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись хеша
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/**
	 * Выполняем перебор байтов хеша
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		// Записываем младший полубайт
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Выводим запись хеша
	return result;
}

/**
 * @brief Метод выработки хеша целого сообщения строкой
 *
 * @param type    разновидность хеша
 * @param message хешируемое сообщение
 *
 * @return        запись хеша шестнадцатеричной строкой
 *
 */
static std::string whole(const digest::sha_t type, const std::string & message) {
	// Место, в которое записывается хеш
	uint8_t result[64];
	// Если хеш выработать не удалось
	if(!digest::sha2(type, view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), result, sizeof(result)))
		// Выводим пустую запись
		return "";
	// Выводим запись хеша
	return text(result, static_cast <size_t> (type));
}

/**
 * Проверка векторов FIPS 180-4 на коротком сообщении «abc»
 */
TEST(Sha2Test, Abc){
	// Раздел A.1 и B.1 FIPS 180-4 и приложения к нему: хеши сообщения «abc»
	ASSERT_EQ(whole(digest::sha_t::SHA224, "abc"), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
	// Хеш SHA-256 сообщения «abc»
	ASSERT_EQ(whole(digest::sha_t::SHA256, "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	// Хеш SHA-384 сообщения «abc»
	ASSERT_EQ(whole(digest::sha_t::SHA384, "abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
	// Хеш SHA-512 сообщения «abc»
	ASSERT_EQ(whole(digest::sha_t::SHA512, "abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

/**
 * Проверка хешей пустого сообщения
 */
TEST(Sha2Test, Empty){
	// Хеш SHA-224 пустого сообщения
	ASSERT_EQ(whole(digest::sha_t::SHA224, ""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
	// Хеш SHA-256 пустого сообщения
	ASSERT_EQ(whole(digest::sha_t::SHA256, ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	// Хеш SHA-384 пустого сообщения
	ASSERT_EQ(whole(digest::sha_t::SHA384, ""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
	// Хеш SHA-512 пустого сообщения
	ASSERT_EQ(whole(digest::sha_t::SHA512, ""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

/**
 * Проверка векторов на сообщениях в два блока: дополнение переходит через границу блока
 */
TEST(Sha2Test, Twoblock){
	// Сообщение в 56 байтов: отделитель и поле длины не умещаются в первый блок SHA-256
	const std::string shorter = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	// Сообщение в 112 байтов: то же для блока в 128 байтов
	const std::string longer = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	// Хеш SHA-224 сообщения в два блока
	ASSERT_EQ(whole(digest::sha_t::SHA224, shorter), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
	// Хеш SHA-256 сообщения в два блока
	ASSERT_EQ(whole(digest::sha_t::SHA256, shorter), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	// Хеш SHA-384 сообщения в два блока
	ASSERT_EQ(whole(digest::sha_t::SHA384, longer), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
	// Хеш SHA-512 сообщения в два блока
	ASSERT_EQ(whole(digest::sha_t::SHA512, longer), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

/**
 * Проверка миллиона знаков «a» и независимости хеша от нарезки на куски
 */
TEST(Sha2Test, Million){
	// Сообщение в миллион знаков «a»
	const std::string message(1000000, 'a');
	// Хеш SHA-256 миллиона знаков «a» целиком
	ASSERT_EQ(whole(digest::sha_t::SHA256, message), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
	// Хеш SHA-512 миллиона знаков «a» целиком
	ASSERT_EQ(whole(digest::sha_t::SHA512, message), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
	// Размеры кусков, которыми подаётся сообщение
	const size_t chunks[] = {1, 3, 63, 64, 65, 127, 128, 129, 1000, 4097};
	/**
	 * Выполняем перебор размеров кусков
	 */
	for(size_t c = 0; c < (sizeof(chunks) / sizeof(chunks[0])); c++){
		// Объект хеширования SHA-512
		digest::sha2_t hasher(digest::sha_t::SHA512);
		/**
		 * Выполняем подачу сообщения кусками
		 */
		for(size_t offset = 0; offset < message.size(); offset += chunks[c]){
			// Размер очередного куска
			const size_t size = (((message.size() - offset) < chunks[c]) ? (message.size() - offset) : chunks[c]);
			// Выполняем подачу очередного куска
			hasher.update(view_t(reinterpret_cast <const uint8_t *> (message.data()) + offset, size));
		}
		// Место, в которое записывается хеш
		uint8_t result[64];
		// Проверяем снятие хеша
		ASSERT_TRUE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
		// Проверяем схождение хеша с выработанным целиком
		ASSERT_EQ(text(result, 64), "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b") << "кусок " << chunks[c];
		// Проверяем отказ повторного снятия хеша без сброса
		ASSERT_FALSE(hasher.finish(result, sizeof(result))) << "кусок " << chunks[c];
	}
}

/**
 * Проверка векторов AWH, закреплённых по BoringSSL
 */
TEST(Sha2Test, Foreign){
	// Вход векторов AWH
	const std::string message = "Hello World, Hello World, Hello World, Hello World, Hello World, Hello World!!!!!!!!!!!!!!!!?";
	// Хеш SHA-224 по BoringSSL
	ASSERT_EQ(whole(digest::sha_t::SHA224, message), "e919819b0c7386e38e040c7bbd876bcbe35de8c4364179b28f4ebb95");
	// Хеш SHA-256 по BoringSSL
	ASSERT_EQ(whole(digest::sha_t::SHA256, message), "3a4f9cfad7df5274dc724737d9176cc57787aaa930e0b4e7d82398fd4a82facf");
	// Хеш SHA-384 по BoringSSL
	ASSERT_EQ(whole(digest::sha_t::SHA384, message), "b996ff91f7ef04fe8ea7ee01dd1015d31882daee84054a54ad1e517175ff0c9adab2ce958deac16828268b2f599a96c0");
	// Хеш SHA-512 по BoringSSL
	ASSERT_EQ(whole(digest::sha_t::SHA512, message), "4eb68fe9cda573be3ef1183b34a776fbc62bbb6e0571632afbbcb292e95e655160d984ded4b8fe9b1a221d9d5250c5c6587fc18556194b95c7159ba8e19c1779");
}

/**
 * Проверка отказов договора
 */
TEST(Sha2Test, Refusals){
	// Место, в которое записывается хеш
	uint8_t result[64];
	// Объект хеширования без разновидности
	digest::sha2_t none(digest::sha_t::NONE);
	// Проверяем отказ снятия хеша без разновидности
	ASSERT_FALSE(none.finish(result, sizeof(result)));
	// Объект хеширования SHA-256
	digest::sha2_t hasher(digest::sha_t::SHA256);
	// Проверяем размер блока SHA-256
	ASSERT_EQ(hasher.block(), 64u);
	// Проверяем отказ снятия хеша в место короче хеша
	ASSERT_FALSE(hasher.finish(result, 31));
	// Проверяем отказ снятия хеша в пустое место
	ASSERT_FALSE(hasher.finish(nullptr, sizeof(result)));
	// Проверяем снятие хеша в место ровно по длине
	ASSERT_TRUE(hasher.finish(result, 32));
	// Проверяем хеш пустого сообщения после отказов
	ASSERT_EQ(text(result, 32), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	// Выполняем сброс на SHA-384
	hasher.reset(digest::sha_t::SHA384);
	// Проверяем разновидность после сброса
	ASSERT_EQ(hasher.type(), digest::sha_t::SHA384);
	// Проверяем размер блока SHA-384
	ASSERT_EQ(hasher.block(), 128u);
	// Выполняем подачу сообщения «abc»
	hasher.update(view_t(reinterpret_cast <const uint8_t *> ("abc"), 3));
	// Проверяем снятие хеша после сброса
	ASSERT_TRUE(hasher.finish(result, sizeof(result)));
	// Проверяем хеш SHA-384 сообщения «abc»
	ASSERT_EQ(text(result, 48), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

/**
 * Проверка схождения обоих путей SHA-256: командами машины и таблицами
 */
TEST(Sha2Test, Paths){
	// Сообщение в 70 000 байтов
	std::string message(70000, 'x');
	/**
	 * Выполняем заполнение сообщения
	 */
	for(size_t i = 0; i < message.size(); i++)
		// Записываем очередной знак
		message[i] = static_cast <char> (i * 13 + 5);
	// Хеш на пути, выбранном машиной
	const std::string first = whole(digest::sha_t::SHA256, message);
	// Запрещаем машинные команды
	machine::allow(false);
	// Хеш таблицами
	const std::string second = whole(digest::sha_t::SHA256, message);
	// Возвращаем машинные команды
	machine::allow(true);
	// Проверяем схождение хешей
	ASSERT_EQ(first, second);
	// Проверяем длину хеша
	ASSERT_EQ(first.size(), 64u);
}

/**
 * Проверка схождения обоих путей SHA-512 и SHA-384: командами ARMv8.2 и переносимым
 * путём, длины 0…4096, поток кусками случайной длины через границы блоков в 128 байтов
 */
TEST(Sha2Test, Paths512){
	// Генератор сообщений и длин кусков с закреплённым зерном
	std::mt19937 generator(20260906);
	/**
	 * Выполняем перебор длин
	 */
	for(size_t length = 0; length <= 4096; length++){
		// Сообщение
		std::string message(length, 'x');
		/**
		 * Выполняем заполнение сообщения
		 */
		for(size_t i = 0; i < message.size(); i++)
			// Записываем очередной знак
			message[i] = static_cast <char> (generator());
		// Хеши на пути, выбранном машиной
		const std::string first512 = whole(digest::sha_t::SHA512, message), first384 = whole(digest::sha_t::SHA384, message);
		// Запрещаем машинные команды
		machine::allow(false);
		// Хеш SHA-384 целиком переносимым путём
		const std::string second384 = whole(digest::sha_t::SHA384, message);
		// Объект хеширования SHA-512 переносимым путём
		digest::sha2_t hasher(digest::sha_t::SHA512);
		// Позиция внутри сообщения
		size_t position = 0;
		/**
		 * Выполняем подачу сообщения кусками случайной длины
		 */
		while(position < length){
			// Длина очередного куска
			size_t chunk = (1 + (generator() % 300));
			// Если кусок длиннее остатка
			if(chunk > (length - position))
				// Ограничиваем кусок остатком
				chunk = (length - position);
			// Подаём очередной кусок
			hasher.update(view_t(reinterpret_cast <const uint8_t *> (message.data()) + position, chunk));
			// Сдвигаем позицию
			position += chunk;
		}
		// Место, в которое записывается хеш
		uint8_t result[64];
		// Проверяем снятие хеша
		ASSERT_TRUE(hasher.finish(result, sizeof(result)));
		// Возвращаем машинные команды
		machine::allow(true);
		// Проверяем схождение хешей SHA-512
		ASSERT_EQ(first512, text(result, sizeof(result))) << "length " << length;
		// Проверяем схождение хешей SHA-384
		ASSERT_EQ(first384, second384) << "length " << length;
	}
}
