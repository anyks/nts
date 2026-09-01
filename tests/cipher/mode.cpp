/**
 * @file mode.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл проверок модуля режимов работы блочных шифров
 *
 * @note Контрольные примеры взяты из приложения А ГОСТ Р 34.13-2015 целиком: все
 *       шесть режимов для обоих шифров вместе с их синхропосылками и длинами
 *       регистров сдвига
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstring>
#include <main.hpp>
#include <cipher/mode.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
 *
 * @return     число разобранных байтов
 *
 */
static size_t bytes(const char * text, uint8_t * data) {
	// Число разобранных байтов
	size_t result = 0;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		data[result++] = value;
	}
	// Выводим число разобранных байтов
	return result;
}
/**
 * @brief Метод сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
 *
 * @return     собранная запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Собираемая запись
	std::string result;
	// Набор шестнадцатеричных знаков
	static const char * letters = "0123456789abcdef";
	/**
	 * Выполняем перебор собираемых байтов
	 */
	for(size_t i = 0; i < size; i++){
		// Записываем старший знак очередного байта
		result.append(1, letters[(data[i] >> 4) & 0x0F]);
		// Записываем младший знак очередного байта
		result.append(1, letters[data[i] & 0x0F]);
	}
	// Выводим собранную запись
	return result;
}

/**
 * Ключ шифрования контрольных примеров для шифра «Кузнечик»
 */
static const char * KUZNYECHIK_SECRET = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";

/**
 * Открытый текст контрольных примеров для шифра «Кузнечик»
 */
static const char * KUZNYECHIK_PLAIN =
	"1122334455667700ffeeddccbbaa9988"
	"00112233445566778899aabbcceeff0a"
	"112233445566778899aabbcceeff0a00"
	"2233445566778899aabbcceeff0a0011";

/**
 * Ключ шифрования контрольных примеров для шифра «Магма»
 */
static const char * MAGMA_SECRET = "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/**
 * Открытый текст контрольных примеров для шифра «Магма»
 */
static const char * MAGMA_PLAIN =
	"92def06b3c130a59"
	"db54c704f8189d20"
	"4a98fb2e67a8024c"
	"8912409b17b57e41";

/**
 * @brief Проверка отказов режимов работы на негодных доводах
 *
 * @note Заслоны эти стерегут не подделку, а оплошность потребителя фреймворка:
 *       непереданное место, длину не по размеру блока, вектор замены не той длины.
 *       Пропущенный такой заслон обращает чужую оплошность в выход за память, оттого
 *       проверяются они все, и смысл проверки раскрывается под санитайзерами
 *
 */
TEST(ModeTest, Refusals) {
	// Ключ шифрования
	uint8_t secret[32];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Место, в которое складывается итог работы режима
	uint8_t result[64];
	// Область байтов, подаваемая режимам работы
	uint8_t source[64];
	// Выполняем обнуление подаваемой области байтов
	::memset(source, 0x33, sizeof(source));
	// Вектор замены, годный режимам работы
	uint8_t iv[32];
	// Выполняем обнуление вектора замены
	::memset(iv, 0x44, sizeof(iv));
	// Размер блока применяемого шифра
	const size_t size = cipher::KUZNYECHIK_BLOCK;
	/**
	 * Режим простой замены: заведения он требует одного лишь шифра, а работы -
	 * переданных мест и длины, кратной размеру блока
	 */
	{
		// Объект режима простой замены
		cipher::codebook_t mode;
		/**
		 * Описатель шифра, ни на какой шифр не указывающий: заводить им режим работы
		 * нельзя, ибо звать по такому описателю нечего
		 */
		ASSERT_FALSE(mode.start(cipher::block_t()));
		// Проверяем отказ работы незаведённого режима
		ASSERT_FALSE(mode.encrypt(view_t(source, size), result));
		// Проверяем отказ снятия защиты незаведённым режимом
		ASSERT_FALSE(mode.decrypt(view_t(source, size), result));
		// Выполняем заведение режима простой замены
		ASSERT_TRUE(mode.start(cipher::block_t(base)));
		// Проверяем отказ работы при непереданной области байтов
		ASSERT_FALSE(mode.encrypt(view_t(nullptr, size), result));
		// Проверяем отказ работы при непереданном месте итога
		ASSERT_FALSE(mode.encrypt(view_t(source, size), nullptr));
		// Проверяем отказ снятия защиты при непереданной области байтов
		ASSERT_FALSE(mode.decrypt(view_t(nullptr, size), result));
		// Проверяем отказ снятия защиты при непереданном месте итога
		ASSERT_FALSE(mode.decrypt(view_t(source, size), nullptr));
		// Проверяем отказ работы при длине не по размеру блока
		ASSERT_FALSE(mode.encrypt(view_t(source, size - 1), result));
		// Проверяем отказ снятия защиты при длине не по размеру блока
		ASSERT_FALSE(mode.decrypt(view_t(source, size - 1), result));
	}
	/**
	 * Режим гаммирования: вектор замены ему нужен ровно в половину блока, и работа
	 * его длины, кратной блоку, не требует
	 */
	{
		// Объект режима гаммирования
		cipher::counter_t mode;
		// Проверяем отказ заведения незаполненным описателем шифра
		ASSERT_FALSE(mode.start(cipher::block_t(), view_t(iv, size / 2)));
		// Проверяем отказ работы незаведённого режима
		ASSERT_FALSE(mode.encrypt(view_t(source, size), result));
		// Проверяем отказ снятия защиты незаведённым режимом
		ASSERT_FALSE(mode.decrypt(view_t(source, size), result));
		// Проверяем отказ заведения при непереданном векторе замены
		ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nullptr, size / 2)));
		// Проверяем отказ заведения при векторе замены не той длины
		ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(iv, size)));
		// Выполняем заведение режима гаммирования
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, size / 2)));
		// Проверяем успешность работы при пустой области байтов
		ASSERT_TRUE(mode.encrypt(view_t(nullptr, 0), result));
		// Проверяем отказ работы при непереданной области байтов
		ASSERT_FALSE(mode.encrypt(view_t(nullptr, size), result));
		// Проверяем отказ работы при непереданном месте итога
		ASSERT_FALSE(mode.encrypt(view_t(source, size), nullptr));
	}
	/**
	 * Режимы обратной связи: вектор замены им нужен кратным размеру блока и не
	 * короче его самого
	 */
	{
		// Объект режима обратной связи по шифртексту
		cipher::chaining_t chaining;
		// Проверяем отказ заведения при непереданном векторе замены
		ASSERT_FALSE(chaining.start(cipher::block_t(base), view_t(nullptr, size)));
		// Проверяем отказ заведения при векторе замены короче блока
		ASSERT_FALSE(chaining.start(cipher::block_t(base), view_t(iv, size - 1)));
		// Проверяем отказ заведения при векторе замены не кратном блоку
		ASSERT_FALSE(chaining.start(cipher::block_t(base), view_t(iv, size + 1)));
		// Выполняем заведение режима обратной связи по шифртексту
		ASSERT_TRUE(chaining.start(cipher::block_t(base), view_t(iv, size)));
		// Проверяем отказ работы при длине не по размеру блока
		ASSERT_FALSE(chaining.encrypt(view_t(source, size - 1), result));
		// Объект режима обратной связи по гамме
		cipher::feedback_t feedback;
		// Проверяем отказ заведения при непереданном векторе замены
		ASSERT_FALSE(feedback.start(cipher::block_t(base), view_t(nullptr, size)));
		// Проверяем отказ заведения при векторе замены короче блока
		ASSERT_FALSE(feedback.start(cipher::block_t(base), view_t(iv, size - 1)));
		// Выполняем заведение режима обратной связи по гамме
		ASSERT_TRUE(feedback.start(cipher::block_t(base), view_t(iv, size)));
		// Проверяем отказ работы при непереданном месте итога
		ASSERT_FALSE(feedback.encrypt(view_t(source, size), nullptr));
		// Объект режима гаммирования с обратной связью по выходу
		cipher::output_t output;
		// Проверяем отказ заведения при векторе замены короче блока
		ASSERT_FALSE(output.start(cipher::block_t(base), view_t(iv, size - 1)));
		// Выполняем заведение режима гаммирования с обратной связью по выходу
		ASSERT_TRUE(output.start(cipher::block_t(base), view_t(iv, size)));
		// Проверяем отказ работы при непереданной области байтов
		ASSERT_FALSE(output.encrypt(view_t(nullptr, size), result));
		// Проверяем отказ снятия защиты при непереданном месте итога
		ASSERT_FALSE(output.decrypt(view_t(source, size), nullptr));
		// Проверяем отказ снятия защиты незаведённого режима обратной связи
		ASSERT_FALSE(chaining.decrypt(view_t(source, size - 1), result));
		// Проверяем отказ снятия защиты при непереданном месте итога
		ASSERT_FALSE(feedback.decrypt(view_t(source, size), nullptr));
	}
	/**
	 * Режим выработки имитовставки: длина её берётся не свыше размера блока, и
	 * нулевой длины у неё не бывает
	 */
	{
		// Объект режима выработки имитовставки
		cipher::imitation_t mode;
		// Проверяем отказ подачи байтов незаведённому режиму
		ASSERT_FALSE(mode.update(view_t(source, size)));
		// Выполняем заведение режима выработки имитовставки
		ASSERT_TRUE(mode.start(cipher::block_t(base)));
		// Проверяем успешность подачи пустой области байтов
		ASSERT_TRUE(mode.update(view_t(nullptr, 0)));
		// Проверяем отказ подачи непереданной области байтов
		ASSERT_FALSE(mode.update(view_t(nullptr, size)));
		// Выполняем подачу байтов режиму выработки имитовставки
		ASSERT_TRUE(mode.update(view_t(source, size)));
		// Проверяем отказ выдачи имитовставки в непереданное место
		ASSERT_FALSE(mode.finish(nullptr, size));
		// Проверяем отказ выдачи имитовставки нулевой длины
		ASSERT_FALSE(mode.finish(result, 0));
		// Проверяем отказ выдачи имитовставки длиною свыше блока
		ASSERT_FALSE(mode.finish(result, size + 1));
		// Проверяем успешность выдачи имитовставки
		ASSERT_TRUE(mode.finish(result, size));
	}
}

/**
 * @brief Проверка режима простой замены на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikCodebook) {
	// Ключ шифрования
	uint8_t secret[32];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима простой замены
	cipher::codebook_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"7f679d90bebc24305a468d42b9d4edcd"
		"b429912c6e0032f9285452d76718d08b"
		"f0ca33549d247ceef3f5a5313bd4b157"
		"d0b09ccde830b9eb3a02c4c5aa8ada98"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[64];
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима гаммирования на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikCounter) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[8];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования
	cipher::counter_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"f195d8bec10ed1dbd57b5fa240bda1b8"
		"85eee733f6a13e5df33ce4b33c45dee4"
		"a5eae88be6356ed3d5e877f13564a3a5"
		"cb91fab1f20cbab6d1c6d15820bdba73"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[64];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка независимости режима гаммирования от нарезки сообщения на куски
 *
 */
TEST(ModeTest, KuznyechikCounterChunks) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[8];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение
	 */
	for(size_t chunk = 1; chunk <= 17; chunk++){
		// Объект режима гаммирования
		cipher::counter_t mode;
		// Выполняем запуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
		/**
		 * Выполняем подачу сообщения кусками выбранного размера
		 */
		for(size_t offset = 0; offset < size; offset += chunk){
			// Определяем размер очередного куска сообщения
			const size_t count = ((size - offset) < chunk ? (size - offset) : chunk);
			// Выполняем зашифрование очередного куска сообщения
			ASSERT_TRUE(mode.encrypt(view_t(plain + offset, count), cipher + offset));
		}
		// Сличаем полученный шифртекст с контрольным примером
		ASSERT_EQ(text(cipher, size), std::string(
			"f195d8bec10ed1dbd57b5fa240bda1b8"
			"85eee733f6a13e5df33ce4b33c45dee4"
			"a5eae88be6356ed3d5e877f13564a3a5"
			"cb91fab1f20cbab6d1c6d15820bdba73"
		)) << "Размер куска: " << chunk;
	}
}
/**
 * @brief Проверка режима гаммирования с обратной связью по выходу на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikOutput) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[32];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования с обратной связью по выходу
	cipher::output_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"81800a59b1842b24ff1f795e897abd95"
		"ed5b47a7048cfab48fb521369d9326bf"
		"66a257ac3ca0b8b1c80fe7fc10288a13"
		"203ebbc066138660a0292243f6903150"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[64];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима простой замены с зацеплением на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikChaining) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[32];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима простой замены с зацеплением
	cipher::chaining_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"689972d4a085fa4d90e52e3d6d7dcc27"
		"2826e661b478eca6af1e8e448d5ea5ac"
		"fe7babf1e91999e85640e8b0f49d90d0"
		"167688065a895c631a2d9a1560b63970"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[64];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима гаммирования с обратной связью по шифртексту на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikFeedback) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[32];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования с обратной связью по шифртексту
	cipher::feedback_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"81800a59b1842b24ff1f795e897abd95"
		"ed5b47a7048cfab48fb521369d9326bf"
		"79f2a8eb5cc68d38842d264e97a238b5"
		"4ffebecd4e922de6c75bd9dd44fbf4d1"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[64];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима выработки имитовставки на шифре «Кузнечик»
 *
 */
TEST(ModeTest, KuznyechikImitation) {
	// Ключ шифрования
	uint8_t secret[32];
	// Открытый текст
	uint8_t plain[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима выработки имитовставки
	cipher::imitation_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	// Выполняем добавление сообщения
	ASSERT_TRUE(mode.update(view_t(plain, size)));
	// Место, в которое помещается имитовставка
	uint8_t mac[8];
	// Выполняем снятие имитовставки
	ASSERT_TRUE(mode.finish(mac, sizeof(mac)));
	// Сличаем полученную имитовставку с контрольным примером
	ASSERT_EQ(text(mac, sizeof(mac)), std::string("336f4d296059fbe3"));
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение
	 */
	for(size_t chunk = 1; chunk <= 17; chunk++){
		// Выполняем перезапуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base)));
		/**
		 * Выполняем подачу сообщения кусками выбранного размера
		 */
		for(size_t offset = 0; offset < size; offset += chunk){
			// Определяем размер очередного куска сообщения
			const size_t count = ((size - offset) < chunk ? (size - offset) : chunk);
			// Выполняем добавление очередного куска сообщения
			ASSERT_TRUE(mode.update(view_t(plain + offset, count)));
		}
		// Выполняем снятие имитовставки
		ASSERT_TRUE(mode.finish(mac, sizeof(mac)));
		// Сличаем полученную имитовставку с контрольным примером
		ASSERT_EQ(text(mac, sizeof(mac)), std::string("336f4d296059fbe3")) << "Размер куска: " << chunk;
	}
}
/**
 * @brief Проверка режима простой замены на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaCodebook) {
	// Ключ шифрования
	uint8_t secret[32];
	// Открытый текст и шифртекст
	uint8_t plain[32], cipher[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима простой замены
	cipher::codebook_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"2b073f0494f372a0"
		"de70e715d3556e48"
		"11d8d9e9eacfbc1e"
		"7c68260996c67efb"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[32];
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима гаммирования на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaCounter) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[4];
	// Открытый текст и шифртекст
	uint8_t plain[32], cipher[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("12345678", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования
	cipher::counter_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"4e98110c97b7b93c"
		"3e250d93d6e85d69"
		"136d868807b2dbef"
		"568eb680ab52a12d"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[32];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима гаммирования с обратной связью по выходу на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaOutput) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[16];
	// Открытый текст и шифртекст
	uint8_t plain[32], cipher[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcdef234567890abcdef1", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования с обратной связью по выходу
	cipher::output_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"db37e0e266903c83"
		"0d46644c1f9a089c"
		"a0f83062430e327e"
		"c824efb8bd4fdb05"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[32];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима простой замены с зацеплением на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaChaining) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[24];
	// Открытый текст и шифртекст
	uint8_t plain[32], cipher[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcdef234567890abcdef134567890abcdef12", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима простой замены с зацеплением
	cipher::chaining_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"96d1b05eea683919"
		"aff76129abb937b9"
		"5058b4a1c4bc0019"
		"20b78b1a7cd7e667"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[32];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима гаммирования с обратной связью по шифртексту на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaFeedback) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[16];
	// Открытый текст и шифртекст
	uint8_t plain[32], cipher[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcdef234567890abcdef1", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима гаммирования с обратной связью по шифртексту
	cipher::feedback_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"db37e0e266903c83"
		"0d46644c1f9a089c"
		"24bdd2035315d38b"
		"bcc0321421075505"
	));
	// Место, в которое помещается расшифрованный текст
	uint8_t back[32];
	// Выполняем перезапуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка режима выработки имитовставки на шифре «Магма»
 *
 */
TEST(ModeTest, MagmaImitation) {
	// Ключ шифрования
	uint8_t secret[32];
	// Открытый текст
	uint8_t plain[32];
	// Выполняем разбор ключа шифрования
	bytes(MAGMA_SECRET, secret);
	// Выполняем разбор открытого текста
	const size_t size = bytes(MAGMA_PLAIN, plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима выработки имитовставки
	cipher::imitation_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base)));
	// Выполняем добавление сообщения
	ASSERT_TRUE(mode.update(view_t(plain, size)));
	// Место, в которое помещается имитовставка
	uint8_t mac[4];
	// Выполняем снятие имитовставки
	ASSERT_TRUE(mode.finish(mac, sizeof(mac)));
	// Сличаем полученную имитовставку с контрольным примером
	ASSERT_EQ(text(mac, sizeof(mac)), std::string("154e7210"));
}
/**
 * @brief Проверка отказов режимов работы
 *
 */
TEST(ModeTest, Failures) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[32];
	// Открытый текст и шифртекст
	uint8_t plain[64], cipher[64];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Выполняем разбор синхропосылки
	bytes("1234567890abcef0a1b2c3d4e5f0011223344556677889901213141516171819", iv);
	// Выполняем разбор открытого текста
	const size_t size = bytes(KUZNYECHIK_PLAIN, plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима простой замены
	cipher::codebook_t codebook;
	// Проверяем отказ работы режима до его запуска
	ASSERT_FALSE(codebook.ready());
	// Проверяем отказ зашифрования до запуска режима работы
	ASSERT_FALSE(codebook.encrypt(view_t(plain, size), cipher));
	// Проверяем отказ запуска режима работы с непригодным базовым алгоритмом
	ASSERT_FALSE(codebook.start(cipher::block_t()));
	// Выполняем запуск режима работы
	ASSERT_TRUE(codebook.start(cipher::block_t(base)));
	// Проверяем отказ зашифрования сообщения некратной блоку длины
	ASSERT_FALSE(codebook.encrypt(view_t(plain, size - 1), cipher));
	// Объект режима гаммирования
	cipher::counter_t counter;
	// Проверяем отказ запуска режима работы с синхропосылкой не в половину блока
	ASSERT_FALSE(counter.start(cipher::block_t(base), view_t(iv, 16)));
	// Проверяем отказ запуска режима работы с блоком гаммы длиннее блока шифра
	ASSERT_FALSE(counter.start(cipher::block_t(base), view_t(iv, 8), 17));
	// Объект режима простой замены с зацеплением
	cipher::chaining_t chaining;
	// Проверяем отказ запуска режима работы с синхропосылкой некратной блоку длины
	ASSERT_FALSE(chaining.start(cipher::block_t(base), view_t(iv, 24)));
	// Проверяем отказ запуска режима работы с синхропосылкой длиннее регистра сдвига
	ASSERT_FALSE(chaining.start(cipher::block_t(base), view_t(iv, cipher::MODE_REGISTER + 16)));
	// Объект режима выработки имитовставки
	cipher::imitation_t imitation;
	// Выполняем запуск режима работы
	ASSERT_TRUE(imitation.start(cipher::block_t(base)));
	// Проверяем отказ снятия имитовставки длиннее блока шифра
	ASSERT_FALSE(imitation.finish(cipher, 17));
	// Проверяем отказ снятия имитовставки нулевой длины
	ASSERT_FALSE(imitation.finish(cipher, 0));
	// Выполняем сброс состояния режима работы
	imitation.clear();
	// Проверяем отказ добавления сообщения после сброса состояния режима работы
	ASSERT_FALSE(imitation.update(view_t(plain, size)));
}
