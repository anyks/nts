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
#include <cipher/aes.hpp>
#include <sys/machine.hpp>
#include <random>
#include <vector>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Функция разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 * @param data место, в которое помещаются разобранные байты
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
 * @brief Функция сборки записи шестнадцатеричными знаками
 *
 * @param data собираемые байты
 * @param size число собираемых байтов
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
 * @brief Проверка независимости режима простой замены от нарезки сообщения на куски
 *
 */
TEST(ModeTest, KuznyechikCodebookChunks) {
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
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение: режим не держит
	 * состояния, но длина всякого куска обязана быть кратна длине блока шифра
	 */
	for(size_t chunk = cipher::KUZNYECHIK_BLOCK; chunk <= size; chunk += cipher::KUZNYECHIK_BLOCK){
		// Объект режима простой замены
		cipher::codebook_t mode;
		// Выполняем запуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base)));
		// Проверяем отказ зашифрования куска длиной не в целое число блоков
		ASSERT_FALSE(mode.encrypt(view_t(plain, chunk - 1), cipher));
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
			"7f679d90bebc24305a468d42b9d4edcd"
			"b429912c6e0032f9285452d76718d08b"
			"f0ca33549d247ceef3f5a5313bd4b157"
			"d0b09ccde830b9eb3a02c4c5aa8ada98"
		)) << "Размер куска: " << chunk;
	}
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
 * @brief Проверка независимости режима гаммирования с обратной связью по выходу от нарезки сообщения на куски
 *
 */
TEST(ModeTest, KuznyechikOutputChunks) {
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
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение: регистр сдвига и
	 * остаток блока гаммы переносятся из вызова в вызов
	 */
	for(size_t chunk = 1; chunk <= 17; chunk++){
		// Объект режима гаммирования с обратной связью по выходу
		cipher::output_t mode;
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
			"81800a59b1842b24ff1f795e897abd95"
			"ed5b47a7048cfab48fb521369d9326bf"
			"66a257ac3ca0b8b1c80fe7fc10288a13"
			"203ebbc066138660a0292243f6903150"
		)) << "Размер куска: " << chunk;
	}
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
 * @brief Проверка независимости режима простой замены с зацеплением от нарезки сообщения на куски
 *
 */
TEST(ModeTest, KuznyechikChainingChunks) {
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
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение: регистр зацепления
	 * переносится из вызова в вызов, оттого последний блок прежнего куска служит звеном
	 * зацепления первому блоку следующего
	 */
	for(size_t chunk = cipher::KUZNYECHIK_BLOCK; chunk <= size; chunk += cipher::KUZNYECHIK_BLOCK){
		// Объект режима простой замены с зацеплением
		cipher::chaining_t mode;
		// Выполняем запуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
		// Проверяем отказ зашифрования куска длиной не в целое число блоков
		ASSERT_FALSE(mode.encrypt(view_t(plain, chunk - 1), cipher));
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
			"689972d4a085fa4d90e52e3d6d7dcc27"
			"2826e661b478eca6af1e8e448d5ea5ac"
			"fe7babf1e91999e85640e8b0f49d90d0"
			"167688065a895c631a2d9a1560b63970"
		)) << "Размер куска: " << chunk;
	}
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
 * @brief Проверка независимости режима гаммирования с обратной связью по шифртексту от нарезки сообщения на куски
 *
 */
TEST(ModeTest, KuznyechikFeedbackChunks) {
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
	/**
	 * Выполняем перебор размеров куска, которыми подаётся сообщение: регистр сдвига и
	 * остаток блока гаммы переносятся из вызова в вызов
	 */
	for(size_t chunk = 1; chunk <= 17; chunk++){
		// Объект режима гаммирования с обратной связью по шифртексту
		cipher::feedback_t mode;
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
			"81800a59b1842b24ff1f795e897abd95"
			"ed5b47a7048cfab48fb521369d9326bf"
			"79f2a8eb5cc68d38842d264e97a238b5"
			"4ffebecd4e922de6c75bd9dd44fbf4d1"
		)) << "Размер куска: " << chunk;
	}
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

/**
 * Проверка отказов заведения режимов неполным описателем шифра
 */
TEST(ModeTest, Descriptor) {
	// Ключ шифрования
	uint8_t secret[32];
	// Выполняем разбор ключа шифрования
	bytes(KUZNYECHIK_SECRET, secret);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Годный описатель базового шифра, служащий образцом порчи
	const cipher::block_t sample(base);
	// Вектор замены, годный режимам работы
	uint8_t iv[cipher::MODE_REGISTER + cipher::MODE_BLOCK];
	// Выполняем заполнение вектора замены
	::memset(iv, 0x44, sizeof(iv));
	// Объект режима простой замены
	cipher::codebook_t codebook;
	/**
	 * Пригодность описателя сверяется по ПЯТИ признакам сразу, и всякий из них
	 * отвергает описатель в одиночку. Описатель, у которого недостаёт лишь одного
	 * признака, трогает ровно ту часть заслона, что за него отвечает
	 */
	cipher::block_t undecipherable = sample;
	// Убираем из описателя обращение к расшифрованию блока
	undecipherable.decrypt = nullptr;
	// Проверяем отказ заведения описателем без обращения к расшифрованию
	ASSERT_FALSE(codebook.start(undecipherable));
	// Описатель шифра, у которого не заполнено обращение к зашифрованию
	cipher::block_t unencipherable = sample;
	// Убираем из описателя обращение к зашифрованию блока
	unencipherable.encrypt = nullptr;
	// Проверяем отказ заведения описателем без обращения к зашифрованию
	ASSERT_FALSE(codebook.start(unencipherable));
	// Описатель шифра, у которого объявлен нулевой размер блока
	cipher::block_t sizeless = sample;
	// Обнуляем размер блока описателя шифра
	sizeless.size = 0;
	// Проверяем отказ заведения описателем с нулевым размером блока
	ASSERT_FALSE(codebook.start(sizeless));
	/**
	 * Размер блока сверяется с наибольшим, какой режимы вмещают: описатель, объявивший
	 * блок больше того, отвергается, ибо места под такой блок у режима нет
	 */
	cipher::block_t oversized = sample;
	// Объявляем размер блока описателя шифра сверх вмещаемого режимами
	oversized.size = (cipher::MODE_BLOCK + 1);
	// Проверяем отказ заведения описателем с непомерным размером блока
	ASSERT_FALSE(codebook.start(oversized));
	// Проверяем успешность заведения годным описателем шифра
	ASSERT_TRUE(codebook.start(sample));
	// Объект режима гаммирования с зацеплением
	cipher::chaining_t chaining;
	/**
	 * Вектор замены режимов с зацеплением занимает целое число блоков и целиком
	 * умещается в сдвиговом регистре: длиннее регистра он быть не смеет
	 */
	ASSERT_FALSE(chaining.start(sample, view_t(iv, (cipher::MODE_REGISTER + cipher::MODE_BLOCK))));
	// Проверяем успешность заведения вектором замены длиною в сдвиговый регистр
	ASSERT_TRUE(chaining.start(sample, view_t(iv, cipher::MODE_REGISTER)));
	// Объект режима гаммирования с обратной связью по выходу
	cipher::output_t output;
	// Место, в которое складывается итог работы режимов
	uint8_t produced[64] = {0};
	// Область байтов, подаваемая режимам работы
	uint8_t supplied[64] = {0};
	// Выполняем заполнение подаваемой области байтов
	::memset(supplied, 0x33, sizeof(supplied));
	/**
	 * Незаведённость режима сверяется ПЕРВОЙ половиной условия, прежде переданности
	 * мест, и держит эту половину всякий режим САМ: проверка одного о другом не
	 * говорит ничего
	 */
	ASSERT_FALSE(output.encrypt(view_t(supplied, sizeof(supplied)), produced));
	// Проверяем отказ расшифрования незаведённым режимом по выходу
	ASSERT_FALSE(output.decrypt(view_t(supplied, sizeof(supplied)), produced));
	// Объект незаведённого режима гаммирования с зацеплением
	cipher::chaining_t unchained;
	// Проверяем отказ зашифрования незаведённым режимом с зацеплением
	ASSERT_FALSE(unchained.encrypt(view_t(supplied, sizeof(supplied)), produced));
	// Проверяем отказ расшифрования незаведённым режимом с зацеплением
	ASSERT_FALSE(unchained.decrypt(view_t(supplied, sizeof(supplied)), produced));
	// Объект режима обратной связи по шифртексту
	cipher::feedback_t unstarted;
	// Проверяем отказ зашифрования незаведённым режимом обратной связи
	ASSERT_FALSE(unstarted.encrypt(view_t(supplied, sizeof(supplied)), produced));
	// Проверяем отказ расшифрования незаведённым режимом обратной связи
	ASSERT_FALSE(unstarted.decrypt(view_t(supplied, sizeof(supplied)), produced));
	// Объект режима выработки имитовставки
	cipher::imitation_t imitation;
	// Проверяем отказ подачи содержимого незаведённому режиму имитовставки
	ASSERT_FALSE(imitation.update(view_t(supplied, sizeof(supplied))));
	// Проверяем отказ снятия имитовставки с незаведённого режима
	ASSERT_FALSE(imitation.finish(produced, cipher::KUZNYECHIK_BLOCK));
	// Проверяем отказ заведения режима по выходу с непереданным вектором замены
	ASSERT_FALSE(output.start(sample, view_t(nullptr, cipher::MODE_BLOCK)));
	// Проверяем отказ заведения вектором замены длиннее сдвигового регистра
	ASSERT_FALSE(output.start(sample, view_t(iv, (cipher::MODE_REGISTER + cipher::MODE_BLOCK))));
	// Проверяем успешность заведения вектором замены длиною в сдвиговый регистр
	ASSERT_TRUE(output.start(sample, view_t(iv, cipher::MODE_REGISTER)));
	// Объект режима обратной связи по выходу
	cipher::feedback_t feedback;
	// Проверяем отказ заведения вектором замены длиннее сдвигового регистра
	ASSERT_FALSE(feedback.start(sample, view_t(iv, (cipher::MODE_REGISTER + cipher::MODE_BLOCK))));
	// Проверяем успешность заведения вектором замены длиною в сдвиговый регистр
	ASSERT_TRUE(feedback.start(sample, view_t(iv, cipher::MODE_REGISTER)));
	// Место, в которое складывается итог работы режима с зацеплением
	uint8_t result[64] = {0};
	// Область байтов, подаваемая режиму с зацеплением
	uint8_t source[64] = {0};
	// Выполняем заполнение подаваемой области байтов
	::memset(source, 0x33, sizeof(source));
	/**
	 * Работа режимов с зацеплением требует переданными ОБА места, и всякое из них
	 * отвергает работу в одиночку: непереданное место итога при годной подаче трогает
	 * ту половину заслона, что отвечает за итог
	 */
	ASSERT_FALSE(chaining.encrypt(view_t(source, sizeof(source)), nullptr));
	// Проверяем отказ расшифрования с зацеплением в непереданное место
	ASSERT_FALSE(chaining.decrypt(view_t(source, sizeof(source)), nullptr));
	// Проверяем отказ зашифрования с зацеплением непереданной подачи
	ASSERT_FALSE(chaining.encrypt(view_t(nullptr, sizeof(source)), result));
	// Проверяем отказ расшифрования с зацеплением непереданной подачи
	ASSERT_FALSE(chaining.decrypt(view_t(nullptr, sizeof(source)), result));
	// Проверяем успешность зашифрования с зацеплением годной подачи
	ASSERT_TRUE(chaining.encrypt(view_t(source, sizeof(source)), result));
	/**
	 * Тот же заслон стоит у режима с обратной связью по выходу: сверка мест берётся
	 * лишь при непустой подаче, и пустая подача проходит без всяких мест
	 */
	ASSERT_FALSE(feedback.encrypt(view_t(nullptr, sizeof(source)), result));
	// Проверяем отказ расшифрования с обратной связью непереданной подачи
	ASSERT_FALSE(feedback.decrypt(view_t(nullptr, sizeof(source)), result));
	// Проверяем отказ зашифрования с обратной связью в непереданное место
	ASSERT_FALSE(feedback.encrypt(view_t(source, sizeof(source)), nullptr));
	// Проверяем отказ расшифрования с обратной связью в непереданное место
	ASSERT_FALSE(feedback.decrypt(view_t(source, sizeof(source)), nullptr));
	// Проверяем успешность зашифрования с обратной связью пустой подачи
	ASSERT_TRUE(feedback.encrypt(view_t(nullptr, 0), nullptr));
	// Проверяем успешность расшифрования с обратной связью пустой подачи
	ASSERT_TRUE(feedback.decrypt(view_t(nullptr, 0), nullptr));
	// Проверяем успешность зашифрования по выходу пустой подачи
	ASSERT_TRUE(output.encrypt(view_t(nullptr, 0), nullptr));
	// Проверяем отказ зашифрования по выходу непереданной подачи
	ASSERT_FALSE(output.encrypt(view_t(nullptr, sizeof(source)), result));
	/**
	 * Вектор замены режимов с зацеплением занимает ЦЕЛОЕ число блоков шифра: длина, в
	 * блок не уложившаяся, трогает ту часть заслона, что отвечает за кратность
	 */
	ASSERT_FALSE(output.start(sample, view_t(iv, (cipher::MODE_BLOCK + 1))));
	// Проверяем отказ заведения вектором замены короче блока шифра
	ASSERT_FALSE(output.start(sample, view_t(iv, (cipher::MODE_BLOCK - 1))));
}

/**
 * Проверка готовности режимов и отказов установки на негодном описании шифра
 */
TEST(ModeTest, Unready) {
	// Секретный ключ Кузнечика
	uint8_t secret[32];
	// Разбор секретного ключа из шестнадцатеричной записи
	bytes(KUZNYECHIK_SECRET, secret);
	// Базовый шифр Кузнечик
	cipher::kuznyechik_t base;
	// Ключ Кузнечика принимается
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Синхропосылка
	uint8_t iv[32];
	::memset(iv, 0x44, sizeof(iv));
	// Размер блока Кузнечика
	const size_t size = cipher::KUZNYECHIK_BLOCK;
	// Всякий режим до установки не готов, а после установки готов
	cipher::codebook_t codebook;
	// Простая замена до установки не готова
	ASSERT_FALSE(codebook.ready());
	// Запуск простой замены на шифре
	ASSERT_TRUE(codebook.start(cipher::block_t(base)));
	ASSERT_TRUE(codebook.ready());
	// Гаммирование сцеплением счётчика
	cipher::counter_t counter;
	// Гаммирование до установки не готово
	ASSERT_FALSE(counter.ready());
	// Запуск гаммирования с укороченной синхропосылкой
	ASSERT_TRUE(counter.start(cipher::block_t(base), view_t(iv, size / 2)));
	ASSERT_TRUE(counter.ready());
	/**
	 * Описание шифра без самого шифра непригодно всякому режиму: у гаммирования с
	 * обратной связью, сцепления и имитовставки заслон тот же, что у простой замены
	 */
	cipher::output_t output;
	// Описание без шифра до установки не готово
	ASSERT_FALSE(output.ready());
	ASSERT_FALSE(output.start(cipher::block_t(), view_t(iv, size)));
	// Длина гаммы не больше блока: раздел 5.3 ГОСТ Р 34.13-2015
	ASSERT_FALSE(output.start(cipher::block_t(base), view_t(iv, size), size + 1));
	// Запуск гаммирования с обратной связью по выходу на шифре
	ASSERT_TRUE(output.start(cipher::block_t(base), view_t(iv, size)));
	ASSERT_TRUE(output.ready());
	// Сцепление блоков
	cipher::chaining_t chaining;
	// Сцепление до установки не готово
	ASSERT_FALSE(chaining.ready());
	ASSERT_FALSE(chaining.start(cipher::block_t(), view_t(iv, size)));
	// Запуск сцепления на шифре
	ASSERT_TRUE(chaining.start(cipher::block_t(base), view_t(iv, size)));
	ASSERT_TRUE(chaining.ready());
	// Гаммирование с обратной связью по шифротексту
	cipher::feedback_t feedback;
	// Гаммирование с обратной связью до установки не готово
	ASSERT_FALSE(feedback.ready());
	ASSERT_FALSE(feedback.start(cipher::block_t(), view_t(iv, size)));
	// Длина гаммы не больше блока: раздел 5.5 ГОСТ Р 34.13-2015
	ASSERT_FALSE(feedback.start(cipher::block_t(base), view_t(iv, size), size + 1));
	// Запуск гаммирования с обратной связью по шифротексту на шифре
	ASSERT_TRUE(feedback.start(cipher::block_t(base), view_t(iv, size)));
	ASSERT_TRUE(feedback.ready());
	// Имитовставка
	cipher::imitation_t imitation;
	// Имитовставка до установки не готова
	ASSERT_FALSE(imitation.ready());
	ASSERT_FALSE(imitation.start(cipher::block_t()));
	// Запуск имитовставки на шифре
	ASSERT_TRUE(imitation.start(cipher::block_t(base)));
	ASSERT_TRUE(imitation.ready());
}
/**
 * @brief Проверка режима простой замены с зацеплением на шифре AES по векторам SP 800-38A
 *
 * @details Приложение F.2 NIST SP 800-38A: примеры F.2.1 (CBC-AES128), F.2.3 (CBC-AES192) и
 *          F.2.5 (CBC-AES256) на четырёх блоках открытого текста с одной синхропосылкой;
 *          расшифрование сверяется по примерам F.2.2, F.2.4 и F.2.6 теми же данными
 *
 */
TEST(ModeTest, AesChaining) {
	// Описание примера приложения F.2 SP 800-38A
	static const struct Example {
		// Ключ шифрования
		const char * key;
		// Ожидаемый шифртекст
		const char * cipher;
	} examples[] = {
		{"2b7e151628aed2a6abf7158809cf4f3c", "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"},
		{"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd"},
		{"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"}
	};
	/**
	 * Выполняем перебор примеров приложения F.2
	 */
	for(size_t i = 0; i < (sizeof(examples) / sizeof(examples[0])); i++){
		// Ключ шифрования
		uint8_t secret[32];
		// Синхропосылка
		uint8_t iv[16];
		// Открытый текст и шифртекст
		uint8_t plain[64], cipher[64];
		// Выполняем разбор ключа шифрования
		const size_t width = bytes(examples[i].key, secret);
		// Выполняем разбор синхропосылки
		bytes("000102030405060708090a0b0c0d0e0f", iv);
		// Выполняем разбор открытого текста: четыре блока приложения F
		const size_t size = bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", plain);
		// Объект блочного шифра AES
		cipher::aes_t base;
		// Выполняем установку ключа шифрования
		ASSERT_TRUE(base.key(view_t(secret, width)));
		// Объект режима простой замены с зацеплением
		cipher::chaining_t mode;
		// Выполняем запуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
		// Выполняем зашифрование открытого текста
		ASSERT_TRUE(mode.encrypt(view_t(plain, size), cipher));
		// Сличаем полученный шифртекст с контрольным примером
		ASSERT_EQ(text(cipher, size), std::string(examples[i].cipher)) << "пример " << i;
		// Место, в которое помещается расшифрованный текст
		uint8_t back[64];
		// Выполняем перезапуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
		// Выполняем расшифрование шифртекста
		ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
		// Сличаем расшифрованный текст с исходным
		ASSERT_EQ(::memcmp(back, plain, size), 0) << "пример " << i;
		// Порча одного байта шифртекста портит свой блок и один байт следующего, а не всё
		cipher[0] ^= 0x01;
		// Выполняем перезапуск режима работы
		ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(iv, sizeof(iv))));
		// Выполняем расшифрование порченого шифртекста
		ASSERT_TRUE(mode.decrypt(view_t(cipher, size), back));
		// Первый блок не сошёлся
		ASSERT_NE(::memcmp(back, plain, 16), 0);
		// Второй блок разошёлся ровно первым байтом
		ASSERT_EQ(back[16], static_cast <uint8_t> (plain[16] ^ 0x01));
		// Третий и четвёртый блоки целы
		ASSERT_EQ(::memcmp(back + 32, plain + 32, 32), 0);
	}
}
/**
 * @brief Проверка гаммы AES ядром шифра по многу блоков: итог тот же, что поблочно, при любой нарезке
 *
 */
TEST(ModeTest, AesCounterStream) {
	// Ключ шифрования
	uint8_t secret[32];
	// Синхропосылка
	uint8_t iv[8];
	/**
	 * Выполняем заполнение ключа
	 */
	for(size_t i = 0; i < sizeof(secret); i++)
		// Записываем очередной байт ключа
		secret[i] = static_cast <uint8_t> ((i * 7) + 3);
	/**
	 * Выполняем заполнение синхропосылки
	 */
	for(size_t i = 0; i < sizeof(iv); i++)
		// Записываем очередной байт синхропосылки
		iv[i] = static_cast <uint8_t> (0xF0 + i);
	// Объект блочного шифра
	cipher::aes_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Описание шифра с ядром гаммы
	const cipher::block_t kernel(base);
	// Описание того же шифра без ядра гаммы и без пачек: гамма поблочно
	cipher::block_t blockwise(base);
	// Снимаем ядро гаммы
	blockwise.stream = nullptr;
	// Снимаем пачки
	blockwise.batch = nullptr;
	// Генератор данных и длин кусков с закреплённым зерном
	std::mt19937 generator(20260923);
	// Длины сообщений: границы блока, пачек в тридцать два и сто двадцать восемь блоков и запись
	const size_t lengths[] = {0, 1, 15, 16, 17, 63, 64, 65, 511, 512, 513, 1023, 1024, 1025, 1200, 1201, 2047, 2048, 4103};
	/**
	 * Выполняем перебор путей шифра: команды машины и таблицы
	 */
	for(size_t pass = 0; pass < 2; pass++){
		// Разрешаем либо запрещаем машинные команды
		machine::allow(pass == 0);
		/**
		 * Выполняем перебор длин
		 */
		for(const size_t length : lengths){
			// Открытый текст, шифртексты обоих путей и раскрытый текст
			std::vector <uint8_t> plain(length), first(length), second(length), opened(length);
			/**
			 * Выполняем заполнение открытого текста
			 */
			for(size_t i = 0; i < length; i++)
				// Записываем очередной байт
				plain[i] = static_cast <uint8_t> (generator());
			// Объект режима гаммирования
			cipher::counter_t mode;
			// Проверяем запуск режима с ядром гаммы
			ASSERT_TRUE(mode.start(kernel, view_t(iv, sizeof(iv))));
			// Проверяем зашифрование целиком ядром гаммы
			ASSERT_TRUE(mode.encrypt(view_t(plain.data(), length), first.data()));
			// Проверяем запуск режима поблочно
			ASSERT_TRUE(mode.start(blockwise, view_t(iv, sizeof(iv))));
			// Проверяем зашифрование целиком поблочно
			ASSERT_TRUE(mode.encrypt(view_t(plain.data(), length), second.data()));
			// Проверяем схождение шифртекстов обоих путей
			ASSERT_EQ(::memcmp(first.data(), second.data(), length), 0) << "pass " << pass << " length " << length;
			// Проверяем перезапуск режима с ядром гаммы
			ASSERT_TRUE(mode.start(kernel, view_t(iv, sizeof(iv))));
			// Позиция внутри данных
			size_t position = 0;
			/**
			 * Выполняем расшифрование кусками случайной длины через границы пачек
			 */
			while(position < length){
				// Длина очередного куска
				size_t chunk = (1 + (generator() % 700));
				// Если кусок длиннее остатка
				if(chunk > (length - position))
					// Ограничиваем кусок остатком
					chunk = (length - position);
				// Проверяем расшифрование куска
				ASSERT_TRUE(mode.decrypt(view_t(first.data() + position, chunk), opened.data() + position));
				// Сдвигаем позицию
				position += chunk;
			}
			// Проверяем возврат открытого текста кусками
			ASSERT_EQ(::memcmp(opened.data(), plain.data(), length), 0) << "pass " << pass << " length " << length;
		}
	}
	// Возвращаем машинные команды
	machine::allow(true);
}
