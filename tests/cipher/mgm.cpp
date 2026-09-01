/**
 * @file mgm.cpp
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
 * @brief Исходный файл проверок модуля режима шифрования с проверкой целостности MGM
 *
 * @note Контрольные примеры взяты из приложения А RFC 9058: оба примера для шифра
 *       «Кузнечик» и оба примера для шифра «Магма»
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
#include <cipher/mgm.hpp>

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
 * @brief Проверка отказов режима с проверкой целостности на негодных доводах
 *
 * @note Заслоны эти стерегут оплошность потребителя фреймворка: непереданное место,
 *       неповторимое значение не по размеру блока, метку подлинности не той длины.
 *       Отдельно проверяется отказ на пустой подаче: шифровать и заверять нечего,
 *       и молча выдавать метку пустоты режим не вправе
 *
 */
TEST(MgmTest, Refusals) {
	// Ключ шифрования
	uint8_t secret[32];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Размер блока применяемого шифра
	const size_t size = cipher::KUZNYECHIK_BLOCK;
	// Неповторимое значение, годное режиму работы
	uint8_t nonce[cipher::KUZNYECHIK_BLOCK];
	// Выполняем набивку неповторимого значения
	::memset(nonce, 0x11, sizeof(nonce));
	/**
	 * Старший разряд неповторимого значения обнуляется: режим кладёт ему быть нулём
	 */
	nonce[0] &= 0x7F;
	// Область байтов, подаваемая режиму работы
	uint8_t source[32];
	// Выполняем набивку подаваемой области байтов
	::memset(source, 0x22, sizeof(source));
	// Место, в которое складывается итог работы режима
	uint8_t result[32];
	// Место, в которое складывается метка подлинности
	uint8_t tag[cipher::KUZNYECHIK_BLOCK];
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Проверяем отказ работы незаведённого режима
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, 0), view_t(source, size), result, tag));
	// Проверяем отказ заведения незаполненным описателем шифра
	ASSERT_FALSE(mode.start(cipher::block_t(), view_t(nonce, sizeof(nonce))));
	// Проверяем отказ заведения при непереданном неповторимом значении
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nullptr, size)));
	// Проверяем отказ заведения при неповторимом значении не по размеру блока
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nonce, size - 1)));
	// Выполняем заведение режима шифрования с проверкой целостности
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Проверяем отказ работы при непереданном месте метки подлинности
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, 0), view_t(source, size), result, nullptr));
	// Проверяем отказ работы при непереданной области байтов
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, 0), view_t(nullptr, size), result, tag));
	// Проверяем отказ работы при непереданном месте итога
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, 0), view_t(source, size), nullptr, tag));
	// Проверяем отказ работы при непереданных связанных данных
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, size), view_t(source, size), result, tag));
	/**
	 * Пустая подача отвергается: ни шифровать, ни заверять нечего, а метка,
	 * выданная на пустоту, заверяла бы отсутствие сообщения
	 */
	ASSERT_FALSE(mode.encrypt(view_t(nullptr, 0), view_t(nullptr, 0), result, tag));
	// Выполняем зашифрование подаваемой области байтов
	ASSERT_TRUE(mode.encrypt(view_t(nullptr, 0), view_t(source, size), result, tag));
	// Выполняем заведение режима заново для снятия защиты
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Проверяем отказ снятия защиты при непереданной метке подлинности
	ASSERT_FALSE(mode.decrypt(view_t(nullptr, 0), view_t(result, size), source, view_t(nullptr, size)));
	// Проверяем отказ снятия защиты при метке подлинности не той длины
	ASSERT_FALSE(mode.decrypt(view_t(nullptr, 0), view_t(result, size), source, view_t(tag, size - 1)));
	// Проверяем отказ снятия защиты при непереданном месте итога
	ASSERT_FALSE(mode.decrypt(view_t(nullptr, 0), view_t(result, size), nullptr, view_t(tag, size)));
	// Проверяем отказ снятия защиты при непереданных связанных данных
	ASSERT_FALSE(mode.decrypt(view_t(nullptr, size), view_t(result, size), source, view_t(tag, size)));
	// Проверяем отказ снятия защиты при пустой подаче
	ASSERT_FALSE(mode.decrypt(view_t(nullptr, 0), view_t(nullptr, 0), source, view_t(tag, size)));
}

/**
 * @brief Проверка первого контрольного примера на шифре «Кузнечик»
 *
 */
TEST(GaloisTest, KuznyechikFirst) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[16];
	// Связанные данные
	uint8_t associated[41];
	// Открытый текст, шифртекст и расшифрованный текст
	uint8_t plain[67], cipher[67], back[67];
	// Метка целостности
	uint8_t tag[16];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("1122334455667700ffeeddccbbaa9988", nonce);
	// Выполняем разбор связанных данных
	const size_t length = bytes("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505", associated);
	// Выполняем разбор открытого текста
	const size_t size = bytes(
		"1122334455667700ffeeddccbbaa9988"
		"00112233445566778899aabbcceeff0a"
		"112233445566778899aabbcceeff0a00"
		"2233445566778899aabbcceeff0a0011"
		"aabbcc", plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(associated, length), view_t(plain, size), cipher, tag));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"a9757b8147956e9055b8a33de89f42fc"
		"8075d2212bf9fd5bd3f7069aadc16b39"
		"497ab15915a6ba85936b5d0ea9f6851c"
		"c60c14d4d3f883d0ab94420695c76deb"
		"2c7552"
	));
	// Сличаем полученную метку целостности с контрольным примером
	ASSERT_EQ(text(tag, sizeof(tag)), std::string("cf5d656f40c34f5c46e8bb0e29fcdb4c"));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag))));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка второго контрольного примера на шифре «Кузнечик»
 *
 */
TEST(GaloisTest, KuznyechikSecond) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[16];
	// Связанные данные
	uint8_t associated[16];
	// Метка целостности
	uint8_t tag[16];
	// Выполняем разбор ключа шифрования
	bytes("99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("1122334455667700ffeeddccbbaa9988", nonce);
	// Выполняем разбор связанных данных
	const size_t length = bytes("01010101010101010101010101010101", associated);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем выработку метки целостности без зашифрования сообщения
	ASSERT_TRUE(mode.encrypt(view_t(associated, length), view_t(), nullptr, tag));
	// Сличаем полученную метку целостности с контрольным примером
	ASSERT_EQ(text(tag, sizeof(tag)), std::string("7901e9ea2085cd247ed249695f9f8a85"));
	// Выполняем проверку метки целостности
	ASSERT_TRUE(mode.decrypt(view_t(associated, length), view_t(), nullptr, view_t(tag, sizeof(tag))));
}
/**
 * @brief Проверка первого контрольного примера на шифре «Магма»
 *
 */
TEST(GaloisTest, MagmaFirst) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[8];
	// Связанные данные
	uint8_t associated[41];
	// Открытый текст, шифртекст и расшифрованный текст
	uint8_t plain[67], cipher[67], back[67];
	// Метка целостности
	uint8_t tag[8];
	// Выполняем разбор ключа шифрования
	bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("12def06b3c130a59", nonce);
	// Выполняем разбор связанных данных
	const size_t length = bytes("01010101010101010202020202020202030303030303030304040404040404040505050505050505ea", associated);
	// Выполняем разбор открытого текста
	const size_t size = bytes(
		"ffeeddccbbaa9988"
		"1122334455667700"
		"8899aabbcceeff0a"
		"0011223344556677"
		"99aabbcceeff0a00"
		"1122334455667788"
		"aabbcceeff0a0011"
		"2233445566778899"
		"aabbcc", plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(associated, length), view_t(plain, size), cipher, tag));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string(
		"c795066c5f9ea03b"
		"85113342459185ae"
		"1f2e00d6bf2b785d"
		"940470b8bb9c8e7d"
		"9a5dd3731f7ddc70"
		"ec27cb0ace6fa576"
		"70f65c646abb75d5"
		"47aa37c3bcb5c34e"
		"03bb9c"
	));
	// Сличаем полученную метку целостности с контрольным примером
	ASSERT_EQ(text(tag, sizeof(tag)), std::string("a7928069aa10fd10"));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag))));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка второго контрольного примера на шифре «Магма»
 *
 */
TEST(GaloisTest, MagmaSecond) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[8];
	// Открытый текст, шифртекст и расшифрованный текст
	uint8_t plain[8], cipher[8], back[8];
	// Метка целостности
	uint8_t tag[8];
	// Выполняем разбор ключа шифрования
	bytes("99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("0077665544332211", nonce);
	// Выполняем разбор открытого текста
	const size_t size = bytes("22334455667700ff", plain);
	// Объект блочного шифра
	cipher::magma_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем зашифрование открытого текста без связанных данных
	ASSERT_TRUE(mode.encrypt(view_t(), view_t(plain, size), cipher, tag));
	// Сличаем полученный шифртекст с контрольным примером
	ASSERT_EQ(text(cipher, size), std::string("6a95e1426b259d4e"));
	// Сличаем полученную метку целостности с контрольным примером
	ASSERT_EQ(text(tag, sizeof(tag)), std::string("334ee270450bec9e"));
	// Выполняем расшифрование шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(), view_t(cipher, size), back, view_t(tag, sizeof(tag))));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка отказа расшифрования при порче сообщения
 *
 */
TEST(GaloisTest, Forgery) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[16];
	// Связанные данные
	uint8_t associated[16];
	// Открытый текст, шифртекст и расшифрованный текст
	uint8_t plain[32], cipher[32], back[32];
	// Метка целостности
	uint8_t tag[16];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("1122334455667700ffeeddccbbaa9988", nonce);
	// Выполняем разбор связанных данных
	const size_t length = bytes("01010101010101010101010101010101", associated);
	// Выполняем разбор открытого текста
	const size_t size = bytes("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a", plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Выполняем запуск режима работы
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(associated, length), view_t(plain, size), cipher, tag));
	/**
	 * Выполняем перебор байтов шифртекста
	 */
	for(size_t i = 0; i < size; i++){
		// Выполняем порчу очередного байта шифртекста
		cipher[i] = static_cast <uint8_t> (cipher[i] ^ 0x01);
		// Проверяем отказ расшифрования испорченного шифртекста
		ASSERT_FALSE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта шифртекста
		cipher[i] = static_cast <uint8_t> (cipher[i] ^ 0x01);
	}
	/**
	 * Выполняем перебор байтов связанных данных
	 */
	for(size_t i = 0; i < length; i++){
		// Выполняем порчу очередного байта связанных данных
		associated[i] = static_cast <uint8_t> (associated[i] ^ 0x01);
		// Проверяем отказ расшифрования при порче связанных данных
		ASSERT_FALSE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта связанных данных
		associated[i] = static_cast <uint8_t> (associated[i] ^ 0x01);
	}
	/**
	 * Выполняем перебор байтов метки целостности
	 */
	for(size_t i = 0; i < sizeof(tag); i++){
		// Выполняем порчу очередного байта метки целостности
		tag[i] = static_cast <uint8_t> (tag[i] ^ 0x01);
		// Проверяем отказ расшифрования при порче метки целостности
		ASSERT_FALSE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag)))) << "Место порчи: " << i;
		// Выполняем восстановление очередного байта метки целостности
		tag[i] = static_cast <uint8_t> (tag[i] ^ 0x01);
	}
	// Проверяем успешность расшифрования восстановленного шифртекста
	ASSERT_TRUE(mode.decrypt(view_t(associated, length), view_t(cipher, size), back, view_t(tag, sizeof(tag))));
	// Сличаем расшифрованный текст с исходным
	ASSERT_EQ(::memcmp(back, plain, size), 0);
}
/**
 * @brief Проверка отказов режима работы
 *
 */
TEST(GaloisTest, Failures) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[16];
	// Открытый текст и шифртекст
	uint8_t plain[16], cipher[16];
	// Метка целостности
	uint8_t tag[16];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("1122334455667700ffeeddccbbaa9988", nonce);
	// Выполняем разбор открытого текста
	const size_t size = bytes("1122334455667700ffeeddccbbaa9988", plain);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t mode;
	// Проверяем отказ работы режима до его запуска
	ASSERT_FALSE(mode.ready());
	// Проверяем отказ зашифрования до запуска режима работы
	ASSERT_FALSE(mode.encrypt(view_t(), view_t(plain, size), cipher, tag));
	// Проверяем отказ запуска режима работы с непригодным базовым алгоритмом
	ASSERT_FALSE(mode.start(cipher::block_t(), view_t(nonce, sizeof(nonce))));
	// Проверяем отказ запуска режима работы с меткой целостности короче наименьшей
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce)), cipher::MGM_TAG - 1));
	// Проверяем отказ запуска режима работы с меткой целостности длиннее блока шифра
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce)), 17));
	// Проверяем отказ запуска режима работы с начальным заполнением не в блок шифра
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nonce, 8)));
	// Выполняем установку единичного старшего разряда начального заполнения счётчика
	nonce[0] = static_cast <uint8_t> (nonce[0] | 0x80);
	// Проверяем отказ запуска режима работы с занятым старшим разрядом заполнения
	ASSERT_FALSE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем снятие единичного старшего разряда начального заполнения счётчика
	nonce[0] = static_cast <uint8_t> (nonce[0] & 0x7F);
	// Выполняем запуск режима работы с укороченной меткой целостности
	ASSERT_TRUE(mode.start(cipher::block_t(base), view_t(nonce, sizeof(nonce)), cipher::MGM_TAG));
	// Проверяем длину метки целостности
	ASSERT_EQ(mode.size(), cipher::MGM_TAG);
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(mode.encrypt(view_t(), view_t(plain, size), cipher, tag));
	// Место, в которое помещается полная метка целостности
	uint8_t full[16];
	// Объект режима шифрования с полной меткой целостности
	cipher::galois_t whole;
	// Выполняем запуск режима работы с полной меткой целостности
	ASSERT_TRUE(whole.start(cipher::block_t(base), view_t(nonce, sizeof(nonce))));
	// Выполняем зашифрование открытого текста
	ASSERT_TRUE(whole.encrypt(view_t(), view_t(plain, size), cipher, full));
	/**
	 * Укороченная метка целостности снимается со старших байтов полной, оттого её
	 * начало обязано совпадать с началом полной метки
	 */
	ASSERT_EQ(::memcmp(tag, full, cipher::MGM_TAG), 0);
	// Проверяем отказ проверки метки целостности иной длины
	ASSERT_FALSE(mode.decrypt(view_t(), view_t(cipher, size), plain, view_t(tag, sizeof(tag))));
	// Проверяем отказ зашифрования при пустых связанных данных и пустом сообщении
	ASSERT_FALSE(mode.encrypt(view_t(), view_t(), nullptr, tag));
}

/**
 * Проверка обратимости шифрования при всякой длине сообщения
 *
 * @note Умножение в поле приводится по многочлену дважды, и второе приведение
 *       затрагивает лишь семь старших разрядов: длины, при которых оно и случается,
 *       контрольными примерами RFC 9058 не покрыты вовсе
 */
TEST(GaloisTest, Lengths) {
	// Ключ шифрования
	uint8_t secret[32];
	// Начальное заполнение счётчика
	uint8_t nonce[16];
	// Открытый текст, шифртекст и расшифрованный текст
	uint8_t plain[128], sealed[128], back[128];
	// Связанные данные
	uint8_t associated[64];
	// Метка целостности
	uint8_t tag[16];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Выполняем разбор начального заполнения счётчика
	bytes("1122334455667700ffeeddccbbaa9988", nonce);
	/**
	 * Выполняем заполнение открытого текста и связанных данных
	 */
	for(size_t i = 0; i < sizeof(plain); i++){
		// Записываем очередной байт открытого текста
		plain[i] = static_cast <uint8_t> ((i * 37) + 11);
		// Если очередной байт связанных данных ещё не заполнен
		if(i < sizeof(associated))
			// Записываем очередной байт связанных данных
			associated[i] = static_cast <uint8_t> ((i * 53) + 7);
	}
	// Объект блочного шифра «Кузнечик»
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Объект блочного шифра «Магма»
	cipher::magma_t small;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(small.key(view_t(secret, sizeof(secret))));
	/**
	 * Выполняем перебор блочных шифров режима работы
	 */
	for(size_t item = 0; item < 2; item++){
		// Получаем описание базового алгоритма блочного шифрования
		const cipher::block_t block = ((item == 0) ? cipher::block_t(base) : cipher::block_t(small));
		/**
		 * Выполняем перебор длин шифруемого сообщения
		 */
		for(size_t size = 0; size <= sizeof(plain); size += 3){
			// Получаем длину связанных данных сообщения
			const size_t length = ((size / 3) % (sizeof(associated) + 1));
			// Если ни сообщения, ни связанных данных не осталось
			if((size == 0) && (length == 0))
				// Переходим к следующей длине шифруемого сообщения
				continue;
			// Объект режима шифрования с проверкой целостности
			cipher::galois_t mode;
			// Выполняем запуск режима работы
			ASSERT_TRUE(mode.start(block, view_t(nonce, block.size))) << "длина " << size;
			// Выполняем зашифрование открытого текста
			ASSERT_TRUE(mode.encrypt(view_t(associated, length), view_t(plain, size), sealed, tag)) << "длина " << size;
			// Объект режима расшифрования с проверкой целостности
			cipher::galois_t back_mode;
			// Выполняем запуск режима работы
			ASSERT_TRUE(back_mode.start(block, view_t(nonce, block.size))) << "длина " << size;
			// Выполняем расшифрование шифртекста
			ASSERT_TRUE(back_mode.decrypt(view_t(associated, length), view_t(sealed, size), back, view_t(tag, block.size))) << "длина " << size;
			// Проверяем схождение расшифрованного текста с исходным
			ASSERT_EQ(::memcmp(back, plain, size), 0) << "длина " << size;
		}
	}
}

/**
 * Проверка отказов MGM на неполный описатель шифра и негодные места
 */
TEST(MgmTest, Descriptor) {
	// Ключ шифрования
	uint8_t secret[32];
	// Выполняем разбор ключа шифрования
	bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", secret);
	// Объект блочного шифра
	cipher::kuznyechik_t base;
	// Выполняем установку ключа шифрования
	ASSERT_TRUE(base.key(view_t(secret, sizeof(secret))));
	// Годный описатель базового шифра, служащий образцом порчи
	const cipher::block_t sample(base);
	// Неповторимое значение, годное режиму работы
	uint8_t nonce[cipher::KUZNYECHIK_BLOCK];
	// Выполняем заполнение неповторимого значения
	::memset(nonce, 0x11, sizeof(nonce));
	// Снимаем старший разряд неповторимого значения, как того требует MGM
	nonce[0] = static_cast <uint8_t> (nonce[0] & 0x7F);
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Описатель шифра, у которого не заполнено обращение к зашифрованию
	cipher::block_t unencipherable = sample;
	// Убираем из описателя обращение к зашифрованию блока
	unencipherable.encrypt = nullptr;
	// Проверяем отказ заведения описателем без обращения к зашифрованию
	ASSERT_FALSE(galois.start(unencipherable, view_t(nonce, sizeof(nonce))));
	/**
	 * Умножение в поле Галуа MGM определено лишь для блоков в шестьдесят четыре и сто
	 * двадцать восемь разрядов: размер блока сверяется с ОБОИМИ по отдельности, и
	 * описатель с иным размером трогает вторую из двух половин
	 */
	cipher::block_t alien = sample;
	// Объявляем размер блока описателя шифра, полю Галуа не отвечающий
	alien.size = 4;
	// Проверяем отказ заведения описателем с размером блока не того поля
	ASSERT_FALSE(galois.start(alien, view_t(nonce, sizeof(nonce))));
	// Выполняем заведение режима работы годным описателем шифра
	ASSERT_TRUE(galois.start(sample, view_t(nonce, sizeof(nonce))));
	// Шифруемое содержимое и место, в которое складывается итог работы
	uint8_t source[32], result[32], tag[cipher::KUZNYECHIK_BLOCK];
	// Выполняем заполнение шифруемого содержимого
	::memset(source, 0x33, sizeof(source));
	// Выполняем наложение шифрования с проверкой целостности
	ASSERT_TRUE(galois.encrypt(view_t(nullptr, 0), view_t(source, sizeof(source)), result, tag));
	// Выполняем заведение режима работы стороны расшифрования
	ASSERT_TRUE(galois.start(sample, view_t(nonce, sizeof(nonce))));
	// Проверяем отказ расшифрования при непереданном месте итога
	ASSERT_FALSE(galois.decrypt(view_t(nullptr, 0), view_t(result, sizeof(result)), nullptr, view_t(tag, sizeof(tag))));
	// Проверяем отказ расшифрования при непереданном шифртексте
	ASSERT_FALSE(galois.decrypt(view_t(nullptr, 0), view_t(nullptr, sizeof(result)), source, view_t(tag, sizeof(tag))));
	// Проверяем отказ расшифрования при непереданных связанных данных
	ASSERT_FALSE(galois.decrypt(view_t(nullptr, sizeof(source)), view_t(result, sizeof(result)), source, view_t(tag, sizeof(tag))));
	// Проверяем успешность расшифрования годной подачей
	ASSERT_TRUE(galois.decrypt(view_t(nullptr, 0), view_t(result, sizeof(result)), source, view_t(tag, sizeof(tag))));
}
