/**
 * @file cipher.cpp
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
 * @brief Исходный файл проверок модулей блочного шифрования «Кузнечик» и «Магма»
 *
 * @note Контрольные примеры взяты из ГОСТ Р 34.12-2015 (перепечатан RFC 7801 для
 *       «Кузнечика» и RFC 8891 для «Магмы»)
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
#include <cipher/magma.hpp>
#include <cipher/kuznyechik.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text  разбираемая запись
 * @param data  место, в которое помещаются разобранные байты
 *
 * @return      число разобранных байтов
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
 * @brief Проверка шифра «Кузнечик» по контрольному примеру
 *
 */
TEST(CipherTest, Kuznyechik) {
	// Ключ, открытый и зашифрованный блоки
	uint8_t key[cipher::KUZNYECHIK_KEY], plain[cipher::KUZNYECHIK_BLOCK];
	uint8_t result[cipher::KUZNYECHIK_BLOCK], back[cipher::KUZNYECHIK_BLOCK];
	// Разбираем ключ шифрования
	ASSERT_EQ(bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", key), cipher::KUZNYECHIK_KEY);
	// Разбираем открытый блок
	ASSERT_EQ(bytes("1122334455667700ffeeddccbbaa9988", plain), cipher::KUZNYECHIK_BLOCK);
	// Создаём объект шифра
	cipher::kuznyechik_t engine;
	// Проверяем неготовность шифра до установки ключа
	ASSERT_FALSE(engine.ready());
	// Проверяем отказ зашифрования до установки ключа
	ASSERT_FALSE(engine.encrypt(plain, result));
	// Проверяем успешность установки ключа
	ASSERT_TRUE(engine.key(view_t(key, sizeof(key))));
	// Проверяем готовность шифра к работе
	ASSERT_TRUE(engine.ready());
	// Проверяем успешность зашифрования
	ASSERT_TRUE(engine.encrypt(plain, result));
	// Проверяем совпадение зашифрованного блока с контрольным примером
	ASSERT_STREQ(text(result, sizeof(result)).c_str(), "7f679d90bebc24305a468d42b9d4edcd");
	// Проверяем успешность расшифрования
	ASSERT_TRUE(engine.decrypt(result, back));
	// Проверяем совпадение расшифрованного блока с исходным
	ASSERT_STREQ(text(back, sizeof(back)).c_str(), "1122334455667700ffeeddccbbaa9988");
}
/**
 * @brief Проверка шифра «Магма» по контрольному примеру
 *
 */
TEST(CipherTest, Magma) {
	// Ключ, открытый и зашифрованный блоки
	uint8_t key[cipher::MAGMA_KEY], plain[cipher::MAGMA_BLOCK];
	uint8_t result[cipher::MAGMA_BLOCK], back[cipher::MAGMA_BLOCK];
	// Разбираем ключ шифрования
	ASSERT_EQ(bytes("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key), cipher::MAGMA_KEY);
	// Разбираем открытый блок
	ASSERT_EQ(bytes("fedcba9876543210", plain), cipher::MAGMA_BLOCK);
	// Создаём объект шифра
	cipher::magma_t engine;
	// Проверяем неготовность шифра до установки ключа
	ASSERT_FALSE(engine.ready());
	// Проверяем отказ зашифрования до установки ключа
	ASSERT_FALSE(engine.encrypt(plain, result));
	// Проверяем успешность установки ключа
	ASSERT_TRUE(engine.key(view_t(key, sizeof(key))));
	// Проверяем успешность зашифрования
	ASSERT_TRUE(engine.encrypt(plain, result));
	// Проверяем совпадение зашифрованного блока с контрольным примером
	ASSERT_STREQ(text(result, sizeof(result)).c_str(), "4ee901e5c2d8ca3d");
	// Проверяем успешность расшифрования
	ASSERT_TRUE(engine.decrypt(result, back));
	// Проверяем совпадение расшифрованного блока с исходным
	ASSERT_STREQ(text(back, sizeof(back)).c_str(), "fedcba9876543210");
}
/**
 * @brief Проверка обратимости шифров на наборе блоков
 *
 */
TEST(CipherTest, Reversibility) {
	// Ключ шифрования
	uint8_t key[32];
	/**
	 * Выполняем сборку ключа шифрования
	 */
	for(size_t i = 0; i < sizeof(key); i++)
		// Записываем очередной байт ключа шифрования
		key[i] = static_cast <uint8_t> ((i * 73) & 0xFF);
	// Создаём объекты шифров
	cipher::kuznyechik_t first;
	cipher::magma_t second;
	// Проверяем успешность установки ключей
	ASSERT_TRUE(first.key(view_t(key, sizeof(key))));
	ASSERT_TRUE(second.key(view_t(key, sizeof(key))));
	// Преобразуемые блоки
	uint8_t plain[16], result[16], back[16];
	/**
	 * Выполняем перебор преобразуемых блоков
	 */
	for(size_t i = 0; i < 256; i++){
		/**
		 * Выполняем сборку очередного преобразуемого блока
		 */
		for(size_t j = 0; j < sizeof(plain); j++)
			// Записываем очередной байт преобразуемого блока
			plain[j] = static_cast <uint8_t> (((i * 31) + (j * 17)) & 0xFF);
		// Проверяем обратимость шифра «Кузнечик»
		ASSERT_TRUE(first.encrypt(plain, result)) << "блок " << i;
		ASSERT_TRUE(first.decrypt(result, back)) << "блок " << i;
		ASSERT_EQ(::memcmp(plain, back, cipher::KUZNYECHIK_BLOCK), 0) << "блок " << i;
		// Проверяем, что зашифрованный блок отличается от открытого
		ASSERT_NE(::memcmp(plain, result, cipher::KUZNYECHIK_BLOCK), 0) << "блок " << i;
		// Проверяем обратимость шифра «Магма»
		ASSERT_TRUE(second.encrypt(plain, result)) << "блок " << i;
		ASSERT_TRUE(second.decrypt(result, back)) << "блок " << i;
		ASSERT_EQ(::memcmp(plain, back, cipher::MAGMA_BLOCK), 0) << "блок " << i;
	}
}
/**
 * @brief Проверка преобразования блока на месте
 *
 */
TEST(CipherTest, InPlace) {
	// Ключ и преобразуемый блок
	uint8_t key[32], block[16], expected[16];
	// Разбираем ключ шифрования
	ASSERT_EQ(bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef", key), size_t(32));
	// Разбираем преобразуемый блок
	ASSERT_EQ(bytes("1122334455667700ffeeddccbbaa9988", block), size_t(16));
	// Создаём объект шифра
	cipher::kuznyechik_t engine;
	// Проверяем успешность установки ключа
	ASSERT_TRUE(engine.key(view_t(key, sizeof(key))));
	// Выполняем зашифрование блока на месте
	ASSERT_TRUE(engine.encrypt(block, block));
	// Проверяем совпадение зашифрованного блока с контрольным примером
	ASSERT_STREQ(text(block, sizeof(block)).c_str(), "7f679d90bebc24305a468d42b9d4edcd");
	// Разбираем ожидаемый открытый блок
	ASSERT_EQ(bytes("1122334455667700ffeeddccbbaa9988", expected), size_t(16));
	// Выполняем расшифрование блока на месте
	ASSERT_TRUE(engine.decrypt(block, block));
	// Проверяем совпадение расшифрованного блока с исходным
	ASSERT_EQ(::memcmp(block, expected, sizeof(block)), 0);
}
/**
 * @brief Проверка отказов установки ключа и затирания ключей
 *
 */
TEST(CipherTest, Refusal) {
	// Ключ шифрования и преобразуемый блок
	uint8_t key[32], block[16];
	// Обнуляем ключ шифрования
	::memset(key, 0, sizeof(key));
	// Обнуляем преобразуемый блок
	::memset(block, 0, sizeof(block));
	// Создаём объект шифра
	cipher::kuznyechik_t engine;
	// Проверяем отказ расшифрования незаведённым шифром
	ASSERT_FALSE(engine.decrypt(block, block));
	// Проверяем отказ установки ключа недостаточной длины
	ASSERT_FALSE(engine.key(view_t(key, 31)));
	// Проверяем отказ установки ключа избыточной длины
	ASSERT_FALSE(engine.key(view_t(key, sizeof(key) - 1)));
	// Проверяем отказ установки отсутствующего ключа
	ASSERT_FALSE(engine.key(view_t()));
	// Проверяем неготовность шифра после отказа установки ключа
	ASSERT_FALSE(engine.ready());
	// Проверяем успешность установки ключа верной длины
	ASSERT_TRUE(engine.key(view_t(key, sizeof(key))));
	// Проверяем отказ зашифрования в отсутствующее место
	ASSERT_FALSE(engine.encrypt(block, nullptr));
	// Проверяем отказ зашифрования отсутствующего блока
	ASSERT_FALSE(engine.encrypt(nullptr, block));
	// Проверяем отказ расшифрования в отсутствующее место
	ASSERT_FALSE(engine.decrypt(block, nullptr));
	// Проверяем отказ расшифрования отсутствующего блока
	ASSERT_FALSE(engine.decrypt(nullptr, block));
	// Выполняем затирание раундовых ключей
	engine.clear();
	// Проверяем неготовность шифра после затирания ключей
	ASSERT_FALSE(engine.ready());
	// Проверяем отказ зашифрования после затирания ключей
	ASSERT_FALSE(engine.encrypt(block, block));
	/**
	 * «Магма» стережёт свои доводы теми же заслонами, что и «Кузнечик», и заслоны эти
	 * у неё СВОИ: сверять их у одного шифра и полагать проверенными у другого нельзя
	 */
	cipher::magma_t magma;
	// Проверяем отказ установки непереданного ключа шифрования
	ASSERT_FALSE(magma.key(view_t(nullptr, cipher::MAGMA_KEY)));
	// Проверяем отказ установки ключа шифрования не той длины
	ASSERT_FALSE(magma.key(view_t(key, (cipher::MAGMA_KEY - 1))));
	// Проверяем неготовность шифра после отказа установки ключа
	ASSERT_FALSE(magma.ready());
	// Проверяем отказ зашифрования незаведённым шифром
	ASSERT_FALSE(magma.encrypt(block, block));
	// Проверяем отказ расшифрования незаведённым шифром
	ASSERT_FALSE(magma.decrypt(block, block));
	// Проверяем успешность установки ключа шифрования положенной длины
	ASSERT_TRUE(magma.key(view_t(key, cipher::MAGMA_KEY)));
	// Проверяем отказ зашифрования непереданного блока
	ASSERT_FALSE(magma.encrypt(nullptr, block));
	// Проверяем отказ зашифрования в непереданное место
	ASSERT_FALSE(magma.encrypt(block, nullptr));
	// Проверяем отказ расшифрования непереданного блока
	ASSERT_FALSE(magma.decrypt(nullptr, block));
	// Проверяем отказ расшифрования в непереданное место
	ASSERT_FALSE(magma.decrypt(block, nullptr));
	// Выполняем затирание раундовых ключей шифра
	magma.clear();
	// Проверяем неготовность шифра после затирания ключей
	ASSERT_FALSE(magma.ready());
	// Проверяем отказ расшифрования после затирания ключей
	ASSERT_FALSE(magma.decrypt(block, block));
}
