/**
 * @file x448.cpp
 * @date 2026-09-09
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
 * @brief Проверки модуля выработки общего ключа X448 по RFC 7748: векторы раздела 6.2,
 *        сличение с системным openssl, порождение пары, отказ на точках малого порядка
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <main.hpp>
#include <agreement/x448.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Служебные помощники проверок
 *
 */
namespace {
	/**
	 * @brief Функция разбора шестнадцатеричной записи
	 *
	 * @param text запись
	 * @param data место байтов
	 * @return     число байтов
	 *
	 */
	static size_t bytes(const char * text, uint8_t * data) {
		// Объявляем счётчик записанных байтов
		size_t result = 0;
		/** Перебираем: пары шестнадцатеричных знаков записи, пока не достигнут конец строки */
		for(size_t i = 0; text[i * 2] != '\0'; i++){
			// Объявляем собираемый байт
			uint8_t value = 0;
			/** Перебираем: оба полубайта очередной пары записи */
			for(size_t j = 0; j < 2; j++){
				// Извлекаем очередной знак записи
				const char letter = text[(i * 2) + j];
				// Собираем байт из двух полубайтов
				value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
			}
			// Записываем собранный байт
			data[result++] = value;
		}
		// Возвращаем число записанных байтов
		return result;
	}
	/**
	 * @brief Функция шестнадцатеричной записи байтов
	 *
	 * @param data байты
	 * @param size длина
	 * @return     запись
	 *
	 */
	static std::string text(const uint8_t * data, const size_t size) {
		// Объявляем строку записи
		std::string result;
		// Таблица шестнадцатеричных знаков
		static const char * letters = "0123456789abcdef";
		/** Перебираем: все байты буфера от начала до конца */
		for(size_t i = 0; i < size; i++){
			// Дописываем старший полубайт
			result.append(1, letters[(data[i] >> 4) & 0x0F]);
			// Дописываем младший полубайт
			result.append(1, letters[data[i] & 0x0F]);
		}
		// Возвращаем собранную запись
		return result;
	}
	/**
	 * @brief Функция чтения файла целиком
	 *
	 * @param path путь
	 * @return     содержимое
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Объявляем строку содержимого
		std::string result;
		// Открываем файл на чтение
		FILE * file = ::fopen(path.c_str(), "rb");
		// Проверяем удачу открытия
		if(file == nullptr)
			// При отказе возвращаем пустое содержимое
			return result;
		// Объявляем буфер чтения
		char buffer[256];
		// Объявляем число прочитанных байтов
		size_t count = 0;
		/** Повторяем: чтение порциями, пока файл не исчерпан */
		while((count = ::fread(buffer, 1, sizeof(buffer), file)) > 0)
			// Дописываем прочитанную порцию
			result.append(buffer, count);
		::fclose(file);
		// Возвращаем собранное содержимое
		return result;
	}
	/**
	 * @brief Функция записи файла
	 *
	 * @param path путь
	 * @param data байты
	 * @param size длина
	 * @return     признак успешности
	 *
	 */
	static bool spill(const std::string & path, const uint8_t * data, const size_t size) {
		// Открываем файл на запись
		FILE * file = ::fopen(path.c_str(), "wb");
		// Проверяем удачу открытия
		if(file == nullptr)
			// При отказе сообщаем неудачу
			return false;
		// Записываем байты и сверяем их число
		const bool ok = (::fwrite(data, 1, size, file) == size);
		::fclose(file);
		// Возвращаем признак успешности
		return ok;
	}
	/**
	 * @brief Функция запуска команды оболочки
	 *
	 * @param command команда
	 * @return        признак нулевого кода завершения
	 *
	 */
	static bool run(const std::string & command) {
		// Запускаем команду и сверяем код завершения
		return (::system((command + " </dev/null").c_str()) == 0);
	}
};

/**
 * Секретный ключ Алисы раздела 6.2 RFC 7748
 */
static const char * ALICE_SECRET = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";

/**
 * Открытый ключ Алисы раздела 6.2 RFC 7748
 */
static const char * ALICE_PUBLIC = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";

/**
 * Секретный ключ Боба раздела 6.2 RFC 7748
 */
static const char * BOB_SECRET = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";

/**
 * Открытый ключ Боба раздела 6.2 RFC 7748
 */
static const char * BOB_PUBLIC = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";

/**
 * Общее значение раздела 6.2 RFC 7748
 */
static const char * SHARED = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

/**
 * @brief Проверка векторов раздела 6.2 RFC 7748: открытые ключи и общее значение обеих сторон
 *
 */
TEST(X448Test, Vectors) {
	// Объявляем буферы ключей и общего значения
	uint8_t alice[56], bob[56], key[56], shared[56];
	// Раскладываем секретный ключ Алисы
	ASSERT_EQ(bytes(ALICE_SECRET, alice), static_cast <size_t> (56));
	ASSERT_EQ(bytes(BOB_SECRET, bob), static_cast <size_t> (56));
	// Открытый ключ Алисы
	ASSERT_TRUE(agreement::x448(view_t(alice, sizeof(alice)), key));
	// Сверяем запись с вектором открытого ключа
	ASSERT_EQ(text(key, sizeof(key)), std::string(ALICE_PUBLIC));
	// Открытый ключ Боба
	ASSERT_TRUE(agreement::x448(view_t(bob, sizeof(bob)), key));
	// Сверяем запись с вектором открытого ключа
	ASSERT_EQ(text(key, sizeof(key)), std::string(BOB_PUBLIC));
	// Общее значение со стороны Алисы
	ASSERT_TRUE(agreement::x448(view_t(alice, sizeof(alice)), view_t(key, sizeof(key)), shared));
	// Сверяем общее значение с вектором
	ASSERT_EQ(text(shared, sizeof(shared)), std::string(SHARED));
	// Общее значение со стороны Боба
	ASSERT_TRUE(agreement::x448(view_t(alice, sizeof(alice)), key));
	ASSERT_TRUE(agreement::x448(view_t(bob, sizeof(bob)), view_t(key, sizeof(key)), shared));
	// Сверяем общее значение с вектором
	ASSERT_EQ(text(shared, sizeof(shared)), std::string(SHARED));
}

/**
 * @brief Проверка зажима: секретный ключ с любыми младшими и старшими разрядами даёт тот же итог
 *
 */
TEST(X448Test, Clamping) {
	// Объявляем буферы ключей и итогов
	uint8_t alice[56], loose[56], first[56], second[56];
	// Раскладываем секретный ключ Алисы
	ASSERT_EQ(bytes(ALICE_SECRET, alice), static_cast <size_t> (56));
	::memcpy(loose, alice, sizeof(loose));
	// Портим зажимаемые разряды: два младших и старший
	loose[0] |= 0x03;
	// Сбрасываем старший разряд
	loose[55] &= 0x7F;
	// Вычисляем итог по исходному ключу
	ASSERT_TRUE(agreement::x448(view_t(alice, sizeof(alice)), first));
	ASSERT_TRUE(agreement::x448(view_t(loose, sizeof(loose)), second));
	// Сверяем оба итога
	ASSERT_EQ(text(first, sizeof(first)), text(second, sizeof(second)));
}

/**
 * @brief Проверка отказов: точки малого порядка (0 и 1), негодные длины и nullptr
 *
 */
TEST(X448Test, Reject) {
	// Объявляем буферы ключа, точки и итога
	uint8_t alice[56], point[56], result[56];
	// Раскладываем секретный ключ Алисы
	ASSERT_EQ(bytes(ALICE_SECRET, alice), static_cast <size_t> (56));
	// Точка нулевой первой координаты: порядок один
	::memset(point, 0, sizeof(point));
	// Проверяем отказ умножения
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Итог затёрт
	uint8_t zero[56];
	::memset(zero, 0, sizeof(zero));
	// Сверяем итог с нулевым буфером
	ASSERT_EQ(::memcmp(result, zero, sizeof(zero)), 0);
	// Точка с первой координатой единица: порядок два
	point[0] = 1;
	// Проверяем отказ умножения
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Точка, равная модулю p = 2^448 - 2^224 - 1 младшим байтом вперёд: приводится к нулю и отвергается
	::memset(point, 0xFF, sizeof(point));
	// Выставляем байт на единицу меньше модуля
	point[28] = 0xFE;
	// Проверяем отказ умножения
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Негодные длины и места
	ASSERT_FALSE(agreement::x448(view_t(alice, 32), view_t(point, sizeof(point)), result));
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), view_t(point, 55), result));
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), nullptr));
	ASSERT_FALSE(agreement::x448(view_t(alice, 55), result));
	ASSERT_FALSE(agreement::x448(view_t(alice, sizeof(alice)), nullptr));
	ASSERT_FALSE(agreement::pair448(nullptr, result));
	ASSERT_FALSE(agreement::pair448(alice, nullptr));
}

/**
 * @brief Проверка порождения пары ключей: зажим на месте, сходимость с выводом, обмен двух пар
 *
 */
TEST(X448Test, Generate) {
	// Объявляем буферы двух пар ключей и общих значений
	uint8_t secretA[56], keyA[56], secretB[56], keyB[56], sharedA[56], sharedB[56], derived[56];
	// Порождаем пару ключей Алисы
	ASSERT_TRUE(agreement::pair448(secretA, keyA));
	ASSERT_TRUE(agreement::pair448(secretB, keyB));
	// Зажим на месте
	EXPECT_EQ(secretA[0] & 0x03, 0);
	EXPECT_EQ(secretA[55] & 0x80, 0x80);
	// Открытый ключ выводится из секретного
	ASSERT_TRUE(agreement::x448(view_t(secretA, sizeof(secretA)), derived));
	// Сверяем вывод с открытым ключом пары
	EXPECT_EQ(text(derived, sizeof(derived)), text(keyA, sizeof(keyA)));
	// Две пары различны
	EXPECT_NE(text(keyA, sizeof(keyA)), text(keyB, sizeof(keyB)));
	// Обмен сходится
	ASSERT_TRUE(agreement::x448(view_t(secretA, sizeof(secretA)), view_t(keyB, sizeof(keyB)), sharedA));
	ASSERT_TRUE(agreement::x448(view_t(secretB, sizeof(secretB)), view_t(keyA, sizeof(keyA)), sharedB));
	// Сверяем общие значения сторон
	EXPECT_EQ(text(sharedA, sizeof(sharedA)), text(sharedB, sizeof(sharedB)));
}

/**
 * @brief Сличение с системным openssl: открытый ключ из чужого секретного и общее значение
 *
 */
TEST(X448Test, Foreign) {
	// Проверяем наличие системного openssl с X448
	if(!run("openssl genpkey -algorithm X448 -out /dev/null >/dev/null 2>&1")){
		// Пропускаем проверку без openssl
		GTEST_SKIP() << "Системный openssl без X448";
	}
	// Задаём шаблон имени временного каталога
	char pattern[] = "/tmp/ants-x448-XXXXXX";
	// Создаём временный каталог и проверяем удачу
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Запоминаем путь временного каталога
	const std::string dir(pattern);
	// Порождаем секретный ключ Алисы через openssl
	ASSERT_TRUE(run("openssl genpkey -algorithm X448 -out " + dir + "/alice.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/alice.pem -outform DER -out " + dir + "/alice.der 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/alice.pem -pubout -outform DER -out " + dir + "/alice-pub.der 2>/dev/null"));
	// Читаем оба файла целиком
	const std::string secret = slurp(dir + "/alice.der"), pub = slurp(dir + "/alice-pub.der");
	// PKCS#8: 16 байтов заголовка и 56 байтов ключа; SubjectPublicKeyInfo: 12 байтов заголовка и 56 байтов ключа
	ASSERT_EQ(secret.size(), static_cast <size_t> (72));
	ASSERT_EQ(pub.size(), static_cast <size_t> (68));
	// Объявляем буфер открытого ключа
	uint8_t key[56];
	// Выводим открытый ключ из секретного записи PKCS#8
	ASSERT_TRUE(agreement::x448(view_t(reinterpret_cast <const uint8_t *> (secret.data()) + 16, 56), key));
	// Сверяем запись с ключом из SubjectPublicKeyInfo
	ASSERT_EQ(text(key, sizeof(key)), text(reinterpret_cast <const uint8_t *> (pub.data()) + 12, 56));
	// Ключ Боба из RFC 7748 в записи PKCS#8
	uint8_t bob[56], pkcs8[72];
	// Раскладываем секретный ключ Боба
	ASSERT_EQ(bytes(BOB_SECRET, bob), static_cast <size_t> (56));
	ASSERT_EQ(bytes("3046020100300506032b656f043a0438", pkcs8), static_cast <size_t> (16));
	::memcpy(pkcs8 + 16, bob, sizeof(bob));
	// Записываем ключ Боба в файл записи PKCS#8
	ASSERT_TRUE(spill(dir + "/bob.der", pkcs8, sizeof(pkcs8)));
	ASSERT_TRUE(run("openssl pkey -inform DER -in " + dir + "/bob.der -pubout -out " + dir + "/bob-pub.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/alice.pem -peerkey " + dir + "/bob-pub.pem -out " + dir + "/shared.bin 2>/dev/null"));
	// Читаем общее значение openssl
	const std::string shared = slurp(dir + "/shared.bin");
	// Проверяем длину общего значения
	ASSERT_EQ(shared.size(), static_cast <size_t> (56));
	// Объявляем буфер общего значения
	uint8_t result[56];
	// Вычисляем общее значение со стороны Боба
	ASSERT_TRUE(agreement::x448(view_t(bob, sizeof(bob)), view_t(key, sizeof(key)), result));
	// Сверяем общее значение с выводом openssl
	ASSERT_EQ(text(result, sizeof(result)), text(reinterpret_cast <const uint8_t *> (shared.data()), 56));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}
