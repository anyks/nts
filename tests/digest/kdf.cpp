/**
 * @file kdf.cpp
 * @date 2026-09-01
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
 * @brief Исходный файл проверок модуля выработки производного ключа
 *
 * @note Контрольный пример взят из Р 50.1.113-2016, раздел 4.4: выработка
 *       производного ключа KDF_GOSTR3411_2012_256
 *
 * @note Схождение с этим примером доказывает и порядок записи ключа: выработка
 *       строится на строке байтов, и запись вектором её бы не дала
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
#include <digest/kdf.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Ключ выработки производного ключа контрольного примера
 */
static const char * SECRET = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/**
 * Метка назначения производного ключа контрольного примера
 */
static const char * LABEL = "26bdb878";

/**
 * Затравка выработки производного ключа контрольного примера
 */
static const char * SEED = "af21434145656378";

/**
 * Производный ключ контрольного примера
 */
static const char * DERIVED = "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9";

/**
 * @brief Метод разбора записи байтов
 *
 * @param text разбираемая запись байтов
 * @param data место, в которое помещается итог разбора
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
 * Проверка схождения с контрольным примером Р 50.1.113-2016
 */
TEST(KdfTest, Sample) {
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], label[8], seed[16], derived[32], result[32];
	// Выполняем разбор ключа выработки производного ключа
	const size_t length = bytes(SECRET, secret);
	// Выполняем разбор метки назначения производного ключа
	const size_t marked = bytes(LABEL, label);
	// Выполняем разбор затравки выработки производного ключа
	const size_t sown = bytes(SEED, seed);
	// Выполняем разбор производного ключа контрольного примера
	const size_t size = bytes(DERIVED, derived);
	// Выполняем выработку производного ключа
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(seed, sown), result));
	// Проверяем схождение выработанного ключа с контрольным примером
	ASSERT_EQ(::memcmp(result, derived, size), 0);
}

/**
 * Проверка отказов выработки производного ключа на негодные доводы
 */
TEST(KdfTest, Refusals) {
	// Места, в которые помещаются разбираемые записи
	uint8_t secret[32], label[8], seed[16], result[32];
	// Выполняем разбор ключа выработки производного ключа
	const size_t length = bytes(SECRET, secret);
	// Выполняем разбор метки назначения производного ключа
	const size_t marked = bytes(LABEL, label);
	// Выполняем разбор затравки выработки производного ключа
	const size_t sown = bytes(SEED, seed);
	// Проверяем отказ выработки в непереданное место
	ASSERT_FALSE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(seed, sown), nullptr));
	// Проверяем отказ выработки без ключа выработки
	ASSERT_FALSE(digest::kdf(view_t(nullptr, length), view_t(label, marked), view_t(seed, sown), result));
	/**
	 * Длина ключа выработки НЕ ограничивается. Р 50.1.113-2016 отводит ключу двести
	 * пятьдесят шесть разрядов, но выработка строится на HMAC, а раздел 2 RFC 2104
	 * принимает ключ всякой длины, заменяя длинный его хешем. Ключ иной длины оттого
	 * отказа не даёт - он даёт другой производный ключ
	 */
	uint8_t shorter[32] = {0};
	// Выполняем выработку производного ключа ключом иной длины
	ASSERT_TRUE(digest::kdf(view_t(secret, (length - 1)), view_t(label, marked), view_t(seed, sown), shorter));
	// Выполняем выработку производного ключа ключом положенной длины
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(seed, sown), result));
	// Проверяем расхождение производных ключей, выработанных ключами разной длины
	ASSERT_NE(::memcmp(shorter, result, sizeof(shorter)), 0);
	// Место, в которое помещается непомерно длинная метка назначения
	uint8_t lengthy[digest::KDF_LIMIT + 1];
	// Выполняем заполнение непомерно длинной метки назначения
	::memset(lengthy, 0x5A, sizeof(lengthy));
	/**
	 * Метка назначения и затравка вместе с ключом и счётчиком идут в один хеш, и
	 * длина всякой из них сверяется ОТДЕЛЬНОЙ половиной заслона
	 */
	ASSERT_FALSE(digest::kdf(view_t(secret, length), view_t(lengthy, sizeof(lengthy)), view_t(seed, sown), result));
	// Проверяем отказ выработки затравкой сверх дозволенной длины
	ASSERT_FALSE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(lengthy, sizeof(lengthy)), result));
	// Проверяем успешность выработки меткой назначения дозволенной длины
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(lengthy, digest::KDF_LIMIT), view_t(seed, sown), result));
	// Проверяем успешность выработки затравкой дозволенной длины
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(lengthy, digest::KDF_LIMIT), result));
	// Производный ключ, выработанный без метки назначения и затравки
	uint8_t bare[32] = {0};
	/**
	 * Непереданные метка назначения и затравка означают их отсутствие, и выработка
	 * без них отказом не является: в хеш идёт один лишь ключ со счётчиком
	 */
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(nullptr, 0), view_t(nullptr, 0), bare));
	// Производный ключ, выработанный метками нулевой длины
	uint8_t hollow[32] = {0};
	// Выполняем выработку производного ключа метками нулевой длины
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(label, 0), view_t(seed, 0), hollow));
	// Проверяем схождение выработки метками нулевой длины с выработкой без них
	ASSERT_EQ(::memcmp(bare, hollow, sizeof(bare)), 0);
	// Проверяем расхождение выработки без метки с выработкой контрольного примера
	ASSERT_TRUE(digest::kdf(view_t(secret, length), view_t(label, marked), view_t(seed, sown), result));
	// Проверяем, что метка назначения на выработанный ключ влияет
	ASSERT_NE(::memcmp(bare, result, sizeof(bare)), 0);
}

/**
 * Проверка выработки ключа пользователя SNMPv3 по приложению A.5 RFC 3414
 */
TEST(KdfTest, Snmpv3) {
	// Опознаватель движка SNMP контрольного примера (12 байтов)
	uint8_t engine[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	// Пароль пользователя контрольного примера
	const uint8_t password[] = {'n', 'e', 'w', 's', 'y', 'r', 'u', 'p'};
	// Локализованный ключ SHA-1 контрольного примера A.5.2
	uint8_t wantSha[20];
	bytes("78e2dcce79d59403b58c1bbaa5bff46391f1cd25", wantSha);
	// Место локализованного ключа
	uint8_t kul[20];
	// Выработка SHA-1 обязана удаться
	ASSERT_TRUE(digest::snmpv3(digest::hash_t::SHA1, view_t(password, sizeof(password)), view_t(engine, sizeof(engine)), kul));
	// Ключ обязан совпасть с контрольным примером побайтно
	ASSERT_EQ(::memcmp(kul, wantSha, sizeof(wantSha)), 0);
	// Локализованный ключ MD5 контрольного примера A.5.1
	uint8_t wantMd5[16];
	bytes("87021d7bd9d101ba05ea6e3bf9d9bd4a", wantMd5);
	// Выработка MD5 обязана удаться
	ASSERT_TRUE(digest::snmpv3(digest::hash_t::MD5, view_t(password, sizeof(password)), view_t(engine, sizeof(engine)), kul));
	// Ключ обязан совпасть с контрольным примером побайтно
	ASSERT_EQ(::memcmp(kul, wantMd5, sizeof(wantMd5)), 0);
	// Выработка с неизвестным алгоритмом обязана отказать
	ASSERT_FALSE(digest::snmpv3(digest::hash_t::NONE, view_t(password, sizeof(password)), view_t(engine, sizeof(engine)), kul));
	// Выработка с пустым паролем обязана отказать
	ASSERT_FALSE(digest::snmpv3(digest::hash_t::SHA1, view_t(nullptr, 0), view_t(engine, sizeof(engine)), kul));
	// Выработка в непереданное место обязана отказать
	ASSERT_FALSE(digest::snmpv3(digest::hash_t::SHA1, view_t(password, sizeof(password)), view_t(engine, sizeof(engine)), nullptr));
}

/**
 * Проверка выработки ключевого материала prf+ протокола IKEv2 по разделу 2.13 RFC 7296
 */
TEST(KdfTest, PrfPlus) {
	// Ключ псевдослучайной функции
	const uint8_t key[] = {0x01, 0x02, 0x03, 0x04};
	// Затравка выработки
	const uint8_t seed[] = {0x09, 0x08, 0x07};
	// Место ключевого материала
	uint8_t result[64];
	// Выработка обязана удаться
	ASSERT_TRUE(digest::prfplus(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(seed, sizeof(seed)), result, sizeof(result)));
	/**
	 * Эталон первых 32 байтов, вычисленный независимо по определению:
	 * T1 = prf(K, S ‖ 0x01), T2 = prf(K, T1 ‖ S ‖ 0x02)
	 */
	uint8_t want[32];
	bytes("cbba4a22fdeb59f8044dbc78fce7130e19b21dea23339aba3d698f2c1e48d0bd", want);
	// Материал обязан совпасть с эталоном побайтно
	ASSERT_EQ(::memcmp(result, want, sizeof(want)), 0);
	// Начало длинной выработки обязано совпадать с короткой
	uint8_t shorter[16];
	ASSERT_TRUE(digest::prfplus(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(seed, sizeof(seed)), shorter, sizeof(shorter)));
	ASSERT_EQ(::memcmp(result, shorter, sizeof(shorter)), 0);
	// Выработка с неизвестным алгоритмом обязана отказать
	ASSERT_FALSE(digest::prfplus(digest::hash_t::NONE, view_t(key, sizeof(key)), view_t(seed, sizeof(seed)), result, sizeof(result)));
	// Выработка в непереданное место обязана отказать
	ASSERT_FALSE(digest::prfplus(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(seed, sizeof(seed)), nullptr, sizeof(result)));
	// Выработка нулевой длины обязана отказать
	ASSERT_FALSE(digest::prfplus(digest::hash_t::SHA256, view_t(key, sizeof(key)), view_t(seed, sizeof(seed)), result, 0));
}
