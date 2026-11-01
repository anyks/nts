/**
 * @file x25519.cpp
 * @date 2026-09-04
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
 * @brief Исходный файл проверок модуля выработки общего ключа на кривой Curve25519
 *
 * @note Контрольные примеры взяты из RFC 7748: два вектора умножения и итоги
 *       повторений раздела 5.2, обмен Алисы и Боба раздела 6.1. Сверх того итоги
 *       сличаются с системным OpenSSL
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
#include <starve.hpp>
#include <agreement/x25519.hpp>
#include <keys/keys.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Секретный ключ Алисы раздела 6.1 RFC 7748
 */
static const char * ALICE_SECRET = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

/**
 * Открытый ключ Алисы раздела 6.1 RFC 7748
 */
static const char * ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

/**
 * Секретный ключ Боба раздела 6.1 RFC 7748
 */
static const char * BOB_SECRET = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

/**
 * Открытый ключ Боба раздела 6.1 RFC 7748
 */
static const char * BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

/**
 * Общее значение Алисы и Боба раздела 6.1 RFC 7748
 */
static const char * SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

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
 * @brief Функция чтения файла целиком
 *
 * @param path путь к читаемому файлу
 * @return     содержимое файла
 *
 */
static std::string slurp(const std::string & path) {
	// Содержимое файла
	std::string result;
	// Открываем файл на чтение
	FILE * file = ::fopen(path.c_str(), "rb");
	// Если файл открыть не удалось
	if(file == nullptr)
		// Выводим пустое содержимое
		return result;
	// Место чтения куска файла
	char buffer[256];
	// Число прочитанных байтов
	size_t count = 0;
	/**
	 * Выполняем чтение файла кусками
	 */
	while((count = ::fread(buffer, 1, sizeof(buffer), file)) > 0)
		// Дописываем прочитанный кусок
		result.append(buffer, count);
	// Закрываем файл
	::fclose(file);
	// Выводим содержимое файла
	return result;
}
/**
 * @brief Функция записи файла целиком
 *
 * @param path путь к записываемому файлу
 * @param data записываемые байты
 * @param size число записываемых байтов
 * @return     признак успешности записи
 *
 */
static bool spill(const std::string & path, const uint8_t * data, const size_t size) {
	// Открываем файл на запись
	FILE * file = ::fopen(path.c_str(), "wb");
	// Если файл открыть не удалось
	if(file == nullptr)
		// Выводим отказ записи
		return false;
	// Выполняем запись байтов
	const bool ok = (::fwrite(data, 1, size, file) == size);
	// Закрываем файл
	::fclose(file);
	// Выводим признак успешности записи
	return ok;
}
/**
 * @brief Функция исполнения команды оболочки
 *
 * @param command исполняемая команда
 * @return        признак нулевого кода завершения
 *
 */
static bool run(const std::string & command) {
	// Выводим признак нулевого кода завершения команды
	return (::system((command + " </dev/null").c_str()) == 0);
}

/**
 * @brief Проверка векторов умножения раздела 5.2 RFC 7748
 *
 */
TEST(X25519Test, Vectors) {
	// Места скаляра, координаты и итога
	uint8_t scalar[32], point[32], result[32];
	// Выполняем разбор первого скаляра
	ASSERT_EQ(bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar), static_cast <size_t> (32));
	// Выполняем разбор первой координаты
	ASSERT_EQ(bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point), static_cast <size_t> (32));
	// Выполняем умножение
	ASSERT_TRUE(agreement::x25519(view_t(scalar, sizeof(scalar)), view_t(point, sizeof(point)), result));
	// Сличаем итог с контрольным значением
	ASSERT_EQ(text(result, sizeof(result)), std::string("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
	// Выполняем разбор второго скаляра
	ASSERT_EQ(bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar), static_cast <size_t> (32));
	// Выполняем разбор второй координаты: её старший разряд поставлен и обязан отбрасываться
	ASSERT_EQ(bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", point), static_cast <size_t> (32));
	// Выполняем умножение
	ASSERT_TRUE(agreement::x25519(view_t(scalar, sizeof(scalar)), view_t(point, sizeof(point)), result));
	// Сличаем итог с контрольным значением
	ASSERT_EQ(text(result, sizeof(result)), std::string("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
}
/**
 * @brief Проверка повторений раздела 5.2 RFC 7748
 *
 */
TEST(X25519Test, Iterations) {
	// Скаляр и координата начинаются с точки основания
	uint8_t scalar[32] = {9}, point[32] = {9}, result[32];
	/**
	 * Выполняем тысячу повторений: итог становится скаляром, прежний скаляр - координатой
	 */
	for(size_t i = 0; i < 1000; i++){
		// Выполняем умножение
		ASSERT_TRUE(agreement::x25519(view_t(scalar, sizeof(scalar)), view_t(point, sizeof(point)), result));
		// Прежний скаляр становится координатой
		::memcpy(point, scalar, sizeof(point));
		// Итог становится скаляром
		::memcpy(scalar, result, sizeof(scalar));
		// Если завершилось первое повторение
		if(i == 0){
			// Сличаем итог с контрольным значением первого повторения
			ASSERT_EQ(text(scalar, sizeof(scalar)), std::string("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"));
		}
	}
	// Сличаем итог с контрольным значением тысячного повторения
	ASSERT_EQ(text(scalar, sizeof(scalar)), std::string("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
}
/**
 * @brief Проверка обмена Алисы и Боба раздела 6.1 RFC 7748
 *
 */
TEST(X25519Test, Exchange) {
	// Места ключей и общих значений
	uint8_t alice[32], bob[32], key[32], first[32], second[32];
	// Выполняем разбор секретного ключа Алисы
	ASSERT_EQ(bytes(ALICE_SECRET, alice), static_cast <size_t> (32));
	// Выполняем разбор секретного ключа Боба
	ASSERT_EQ(bytes(BOB_SECRET, bob), static_cast <size_t> (32));
	// Выполняем выработку открытого ключа Алисы
	ASSERT_TRUE(agreement::x25519(view_t(alice, sizeof(alice)), key));
	// Сличаем открытый ключ Алисы с контрольным значением
	ASSERT_EQ(text(key, sizeof(key)), std::string(ALICE_PUBLIC));
	// Выполняем выработку общего значения Бобом из ключа Алисы
	ASSERT_TRUE(agreement::x25519(view_t(bob, sizeof(bob)), view_t(key, sizeof(key)), first));
	// Выполняем выработку открытого ключа Боба
	ASSERT_TRUE(agreement::x25519(view_t(bob, sizeof(bob)), key));
	// Сличаем открытый ключ Боба с контрольным значением
	ASSERT_EQ(text(key, sizeof(key)), std::string(BOB_PUBLIC));
	// Выполняем выработку общего значения Алисой из ключа Боба
	ASSERT_TRUE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(key, sizeof(key)), second));
	// Сличаем общее значение Алисы с контрольным значением
	ASSERT_EQ(text(second, sizeof(second)), std::string(SHARED));
	// Сличаем общее значение Боба с общим значением Алисы
	ASSERT_EQ(::memcmp(first, second, sizeof(first)), 0);
}
/**
 * @brief Проверка отказа на нулевом общем значении и негодных доводах
 *
 */
TEST(X25519Test, Reject) {
	// Места ключей и общего значения
	uint8_t alice[32], point[32], result[32];
	// Выполняем разбор секретного ключа Алисы
	ASSERT_EQ(bytes(ALICE_SECRET, alice), static_cast <size_t> (32));
	// Нулевая точка: точка малого порядка, выдающая нулевое общее значение
	::memset(point, 0, sizeof(point));
	// Проверяем отказ на нулевой точке
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Точка с первой координатой единица: тоже малого порядка
	point[0] = 1;
	// Проверяем отказ на точке единица
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Точка малого порядка восемь из раздела 7 RFC 7748
	ASSERT_EQ(bytes("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", point), static_cast <size_t> (32));
	// Проверяем отказ на точке порядка восемь
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Точка p - 1: после сброса старшего разряда равна минус единице, порядок четыре
	ASSERT_EQ(bytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", point), static_cast <size_t> (32));
	// Проверяем отказ на точке минус единица
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), result));
	// Проверяем отказ на секретном ключе неверной длины
	ASSERT_FALSE(agreement::x25519(view_t(alice, 31), view_t(point, sizeof(point)), result));
	// Проверяем отказ на точке неверной длины
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, 33), result));
	// Проверяем отказ на пустом месте итога
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), view_t(point, sizeof(point)), nullptr));
	// Проверяем отказ выработки открытого ключа на пустом секретном ключе
	ASSERT_FALSE(agreement::x25519(view_t(), result));
	// Проверяем отказ выработки открытого ключа в пустое место
	ASSERT_FALSE(agreement::x25519(view_t(alice, sizeof(alice)), nullptr));
}
/**
 * @brief Проверка сличения с системным OpenSSL
 *
 * @note Секретный ключ извлекается из записи PKCS#8 по смещению шестнадцать, открытый
 *       ключ из записи SubjectPublicKeyInfo по смещению двенадцать: обе записи ключей
 *       X25519 постоянной длины
 *
 */
TEST(X25519Test, Foreign) {
	// Если системный openssl не умеет X25519 (старше 1.1.1), сличать не с чем
	if(!run("openssl genpkey -algorithm X25519 -out /dev/null >/dev/null 2>&1"))
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "Системный openssl без X25519";
	// Заготовка пути временного каталога
	char pattern[] = "/tmp/ants-x25519-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	// Выполняем выработку ключа Алисы системным OpenSSL
	ASSERT_TRUE(run("openssl genpkey -algorithm X25519 -out " + dir + "/alice.pem 2>/dev/null"));
	// Выполняем запись секретного ключа Алисы в DER
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/alice.pem -outform DER -out " + dir + "/alice.der 2>/dev/null"));
	// Выполняем запись открытого ключа Алисы в DER
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/alice.pem -pubout -outform DER -out " + dir + "/alice-pub.der 2>/dev/null"));
	// Читаем записи ключей Алисы
	const std::string secret = slurp(dir + "/alice.der"), pub = slurp(dir + "/alice-pub.der");
	// Проверяем длину записи PKCS#8
	ASSERT_EQ(secret.size(), static_cast <size_t> (48));
	// Проверяем длину записи SubjectPublicKeyInfo
	ASSERT_EQ(pub.size(), static_cast <size_t> (44));
	// Выполняем выработку открытого ключа Алисы своим кодом
	uint8_t key[32];
	// Выполняем выработку открытого ключа из извлечённого секретного
	ASSERT_TRUE(agreement::x25519(view_t(reinterpret_cast <const uint8_t *> (secret.data()) + 16, 32), key));
	// Сличаем свой открытый ключ с открытым ключом OpenSSL
	ASSERT_EQ(text(key, sizeof(key)), text(reinterpret_cast <const uint8_t *> (pub.data()) + 12, 32));
	// Секретный ключ Боба из RFC 7748
	uint8_t bob[32];
	// Выполняем разбор секретного ключа Боба
	ASSERT_EQ(bytes(BOB_SECRET, bob), static_cast <size_t> (32));
	// Заголовок записи PKCS#8 ключа X25519
	uint8_t pkcs8[48];
	// Выполняем разбор заголовка записи PKCS#8
	ASSERT_EQ(bytes("302e020100300506032b656e04220420", pkcs8), static_cast <size_t> (16));
	// Дописываем секретный ключ Боба в запись
	::memcpy(pkcs8 + 16, bob, sizeof(bob));
	// Выполняем запись ключа Боба в файл
	ASSERT_TRUE(spill(dir + "/bob.der", pkcs8, sizeof(pkcs8)));
	// Выполняем запись открытого ключа Боба системным OpenSSL
	ASSERT_TRUE(run("openssl pkey -inform DER -in " + dir + "/bob.der -pubout -out " + dir + "/bob-pub.pem 2>/dev/null"));
	// Выполняем выработку общего значения Алисой системным OpenSSL
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/alice.pem -peerkey " + dir + "/bob-pub.pem -out " + dir + "/shared.bin 2>/dev/null"));
	// Читаем общее значение OpenSSL
	const std::string shared = slurp(dir + "/shared.bin");
	// Проверяем длину общего значения
	ASSERT_EQ(shared.size(), static_cast <size_t> (32));
	// Место общего значения своего кода
	uint8_t result[32];
	// Выполняем выработку общего значения Бобом своим кодом из ключа Алиса
	ASSERT_TRUE(agreement::x25519(view_t(bob, sizeof(bob)), view_t(key, sizeof(key)), result));
	// Сличаем общие значения
	ASSERT_EQ(text(result, sizeof(result)), text(reinterpret_cast <const uint8_t *> (shared.data()), 32));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * @brief Проверка порождения пары ключей: зажим, сходимость с выводом, различие и обмен
 *
 */
TEST(X25519Test, Generate) {
	// Ключи первой пары
	uint8_t secret[32], key[32];
	// Порождение без мест отвергается
	ASSERT_FALSE(agreement::generate(nullptr, key));
	ASSERT_FALSE(agreement::generate(secret, nullptr));
	// Выполняем порождение первой пары
	ASSERT_TRUE(agreement::generate(secret, key));
	// Три младших разряда секретного ключа сброшены
	ASSERT_EQ(secret[0] & 7, 0);
	// Старший разряд секретного ключа сброшен
	ASSERT_EQ(secret[31] & 128, 0);
	// Разряд 254 секретного ключа поставлен
	ASSERT_EQ(secret[31] & 64, 64);
	// Открытый ключ, выведенный из секретного отдельно
	uint8_t derived[32];
	// Выполняем вывод открытого ключа
	ASSERT_TRUE(agreement::x25519(view_t(secret, sizeof(secret)), derived));
	// Открытый ключ пары совпадает с выведенным
	ASSERT_EQ(text(key, sizeof(key)), text(derived, sizeof(derived)));
	// Ключи второй пары
	uint8_t other[32], point[32];
	// Выполняем порождение второй пары
	ASSERT_TRUE(agreement::generate(other, point));
	// Секретные ключи пар различны
	ASSERT_NE(::memcmp(secret, other, sizeof(secret)), 0);
	// Открытые ключи пар различны
	ASSERT_NE(::memcmp(key, point, sizeof(key)), 0);
	// Общие значения сторон
	uint8_t first[32], second[32];
	// Выполняем выработку общего значения первой стороной
	ASSERT_TRUE(agreement::x25519(view_t(secret, sizeof(secret)), view_t(point, sizeof(point)), first));
	// Выполняем выработку общего значения второй стороной
	ASSERT_TRUE(agreement::x25519(view_t(other, sizeof(other)), view_t(key, sizeof(key)), second));
	// Общие значения сходятся
	ASSERT_EQ(text(first, sizeof(first)), text(second, sizeof(second)));
}
/**
 * @brief Проверка порождения при нехватке памяти: порождение памяти не выделяет
 *
 */
TEST(X25519Test, GenerateStarved) {
	/**
	 * Выполняем перебор запасов выделений: порождение обязано удаваться при всяком
	 * запасе, ибо памяти не выделяет, а выделение под noexcept прервало бы исполнение
	 */
	for(size_t budget = 0; budget < 8; budget++){
		// Места ключей
		uint8_t secret[32], key[32];
		// Итог порождения при отмеренном запасе
		bool outcome = false;
		{
			// Отмеряем запас выделений на время порождения
			starve::ration_t ration(budget);
			// Выполняем порождение при отмеренном запасе
			outcome = agreement::generate(secret, key);
		}
		// Порождение удалось
		ASSERT_TRUE(outcome) << "запас " << budget;
	}
}
/**
 * @brief Проверка записи порождённой пары и обмена с системным openssl
 *
 */
TEST(X25519Test, GenerateOpenssl) {
	// Ключ в виде записи
	keys::key_t key;
	// Устанавливаем вид ключа
	key.kind = keys::kind_t::X25519;
	// Выделяем место под ключ соглашения: 32 байта
	key.d.assign(32, 0);
	// Выделяем место под ключ проверки: 32 байта
	key.key.assign(32, 0);
	// Выполняем порождение пары
	ASSERT_TRUE(agreement::generate(key.d.data(), key.key.data()));
	// Записи ключей
	std::string secret, pub;
	// Выполняем запись секретного ключа PKCS #8
	ASSERT_EQ(keys::encode(key, keys::container_t::PRIVATE, secret), keys::error_t::NONE);
	// Выполняем запись открытого ключа SubjectPublicKeyInfo
	ASSERT_EQ(keys::encode(key, keys::container_t::PUBLIC, pub), keys::error_t::NONE);
	// Разобранные ключи
	keys::key_t parsed, opened;
	// Выполняем разбор записи секретного ключа
	ASSERT_EQ(keys::decode(secret, view_t(), parsed), keys::error_t::NONE);
	// Выполняем разбор записи открытого ключа
	ASSERT_EQ(keys::decode(pub, view_t(), opened), keys::error_t::NONE);
	// Разобранный секретный ключ совпадает с порождённым
	ASSERT_EQ(parsed.d, key.d);
	// Разобранный открытый ключ совпадает с порождённым
	ASSERT_EQ(opened.key, key.key);
	// Если системный openssl не умеет X25519 (старше 1.1.1), сличать не с чем
	if(!run("openssl genpkey -algorithm X25519 -out /dev/null >/dev/null 2>&1"))
		// Объявляем пропуск проверки вслух
		GTEST_SKIP() << "Системный openssl без X25519";
	// Заготовка пути временного каталога
	char pattern[] = "/tmp/ants-x25519-gen-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	// Выполняем запись ключей в файлы
	ASSERT_TRUE(spill(dir + "/key.pem", reinterpret_cast <const uint8_t *> (secret.data()), secret.size()));
	ASSERT_TRUE(spill(dir + "/pub.pem", reinterpret_cast <const uint8_t *> (pub.data()), pub.size()));
	// Системный openssl читает секретный ключ
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/key.pem -noout 2>/dev/null"));
	// Системный openssl читает открытый ключ
	ASSERT_TRUE(run("openssl pkey -pubin -in " + dir + "/pub.pem -noout 2>/dev/null"));
	// Системный openssl выводит открытый ключ из секретного
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/key.pem -pubout -out " + dir + "/derived.pem 2>/dev/null"));
	// Выведенный openssl открытый ключ совпадает с нашим байт в байт
	ASSERT_EQ(slurp(dir + "/derived.pem"), pub);
	// Выполняем порождение встречной пары системным openssl
	ASSERT_TRUE(run("openssl genpkey -algorithm X25519 -out " + dir + "/peer.pem 2>/dev/null"));
	// Выполняем запись открытого ключа встречной пары в DER
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/peer.pem -pubout -outform DER -out " + dir + "/peer-pub.der 2>/dev/null"));
	// Выполняем выработку общего значения встречной стороной нашим открытым ключом
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/peer.pem -peerkey " + dir + "/pub.pem -out " + dir + "/shared.bin 2>/dev/null"));
	// Читаем открытый ключ встречной пары и общее значение
	const std::string peer = slurp(dir + "/peer-pub.der"), shared = slurp(dir + "/shared.bin");
	// Проверяем длины записей
	ASSERT_EQ(peer.size(), static_cast <size_t> (44));
	ASSERT_EQ(shared.size(), static_cast <size_t> (32));
	// Место общего значения своей стороны
	uint8_t result[32];
	// Выполняем выработку общего значения порождённым секретным ключом
	ASSERT_TRUE(agreement::x25519(view_t(key.d.data(), key.d.size()), view_t(reinterpret_cast <const uint8_t *> (peer.data()) + 12, 32), result));
	// Общие значения сходятся
	ASSERT_EQ(text(result, sizeof(result)), text(reinterpret_cast <const uint8_t *> (shared.data()), 32));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}
