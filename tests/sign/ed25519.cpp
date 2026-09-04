/**
 * @file ed25519.cpp
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
 * @brief Исходный файл проверок модуля электронной подписи Ed25519
 *
 * @note Контрольные примеры взяты из раздела 7.1 RFC 8032 целиком: зерно, ключ
 *       проверки, сообщение и подпись. Сверх того подписи сличаются с системным OpenSSL
 *       в обе стороны
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <main.hpp>
#include <sign/ed25519.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Контрольный пример «TEST 1» раздела 7.1 RFC 8032: зерно, ключ проверки, сообщение и подпись
 */
static const char * ONE_SECRET = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
static const char * ONE_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
static const char * ONE_MESSAGE =
	"";
static const char * ONE_SIGNATURE =
	"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
	"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

/**
 * Контрольный пример «TEST 2» раздела 7.1 RFC 8032: зерно, ключ проверки, сообщение и подпись
 */
static const char * TWO_SECRET = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
static const char * TWO_PUBLIC = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
static const char * TWO_MESSAGE =
	"72";
static const char * TWO_SIGNATURE =
	"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
	"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

/**
 * Контрольный пример «TEST 3» раздела 7.1 RFC 8032: зерно, ключ проверки, сообщение и подпись
 */
static const char * THREE_SECRET = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
static const char * THREE_PUBLIC = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
static const char * THREE_MESSAGE =
	"af82";
static const char * THREE_SIGNATURE =
	"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
	"18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

/**
 * Контрольный пример «TEST 1024» раздела 7.1 RFC 8032: зерно, ключ проверки, сообщение и подпись
 */
static const char * LONG_SECRET = "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5";
static const char * LONG_PUBLIC = "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e";
static const char * LONG_MESSAGE =
	"08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
	"fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
	"79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
	"658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
	"1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
	"ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
	"06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
	"efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
	"aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
	"85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
	"d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
	"554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
	"88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
	"2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
	"07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
	"b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
	"ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
	"c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
	"51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
	"42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
	"ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
	"f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
	"d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
	"de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
	"88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
	"2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
	"6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
	"b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
	"0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
	"369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
	"b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
	"0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0";
static const char * LONG_SIGNATURE =
	"0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
	"aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03";

/**
 * Контрольный пример «TEST SHA(abc)» раздела 7.1 RFC 8032: зерно, ключ проверки, сообщение и подпись
 */
static const char * ABC_SECRET = "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
static const char * ABC_PUBLIC = "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
static const char * ABC_MESSAGE =
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
	"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
static const char * ABC_SIGNATURE =
	"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
	"09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";

/**
 * @brief Метод разбора записи шестнадцатеричными знаками
 *
 * @param text разбираемая запись
 *
 * @return     разобранные байты
 *
 */
static std::vector <uint8_t> bytes(const char * text) {
	// Разобранные байты
	std::vector <uint8_t> result;
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
		result.push_back(value);
	}
	// Выводим разобранные байты
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
 * @brief Метод получения области байтов вектора
 *
 * @param data вектор байтов
 *
 * @return     область байтов вектора
 *
 */
static view_t view(const std::vector <uint8_t> & data) {
	// Выводим область байтов вектора
	return view_t(data.empty() ? nullptr : data.data(), data.size());
}
/**
 * @brief Метод чтения файла целиком
 *
 * @param path путь к читаемому файлу
 *
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
 * @brief Метод записи файла целиком
 *
 * @param path путь к записываемому файлу
 * @param data записываемые байты
 * @param size число записываемых байтов
 *
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
 * @brief Метод исполнения команды оболочки
 *
 * @param command исполняемая команда
 *
 * @return        признак нулевого кода завершения
 *
 */
static bool run(const std::string & command) {
	// Выводим признак нулевого кода завершения команды
	return (::system(command.c_str()) == 0);
}
/**
 * @brief Метод проверки контрольного примера
 *
 * @param secret    зерно ключа подписи
 * @param pub       ключ проверки подписи
 * @param message   подписываемое сообщение
 * @param signature ожидаемая подпись
 *
 */
static void example(const char * secret, const char * pub, const char * message, const char * signature) {
	// Объект модуля электронной подписи
	sign::ed25519_t ed25519;
	// Проверяем размер подписи
	ASSERT_EQ(ed25519.size(), static_cast <size_t> (64));
	// Разобранные записи примера
	const std::vector <uint8_t> seed = bytes(secret), data = bytes(message), expected = bytes(signature);
	// Выполняем установку ключа подписи
	ASSERT_TRUE(ed25519.secret(view(seed)));
	// Место ключа проверки подписи
	uint8_t key[32];
	// Выполняем получение ключа проверки подписи
	ASSERT_TRUE(ed25519.key(key, sizeof(key)));
	// Сличаем ключ проверки с контрольным примером
	ASSERT_EQ(text(key, sizeof(key)), std::string(pub));
	// Место выработанной подписи
	uint8_t result[64];
	// Выполняем выработку подписи
	ASSERT_TRUE(ed25519.make(view(data), result));
	// Сличаем выработанную подпись с контрольным примером
	ASSERT_EQ(text(result, sizeof(result)), std::string(signature));
	// Выполняем проверку выработанной подписи тем же объектом
	ASSERT_TRUE(ed25519.check(view(data), view_t(result, sizeof(result))));
	// Объект проверки подписи одним ключом проверки
	sign::ed25519_t verifier;
	// Выполняем установку ключа проверки подписи
	ASSERT_TRUE(verifier.key(view_t(key, sizeof(key))));
	// Выполняем проверку подписи контрольного примера
	ASSERT_TRUE(verifier.check(view(data), view(expected)));
	// Проверяем отказ выработки подписи без ключа подписи
	ASSERT_FALSE(verifier.make(view(data), result));
}

/**
 * @brief Проверка контрольного примера TEST 1
 *
 */
TEST(Ed25519Test, One) {
	// Выполняем проверку контрольного примера
	example(ONE_SECRET, ONE_PUBLIC, ONE_MESSAGE, ONE_SIGNATURE);
}
/**
 * @brief Проверка контрольного примера TEST 2
 *
 */
TEST(Ed25519Test, Two) {
	// Выполняем проверку контрольного примера
	example(TWO_SECRET, TWO_PUBLIC, TWO_MESSAGE, TWO_SIGNATURE);
}
/**
 * @brief Проверка контрольного примера TEST 3
 *
 */
TEST(Ed25519Test, Three) {
	// Выполняем проверку контрольного примера
	example(THREE_SECRET, THREE_PUBLIC, THREE_MESSAGE, THREE_SIGNATURE);
}
/**
 * @brief Проверка контрольного примера TEST 1024
 *
 */
TEST(Ed25519Test, Long) {
	// Выполняем проверку контрольного примера
	example(LONG_SECRET, LONG_PUBLIC, LONG_MESSAGE, LONG_SIGNATURE);
}
/**
 * @brief Проверка контрольного примера TEST SHA(abc)
 *
 */
TEST(Ed25519Test, Abc) {
	// Выполняем проверку контрольного примера
	example(ABC_SECRET, ABC_PUBLIC, ABC_MESSAGE, ABC_SIGNATURE);
}
/**
 * @brief Проверка отказов на битой и неканонической подписи
 *
 */
TEST(Ed25519Test, Reject) {
	// Объект модуля электронной подписи
	sign::ed25519_t ed25519;
	// Разобранные записи примера
	const std::vector <uint8_t> pub = bytes(THREE_PUBLIC), data = bytes(THREE_MESSAGE);
	// Изменяемая подпись примера
	std::vector <uint8_t> signature = bytes(THREE_SIGNATURE);
	// Выполняем установку ключа проверки подписи
	ASSERT_TRUE(ed25519.key(view(pub)));
	// Проверяем схождение нетронутой подписи
	ASSERT_TRUE(ed25519.check(view(data), view(signature)));
	// Портим байт точки R подписи
	signature[3] ^= 0x01;
	// Проверяем отказ на битой точке R
	ASSERT_FALSE(ed25519.check(view(data), view(signature)));
	// Возвращаем байт точки R
	signature[3] ^= 0x01;
	// Портим байт скаляра S подписи
	signature[40] ^= 0x80;
	// Проверяем отказ на битом скаляре S
	ASSERT_FALSE(ed25519.check(view(data), view(signature)));
	// Возвращаем байт скаляра S
	signature[40] ^= 0x80;
	// Изменяемое сообщение
	std::vector <uint8_t> altered = data;
	// Портим байт сообщения
	altered[0] ^= 0x01;
	// Проверяем отказ на битом сообщении
	ASSERT_FALSE(ed25519.check(view(altered), view(signature)));
	// Порядок подгруппы, записанный младшим байтом вперёд
	const std::vector <uint8_t> order = bytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	// Подпись со скаляром S, равным порядку: не меньше L, обязана отвергаться
	std::vector <uint8_t> forged = signature;
	// Записываем порядок скаляром S
	::memcpy(forged.data() + 32, order.data(), 32);
	// Проверяем отказ на скаляре, равном порядку
	ASSERT_FALSE(ed25519.check(view(data), view(forged)));
	/**
	 * Подпись со скаляром S + L: та же точка, ковкая копия подписи, обязана отвергаться
	 * по разделу 8.4 RFC 8032 даже при сходящейся арифметике
	 */
	uint16_t carry = 0;
	/**
	 * Выполняем сложение скаляра S с порядком младшим байтом вперёд
	 */
	for(size_t i = 0; i < 32; i++){
		// Складываем очередные байты с переносом
		carry = static_cast <uint16_t> (signature[32 + i] + order[i] + carry);
		// Записываем младший байт суммы
		forged[32 + i] = static_cast <uint8_t> (carry);
		// Запоминаем перенос
		carry >>= 8;
	}
	// Проверяем отказ на скаляре S + L
	ASSERT_FALSE(ed25519.check(view(data), view(forged)));
	// Проверяем отказ на подписи неверной длины
	ASSERT_FALSE(ed25519.check(view(data), view_t(signature.data(), 63)));
	// Проверяем отказ на пустой подписи
	ASSERT_FALSE(ed25519.check(view(data), view_t()));
	// Неканоническая запись точки R: вторая координата равна p + 1
	std::vector <uint8_t> noncanonical = signature;
	// Записываем p + 1 младшим байтом вперёд
	::memcpy(noncanonical.data(), bytes("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").data(), 32);
	// Проверяем отказ на неканонической точке R
	ASSERT_FALSE(ed25519.check(view(data), view(noncanonical)));
	// Объект с неканоническим ключом проверки
	sign::ed25519_t other;
	// Ключ проверки с второй координатой p + 1: обязан отвергаться
	const std::vector <uint8_t> badkey = bytes("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
	// Проверяем отказ установки неканонического ключа проверки
	ASSERT_FALSE(other.key(view(badkey)));
	// Ключ проверки с второй координатой два: корня нет, точки на кривой нет
	const std::vector <uint8_t> offcurve = bytes("0200000000000000000000000000000000000000000000000000000000000000");
	// Проверяем отказ установки ключа вне кривой
	ASSERT_FALSE(other.key(view(offcurve)));
	// Ключ проверки с нулевой первой координатой и поставленным знаком: не каноничен
	const std::vector <uint8_t> badsign = bytes("0100000000000000000000000000000000000000000000000000000000000080");
	// Проверяем отказ установки ключа с ложным знаком нуля
	ASSERT_FALSE(other.key(view(badsign)));
	// Проверяем отказ проверки без ключа
	ASSERT_FALSE(other.check(view(data), view(signature)));
	// Проверяем отказ установки зерна неверной длины
	ASSERT_FALSE(other.secret(view_t(pub.data(), 31)));
	// Место ключа проверки
	uint8_t key[32];
	// Проверяем отказ получения ключа проверки без ключа
	ASSERT_FALSE(other.key(key, sizeof(key)));
	// Выполняем установку ключа проверки
	ASSERT_TRUE(other.key(view(pub)));
	// Проверяем отказ получения ключа проверки в малое место
	ASSERT_FALSE(other.key(key, 31));
	// Выполняем сброс состояния
	other.clear();
	// Проверяем отказ проверки после сброса
	ASSERT_FALSE(other.check(view(data), view(signature)));
}
/**
 * @brief Проверка сличения с системным OpenSSL в обе стороны
 *
 * @note Зерно извлекается из записи PKCS#8 по смещению шестнадцать, ключ проверки
 *       из записи SubjectPublicKeyInfo по смещению двенадцать: обе записи ключей
 *       Ed25519 постоянной длины
 *
 */
TEST(Ed25519Test, Foreign) {
	// Заготовка пути временного каталога
	char pattern[] = "/tmp/ants-ed25519-XXXXXX";
	// Создаём временный каталог
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	// Путь временного каталога
	const std::string dir(pattern);
	// Подписываемое сообщение
	const std::string message = "The quick brown fox jumps over the lazy dog: A-NTS Ed25519 interoperability check";
	// Выполняем запись сообщения в файл
	ASSERT_TRUE(spill(dir + "/msg.bin", reinterpret_cast <const uint8_t *> (message.data()), message.size()));
	// Выполняем выработку ключа системным OpenSSL
	ASSERT_TRUE(run("openssl genpkey -algorithm ed25519 -out " + dir + "/key.pem 2>/dev/null"));
	// Выполняем запись ключа подписи в DER
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/key.pem -outform DER -out " + dir + "/key.der 2>/dev/null"));
	// Выполняем запись ключа проверки в DER
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/key.pem -pubout -outform DER -out " + dir + "/pub.der 2>/dev/null"));
	// Выполняем выработку подписи системным OpenSSL
	ASSERT_TRUE(run("openssl pkeyutl -sign -inkey " + dir + "/key.pem -rawin -in " + dir + "/msg.bin -out " + dir + "/sig.bin 2>/dev/null"));
	// Читаем записи ключей и подписи
	const std::string secret = slurp(dir + "/key.der"), pub = slurp(dir + "/pub.der"), sig = slurp(dir + "/sig.bin");
	// Проверяем длину записи PKCS#8
	ASSERT_EQ(secret.size(), static_cast <size_t> (48));
	// Проверяем длину записи SubjectPublicKeyInfo
	ASSERT_EQ(pub.size(), static_cast <size_t> (44));
	// Проверяем длину подписи
	ASSERT_EQ(sig.size(), static_cast <size_t> (64));
	// Объект модуля электронной подписи
	sign::ed25519_t ed25519;
	// Выполняем установку зерна OpenSSL
	ASSERT_TRUE(ed25519.secret(view_t(reinterpret_cast <const uint8_t *> (secret.data()) + 16, 32)));
	// Место ключа проверки
	uint8_t key[32];
	// Выполняем получение ключа проверки
	ASSERT_TRUE(ed25519.key(key, sizeof(key)));
	// Сличаем свой ключ проверки с ключом OpenSSL
	ASSERT_EQ(text(key, sizeof(key)), text(reinterpret_cast <const uint8_t *> (pub.data()) + 12, 32));
	// Область сообщения
	const view_t data(reinterpret_cast <const uint8_t *> (message.data()), message.size());
	// Выполняем проверку подписи OpenSSL своим кодом
	ASSERT_TRUE(ed25519.check(data, view_t(reinterpret_cast <const uint8_t *> (sig.data()), sig.size())));
	// Место своей подписи
	uint8_t result[64];
	// Выполняем выработку подписи своим кодом
	ASSERT_TRUE(ed25519.make(data, result));
	// Подпись детерминирована: обязана совпасть с подписью OpenSSL
	ASSERT_EQ(text(result, sizeof(result)), text(reinterpret_cast <const uint8_t *> (sig.data()), 64));
	// Объект подписи своим зерном из RFC 8032
	sign::ed25519_t own;
	// Разобранное зерно контрольного примера
	const std::vector <uint8_t> seed = bytes(TWO_SECRET);
	// Выполняем установку зерна
	ASSERT_TRUE(own.secret(view(seed)));
	// Выполняем выработку подписи сообщения своим кодом
	ASSERT_TRUE(own.make(data, result));
	// Выполняем запись подписи в файл
	ASSERT_TRUE(spill(dir + "/own-sig.bin", result, sizeof(result)));
	// Заголовок записи PKCS#8 ключа Ed25519
	std::vector <uint8_t> pkcs8 = bytes("302e020100300506032b657004220420");
	// Дописываем зерно в запись
	pkcs8.insert(pkcs8.end(), seed.begin(), seed.end());
	// Выполняем запись ключа в файл
	ASSERT_TRUE(spill(dir + "/own.der", pkcs8.data(), pkcs8.size()));
	// Выполняем запись ключа проверки системным OpenSSL
	ASSERT_TRUE(run("openssl pkey -inform DER -in " + dir + "/own.der -pubout -out " + dir + "/own-pub.pem 2>/dev/null"));
	// Выполняем проверку своей подписи системным OpenSSL
	ASSERT_TRUE(run("openssl pkeyutl -verify -pubin -inkey " + dir + "/own-pub.pem -rawin -in " + dir + "/msg.bin -sigfile " + dir + "/own-sig.bin >/dev/null 2>&1"));
	// Портим байт своей подписи
	result[10] ^= 0x01;
	// Выполняем запись битой подписи в файл
	ASSERT_TRUE(spill(dir + "/own-sig.bin", result, sizeof(result)));
	// Проверяем отказ OpenSSL на битой подписи: заслон сличения сам обязан работать
	ASSERT_FALSE(run("openssl pkeyutl -verify -pubin -inkey " + dir + "/own-pub.pem -rawin -in " + dir + "/msg.bin -sigfile " + dir + "/own-sig.bin >/dev/null 2>&1"));
	// Удаляем временный каталог
	ASSERT_TRUE(run("rm -rf " + dir));
}
