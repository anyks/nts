/**
 * @file ffdhe.cpp
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
 * @brief Проверки модуля выработки общего ключа в конечном поле по RFC 7919: модули против
 *        системного openssl, обмен, отказы на ключах вне подгруппы, сличение с openssl
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
#include <asn1/asn1.hpp>
#include <agreement/ffdhe.hpp>

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
	 * @brief Метод разбора шестнадцатеричной записи
	 *
	 * @param text запись
	 * @param data место байтов
	 * @return     число байтов
	 *
	 */
	static size_t bytes(const char * text, uint8_t * data) {
		size_t result = 0;
		for(size_t i = 0; text[i * 2] != '\0'; i++){
			uint8_t value = 0;
			for(size_t j = 0; j < 2; j++){
				const char letter = text[(i * 2) + j];
				value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
			}
			data[result++] = value;
		}
		return result;
	}
	/**
	 * @brief Метод шестнадцатеричной записи байтов
	 *
	 * @param data байты
	 * @param size длина
	 * @return     запись
	 *
	 */
	static std::string text(const uint8_t * data, const size_t size) {
		std::string result;
		static const char * letters = "0123456789abcdef";
		for(size_t i = 0; i < size; i++){
			result.append(1, letters[(data[i] >> 4) & 0x0F]);
			result.append(1, letters[data[i] & 0x0F]);
		}
		return result;
	}
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь
	 * @return     содержимое
	 *
	 */
	static std::string slurp(const std::string & path) {
		std::string result;
		FILE * file = ::fopen(path.c_str(), "rb");
		if(file == nullptr)
			return result;
		char buffer[256];
		size_t count = 0;
		while((count = ::fread(buffer, 1, sizeof(buffer), file)) > 0)
			result.append(buffer, count);
		::fclose(file);
		return result;
	}
	/**
	 * @brief Метод записи файла
	 *
	 * @param path путь
	 * @param data байты
	 * @param size длина
	 * @return     признак успешности
	 *
	 */
	static bool spill(const std::string & path, const uint8_t * data, const size_t size) {
		FILE * file = ::fopen(path.c_str(), "wb");
		if(file == nullptr)
			return false;
		const bool ok = (::fwrite(data, 1, size, file) == size);
		::fclose(file);
		return ok;
	}
	/**
	 * @brief Метод запуска команды оболочки
	 *
	 * @param command команда
	 * @return        признак нулевого кода завершения
	 *
	 */
	static bool run(const std::string & command) {
		return (::system((command + " </dev/null").c_str()) == 0);
	}
};

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * Длины модулей пяти групп в байтах
	 */
	static const size_t SIZES[5] = {256, 384, 512, 768, 1024};
	/**
	 * Имена групп у openssl
	 */
	static const char * NAMES[5] = {"ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"};
	/**
	 * @brief Метод извлечения шестнадцатеричной записи поля из вывода openssl pkey -text
	 *
	 * @param text  вывод
	 * @param label подпись поля
	 * @param result байты
	 * @return      признак успешности
	 *
	 */
	static bool field(const std::string & text, const std::string & label, std::vector <uint8_t> & result) noexcept {
		result.clear();
		size_t at = text.find(label);
		if(at == std::string::npos)
			return false;
		at += label.size();
		std::string hex;
		for(; at < text.size(); at++){
			const char letter = text[at];
			if((letter == ':') || (letter == ' ') || (letter == '\n') || (letter == '\r'))
				continue;
			if(::isxdigit(static_cast <unsigned char> (letter))){
				hex.push_back(letter);
				continue;
			}
			break;
		}
		if(hex.empty() || ((hex.size() % 2) != 0))
			return false;
		result.assign(hex.size() / 2, 0);
		return (bytes(hex.c_str(), result.data()) == result.size());
	}
	/**
	 * @brief Метод записи целого DER без знака
	 *
	 * @param writer записывающий
	 * @param value  байты старшим вперёд
	 * @return       признак успешности
	 *
	 */
	static bool unsignedInteger(asn1::writer_t & writer, const view_t & value) noexcept {
		std::vector <uint8_t> content;
		size_t skip = 0;
		while((skip + 1 < value.size) && (value.data[skip] == 0))
			skip++;
		if(value.data[skip] & 0x80)
			content.push_back(0);
		content.insert(content.end(), value.data + skip, value.data + value.size);
		return writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(content.data(), content.size()));
	}
	/**
	 * @brief Метод записи открытого ключа DH записью SubjectPublicKeyInfo (PKCS #3) в PEM
	 *
	 * @param path путь файла
	 * @param size длина модуля
	 * @param key  открытый ключ длиной в модуль
	 * @return     признак успешности
	 *
	 */
	static bool publish(const std::string & path, const size_t size, const uint8_t * key) noexcept {
		const view_t prime = agreement::prime(size);
		asn1::writer_t inner;
		if(!unsignedInteger(inner, view_t(key, size)))
			return false;
		asn1::writer_t writer;
		if(!writer.open(asn1::tag_t::SEQUENCE) || !writer.open(asn1::tag_t::SEQUENCE) || !writer.oid("1.2.840.113549.1.3.1") || !writer.open(asn1::tag_t::SEQUENCE))
			return false;
		if(!unsignedInteger(writer, prime) || !writer.integer(2) || !writer.close() || !writer.close())
			return false;
		if(!writer.bits(inner.data()) || !writer.close())
			return false;
		const view_t der = writer.data();
		return spill(path, der.data, der.size);
	}
	/**
	 * @brief Метод снятия ведущих нулей
	 *
	 * @param data байты
	 * @return     запись без ведущих нулей
	 *
	 */
	static std::string trimmed(const std::vector <uint8_t> & data) noexcept {
		size_t skip = 0;
		while((skip + 1 < data.size()) && (data[skip] == 0))
			skip++;
		return text(data.data() + skip, data.size() - skip);
	}
	/**
	 * @brief Метод записи параметров DH (p, g) в DER для openssl
	 *
	 * @param path      путь файла
	 * @param prime     модуль от старшего байта к младшему
	 * @param generator образующая от старшего байта к младшему
	 * @return          признак успешности
	 *
	 */
	static bool params(const std::string & path, const view_t & prime, const view_t & generator) noexcept {
		asn1::writer_t writer;
		if(!writer.open(asn1::tag_t::SEQUENCE))
			return false;
		if(!unsignedInteger(writer, prime) || !unsignedInteger(writer, generator))
			return false;
		if(!writer.close())
			return false;
		const view_t der = writer.data();
		return spill(path, der.data, der.size);
	}
	/**
	 * @brief Метод записи открытого ключа DH записью SubjectPublicKeyInfo в DER
	 *
	 * @param path      путь файла
	 * @param prime     модуль от старшего байта к младшему
	 * @param key       открытый ключ длиной в модуль
	 * @return          признак успешности
	 *
	 */
	static bool publish(const std::string & path, const view_t & prime, const uint8_t * key) noexcept {
		asn1::writer_t inner;
		if(!unsignedInteger(inner, view_t(key, prime.size)))
			return false;
		asn1::writer_t writer;
		if(!writer.open(asn1::tag_t::SEQUENCE) || !writer.open(asn1::tag_t::SEQUENCE) || !writer.oid("1.2.840.113549.1.3.1") || !writer.open(asn1::tag_t::SEQUENCE))
			return false;
		if(!unsignedInteger(writer, prime) || !writer.integer(2) || !writer.close() || !writer.close())
			return false;
		if(!writer.bits(inner.data()) || !writer.close())
			return false;
		const view_t der = writer.data();
		return spill(path, der.data, der.size);
	}
};

/**
 * @brief Проверка модулей пяти групп против системного openssl
 *
 */
TEST(FfdheTest, Primes) {
	for(size_t i = 0; i < 5; i++){
		const view_t prime = agreement::prime(SIZES[i]);
		ASSERT_EQ(prime.size, SIZES[i]) << NAMES[i];
		// Старший и младший байты модуля RFC 7919 равны 0xFF, образующая два
		EXPECT_EQ(prime.data[0], 0xFF) << NAMES[i];
		EXPECT_EQ(prime.data[SIZES[i] - 1], 0xFF) << NAMES[i];
		EXPECT_GT(agreement::exponent(SIZES[i]), static_cast <size_t> (31)) << NAMES[i];
	}
	EXPECT_EQ(agreement::prime(128).size, static_cast <size_t> (0));
	EXPECT_EQ(agreement::exponent(128), static_cast <size_t> (0));
	if(!run("openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out /dev/null >/dev/null 2>&1"))
		GTEST_SKIP() << "Системный openssl без групп RFC 7919";
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	for(size_t i = 0; i < 5; i++){
		ASSERT_TRUE(run("openssl genpkey -genparam -algorithm DH -pkeyopt group:" + std::string(NAMES[i]) + " -out " + dir + "/p.pem 2>/dev/null"));
		// Конвейер в подоболочке: перенаправление ввода помощника run() относится к последнему звену
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p.pem | grep INTEGER | head -1 | sed 's/.*://' > " + dir + "/p.hex)"));
		std::string hex = slurp(dir + "/p.hex");
		while(!hex.empty() && ((hex.back() == '\n') || (hex.back() == '\r')))
			hex.pop_back();
		for(size_t k = 0; k < hex.size(); k++)
			hex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (hex[k])));
		const view_t prime = agreement::prime(SIZES[i]);
		EXPECT_EQ(text(prime.data, prime.size), hex) << NAMES[i];
	}
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * @brief Проверка порождения пар и обмена на всех пяти группах
 *
 */
TEST(FfdheTest, Exchange) {
	for(size_t i = 0; i < 5; i++){
		const size_t size = SIZES[i], length = agreement::exponent(size);
		std::vector <uint8_t> secretA(length), keyA(size), secretB(length), keyB(size), sharedA(size), sharedB(size), derived(size);
		ASSERT_TRUE(agreement::pairffdhe(size, secretA.data(), keyA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::pairffdhe(size, secretB.data(), keyB.data())) << NAMES[i];
		EXPECT_NE(text(keyA.data(), size), text(keyB.data(), size)) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretA.data(), length), derived.data())) << NAMES[i];
		EXPECT_EQ(text(derived.data(), size), text(keyA.data(), size)) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretA.data(), length), view_t(keyB.data(), size), sharedA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secretB.data(), length), view_t(keyA.data(), size), sharedB.data())) << NAMES[i];
		EXPECT_EQ(text(sharedA.data(), size), text(sharedB.data(), size)) << NAMES[i];
	}
}

/**
 * @brief Проверка отказов: ключи 0, 1, p - 1, p, ключ вне подгруппы (p - 2), негодные длины
 *
 */
TEST(FfdheTest, Reject) {
	const size_t size = 256, length = agreement::exponent(size);
	std::vector <uint8_t> secret(length), key(size), peer(size), shared(size);
	ASSERT_TRUE(agreement::pairffdhe(size, secret.data(), key.data()));
	const view_t prime = agreement::prime(size);
	// Ноль
	std::fill(peer.begin(), peer.end(), 0);
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Единица
	peer[size - 1] = 1;
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p
	::memcpy(peer.data(), prime.data, size);
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p - 1
	peer[size - 1] = 0xFE;
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p - 2: невычет вне подгруппы порядка q, но в границах - принимается намеренно (проверки Y^q нет)
	peer[size - 1] = 0xFD;
	EXPECT_TRUE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Два: вычет, лежит в подгруппе - принимается
	std::fill(peer.begin(), peer.end(), 0);
	peer[size - 1] = 2;
	EXPECT_TRUE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Негодные длины и места
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(key.data(), size - 1), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), 0), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), view_t(key.data(), size), nullptr));
	EXPECT_FALSE(agreement::ffdhe(200, view_t(secret.data(), length), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), nullptr));
	EXPECT_FALSE(agreement::pairffdhe(100, secret.data(), key.data()));
	// Нулевой показатель
	std::fill(secret.begin(), secret.end(), 0);
	EXPECT_FALSE(agreement::ffdhe(size, view_t(secret.data(), length), key.data()));
}

/**
 * @brief Сличение с системным openssl: открытый ключ из чужого показателя и общее значение
 *
 */
TEST(FfdheTest, Foreign) {
	if(!run("openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out /dev/null >/dev/null 2>&1"))
		GTEST_SKIP() << "Системный openssl без групп RFC 7919";
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	for(size_t i = 0; i < 3; i++){
		const size_t size = SIZES[i];
		ASSERT_TRUE(run("openssl genpkey -genparam -algorithm DH -pkeyopt group:" + std::string(NAMES[i]) + " -out " + dir + "/p.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl genpkey -paramfile " + dir + "/p.pem -out " + dir + "/a.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl pkey -in " + dir + "/a.pem -text -noout > " + dir + "/a.txt 2>/dev/null")) << NAMES[i];
		const std::string dump = slurp(dir + "/a.txt");
		std::vector <uint8_t> secret, pub;
		ASSERT_TRUE(field(dump, "private-key:", secret)) << dump;
		ASSERT_TRUE(field(dump, "public-key:", pub)) << dump;
		// Открытый ключ из чужого показателя
		std::vector <uint8_t> derived(size);
		ASSERT_TRUE(agreement::ffdhe(size, view_t(secret.data(), secret.size()), derived.data())) << NAMES[i];
		EXPECT_EQ(trimmed(derived), trimmed(pub)) << NAMES[i];
		// Своя пара и общее значение с чужим открытым ключом
		std::vector <uint8_t> mine(agreement::exponent(size)), key(size), shared(size), peer(size, 0);
		ASSERT_TRUE(agreement::pairffdhe(size, mine.data(), key.data())) << NAMES[i];
		// Запись openssl вправе нести ведущий ноль
		size_t skip = 0;
		while((skip + 1 < pub.size()) && (pub[skip] == 0))
			skip++;
		ASSERT_LE(pub.size() - skip, size);
		::memcpy(peer.data() + (size - (pub.size() - skip)), pub.data() + skip, pub.size() - skip);
		ASSERT_TRUE(agreement::ffdhe(size, view_t(mine.data(), mine.size()), view_t(peer.data(), size), shared.data())) << NAMES[i];
		// Своё открытое - в PEM для openssl
		ASSERT_TRUE(publish(dir + "/b.der", size, key.data())) << NAMES[i];
		ASSERT_TRUE(run("openssl pkey -pubin -inform DER -in " + dir + "/b.der -out " + dir + "/b.pem 2>/dev/null")) << NAMES[i];
		ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/a.pem -peerkey " + dir + "/b.pem -out " + dir + "/shared.bin 2>/dev/null")) << NAMES[i];
		const std::string foreign = slurp(dir + "/shared.bin");
		ASSERT_FALSE(foreign.empty()) << NAMES[i];
		EXPECT_EQ(trimmed(shared), trimmed(std::vector <uint8_t> (foreign.begin(), foreign.end()))) << NAMES[i];
	}
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * Проверка модулей, длин показателя и параметров групп RFC 3526
 */
TEST(FfdheTest, Rfc3526Primes) {
	EXPECT_EQ(agreement::prime3526(13).size, static_cast <size_t> (0));
	EXPECT_EQ(agreement::exponent3526(13), static_cast <size_t> (0));
	static const uint8_t IDS[3] = {14, 15, 16};
	static const size_t SIZES[3] = {256, 384, 512};
	static const char * NAMES[3] = {"modp2048", "modp3072", "modp4096"};
	for(size_t i = 0; i < 3; i++){
		const view_t prime = agreement::prime3526(IDS[i]);
		ASSERT_EQ(prime.size, SIZES[i]) << NAMES[i];
		EXPECT_EQ(prime.data[0], 0xFF) << NAMES[i];
		EXPECT_EQ(prime.data[SIZES[i] - 1], 0xFF) << NAMES[i];
		// Обратная совместимость с RFC 7919 по длине модуля и показателя
		EXPECT_EQ(agreement::exponent(SIZES[i]), agreement::exponent3526(IDS[i])) << NAMES[i];
	}
	if(!run("openssl dhparam -help >/dev/null 2>&1"))
		GTEST_SKIP() << "Системный openssl без dhparam";
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	for(size_t i = 0; i < 3; i++){
		const view_t prime = agreement::prime3526(IDS[i]);
		const uint8_t gen[1] = {2};
		ASSERT_TRUE(params(dir + "/p" + std::to_string(IDS[i]) + ".der", prime, view_t(gen, 1))) << NAMES[i];
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p" + std::to_string(IDS[i]) + ".der -inform DER | grep INTEGER | head -1 | sed 's/.*://' > " + dir + "/p" + std::to_string(IDS[i]) + ".hex)")) << NAMES[i];
		std::string hex = slurp(dir + "/p" + std::to_string(IDS[i]) + ".hex");
		while(!hex.empty() && ((hex.back() == '\n') || (hex.back() == '\r')))
			hex.pop_back();
		for(size_t k = 0; k < hex.size(); k++)
			hex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (hex[k])));
		EXPECT_EQ(text(prime.data, prime.size), hex) << NAMES[i];
		ASSERT_TRUE(run("(openssl asn1parse -in " + dir + "/p" + std::to_string(IDS[i]) + ".der -inform DER | grep INTEGER | sed -n '2p' | sed 's/.*://' > " + dir + "/g" + std::to_string(IDS[i]) + ".hex)")) << NAMES[i];
		std::string ghex = slurp(dir + "/g" + std::to_string(IDS[i]) + ".hex");
		while(!ghex.empty() && ((ghex.back() == '\n') || (ghex.back() == '\r')))
			ghex.pop_back();
		for(size_t k = 0; k < ghex.size(); k++)
			ghex[k] = static_cast <char> (::tolower(static_cast <unsigned char> (ghex[k])));
		EXPECT_EQ(std::string("02"), ghex) << NAMES[i];
	}
	ASSERT_TRUE(run("rm -rf " + dir));
}

/**
 * Проверка порождения пар и обмена на группах RFC 3526
 */
TEST(FfdheTest, Rfc3526Exchange) {
	static const uint8_t IDS[3] = {14, 15, 16};
	static const char * NAMES[3] = {"modp2048", "modp3072", "modp4096"};
	const uint8_t gen[1] = {2};
	const view_t generator(gen, 1);
	for(size_t i = 0; i < 3; i++){
		const view_t prime = agreement::prime3526(IDS[i]);
		const size_t size = prime.size;
		const size_t length = agreement::exponent3526(IDS[i]);
		std::vector <uint8_t> secretA(length), keyA(size), secretB(length), keyB(size), sharedA(size), sharedB(size), derived(size);
		ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretA.data(), keyA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secretB.data(), keyB.data())) << NAMES[i];
		EXPECT_NE(text(keyA.data(), size), text(keyB.data(), size)) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretA.data(), length), derived.data())) << NAMES[i];
		EXPECT_EQ(text(derived.data(), size), text(keyA.data(), size)) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretA.data(), length), view_t(keyB.data(), size), sharedA.data())) << NAMES[i];
		ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secretB.data(), length), view_t(keyA.data(), size), sharedB.data())) << NAMES[i];
		EXPECT_EQ(text(sharedA.data(), size), text(sharedB.data(), size)) << NAMES[i];
	}
}

/**
 * Отказы границ для произвольного модуля: ключи 0, 1, p − 1, p, негодные длины и генератор
 */
TEST(FfdheTest, Rfc3526Reject) {
	const view_t prime = agreement::prime3526(14);
	const size_t size = prime.size;
	const size_t length = agreement::exponent3526(14);
	const uint8_t gen[1] = {2};
	const view_t generator(gen, 1);
	std::vector <uint8_t> secret(length), key(size), peer(size), shared(size);
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, length, secret.data(), key.data()));
	// Ноль
	std::fill(peer.begin(), peer.end(), 0);
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Единица
	std::fill(peer.begin(), peer.end(), 0);
	peer[size - 1] = 1;
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p
	::memcpy(peer.data(), prime.data, size);
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p − 1
	peer[size - 1] = 0xFE;
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// p − 2: в границах, принимается
	peer[size - 1] = 0xFD;
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Два: в границах, принимается
	std::fill(peer.begin(), peer.end(), 0);
	peer[size - 1] = 2;
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(peer.data(), size), shared.data()));
	// Негодные длины и места
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(key.data(), size - 1), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), 0), view_t(key.data(), size), shared.data()));
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), view_t(key.data(), size), nullptr));
	EXPECT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), key.data()));
	EXPECT_FALSE(agreement::pairffdhe(prime, generator, 0, secret.data(), key.data()));
	// Негодная образующая
	uint8_t bad = 1;
	EXPECT_FALSE(agreement::ffdhe(prime, view_t(&bad, 1), view_t(secret.data(), length), key.data()));
	// Нулевой показатель
	std::fill(secret.begin(), secret.end(), 0);
	EXPECT_FALSE(agreement::ffdhe(prime, generator, view_t(secret.data(), length), key.data()));
}

/**
 * Сличение modp14 с системным openssl: открытый ключ из чужого показателя и общее значение
 */
TEST(FfdheTest, Rfc3526Foreign) {
	if(!run("openssl dhparam -help >/dev/null 2>&1"))
		GTEST_SKIP() << "Системный openssl без dhparam";
	const view_t prime = agreement::prime3526(14);
	const uint8_t gen[1] = {2};
	const view_t generator(gen, 1);
	char pattern[] = "/tmp/ants-ffdhe-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	ASSERT_TRUE(params(dir + "/p.der", prime, generator));
	ASSERT_TRUE(run("openssl dhparam -in " + dir + "/p.der -inform DER -out " + dir + "/p.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl genpkey -paramfile " + dir + "/p.pem -out " + dir + "/a.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkey -in " + dir + "/a.pem -text -noout > " + dir + "/a.txt 2>/dev/null"));
	const std::string dump = slurp(dir + "/a.txt");
	std::vector <uint8_t> secret, pub;
	ASSERT_TRUE(field(dump, "private-key:", secret)) << dump;
	ASSERT_TRUE(field(dump, "public-key:", pub)) << dump;
	// Открытый ключ из чужого показателя
	std::vector <uint8_t> derived(256);
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(secret.data(), secret.size()), derived.data()));
	EXPECT_EQ(trimmed(derived), trimmed(pub));
	// Своя пара и общее значение с чужим открытым ключом
	std::vector <uint8_t> mine(agreement::exponent3526(14)), key(256), shared(256), peer(256, 0);
	ASSERT_TRUE(agreement::pairffdhe(prime, generator, mine.size(), mine.data(), key.data()));
	// Запись openssl вправе нести ведущий ноль
	size_t skip = 0;
	while((skip + 1 < pub.size()) && (pub[skip] == 0))
		skip++;
	ASSERT_LE(pub.size() - skip, static_cast <size_t> (256));
	::memcpy(peer.data() + (256 - (pub.size() - skip)), pub.data() + skip, pub.size() - skip);
	ASSERT_TRUE(agreement::ffdhe(prime, generator, view_t(mine.data(), mine.size()), view_t(peer.data(), 256), shared.data()));
	// Своё открытое - в PEM для openssl
	ASSERT_TRUE(publish(dir + "/b.der", prime, key.data()));
	ASSERT_TRUE(run("openssl pkey -pubin -inform DER -in " + dir + "/b.der -out " + dir + "/b.pem 2>/dev/null"));
	ASSERT_TRUE(run("openssl pkeyutl -derive -inkey " + dir + "/a.pem -peerkey " + dir + "/b.pem -out " + dir + "/shared.bin 2>/dev/null"));
	const std::string foreign = slurp(dir + "/shared.bin");
	ASSERT_FALSE(foreign.empty());
	EXPECT_EQ(trimmed(shared), trimmed(std::vector <uint8_t> (foreign.begin(), foreign.end())));
	ASSERT_TRUE(run("rm -rf " + dir));
}
