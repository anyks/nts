/**
 * @file raw.cpp
 * @date 2026-09-07
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
 * @brief Проверки сырых поточных шифров без имитовставки: XChaCha20 и AES-CTR - векторы
 *        черновика XChaCha, равносильность записей и статистика гаммы на неверных ключах
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cmath>
#include <string>
#include <vector>
#include <random>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <cipher/chacha.hpp>
#include <cipher/chachapoly.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод записи байтов шестнадцатеричной строкой
 */
static std::string text(const uint8_t * data, const size_t size) {
	std::string result;
	static const char * DIGITS = "0123456789abcdef";
	for(size_t i = 0; i < size; i++){
		result.push_back(DIGITS[data[i] >> 4]);
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	return result;
}
/**
 * @brief Метод разбора шестнадцатеричной строки
 */
static std::vector <uint8_t> bytes(const std::string & hex) {
	std::vector <uint8_t> result;
	auto nib = [](char c) -> int { return ((c >= '0' && c <= '9') ? (c - '0') : ((c >= 'a' && c <= 'f') ? (c - 'a' + 10) : (c - 'A' + 10))); };
	for(size_t i = 0; (i + 1) < hex.size(); i += 2)
		result.push_back(static_cast <uint8_t> ((nib(hex[i]) << 4) | nib(hex[i + 1])));
	return result;
}
/**
 * @brief Статистика гаммы: монобитный критерий и χ² по байтам
 *
 * @param gamma  гамма
 * @param z      место z-оценки монобитного критерия
 * @param chi    место статистики χ² (255 степеней свободы)
 *
 */
static void statistics(const std::vector <uint8_t> & gamma, double & z, double & chi) {
	size_t ones = 0, counts[256] = {0};
	for(size_t i = 0; i < gamma.size(); i++){
		counts[gamma[i]]++;
		for(size_t b = 0; b < 8; b++)
			ones += ((gamma[i] >> b) & 1);
	}
	const double n = static_cast <double> (gamma.size() * 8);
	z = ((2.0 * static_cast <double> (ones)) - n) / std::sqrt(n);
	const double expected = static_cast <double> (gamma.size()) / 256.0;
	chi = 0.0;
	for(size_t i = 0; i < 256; i++){
		const double d = (static_cast <double> (counts[i]) - expected);
		chi += ((d * d) / expected);
	}
}

/**
 * HChaCha20 по приложению A.1 черновика: подключ из ключа 00..1f и заполнения
 */
TEST(RawTest, Hchacha){
	const std::vector <uint8_t> key = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	const std::vector <uint8_t> nonce = bytes("000000090000004a0000000031415927");
	uint8_t subkey[32];
	ASSERT_TRUE(cipher::chacha_t::hchacha(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), subkey));
	EXPECT_EQ(text(subkey, 32), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
	// Отказы
	EXPECT_FALSE(cipher::chacha_t::hchacha(view_t(key.data(), 31), view_t(nonce.data(), 16), subkey));
	EXPECT_FALSE(cipher::chacha_t::hchacha(view_t(key.data(), 32), view_t(nonce.data(), 12), subkey));
	EXPECT_FALSE(cipher::chacha_t::hchacha(view_t(key.data(), 32), view_t(nonce.data(), 16), nullptr));
}

/**
 * XChaCha20 равносилен ChaCha20 на подключе HChaCha20 с заполнением из нулей и хвоста
 * (раздел 2.3 черновика); заполнение чужой длины отвергается
 */
TEST(RawTest, Xchacha){
	const std::vector <uint8_t> key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
	const std::vector <uint8_t> nonce = bytes("404142434445464748494a4b4c4d4e4f5051525354555658");
	const std::string message = "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog.";
	std::vector <uint8_t> first(message.size(), 0), second(message.size(), 0);
	cipher::chacha_t x;
	ASSERT_TRUE(x.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 1));
	ASSERT_TRUE(x.encrypt(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), first.data()));
	uint8_t subkey[32], shorter[12] = {0};
	ASSERT_TRUE(cipher::chacha_t::hchacha(view_t(key.data(), key.size()), view_t(nonce.data(), 16), subkey));
	for(size_t i = 0; i < 8; i++) shorter[4 + i] = nonce[16 + i];
	cipher::chacha_t plain;
	ASSERT_TRUE(plain.start(view_t(subkey, 32), view_t(shorter, 12), 1));
	ASSERT_TRUE(plain.encrypt(view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), second.data()));
	EXPECT_EQ(first, second);
	// Расшифрование возвращает сообщение
	std::vector <uint8_t> back(message.size(), 0);
	cipher::chacha_t y;
	ASSERT_TRUE(y.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size()), 1));
	ASSERT_TRUE(y.decrypt(view_t(first.data(), first.size()), back.data()));
	EXPECT_EQ(std::string(back.begin(), back.end()), message);
	// Заполнение чужой длины
	cipher::chacha_t bad;
	EXPECT_FALSE(bad.start(view_t(key.data(), key.size()), view_t(nonce.data(), 20), 1));
	EXPECT_FALSE(bad.start(view_t(key.data(), key.size()), view_t(nonce.data(), 16), 1));
}

/**
 * XChaCha20-Poly1305 по приложению A.3 черновика: метка имитовставки и круг
 */
TEST(RawTest, Xchachapoly){
	const std::vector <uint8_t> key = bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
	const std::vector <uint8_t> nonce = bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
	const std::vector <uint8_t> aad = bytes("50515253c0c1c2c3c4c5c6c7");
	const std::string message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	std::vector <uint8_t> sealed(message.size(), 0);
	uint8_t tag[16];
	cipher::chachapoly_t aead;
	ASSERT_TRUE(aead.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size())));
	ASSERT_TRUE(aead.encrypt(view_t(aad.data(), aad.size()), view_t(reinterpret_cast <const uint8_t *> (message.data()), message.size()), sealed.data(), tag));
	EXPECT_EQ(text(tag, 16), "c0875924c1c7987947deafd8780acf49");
	// Шифротекст A.3.1 целиком (114 байтов): сырой текст черновика, сверен и с libsodium 1.0.22
	EXPECT_EQ(text(sealed.data(), sealed.size()), "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e");
	// Круг
	std::vector <uint8_t> opened(message.size(), 0);
	cipher::chachapoly_t back;
	ASSERT_TRUE(back.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size())));
	ASSERT_TRUE(back.decrypt(view_t(aad.data(), aad.size()), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, 16)));
	EXPECT_EQ(std::string(opened.begin(), opened.end()), message);
	// Порченая метка отвергается
	tag[0] ^= 0x01;
	cipher::chachapoly_t refused;
	ASSERT_TRUE(refused.start(view_t(key.data(), key.size()), view_t(nonce.data(), nonce.size())));
	EXPECT_FALSE(refused.decrypt(view_t(aad.data(), aad.size()), view_t(sealed.data(), sealed.size()), opened.data(), view_t(tag, 16)));
}

/**
 * Статистика гаммы сырых потоков на заведомо неверных ключах: выход неотличим от
 * равномерного - монобитный критерий и χ² по байтам в пределах пяти сигм; XChaCha20 и AES-CTR
 */
TEST(RawTest, Statistics){
	std::mt19937_64 generator(20260907);
	const size_t length = (1u << 20);
	std::vector <uint8_t> zeros(length, 0), gamma(length, 0);
	for(size_t attempt = 0; attempt < 4; attempt++){
		uint8_t key[32], nonce[24], iv[16];
		for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (generator());
		for(size_t i = 0; i < 24; i++) nonce[i] = static_cast <uint8_t> (generator());
		for(size_t i = 0; i < 16; i++) iv[i] = static_cast <uint8_t> (generator());
		// Заведомо неверный ключ: соседний по одному разряду
		if(attempt == 3) key[0] ^= 0x01;
		double z = 0, chi = 0;
		// XChaCha20
		cipher::chacha_t x;
		ASSERT_TRUE(x.start(view_t(key, 32), view_t(nonce, 24), 0));
		ASSERT_TRUE(x.encrypt(view_t(zeros.data(), zeros.size()), gamma.data()));
		statistics(gamma, z, chi);
		EXPECT_LT(std::fabs(z), 5.0) << "XChaCha20 монобит, попытка " << attempt;
		EXPECT_GT(chi, 150.0) << "XChaCha20 χ², попытка " << attempt;
		EXPECT_LT(chi, 380.0) << "XChaCha20 χ², попытка " << attempt;
		// AES-256-CTR
		cipher::aes_t base;
		ASSERT_TRUE(base.key(view_t(key, 32)));
		cipher::counter_t ctr;
		ASSERT_TRUE(ctr.start(cipher::block_t(base), view_t(iv, 8)));
		ASSERT_TRUE(ctr.encrypt(view_t(zeros.data(), zeros.size()), gamma.data()));
		statistics(gamma, z, chi);
		EXPECT_LT(std::fabs(z), 5.0) << "AES-CTR монобит, попытка " << attempt;
		EXPECT_GT(chi, 150.0) << "AES-CTR χ², попытка " << attempt;
		EXPECT_LT(chi, 380.0) << "AES-CTR χ², попытка " << attempt;
	}
}
