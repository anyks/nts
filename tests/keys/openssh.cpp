/**
 * @file openssh.cpp
 * @date 2026-10-04
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
 * @brief Проверки модуля формата ключей openssh-key-v1
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <keys/openssh.hpp>
#include <sign/ed25519.hpp>
#include <entropy/entropy.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод выполнения команды
 *
 * @param cmd команда
 *
 * @return    признак успешности
 *
 */
static bool run(const std::string & cmd) {
	return ::system(cmd.c_str()) == 0;
}

/**
 * @brief Метод чтения файла
 *
 * @param path путь к файлу
 *
 * @return     содержимое файла
 *
 */
static std::vector <uint8_t> slurp(const std::string & path) {
	std::vector <uint8_t> result;
	FILE * f = ::fopen(path.c_str(), "rb");
	if(f == nullptr)
		return result;
	::fseek(f, 0, SEEK_END);
	const long size = ::ftell(f);
	::fseek(f, 0, SEEK_SET);
	if(size > 0){
		result.resize(static_cast <size_t> (size));
		::fread(result.data(), 1, result.size(), f);
	}
	::fclose(f);
	return result;
}

/**
 * @brief Метод извлечения base64-тела из PEM
 *
 * @param pem  PEM-текст
 * @param der  место для DER
 *
 * @return     признак успешности
 *
 */
static bool pem2der(const std::vector <uint8_t> & pem, std::vector <uint8_t> & der) {
	// Ищем начало base64
	const char * text = reinterpret_cast <const char *> (pem.data());
	const char * begin = ::strstr(text, "-----BEGIN OPENSSH PRIVATE KEY-----");
	if(begin == nullptr)
		return false;
	begin = ::strchr(begin, '\n');
	if(begin == nullptr)
		return false;
	++begin;
	const char * end = ::strstr(begin, "-----END OPENSSH PRIVATE KEY-----");
	if(end == nullptr)
		return false;
	// Собираем base64 без переносов строк
	std::string b64;
	for(const char * p = begin; p < end; ++p){
		if(*p != '\n' && *p != '\r')
			b64.push_back(*p);
	}
	// Декодируем
	static const int8_t TABLE[256] = {
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	};
	der.clear();
	der.reserve(b64.size() * 3 / 4);
	uint32_t v = 0;
	int bits = 0;
	for(const char c : b64){
		const int8_t d = TABLE[static_cast <uint8_t> (c)];
		if(d == -2)
			break;
		if(d < 0)
			return false;
		v = (v << 6) | static_cast <uint32_t> (d);
		bits += 6;
		if(bits >= 8){
			bits -= 8;
			der.push_back(static_cast <uint8_t> (v >> bits));
		}
	}
	return true;
}

/**
 * Проверка разбора незашифрованного ключа ssh-keygen
 */
TEST(OpensshTest, DecodePlain) {
	if(!run("ssh-keygen --help >/dev/null 2>&1"))
		GTEST_SKIP() << "ssh-keygen недоступен";
	char pattern[] = "/tmp/ants-openssh-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	const std::string keyfile = dir + "/key";
	// Генерируем ключ без пароля
	ASSERT_TRUE(run("ssh-keygen -t ed25519 -f " + keyfile + " -N '' -C 'test@ants' >/dev/null 2>&1"));
	// Читаем ключ
	const std::vector <uint8_t> pem = slurp(keyfile);
	ASSERT_FALSE(pem.empty());
	// Извлекаем DER
	std::vector <uint8_t> der;
	ASSERT_TRUE(pem2der(pem, der));
	// Разбираем
	keys::key_t key;
	std::string comment;
	ASSERT_TRUE(keys::openssh::decode(view_t(der.data(), der.size()), view_t(), key, comment));
	EXPECT_EQ(key.kind, keys::kind_t::ED25519);
	EXPECT_EQ(key.d.size(), 32u);
	EXPECT_EQ(key.key.size(), 32u);
	EXPECT_EQ(comment, "test@ants");
	// Проверяем подпись разобранным ключом
	sign::ed25519_t ed;
	ASSERT_TRUE(ed.key(view_t(key.d.data(), key.d.size())));
	const char * message = "test message";
	uint8_t signature[64];
	ASSERT_TRUE(ed.make(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), signature));
	sign::ed25519_t edpub;
	ASSERT_TRUE(edpub.key(view_t(key.key.data(), key.key.size())));
	EXPECT_TRUE(edpub.check(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), view_t(signature, sizeof(signature))));
	// Убираем
	run("rm -rf " + dir);
}

/**
 * Проверка разбора зашифрованного ключа ssh-keygen
 */
TEST(OpensshTest, DecodeEncrypted) {
	if(!run("ssh-keygen --help >/dev/null 2>&1"))
		GTEST_SKIP() << "ssh-keygen недоступен";
	char pattern[] = "/tmp/ants-openssh-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	const std::string keyfile = dir + "/key";
	const std::string password = "testpass123";
	// Генерируем ключ с паролем
	ASSERT_TRUE(run("ssh-keygen -t ed25519 -f " + keyfile + " -N '" + password + "' -a 16 -C 'enc@ants' >/dev/null 2>&1"));
	// Читаем ключ
	const std::vector <uint8_t> pem = slurp(keyfile);
	ASSERT_FALSE(pem.empty());
	// Извлекаем DER
	std::vector <uint8_t> der;
	ASSERT_TRUE(pem2der(pem, der));
	// Разбираем с паролем
	keys::key_t key;
	std::string comment;
	ASSERT_TRUE(keys::openssh::decode(view_t(der.data(), der.size()), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), key, comment));
	EXPECT_EQ(key.kind, keys::kind_t::ED25519);
	EXPECT_EQ(key.d.size(), 32u);
	EXPECT_EQ(key.key.size(), 32u);
	EXPECT_EQ(comment, "enc@ants");
	// Проверяем подпись
	sign::ed25519_t ed;
	ASSERT_TRUE(ed.key(view_t(key.d.data(), key.d.size())));
	const char * message = "encrypted test";
	uint8_t signature[64];
	ASSERT_TRUE(ed.make(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), signature));
	sign::ed25519_t edpub;
	ASSERT_TRUE(edpub.key(view_t(key.key.data(), key.key.size())));
	EXPECT_TRUE(edpub.check(view_t(reinterpret_cast <const uint8_t *> (message), ::strlen(message)), view_t(signature, sizeof(signature))));
	// Убираем
	run("rm -rf " + dir);
}

/**
 * Проверка записи и разбора своего ключа
 */
TEST(OpensshTest, Roundtrip) {
	// Вырабатываем ключ
	keys::key_t key;
	key.kind = keys::kind_t::ED25519;
	key.d.assign(32, 0);
	sign::ed25519_t ed;
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	key.key.assign(32, 0);
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Записываем без пароля
	std::vector <uint8_t> der;
	ASSERT_TRUE(keys::openssh::encode(key, "roundtrip@test", view_t(), der));
	// Разбираем
	keys::key_t parsed;
	std::string comment;
	ASSERT_TRUE(keys::openssh::decode(view_t(der.data(), der.size()), view_t(), parsed, comment));
	EXPECT_EQ(parsed.kind, keys::kind_t::ED25519);
	EXPECT_EQ(parsed.d, key.d);
	EXPECT_EQ(parsed.key, key.key);
	EXPECT_EQ(comment, "roundtrip@test");
	// Записываем с паролем
	const std::string password = "secret";
	std::vector <uint8_t> encder;
	ASSERT_TRUE(keys::openssh::encode(key, "enc@test", view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), encder));
	// Разбираем с паролем
	keys::key_t encparsed;
	std::string enccomment;
	ASSERT_TRUE(keys::openssh::decode(view_t(encder.data(), encder.size()), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), encparsed, enccomment));
	EXPECT_EQ(encparsed.d, key.d);
	EXPECT_EQ(encparsed.key, key.key);
	EXPECT_EQ(enccomment, "enc@test");
	// Неверный пароль отвергается
	keys::key_t bad;
	std::string badcomment;
	const std::string badpass = "wrong";
	EXPECT_FALSE(keys::openssh::decode(view_t(encder.data(), encder.size()), view_t(reinterpret_cast <const uint8_t *> (badpass.data()), badpass.size()), bad, badcomment));
}

/**
 * Проверка строки authorized_keys и отпечатка
 */
TEST(OpensshTest, Publish) {
	// Вырабатываем ключ
	keys::key_t key;
	key.kind = keys::kind_t::ED25519;
	key.d.assign(32, 0);
	sign::ed25519_t ed;
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	key.key.assign(32, 0);
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Строка authorized_keys
	const std::string line = keys::openssh::publish(key, "pub@test");
	EXPECT_TRUE(line.find("ssh-ed25519 ") == 0);
	EXPECT_TRUE(line.find(" pub@test") != std::string::npos);
	// Отпечаток
	const std::string fp = keys::openssh::fingerprint(key);
	EXPECT_TRUE(fp.find("SHA256:") == 0);
	EXPECT_EQ(fp.size(), 7 + 43); // "SHA256:" + 43 символа base64 без padding
}

/**
 * Проверка интероп записи с ssh-keygen
 */
TEST(OpensshTest, InteropWrite) {
	if(!run("ssh-keygen --help >/dev/null 2>&1"))
		GTEST_SKIP() << "ssh-keygen недоступен";
	char pattern[] = "/tmp/ants-openssh-XXXXXX";
	ASSERT_NE(::mkdtemp(pattern), nullptr);
	const std::string dir(pattern);
	// Вырабатываем ключ
	keys::key_t key;
	key.kind = keys::kind_t::ED25519;
	key.d.assign(32, 0);
	sign::ed25519_t ed;
	ASSERT_TRUE(ed.generate(key.d.data(), key.d.size()));
	key.key.assign(32, 0);
	ASSERT_TRUE(ed.key(key.key.data(), key.key.size()));
	// Записываем
	std::vector <uint8_t> der;
	ASSERT_TRUE(keys::openssh::encode(key, "interop@test", view_t(), der));
	// Формируем PEM
	std::string pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
	static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for(size_t i = 0; i < der.size(); i += 3){
		uint32_t v = static_cast <uint32_t> (der[i]) << 16;
		if(i + 1 < der.size())
			v |= static_cast <uint32_t> (der[i + 1]) << 8;
		if(i + 2 < der.size())
			v |= static_cast <uint32_t> (der[i + 2]);
		pem.push_back(ALPHABET[(v >> 18) & 63]);
		pem.push_back(ALPHABET[(v >> 12) & 63]);
		pem.push_back((i + 1 < der.size()) ? ALPHABET[(v >> 6) & 63] : '=');
		pem.push_back((i + 2 < der.size()) ? ALPHABET[v & 63] : '=');
		if((i / 3 + 1) % 18 == 0)
			pem.push_back('\n');
	}
	if(pem.back() != '\n')
		pem.push_back('\n');
	pem += "-----END OPENSSH PRIVATE KEY-----\n";
	// Записываем файл
	const std::string keyfile = dir + "/key";
	FILE * f = ::fopen(keyfile.c_str(), "w");
	ASSERT_NE(f, nullptr);
	::fwrite(pem.data(), 1, pem.size(), f);
	::fclose(f);
	::chmod(keyfile.c_str(), 0600);
	// Проверяем ssh-keygen
	ASSERT_TRUE(run("ssh-keygen -y -f " + keyfile + " > " + dir + "/pub.txt 2>/dev/null"));
	const std::vector <uint8_t> pubtxt = slurp(dir + "/pub.txt");
	ASSERT_FALSE(pubtxt.empty());
	// Сравниваем с нашей строкой
	const std::string ourline = keys::openssh::publish(key, "");
	std::string theirline(reinterpret_cast <const char *> (pubtxt.data()), pubtxt.size());
	// Убираем перевод строки в конце
	while(!theirline.empty() && (theirline.back() == '\n' || theirline.back() == '\r'))
		theirline.pop_back();
	// Убираем комментарий из их строки (ssh-keygen добавляет)
	const size_t space = theirline.rfind(' ');
	if(space != std::string::npos)
		theirline = theirline.substr(0, space);
	// Убираем комментарий из нашей строки
	std::string ourtrimmed = ourline;
	const size_t ourspace = ourtrimmed.rfind(' ');
	if(ourspace != std::string::npos)
		ourtrimmed = ourtrimmed.substr(0, ourspace);
	EXPECT_EQ(ourtrimmed, theirline);
	// Убираем
	run("rm -rf " + dir);
}
