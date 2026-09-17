/**
 * @file argon2.cpp
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
 * @brief Проверки модуля Argon2 по RFC 9106
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>

/**
 * Системные заголовочные файлы: номер процесса для имени временного файла
 */
#include <unistd.h>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <digest/argon2.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 *
 * @return     запись
 *
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
 * @brief Метод вывода метки по параметрам раздела 5 RFC 9106
 *
 * @param type разновидность
 *
 * @return     запись метки либо пустая при отказе
 *
 */
static std::string vector5(const digest::argon_t type) {
	const std::vector <uint8_t> password(32, 0x01), salt(16, 0x02), secret(8, 0x03), associated(12, 0x04);
	uint8_t tag[32];
	if(!digest::argon2(digest::argon_params_t(type, 32, 3, 4), view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(secret.data(), secret.size()), view_t(associated.data(), associated.size()), tag, sizeof(tag)))
		return std::string();
	return text(tag, sizeof(tag));
}

/**
 * Векторы раздела 5 RFC 9106: Argon2d, Argon2i, Argon2id (сверены и с openssl 3.6)
 */
TEST(Argon2Test, Rfc9106){
	ASSERT_EQ(vector5(digest::argon_t::ARGON2D), "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
	ASSERT_EQ(vector5(digest::argon_t::ARGON2I), "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");
	ASSERT_EQ(vector5(digest::argon_t::ARGON2ID), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

/**
 * Сличение с openssl kdf на иных параметрах: длинная метка (H' с шагами), две дорожки,
 * два прохода, память 64 КиБ; пропуск вслух без openssl 3.2+
 */
TEST(Argon2Test, Openssl){
	if(std::system("(openssl list -kdf-algorithms 2>/dev/null | grep -q ARGON2ID) >/dev/null 2>&1") != 0){
		GTEST_SKIP() << "openssl без Argon2 (нужен openssl 3.2+)";
	}
	const struct { digest::argon_t type; const char * name; uint32_t memory, passes, lanes; size_t size; } cases[] = {
		{digest::argon_t::ARGON2ID, "ARGON2ID", 64, 2, 2, 100},
		{digest::argon_t::ARGON2I, "ARGON2I", 40, 1, 1, 48},
		{digest::argon_t::ARGON2D, "ARGON2D", 96, 4, 3, 16},
		{digest::argon_t::ARGON2ID, "ARGON2ID", 1024, 1, 8, 64}
	};
	for(size_t c = 0; c < (sizeof(cases) / sizeof(cases[0])); c++){
		const std::string password = "correct horse battery staple", salt = "NaCl-salt-16byte";
		std::vector <uint8_t> tag(cases[c].size, 0);
		ASSERT_TRUE(digest::argon2(digest::argon_params_t(cases[c].type, cases[c].memory, cases[c].passes, cases[c].lanes), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(reinterpret_cast <const uint8_t *> (salt.data()), salt.size()), view_t(), view_t(), tag.data(), tag.size())) << "случай " << c;
		const std::string out = "/tmp/ants-argon2-" + std::to_string(static_cast <long> (::getpid())) + ".txt";
		const std::string command = "openssl kdf -keylen " + std::to_string(cases[c].size) + " -kdfopt pass:'" + password + "' -kdfopt salt:'" + salt + "' -kdfopt iter:" + std::to_string(cases[c].passes) + " -kdfopt memcost:" + std::to_string(cases[c].memory) + " -kdfopt lanes:" + std::to_string(cases[c].lanes) + " -kdfopt threads:1 " + cases[c].name + " > " + out + " 2>/dev/null";
		ASSERT_EQ(std::system(command.c_str()), 0) << "случай " << c;
		std::string expected;
		{
			FILE * file = ::fopen(out.c_str(), "r");
			ASSERT_NE(file, nullptr);
			int ch = 0;
			while((ch = ::fgetc(file)) != EOF){
				if(((ch >= '0') && (ch <= '9')) || ((ch >= 'A') && (ch <= 'F')))
					expected.push_back(static_cast <char> (((ch >= 'A') && (ch <= 'F')) ? (ch - 'A' + 'a') : ch));
			}
			::fclose(file);
			::remove(out.c_str());
		}
		EXPECT_EQ(text(tag.data(), tag.size()), expected) << "случай " << c;
	}
}

/**
 * Отказы параметров и детерминированность
 */
TEST(Argon2Test, Refusals){
	const std::string password = "p", salt = "12345678";
	const view_t pw(reinterpret_cast <const uint8_t *> (password.data()), password.size()), sl(reinterpret_cast <const uint8_t *> (salt.data()), salt.size());
	uint8_t tag[32], again[32];
	// Умолчания: 64 МиБ, три прохода, четыре дорожки
	digest::argon_params_t defaults;
	EXPECT_EQ(defaults.type, digest::argon_t::ARGON2ID);
	EXPECT_EQ(defaults.memory, 65536u);
	// Память меньше 8·lanes
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 31, 1, 4), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	// Ноль проходов и дорожек
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 0, 4), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 0), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	// Соль короче восьми и метка короче четырёх
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 1), pw, view_t(sl.data, 7), view_t(), view_t(), tag, sizeof(tag)));
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 1), pw, sl, view_t(), view_t(), tag, 3));
	EXPECT_FALSE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 1), pw, sl, view_t(), view_t(), nullptr, 32));
	// Годный вызов и повтор
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 1), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 1), pw, sl, view_t(), view_t(), again, sizeof(again)));
	EXPECT_EQ(text(tag, 32), text(again, 32));
	// Иная разновидность даёт иную метку
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2I, 32, 1, 1), pw, sl, view_t(), view_t(), again, sizeof(again)));
	EXPECT_NE(text(tag, 32), text(again, 32));
	// Память, не кратная 4·p, округляется вниз: 33 КиБ на четырёх дорожках равно 32
	uint8_t rounded[32];
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 33, 1, 4), pw, sl, view_t(), view_t(), rounded, sizeof(rounded)));
	// но H0 берёт m как задано, оттого метка иная
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 4), pw, sl, view_t(), view_t(), again, sizeof(again)));
	EXPECT_NE(text(rounded, 32), text(again, 32));
}

/**
 * Нехватка памяти: паёк выделений набора проверок делает занятие матрицы отказным, метод
 * отвечает false, а не падает; тот же вызов без пайка проходит. Заведомо непосильный объём
 * не запрашивается: на FreeBSD и Linux с перевыделением он не отказывает, а душит машину
 */
TEST(Argon2Test, Memory){
	const std::string password = "p", salt = "12345678";
	const view_t pw(reinterpret_cast <const uint8_t *> (password.data()), password.size()), sl(reinterpret_cast <const uint8_t *> (salt.data()), salt.size());
	uint8_t tag[32], again[32];
	// Контрольный вызов без пайка обязан пройти
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 8192u, 1, 1), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	// Признаки: нехватка встречена, полный успех достигнут
	bool starved = false, complete = false;
	for(size_t budget = 0; (budget < 64) && !complete; budget++){
		bool derived = false;
		{
			starve::ration_t ration(budget);
			derived = digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 8192u, 1, 1), pw, sl, view_t(), view_t(), again, sizeof(again));
		}
		starved = (starved || !derived);
		complete = derived;
		// Если вывод прошёл под пайком, метка та же, что без него
		if(derived)
			EXPECT_EQ(std::memcmp(tag, again, sizeof(tag)), 0) << "паёк " << budget;
	}
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}

/**
 * Строка PHC: разбор и запись, вектор README образцового argon2 (сошёлся с openssl kdf), отказы
 */
TEST(Argon2Test, Phc){
	// Вектор образцового исходника: echo -n password | argon2 somesalt -t 2 -m 16 -p 4 -l 24
	const std::string sample = "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
	digest::argon_record_t record;
	ASSERT_TRUE(digest::phc(sample, record));
	EXPECT_EQ(record.params.type, digest::argon_t::ARGON2I);
	EXPECT_EQ(record.params.memory, 65536u);
	EXPECT_EQ(record.params.passes, 2u);
	EXPECT_EQ(record.params.lanes, 4u);
	EXPECT_EQ(std::string(record.salt.begin(), record.salt.end()), "somesalt");
	ASSERT_EQ(record.tag.size(), 24u);
	// Вывод по записи сходится с выходом строки
	const std::string password = "password";
	std::vector <uint8_t> tag(24, 0);
	ASSERT_TRUE(digest::argon2(record.params, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(record.salt.data(), record.salt.size()), view_t(), view_t(), tag.data(), tag.size()));
	EXPECT_EQ(tag, record.tag);
	EXPECT_EQ(text(tag.data(), tag.size()), "45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6");
	// Запись возвращает строку дословно
	std::string written;
	ASSERT_TRUE(digest::phc(record, written));
	EXPECT_EQ(written, sample);
	// Без выхода: запись параметров для вывода ключа
	record.tag.clear();
	ASSERT_TRUE(digest::phc(record, written));
	EXPECT_EQ(written, "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ");
	digest::argon_record_t again;
	ASSERT_TRUE(digest::phc(written, again));
	EXPECT_TRUE(again.tag.empty());
	EXPECT_EQ(again.salt, record.salt);
	// Отказы разбора
	EXPECT_FALSE(digest::phc("$argon2x$v=19$m=65536,t=2,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$m=65536,t=2,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=16$m=65536,t=2,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$t=2,m=65536,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$m=65536,t=2,p=4,keyid=x$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ=", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$m=65536,t=2,p=4$c29tZQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$m=16,t=2,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ", again));
	EXPECT_FALSE(digest::phc("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$", again));
	// Отказы записи
	digest::argon_record_t bad;
	bad.salt.assign(7, 0x01);
	EXPECT_FALSE(digest::phc(bad, written));
	bad.salt.assign(8, 0x01);
	bad.tag.assign(3, 0x02);
	EXPECT_FALSE(digest::phc(bad, written));
	// Запись с тайным значением либо связанными данными отвергается: строка их не несёт
	bad.tag.clear();
	bad.secret.assign(8, 0x03);
	EXPECT_FALSE(digest::phc(bad, written));
	bad.secret.clear();
	bad.associated.assign(12, 0x04);
	EXPECT_FALSE(digest::phc(bad, written));
	bad.associated.clear();
	EXPECT_TRUE(digest::phc(bad, written));
	// Разбор оставляет тайное значение и связанные данные пустыми
	EXPECT_TRUE(again.secret.empty() && again.associated.empty());
}
