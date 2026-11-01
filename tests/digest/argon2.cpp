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
#include <posix.hpp>

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
 * @brief Функция записи байтов шестнадцатеричной строкой
 *
 * @param data байты
 * @param size число байтов
 * @return     запись
 *
 */
static std::string text(const uint8_t * data, const size_t size) {
	// Объявляем строку записи
	std::string result;
	// Таблица шестнадцатеричных знаков
	static const char * DIGITS = "0123456789abcdef";
	/** Перебираем: все байты буфера от начала до конца */
	for(size_t i = 0; i < size; i++){
		// Дописываем старший полубайт
		result.push_back(DIGITS[data[i] >> 4]);
		result.push_back(DIGITS[data[i] & 0x0F]);
	}
	// Возвращаем собранную запись
	return result;
}
/**
 * @brief Функция вывода метки по параметрам раздела 5 RFC 9106
 *
 * @param type разновидность
 * @return     запись метки либо пустая при отказе
 *
 */
static std::string vector5(const digest::argon_t type) {
	// Задаём пароль, соль, тайное значение и связанные данные вектора
	const std::vector <uint8_t> password(32, 0x01), salt(16, 0x02), secret(8, 0x03), associated(12, 0x04);
	// Объявляем буфер метки
	uint8_t tag[32];
	// Выводим метку по параметрам раздела 5
	if(!digest::argon2(digest::argon_params_t(type, 32, 3, 4), view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(secret.data(), secret.size()), view_t(associated.data(), associated.size()), tag, sizeof(tag)))
		// При отказе возвращаем пустую строку
		return std::string();
	// Возвращаем запись метки
	return text(tag, sizeof(tag));
}

/**
 * Векторы раздела 5 RFC 9106: Argon2d, Argon2i, Argon2id (сверены и с openssl 3.6)
 */
TEST(Argon2Test, Rfc9106){
	// Сверяем метку Argon2d с вектором раздела 5
	ASSERT_EQ(vector5(digest::argon_t::ARGON2D), "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
	ASSERT_EQ(vector5(digest::argon_t::ARGON2I), "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");
	ASSERT_EQ(vector5(digest::argon_t::ARGON2ID), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
}

/**
 * Сличение с openssl kdf на иных параметрах: длинная метка (H' с шагами), две дорожки,
 * два прохода, память 64 КиБ; пропуск вслух без openssl 3.2+
 */
TEST(Argon2Test, Openssl){
	// Проверяем наличие Argon2 в системном openssl
	if(std::system("(openssl list -kdf-algorithms 2>/dev/null | grep -q ARGON2ID) >/dev/null 2>&1") != 0){
		// Пропускаем проверку без openssl 3.2+
		GTEST_SKIP() << "openssl без Argon2 (нужен openssl 3.2+)";
	}
	// Задаём таблицу случаев сличения
	const struct { digest::argon_t type; const char * name; uint32_t memory, passes, lanes; size_t size; } cases[] = {
		{digest::argon_t::ARGON2ID, "ARGON2ID", 64, 2, 2, 100},
		{digest::argon_t::ARGON2I, "ARGON2I", 40, 1, 1, 48},
		{digest::argon_t::ARGON2D, "ARGON2D", 96, 4, 3, 16},
		{digest::argon_t::ARGON2ID, "ARGON2ID", 1024, 1, 8, 64}
	};
	/** Перебираем: все случаи таблицы */
	for(size_t c = 0; c < (sizeof(cases) / sizeof(cases[0])); c++){
		// Задаём пароль и соль случая
		const std::string password = "correct horse battery staple", salt = "NaCl-salt-16byte";
		// Объявляем буфер метки случая
		std::vector <uint8_t> tag(cases[c].size, 0);
		// Выводим метку по параметрам случая
		ASSERT_TRUE(digest::argon2(digest::argon_params_t(cases[c].type, cases[c].memory, cases[c].passes, cases[c].lanes), view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(reinterpret_cast <const uint8_t *> (salt.data()), salt.size()), view_t(), view_t(), tag.data(), tag.size())) << "случай " << c;
		// Задаём путь файла вывода openssl
		const std::string out = "/tmp/ants-argon2-" + std::to_string(static_cast <long> (::getpid())) + ".txt";
		// Составляем команду вывода openssl kdf
		const std::string command = "openssl kdf -keylen " + std::to_string(cases[c].size) + " -kdfopt pass:'" + password + "' -kdfopt salt:'" + salt + "' -kdfopt iter:" + std::to_string(cases[c].passes) + " -kdfopt memcost:" + std::to_string(cases[c].memory) + " -kdfopt lanes:" + std::to_string(cases[c].lanes) + " -kdfopt threads:1 " + cases[c].name + " > " + out + " 2>/dev/null";
		// Запускаем команду и сверяем код завершения
		ASSERT_EQ(std::system(command.c_str()), 0) << "случай " << c;
		// Объявляем строку ожидаемой записи
		std::string expected;
		{
			// Открываем файл вывода на чтение
			FILE * file = ::fopen(out.c_str(), "r");
			// Проверяем удачу открытия
			ASSERT_NE(file, nullptr);
			// Объявляем текущий знак
			int ch = 0;
			/** Повторяем: чтение знаков, пока файл не исчерпан */
			while((ch = ::fgetc(file)) != EOF){
				// Отбираем шестнадцатеричные знаки записи
				if(((ch >= '0') && (ch <= '9')) || ((ch >= 'A') && (ch <= 'F')))
					// Приводим заглавные к строчным и дописываем знак
					expected.push_back(static_cast <char> (((ch >= 'A') && (ch <= 'F')) ? (ch - 'A' + 'a') : ch));
			}
			::fclose(file);
			::remove(out.c_str());
		}
		// Сверяем метку с выводом openssl
		EXPECT_EQ(text(tag.data(), tag.size()), expected) << "случай " << c;
	}
}

/**
 * Отказы параметров и детерминированность
 */
TEST(Argon2Test, Refusals){
	// Задаём пароль и соль проверки
	const std::string password = "p", salt = "12345678";
	// Описываем байты пароля и соли
	const view_t pw(reinterpret_cast <const uint8_t *> (password.data()), password.size()), sl(reinterpret_cast <const uint8_t *> (salt.data()), salt.size());
	// Объявляем буферы меток
	uint8_t tag[32], again[32];
	// Умолчания: 64 МиБ, три прохода, четыре дорожки
	digest::argon_params_t defaults;
	// Сверяем умолчания набора параметров
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
	// Сверяем повторный вывод с первым
	EXPECT_EQ(text(tag, 32), text(again, 32));
	// Иная разновидность даёт иную метку
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2I, 32, 1, 1), pw, sl, view_t(), view_t(), again, sizeof(again)));
	// Сверяем метки разных разновидностей
	EXPECT_NE(text(tag, 32), text(again, 32));
	// Память, не кратная 4·p, округляется вниз: 33 КиБ на четырёх дорожках равно 32
	uint8_t rounded[32];
	// Выводим метку с округлением памяти вниз
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 33, 1, 4), pw, sl, view_t(), view_t(), rounded, sizeof(rounded)));
	// но H0 берёт m как задано, оттого метка иная
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 32, 1, 4), pw, sl, view_t(), view_t(), again, sizeof(again)));
	// Сверяем метку с округлённой памятью
	EXPECT_NE(text(rounded, 32), text(again, 32));
}

/**
 * Нехватка памяти: паёк выделений набора проверок делает занятие матрицы отказным, метод
 * отвечает false, а не падает; тот же вызов без пайка проходит. Заведомо непосильный объём
 * не запрашивается: на FreeBSD и Linux с перевыделением он не отказывает, а душит машину
 */
TEST(Argon2Test, Memory){
	// Задаём пароль и соль проверки
	const std::string password = "p", salt = "12345678";
	// Описываем байты пароля и соли
	const view_t pw(reinterpret_cast <const uint8_t *> (password.data()), password.size()), sl(reinterpret_cast <const uint8_t *> (salt.data()), salt.size());
	// Объявляем буферы меток
	uint8_t tag[32], again[32];
	// Контрольный вызов без пайка обязан пройти
	ASSERT_TRUE(digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 8192u, 1, 1), pw, sl, view_t(), view_t(), tag, sizeof(tag)));
	// Признаки: нехватка встречена, полный успех достигнут
	bool starved = false, complete = false;
	/** Перебираем: пайки выделений от нуля, пока не достигнут полный успех */
	for(size_t budget = 0; (budget < 64) && !complete; budget++){
		// Объявляем признак удачного вывода
		bool derived = false;
		{
			// Устанавливаем паёк выделений
			starve::ration_t ration(budget);
			// Выводим метку под пайком
			derived = digest::argon2(digest::argon_params_t(digest::argon_t::ARGON2ID, 8192u, 1, 1), pw, sl, view_t(), view_t(), again, sizeof(again));
		}
		// Запоминаем встреченную нехватку
		starved = (starved || !derived);
		// Запоминаем достижение полного успеха
		complete = derived;
		// Если вывод прошёл под пайком, метка та же, что без него
		if(derived)
			// Сверяем метку с контрольной
			EXPECT_EQ(std::memcmp(tag, again, sizeof(tag)), 0) << "паёк " << budget;
	}
	// Проверяем признак нехватки
	EXPECT_TRUE(starved);
	EXPECT_TRUE(complete);
}

/**
 * Строка PHC: разбор и запись, вектор README образцового argon2 (сошёлся с openssl kdf), отказы
 */
TEST(Argon2Test, Phc){
	// Вектор образцового исходника: echo -n password | argon2 somesalt -t 2 -m 16 -p 4 -l 24
	const std::string sample = "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
	// Объявляем запись разбора
	digest::argon_record_t record;
	// Разбираем строку PHC
	ASSERT_TRUE(digest::phc(sample, record));
	// Сверяем разновидность
	EXPECT_EQ(record.params.type, digest::argon_t::ARGON2I);
	EXPECT_EQ(record.params.memory, 65536u);
	EXPECT_EQ(record.params.passes, 2u);
	EXPECT_EQ(record.params.lanes, 4u);
	EXPECT_EQ(std::string(record.salt.begin(), record.salt.end()), "somesalt");
	// Сверяем длину метки
	ASSERT_EQ(record.tag.size(), 24u);
	// Вывод по записи сходится с выходом строки
	const std::string password = "password";
	// Объявляем буфер метки
	std::vector <uint8_t> tag(24, 0);
	// Выводим метку по параметрам записи
	ASSERT_TRUE(digest::argon2(record.params, view_t(reinterpret_cast <const uint8_t *> (password.data()), password.size()), view_t(record.salt.data(), record.salt.size()), view_t(), view_t(), tag.data(), tag.size()));
	// Сверяем метку с записью
	EXPECT_EQ(tag, record.tag);
	EXPECT_EQ(text(tag.data(), tag.size()), "45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6");
	// Запись возвращает строку дословно
	std::string written;
	// Записываем запись в строку
	ASSERT_TRUE(digest::phc(record, written));
	// Сверяем строку с исходной
	EXPECT_EQ(written, sample);
	// Без выхода: запись параметров для вывода ключа
	record.tag.clear();
	// Записываем запись без метки
	ASSERT_TRUE(digest::phc(record, written));
	// Сверяем запись без метки с ожиданием
	EXPECT_EQ(written, "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ");
	// Объявляем запись повторного разбора
	digest::argon_record_t again;
	// Разбираем записанную строку
	ASSERT_TRUE(digest::phc(written, again));
	// Проверяем пустоту метки
	EXPECT_TRUE(again.tag.empty());
	// Сверяем соль с исходной
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
	// Задаём соль короче восьми байтов
	bad.salt.assign(7, 0x01);
	// Проверяем отказ записи
	EXPECT_FALSE(digest::phc(bad, written));
	// Задаём годную соль
	bad.salt.assign(8, 0x01);
	// Задаём метку короче четырёх байтов
	bad.tag.assign(3, 0x02);
	// Проверяем отказ записи
	EXPECT_FALSE(digest::phc(bad, written));
	// Запись с тайным значением либо связанными данными отвергается: строка их не несёт
	bad.tag.clear();
	// Задаём тайное значение
	bad.secret.assign(8, 0x03);
	// Проверяем отказ записи
	EXPECT_FALSE(digest::phc(bad, written));
	// Снимаем тайное значение
	bad.secret.clear();
	// Задаём связанные данные
	bad.associated.assign(12, 0x04);
	// Проверяем отказ записи
	EXPECT_FALSE(digest::phc(bad, written));
	// Снимаем связанные данные
	bad.associated.clear();
	// Проверяем удачу записи
	EXPECT_TRUE(digest::phc(bad, written));
	// Разбор оставляет тайное значение и связанные данные пустыми
	EXPECT_TRUE(again.secret.empty() && again.associated.empty());
}
