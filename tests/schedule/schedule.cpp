/**
 * @file schedule.cpp
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
 * @brief Исходный файл проверок модуля расписания ключей протокола TLS 1.3
 *
 * @note Контрольные примеры взяты из приложения А описания наборов шифрования TLS 1.3 на
 *       алгоритмах ГОСТ: цепочка расписания прослежена от начального значения до ключа и
 *       вектора замены направления связи, то есть до того самого материала, на котором
 *       сверялась защита записей
 *
 * @note Привязкой вывода с меткой derived служит хеш пустой переписки: описание наборов
 *       записывает её пустыми кавычками, но раздел 7.1 RFC 8446 требует именно хеша
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <string>
#include <vector>
#include <cstring>
#include <main.hpp>
#include <digest/streebog.hpp>
#include <schedule/schedule.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Начальное значение расписания ключей первого примера
 */
static const char * EARLY = "FBDEFBE527FEEA665AAB9277A2163B8343084FD191C46066260FAC6FD1436C72";

/**
 * Значение, выведенное для перехода к значению рукопожатия
 */
static const char * DERIVED = "DBC3C826D877A3B7D2D2453DBFDC6CFBFB1151B3E84F0C8F26011D8D5BF3EDF7";

/**
 * Значение расписания ключей рукопожатия
 */
static const char * HANDSHAKE = "44245E2C4332D1F78B0F8D16F403EB69ED2A4053847CDC39FA8B3D2974F745E7";

/**
 * Хеш переписки рукопожатия на миг вывода значения направления связи
 */
static const char * TRANSCRIPT = "993BA722124AF3CBFD4771E7FAE32AC1D0E9278CF7843FCBC620E1A0085A87A1";

/**
 * Значение рукопожатия направления связи от сервера
 */
static const char * TRAFFIC = "70A5F2463DF60DBAA2368B67FD45AEFF7C1A0BA42D8ABD72415ECD1D94E9EF54";

/**
 * Ключ направления связи от сервера на пору рукопожатия
 */
static const char * KEY = "E13764B54B9E1B47D43398D6D216DF24C289A396AB6C5B524BBB9C06F39FEF01";

/**
 * Вектор замены направления связи от сервера на пору рукопожатия
 */
static const char * VECTOR = "6969FFAAA4525281EEBBEB4CBD0B640E";

/**
 * Ключ выработки завершения рукопожатия сервером
 */
static const char * FINISHED = "53F1C0388F8A70C0BCA0DD21A030F2381C3437CD0E7EC93D0A965E25632DD79A";

/**
 * Начальное значение расписания ключей второго примера
 */
static const char * EXTERNAL = "42307A996818340DD0562F7FEBE62AB570F3BC889CA9293A890DF209B91BBBF3";

/**
 * @brief Метод разбора строки шестнадцатеричной записи в область байтов
 *
 * @param text разбираемая строка шестнадцатеричной записи
 *
 * @return     разобранная область байтов
 *
 */
static vector <uint8_t> decode(const char * text) noexcept {
	// Разобранная область байтов
	vector <uint8_t> result;
	// Получаем длину разбираемой строки
	const size_t length = ::strlen(text);
	/**
	 * Выполняем перебор пар знаков шестнадцатеричной записи
	 */
	for(size_t i = 0; (i + 1) < length; i += 2)
		// Добавляем очередной разобранный байт
		result.push_back(static_cast <uint8_t> (::strtoul(string(text + i, 2).c_str(), nullptr, 16)));
	// Выводим разобранную область байтов
	return result;
}

/**
 * Проверка извлечения значения расписания ключей
 */
TEST(ScheduleTest, Extract){
	// Соль извлечения начального значения расписания ключей
	const uint8_t zeroes[schedule::SCHEDULE_SECRET] = {0};
	// Место, в которое помещается извлечённое значение
	uint8_t result[schedule::SCHEDULE_SECRET];
	// Выполняем извлечение начального значения расписания ключей
	ASSERT_TRUE(schedule::extract(view_t(zeroes, sizeof(zeroes)), view_t(zeroes, sizeof(zeroes)), result));
	// Получаем начальное значение расписания ключей контрольного примера
	const vector <uint8_t> early = decode(EARLY);
	// Проверяем схождение извлечённого значения с контрольным примером
	ASSERT_EQ(::memcmp(result, early.data(), early.size()), 0);
	// Заранее разделённый ключ второго контрольного примера
	uint8_t external[schedule::SCHEDULE_SECRET];
	// Выполняем заполнение заранее разделённого ключа
	::memset(external, 0x80, sizeof(external));
	// Выполняем извлечение начального значения на заранее разделённом ключе
	ASSERT_TRUE(schedule::extract(view_t(zeroes, sizeof(zeroes)), view_t(external, sizeof(external)), result));
	// Получаем начальное значение второго контрольного примера
	const vector <uint8_t> sample = decode(EXTERNAL);
	// Проверяем схождение извлечённого значения со вторым контрольным примером
	ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0);
}

/**
 * Проверка вывода значений расписания ключей
 */
TEST(ScheduleTest, Derive){
	// Получаем начальное значение расписания ключей контрольного примера
	const vector <uint8_t> early = decode(EARLY);
	// Место, в которое помещается хеш пустой переписки рукопожатия
	uint8_t empty[schedule::SCHEDULE_SECRET];
	// Выполняем выработку хеша пустой переписки рукопожатия
	ASSERT_TRUE(digest::streebog(digest::type_t::SHORT, view_t(nullptr, 0), empty, sizeof(empty)));
	// Метка назначения перехода к значению рукопожатия
	const char * label = "derived";
	// Место, в которое помещается выведенное значение
	uint8_t result[schedule::SCHEDULE_SECRET];
	// Выполняем вывод значения перехода к значению рукопожатия
	ASSERT_TRUE(schedule::secret(view_t(early.data(), early.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(empty, sizeof(empty)), result));
	// Получаем значение перехода контрольного примера
	const vector <uint8_t> derived = decode(DERIVED);
	// Проверяем схождение выведенного значения с контрольным примером
	ASSERT_EQ(::memcmp(result, derived.data(), derived.size()), 0);
	// Получаем значение расписания ключей рукопожатия
	const vector <uint8_t> handshake = decode(HANDSHAKE);
	// Получаем хеш переписки рукопожатия контрольного примера
	const vector <uint8_t> transcript = decode(TRANSCRIPT);
	// Метка назначения значения рукопожатия направления связи от сервера
	const char * traffic = "s hs traffic";
	// Выполняем вывод значения рукопожатия направления связи от сервера
	ASSERT_TRUE(schedule::secret(view_t(handshake.data(), handshake.size()), view_t(reinterpret_cast <const uint8_t *> (traffic), ::strlen(traffic)), view_t(transcript.data(), transcript.size()), result));
	// Получаем значение рукопожатия направления связи контрольного примера
	const vector <uint8_t> sample = decode(TRAFFIC);
	// Проверяем схождение выведенного значения с контрольным примером
	ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0);
}

/**
 * Проверка вывода ключевого материала направления связи
 */
TEST(ScheduleTest, Material){
	// Получаем значение рукопожатия направления связи от сервера
	const vector <uint8_t> traffic = decode(TRAFFIC);
	// Метка назначения ключа направления связи
	const char * key = "key";
	// Место, в которое помещается выведенный ключ направления связи
	uint8_t result[schedule::SCHEDULE_SECRET];
	// Выполняем вывод ключа направления связи
	ASSERT_TRUE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (key), ::strlen(key)), view_t(nullptr, 0), result, sizeof(result)));
	// Получаем ключ направления связи контрольного примера
	const vector <uint8_t> sample = decode(KEY);
	// Проверяем схождение выведенного ключа с контрольным примером
	ASSERT_EQ(::memcmp(result, sample.data(), sample.size()), 0);
	// Метка назначения вектора замены направления связи
	const char * vector = "iv";
	// Получаем вектор замены направления связи контрольного примера
	const std::vector <uint8_t> replacement = decode(VECTOR);
	// Выполняем вывод вектора замены направления связи
	ASSERT_TRUE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (vector), ::strlen(vector)), view_t(nullptr, 0), result, replacement.size()));
	// Проверяем схождение выведенного вектора замены с контрольным примером
	ASSERT_EQ(::memcmp(result, replacement.data(), replacement.size()), 0);
	// Метка назначения ключа выработки завершения рукопожатия
	const char * finished = "finished";
	// Выполняем вывод ключа выработки завершения рукопожатия
	ASSERT_TRUE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (finished), ::strlen(finished)), view_t(nullptr, 0), result, sizeof(result)));
	// Получаем ключ выработки завершения рукопожатия контрольного примера
	const std::vector <uint8_t> sample2 = decode(FINISHED);
	// Проверяем схождение выведенного ключа с контрольным примером
	ASSERT_EQ(::memcmp(result, sample2.data(), sample2.size()), 0);
}

/**
 * Проверка растяжения значения длиннее хеша
 */
TEST(ScheduleTest, Expand){
	// Получаем значение рукопожатия направления связи от сервера
	const vector <uint8_t> traffic = decode(TRAFFIC);
	// Метка назначения растягиваемого значения
	const char * label = "key";
	// Место, в которое помещается растянутое значение
	uint8_t result[schedule::SCHEDULE_SECRET * 3];
	// Выполняем вывод значения длиной в три хеша
	ASSERT_TRUE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(nullptr, 0), result, sizeof(result)));
	// Место, в которое помещается укороченный вывод того же значения
	uint8_t sample[schedule::SCHEDULE_SECRET];
	// Выполняем вывод того же значения длиной в один хеш
	ASSERT_TRUE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(nullptr, 0), sample, sizeof(sample)));
	/**
	 * Требуемая длина входит в описание назначения, оттого выводы разной длины
	 * обязаны разойтись с самого первого байта
	 */
	ASSERT_NE(::memcmp(result, sample, sizeof(sample)), 0);
	// Проверяем отказ вывода значения без метки назначения
	ASSERT_FALSE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(nullptr, 0), view_t(nullptr, 0), sample, sizeof(sample)));
	// Проверяем отказ вывода значения нулевой длины
	ASSERT_FALSE(schedule::derive(view_t(traffic.data(), traffic.size()), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), view_t(nullptr, 0), sample, 0));
}
