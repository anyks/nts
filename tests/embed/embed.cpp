/**
 * @file embed.cpp
 * @date 2026-09-16
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
 * @brief Файл проверок модуля вывода ключа для зашивания в образ
 *
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <embed/embed.hpp>
#include <digest/hash.hpp>
#include <digest/hkdf.hpp>
#include <digest/argon2.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * Метка области вывода из материала — повторяет константу модуля для золотого пина формата
 */
static const std::vector <uint8_t> LABEL_KEY = {'A', '-', 'N', 'T', 'S', ' ', 'e', 'm', 'b', 'e', 'd', ' ', 'k', 'e', 'y'};

/**
 * @brief Сборка буфера связки так же, как это делает модуль: метка, версия восемью октетами
 *        старшим байтом вперёд, затем связка
 *
 */
static std::vector <uint8_t> woven(const std::vector <uint8_t> & label, const uint64_t version, const std::vector <uint8_t> & context){
	// Собираемый буфер
	std::vector <uint8_t> result(label.begin(), label.end());
	/**
	 * Кладём версию старшим байтом вперёд
	 */
	for(size_t i = 8; i > 0; i--){
		// Очередной байт версии со сдвигом (i - 1) * 8 — старший байт вперёд
		result.push_back(static_cast <uint8_t> ((version >> ((i - 1) * 8)) & 0xFF));
	}
	// Кладём связку
	result.insert(result.end(), context.begin(), context.end());
	// Выводим буфер
	return result;
}

/**
 * @brief Проверка: вывод из материала детерминирован — закладка и запуск совпадают побайтно
 *
 */
TEST(EmbedTest, KeyDeterministic){
	// Материал, соль и связка
	const std::vector <uint8_t> material = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
	// Соль вывода ключа
	const std::vector <uint8_t> salt = {0xDE, 0xAD, 0xBE, 0xEF};
	// Связка привязки к образу
	const std::vector <uint8_t> context = {0x01, 0x02, 0x03, 0x04};
	// Два приёмника ключа
	uint8_t first[48], second[48];
	// Выводим ключ дважды при равных входах
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 7, first, sizeof(first)));
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 7, second, sizeof(second)));
	// Оба вывода обязаны совпадать побайтно
	ASSERT_EQ(::memcmp(first, second, sizeof(first)), 0);
}

/**
 * @brief Золотой пин формата: вывод модуля обязан совпадать с прямым HKDF по тем же байтам info.
 *        Пин фиксирует формат вплетения метки, версии и связки — переработка обязана совпасть
 *
 */
TEST(EmbedTest, KeyMatchesRawHkdf){
	// Материал, соль и связка
	const std::vector <uint8_t> material = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	// Соль независимого вывода
	const std::vector <uint8_t> salt = {0xA0, 0xA1, 0xA2, 0xA3};
	// Связка привязки к образу
	const std::vector <uint8_t> context = {0xC0, 0xC1};
	// Версия ключа
	const uint64_t version = 0x0102030405060708ULL;
	// Вывод модуля
	uint8_t mine[40];
	// Вывод ключа модулем
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), version, mine, sizeof(mine)));
	/**
	 * Независимый вывод: извлечение над материалом с солью, затем расширение по собранной info
	 */
	uint8_t prk[32];
	// Извлечение псевдослучайного ключа HKDF-Extract над материалом с солью
	ASSERT_TRUE(digest::extract(digest::hash_t::SHA256, view_t(salt.data(), salt.size()), view_t(material.data(), material.size()), prk, sizeof(prk)));
	// Собираем info так же, как модуль
	const std::vector <uint8_t> info = woven(LABEL_KEY, version, context);
	// Независимый ключ
	uint8_t theirs[40];
	// Расширение HKDF-Expand по собранной info
	ASSERT_TRUE(digest::expand(digest::hash_t::SHA256, view_t(prk, sizeof(prk)), view_t(info.data(), info.size()), theirs, sizeof(theirs)));
	// Оба обязаны совпасть побайтно
	ASSERT_EQ(::memcmp(mine, theirs, sizeof(mine)), 0);
}

/**
 * @brief Проверка: смена версии ключа меняет вывод — отладочная и боевая сборки расходятся
 *
 */
TEST(EmbedTest, KeyVersionDiverges){
	// Материал, соль и связка
	const std::vector <uint8_t> material = {0x11, 0x22, 0x33, 0x44};
	// Соль вывода ключа
	const std::vector <uint8_t> salt = {0x55, 0x66};
	// Связка привязки к образу
	const std::vector <uint8_t> context = {0x77};
	// Приёмники для двух версий
	uint8_t va[32], vb[32];
	// Вывод ключа первой версии
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 1, va, sizeof(va)));
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 2, vb, sizeof(vb)));
	// Ключи разных версий обязаны различаться
	ASSERT_NE(::memcmp(va, vb, sizeof(va)), 0);
}

/**
 * @brief Проверка: смена связки привязки к образу меняет вывод — патч участка ломает ключ
 *
 */
TEST(EmbedTest, KeyContextDiverges){
	// Материал и соль
	const std::vector <uint8_t> material = {0x11, 0x22, 0x33, 0x44};
	// Общая соль обоих выводов
	const std::vector <uint8_t> salt = {0x55, 0x66};
	// Две разные связки — например две контрольные суммы участка
	const std::vector <uint8_t> ca = {0xAA, 0xBB};
	// Вторая связка: младший байт на единицу больше
	const std::vector <uint8_t> cb = {0xAA, 0xBC};
	// Приёмники
	uint8_t ka[32], kb[32];
	// Вывод ключа с первой связкой
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(ca.data(), ca.size()), 1, ka, sizeof(ka)));
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(salt.data(), salt.size()), view_t(cb.data(), cb.size()), 1, kb, sizeof(kb)));
	// Ключи при разной привязке обязаны различаться
	ASSERT_NE(::memcmp(ka, kb, sizeof(ka)), 0);
}

/**
 * @brief Проверка: выведенный ключ не равен исходному материалу — ключ выводится, а не хранится
 *
 */
TEST(EmbedTest, KeyNotMaterial){
	// Материал в тридцать два октета
	std::vector <uint8_t> material(32);
	/**
	 * Заполняем материал возрастающими байтами 1..32
	 */
	for(size_t i = 0; i < material.size(); i++){
		// Очередной байт материала равен его смещению плюс один
		material[i] = static_cast <uint8_t> (i + 1);
	}
	// Приёмник равной длины
	uint8_t derived[32];
	// Вывод ключа без соли и связки
	ASSERT_TRUE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(), view_t(), 1, derived, sizeof(derived)));
	// Вывод обязан отличаться от материала
	ASSERT_NE(::memcmp(derived, material.data(), sizeof(derived)), 0);
}

/**
 * @brief Проверка: негодные входы вывода из материала дают отказ, а не ключ
 *
 */
TEST(EmbedTest, KeyRejectsBadInput){
	// Годный материал
	const std::vector <uint8_t> material = {0x11, 0x22, 0x33, 0x44};
	// Приёмник
	uint8_t out[32];
	// Неизвестный хеш — отказ
	ASSERT_FALSE(embed::key(digest::hash_t::NONE, view_t(material.data(), material.size()), view_t(), view_t(), 1, out, sizeof(out)));
	// Пустой материал — отказ
	ASSERT_FALSE(embed::key(digest::hash_t::SHA256, view_t(), view_t(), view_t(), 1, out, sizeof(out)));
	// Отсутствующий приёмник — отказ
	ASSERT_FALSE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(), view_t(), 1, nullptr, sizeof(out)));
	// Нулевой размер приёмника — отказ
	ASSERT_FALSE(embed::key(digest::hash_t::SHA256, view_t(material.data(), material.size()), view_t(), view_t(), 1, out, 0));
}

/**
 * @brief Проверка: растяжение пароля детерминировано и вплетает версию
 *
 */
TEST(EmbedTest, SecretDeterministicAndVersioned){
	// Лёгкие параметры Argon2id для скорости проверки
	const digest::argon_params_t params(digest::argon_t::ARGON2ID, 64, 1, 1);
	// Пароль и соль (соль не короче восьми октетов)
	const std::vector <uint8_t> password = {'s', 'e', 'c', 'r', 'e', 't'};
	// Соль растяжения (не короче восьми октетов)
	const std::vector <uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	// Связка привязки к образу
	const std::vector <uint8_t> context = {0x09};
	// Два приёмника при равных входах
	uint8_t first[32], second[32];
	// Растяжение пароля первым приёмником
	ASSERT_TRUE(embed::secret(params, view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 5, first, sizeof(first)));
	ASSERT_TRUE(embed::secret(params, view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 5, second, sizeof(second)));
	// Оба вывода при равных входах совпадают
	ASSERT_EQ(::memcmp(first, second, sizeof(first)), 0);
	// Иная версия — иной ключ
	uint8_t other[32];
	// Растяжение того же пароля с иной версией
	ASSERT_TRUE(embed::secret(params, view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(context.data(), context.size()), 6, other, sizeof(other)));
	// Ключи разных версий обязаны различаться
	ASSERT_NE(::memcmp(first, other, sizeof(first)), 0);
}

/**
 * @brief Проверка: негодные входы растяжения пароля дают отказ
 *
 */
TEST(EmbedTest, SecretRejectsBadInput){
	// Лёгкие параметры
	const digest::argon_params_t params(digest::argon_t::ARGON2ID, 64, 1, 1);
	// Пароль и соль
	const std::vector <uint8_t> password = {'p', 'w'};
	// Соль растяжения
	const std::vector <uint8_t> salt = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	// Приёмник
	uint8_t out[32];
	// Отсутствующий приёмник — отказ
	ASSERT_FALSE(embed::secret(params, view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(), 1, nullptr, sizeof(out)));
	// Слишком короткая метка (меньше четырёх октетов) — отказ
	ASSERT_FALSE(embed::secret(params, view_t(password.data(), password.size()), view_t(salt.data(), salt.size()), view_t(), 1, out, 3));
}
