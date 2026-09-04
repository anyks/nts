/**
 * @file alert.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл проверок модуля извещений протокола TLS
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <alert/alert.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Проверка записи и разбора извещения
 */
TEST(AlertTest, Build){
	// Место для записи извещения
	uint8_t buffer[alert::ALERT_LENGTH] = {0};
	// Составляем извещение о завершении передачи данных
	const alert::alert_t alert(alert::level_t::WARNING, alert::description_t::CLOSE);
	// Выполняем запись извещения
	ASSERT_EQ(alert::build(alert, buffer), alert::error_t::NONE);
	// Проверяем уровень записанного извещения
	ASSERT_EQ(buffer[0], 1);
	// Проверяем описание записанного извещения
	ASSERT_EQ(buffer[1], 0);
	// Разобранное извещение
	alert::alert_t result;
	// Выполняем разбор записанного извещения
	ASSERT_EQ(alert::parse(view_t(buffer, sizeof(buffer)), result), alert::error_t::NONE);
	// Проверяем уровень разобранного извещения
	ASSERT_EQ(result.level, alert::level_t::WARNING);
	// Проверяем описание разобранного извещения
	ASSERT_EQ(result.description, alert::description_t::CLOSE);
}

/**
 * Проверка отвержения испорченного извещения
 */
TEST(AlertTest, Reject){
	// Разобранное извещение
	alert::alert_t result;
	// Извещение, у которого пришёл только уровень
	const uint8_t part[1] = {0x02};
	// Проверяем отказ разбора неполного извещения
	ASSERT_EQ(alert::parse(view_t(part, sizeof(part)), result), alert::error_t::HUNGRY);
	// Проверяем отказ разбора непереданной области байтов
	ASSERT_EQ(alert::parse(view_t(), result), alert::error_t::HUNGRY);
	// Два извещения, сложенные в одну запись
	const uint8_t pair[4] = {0x02, 0x28, 0x02, 0x28};
	// Проверяем отказ разбора записи с двумя извещениями
	ASSERT_EQ(alert::parse(view_t(pair, sizeof(pair)), result), alert::error_t::LENGTH);
	// Извещение с уровнем, протоколом не определённым
	const uint8_t level[2] = {0x03, 0x28};
	// Проверяем отказ разбора извещения с неизвестным уровнем
	ASSERT_EQ(alert::parse(view_t(level, sizeof(level)), result), alert::error_t::NONE);
	/**
	 * Раздел 6 RFC 8446: уровень извещения значения не имеет и пропускается, а
	 * описание принимается как есть
	 */
	ASSERT_EQ(result.description, static_cast <alert::description_t> (0x28));
	// Место для записи извещения
	uint8_t buffer[alert::ALERT_LENGTH] = {0};
	// Проверяем отказ записи извещения с неустановленным уровнем
	ASSERT_EQ(alert::build(alert::alert_t(), buffer), alert::error_t::LEVEL);
	// Проверяем отказ записи извещения в непереданное место
	ASSERT_EQ(alert::build(alert::alert_t(alert::level_t::FATAL, alert::description_t::INTERNAL), nullptr), alert::error_t::EMPTY);
}

/**
 * Проверка приёма извещения с неизвестным описанием
 */
TEST(AlertTest, Unknown){
	// Разобранное извещение
	alert::alert_t result;
	// Извещение с описанием, протоколом не определённым
	const uint8_t buffer[2] = {0x02, 0xFF};
	// Проверяем, что неизвестное описание разбору не мешает
	ASSERT_EQ(alert::parse(view_t(buffer, sizeof(buffer)), result), alert::error_t::NONE);
	// Проверяем, что описание сохранено как оно прислано
	ASSERT_EQ(static_cast <uint8_t> (result.description), 0xFF);
	// Проверяем, что описание известным не считается
	ASSERT_FALSE(alert::known(result.description));
	// Проверяем, что неизвестное описание считается смертельным
	ASSERT_TRUE(alert::fatal(result));
	// Проверяем название неизвестного описания
	ASSERT_STREQ(alert::name(result.description), "unknown_alert");
}

/**
 * Проверка решения о разрыве связи
 */
TEST(AlertTest, Fatal){
	// Проверяем, что завершение передачи связь не рвёт
	ASSERT_FALSE(alert::fatal(alert::alert_t(alert::level_t::WARNING, alert::description_t::CLOSE)));
	// Проверяем, что отмена рукопожатия связь не рвёт
	ASSERT_FALSE(alert::fatal(alert::alert_t(alert::level_t::WARNING, alert::description_t::CANCELED)));
	// Проверяем, что уровень предупреждения смертельного отказа не отменяет
	ASSERT_TRUE(alert::fatal(alert::alert_t(alert::level_t::WARNING, alert::description_t::MAC)));
	// Проверяем, что уровень смертельного отказа завершение передачи смертельным не делает
	ASSERT_FALSE(alert::fatal(alert::alert_t(alert::level_t::FATAL, alert::description_t::CLOSE)));
	// Проверяем смертельность отказа согласования условий связи
	ASSERT_TRUE(alert::fatal(alert::alert_t(alert::level_t::FATAL, alert::description_t::HANDSHAKE)));
}

/**
 * Проверка известности и названий описаний извещения
 */
TEST(AlertTest, Names){
	// Набор описаний извещения, определённых протоколом
	const alert::description_t descriptions[] = {
		alert::description_t::CLOSE, alert::description_t::UNEXPECTED,
		alert::description_t::MAC, alert::description_t::DECRYPTION,
		alert::description_t::OVERSIZE, alert::description_t::COMPRESSION,
		alert::description_t::HANDSHAKE, alert::description_t::NOSIGNER,
		alert::description_t::BADCERT, alert::description_t::UNSUPPORTED,
		alert::description_t::REVOKED, alert::description_t::EXPIRED,
		alert::description_t::UNKNOWNCERT, alert::description_t::PARAMETER,
		alert::description_t::AUTHORITY, alert::description_t::ACCESS,
		alert::description_t::DECODE, alert::description_t::DECRYPT,
		alert::description_t::VERSION, alert::description_t::SECURITY,
		alert::description_t::INTERNAL, alert::description_t::FALLBACK,
		alert::description_t::CANCELED, alert::description_t::MISSING,
		alert::description_t::EXTENSION, alert::description_t::NAME,
		alert::description_t::PSK, alert::description_t::REQUIRED,
		alert::description_t::PROTOCOL
	};
	/**
	 * Выполняем перебор описаний извещения
	 */
	for(size_t i = 0; i < (sizeof(descriptions) / sizeof(descriptions[0])); i++){
		// Проверяем известность описания извещения
		ASSERT_TRUE(alert::known(descriptions[i]));
		// Проверяем, что у описания извещения есть название
		ASSERT_STRNE(alert::name(descriptions[i]), "unknown_alert");
	}
	// Проверяем название описания завершения передачи данных
	ASSERT_STREQ(alert::name(alert::description_t::CLOSE), "close_notify");
	// Проверяем название описания отказа проверки целостности записи
	ASSERT_STREQ(alert::name(alert::description_t::MAC), "bad_record_mac");
	// Проверяем название описания обязательной, но не подтверждённой подлинности
	ASSERT_STREQ(alert::name(alert::description_t::REQUIRED), "certificate_required");
}
