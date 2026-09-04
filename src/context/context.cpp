/**
 * @file context.cpp
 * @date 2026-08-31
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
 * @brief Исходный файл общих объявлений фасадов связи
 *
 * @note Заголовочный файл модуля несёт одни объявления: перечисления отказов и
 *       состояний связи, да две записи под подлинность стороны и билет
 *       возобновления. Исходный файл нужен единственно затем, чтобы приведение
 *       билета к началу не лежало в заголовочном файле: правило это общее для всех
 *       модулей библиотеки, и запись, у которой тело всего одно, изъятия не
 *       заслуживает
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <context/context.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Конструктор
 *
 */
nts::context::Ticket::Ticket() noexcept :
	suite(protect::suite_t::NONE), moment(0), lifetime(0), advance(0), age(0) {}
