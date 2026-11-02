/**
 * @file asn1.cpp
 * @date 2026-11-02
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
 * @brief Ворошитель записей ASN.1 с управлением от покрытия
 *
 * @note Глубина обхода ограничена намеренно: ворошитель проверяет вложенные записи,
 *       но не превращает злоумышленную вложенность в переполнение стека самой оснастки
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <asn1/asn1.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты ворошителя записей ASN.1
 */
namespace {
	/**
	 * @brief Функция обхода записи ASN.1 во всю её глубину
	 *
	 * @param reader разборщик обходимой записи ASN.1
	 * @param depth  глубина, на которой ведётся обход записи
	 *
	 */
	void walk(asn1::Reader & reader, const size_t depth) noexcept {
		// Если предельная глубина обхода записи превышена
		if(depth > 16)
			// Выходим из обхода записи ASN.1
			return;
		// Разбираемый элемент записи ASN.1
		asn1::element_t element;
		/**
		 * Выполняем перебор всех элементов записи ASN.1
		 */
		while(reader.next(element)){
			// Если элемент записи имеет составной вид метки
			if(element.constructed){
				// Заводим разборщик содержимого составного элемента
				asn1::Reader inner = reader.enter(element);
				// Выполняем обход содержимого составного элемента
				walk(inner, depth + 1);
			}
		}
	}
}

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщику ASN.1
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Заводим разборщик подаваемой записи ASN.1
		asn1::Reader reader(view_t(data, size));
		// Выполняем обход записи ASN.1 во всю её глубину
		walk(reader, 0);
		// Выводим код продолжения ворошения
		return 0;
	}
}
