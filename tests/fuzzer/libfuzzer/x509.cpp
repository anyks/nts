/**
 * @file x509.cpp
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
 * @brief Ворошитель записей инфраструктуры сертификатов с управлением от покрытия
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
#include <x509/x509.hpp>
#include <x509/crl.hpp>
#include <x509/request.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов разборщикам X.509
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Заводим просмотр подаваемой области байтов
		const view_t input(data, size);
		// Разбираемый сертификат стороны связи
		x509::certificate_t certificate;
		// Выполняем разбор сертификата стороны связи
		certificate.parse(input);
		// Разбираемый запрос на сертификат стороны связи
		x509::request_t request;
		// Выполняем разбор запроса на сертификат стороны связи
		request.parse(input);
		// Разбираемый список отозванных сертификатов
		x509::crl_t crl;
		// Выполняем разбор списка отозванных сертификатов
		crl.parse(input);
		// Выводим код продолжения ворошения
		return 0;
	}
}
