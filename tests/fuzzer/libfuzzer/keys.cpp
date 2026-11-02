/**
 * @file keys.cpp
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
 * @brief Ворошитель контейнеров ключей с управлением от покрытия
 *
 * @note Каждый разбор получает новый итоговый объект: сведения, оставленные
 *       предыдущим кодеком, не должны менять поведение следующего
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <keys/keys.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Поверхность вызова ворошителя
 */
extern "C" {
	/**
	 * @brief Функция подачи недоверенной области байтов кодекам ключей
	 *
	 * @param data начало подаваемой области байтов
	 * @param size размер подаваемой области байтов
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Заводим просмотр подаваемой области байтов
		const view_t input(data, size);
		// Заводим просмотр пароля зашифрованных контейнеров
		const view_t password(reinterpret_cast <const uint8_t *> ("secret"), 6);
		// Разбираемый секретный ключ PrivateKeyInfo или OneAsymmetricKey
		keys::key_t privateKey;
		// Выполняем разбор PrivateKeyInfo и OneAsymmetricKey
		keys::decodePrivateKeyInfo(input, privateKey);
		// Разбираемый открытый ключ SubjectPublicKeyInfo
		keys::key_t publicKey;
		// Выполняем разбор SubjectPublicKeyInfo
		keys::decodeSubjectPublicKeyInfo(input, publicKey);
		// Разбираемый ключ EncryptedPrivateKeyInfo
		keys::key_t encryptedKey;
		// Выполняем разбор EncryptedPrivateKeyInfo
		keys::decodeEncryptedPrivateKeyInfo(input, password, encryptedKey);
		// Разбираемый ключ записи PKCS #12
		keys::key_t pkcs12Key;
		// Цепочка сертификатов записи PKCS #12
		std::vector <std::vector <uint8_t>> certificates;
		// Выполняем разбор записи PKCS #12
		keys::decodePkcs12(input, password, pkcs12Key, certificates);
		// Выводим код продолжения ворошения
		return 0;
	}
}
