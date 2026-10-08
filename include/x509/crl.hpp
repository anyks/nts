/**
 * @file crl.hpp
 * @date 2026-10-06
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
 * \~russian
 * @brief Заголовочный файл модуля списков отзыва сертификатов —
 *        разбор CertificateList по разделу 5 RFC 5280
 *
 * \~english
 * @brief Header file of the certificate revocation list module —
 *        parsing of a CertificateList according to the section 5 of RFC 5280
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <x509/x509.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 *
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей сертификатов X.509
	 *
	 * \~english
	 * @brief Namespace of the X.509 certificate modules
	 *
	 * \~
	 *
	 */
	namespace x509 {
		/**
		 * \~russian
		 * @brief Запись отозванного сертификата
		 *
		 * \~english
		 * @brief Entry of a revoked certificate
		 *
		 * \~
		 *
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Revoked {
			// Просмотр порядкового номера отозванного сертификата
			view_t serial;
			// Дата отзыва в секундах от начала эпохи
			int64_t date;
			// Набор расширений записи отзыва
			vector <extension_t> extensions;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 *
			 * \~english
			 * @brief Constructor
			 *
			 * \~
			 *
			 */
			Revoked() noexcept : date(0) {}
		} revoked_t;

		/**
		 * \~russian
		 * @brief Список отзыва сертификатов
		 *
		 * @details Разобранный список хранит просмотры внутрь разбираемой записи:
		 *          запись обязана пережить объект. Подпись списка проверяется
		 *          отдельным вызовом verify сведениями об открытом ключе издателя.
		 *
		 * \~english
		 * @brief Certificate revocation list
		 * @details The parsed list keeps views inside the encoding being parsed:
		 *          the encoding must outlive the object. The signature of the list is
		 *          checked by a separate call of verify with the public key info of the issuer.
		 *
		 * \~
		 *
		 */
		typedef class __ANTS_SHARED_EXPORT__ Revocations {
			private:
				// Причина последнего отказа
				error_t _error;
			private:
				// Просмотр записи списка целиком
				view_t _element;
				// Просмотр подписываемой части списка
				view_t _body;
			private:
				// Просмотр записи подписи
				view_t _signature;
				// Число неиспользуемых разрядов последнего байта подписи
				uint8_t _unused;
			private:
				// Опознаватель алгоритма подписи
				string _algorithm;
				// Просмотр записи настроек алгоритма подписи
				view_t _parameters;
			private:
				// Имя издателя списка
				name_t _issuer;
			private:
				// Дата выдачи списка в секундах от начала эпохи
				int64_t _thisUpdate;
				// Дата следующего списка в секундах от начала эпохи, ноль при её отсутствии
				int64_t _nextUpdate;
			private:
				// Набор записей отозванных сертификатов
				vector <revoked_t> _revoked;
				// Набор расширений списка
				vector <extension_t> _extensions;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора записи списка отзыва
				 *
				 * @param data просмотр разбираемой записи списка
				 * @return     причина отказа либо error_t::NONE
				 *
				 * @note Просмотры разобранных полей указывают внутрь переданной записи,
				 *       поэтому запись обязана пережить объект списка
				 *
				 * \~english
				 * @brief Method of parsing a revocation list encoding
				 * @param data the view of the revocation list encoding being parsed
				 * @return     the reason of the failure or error_t::NONE
				 *
				 * \~
				 */
				error_t parse(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод очистки разобранных сведений
				 *
				 * \~english
				 * @brief Method of clearing the parsed info
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод извлечения причины последнего отказа
				 *
				 * @return причина последнего отказа
				 *
				 * \~english
				 * @brief Method of getting the reason of the last failure
				 * @return the reason of the last failure
				 *
				 * \~
				 */
				error_t err() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписываемой части списка
				 *
				 * @return просмотр подписываемой части списка
				 *
				 * \~english
				 * @brief Method of getting the signed part of the list
				 * @return the view of the signed part of the list
				 *
				 * \~
				 */
				const view_t & body() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения подписи списка
				 *
				 * @param unused число неиспользуемых разрядов последнего байта подписи
				 * @return       просмотр записи подписи
				 *
				 * \~english
				 * @brief Method of getting the signature of the list
				 * @param unused the number of unused bits in the last byte of the signature
				 * @return       the view of the signature encoding
				 *
				 * \~
				 */
				const view_t & sign(uint8_t & unused) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения опознавателя алгоритма подписи
				 *
				 * @return опознаватель алгоритма подписи
				 *
				 * \~english
				 * @brief Method of getting the identifier of the signature algorithm
				 * @return the identifier of the signature algorithm
				 *
				 * \~
				 */
				const string & algorithms() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения записи настроек алгоритма подписи
				 *
				 * @return просмотр записи настроек либо пустой просмотр
				 *
				 * \~english
				 * @brief Method of getting the encoding of the parameters of the signature algorithm
				 * @return the view of the encoding of the parameters or an empty view
				 *
				 * \~
				 */
				const view_t & settings() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения имени издателя списка
				 *
				 * @return имя издателя списка
				 *
				 * \~english
				 * @brief Method of getting the name of the issuer of the list
				 * @return the name of the issuer of the list
				 *
				 * \~
				 */
				const name_t & issuers() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения дат списка
				 *
				 * @param thisUpdate дата выдачи списка в секундах от начала эпохи
				 * @param nextUpdate дата следующего списка в секундах от начала эпохи, ноль при её отсутствии
				 *
				 * \~english
				 * @brief Method of getting the dates of the list
				 * @param thisUpdate the date of the issuance of the list in seconds since the epoch
				 * @param nextUpdate the date of the next list in seconds since the epoch, zero at its absence
				 *
				 * \~
				 */
				void updates(int64_t & thisUpdate, int64_t & nextUpdate) const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора записей отозванных сертификатов
				 *
				 * @return набор записей отозванных сертификатов
				 *
				 * \~english
				 * @brief Method of getting the set of the entries of the revoked certificates
				 * @return the set of the entries of the revoked certificates
				 *
				 * \~
				 */
				const vector <revoked_t> & revoked() const noexcept;
				/**
				 * \~russian
				 * @brief Метод извлечения набора расширений списка
				 *
				 * @return набор расширений списка
				 *
				 * \~english
				 * @brief Method of getting the set of the extensions of the list
				 * @return the set of the extensions of the list
				 *
				 * \~
				 */
				const vector <extension_t> & extension() const noexcept;
				/**
				 * \~russian
				 * @brief Метод розыска расширения списка по опознавателю
				 *
				 * @param oid опознаватель разыскиваемого расширения
				 * @return    расширение списка либо nullptr
				 *
				 * \~english
				 * @brief Method of finding an extension of the list by its identifier
				 * @param oid the identifier of the extension being sought
				 * @return    the extension of the list or nullptr
				 *
				 * \~
				 */
				const extension_t * extension(const string & oid) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор списка отзыва
				 *
				 * \~english
				 * @brief Constructor of a revocation list
				 *
				 * \~
				 */
				Revocations() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Revocations() noexcept {}
		} crl_t;

		/**
		 * \~russian
		 * @brief Метод проверки подписи списка отзыва
		 *
		 * @param crl список, подпись которого проверяется
		 * @param key сведения об открытом ключе издателя списка
		 *
		 * @return    отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
		 *            непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
		 *
		 * \~english
		 * @brief Method of the check of the signature of a revocation list
		 * @param crl the list the signature of which is checked
		 * @param key the info of the public key of the issuer of the list
		 * @return    the failure of the check: NONE - the signature has converged, SIGNATURE - it has not or is
		 *            unsuitable, KEY - a key of a foreign algorithm, MEMORY - there was not enough memory
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ error_t verify(const crl_t & crl, const key_t & key) noexcept;
	};
};

