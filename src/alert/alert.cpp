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
 * @brief Исходный файл модуля извещений протокола TLS
 *
 * @section Намеренные решения
 *
 *  1. Неизвестное описание извещения отказом разбора не считается. Раздел 6 RFC 8446 велит
 *    принимать всякое описание и обходиться с неизвестным как со смертельным: отвергнув разбор,
 *    сторона лишила бы себя причины разрыва, о которой ей только что сообщили.
 *
 *  2. Уровень извещения разбирается как есть, даже неизвестный, а решение о разрыве связи
 *    принимается по описанию. Раздел 6 RFC 8446 объявляет уровень в издании TLS 1.3 не
 *    имеющим значения и дозволяет его пропускать: встречная сторона вправе прислать
 *    смертельный отказ под уровнем предупреждения либо под чужим уровнем, и поверив уровню,
 *    связь лишилась бы присланного ей описания. Составление своего извещения уровень сверяет.
 *
 *  3. Извещение длиной не в два байта отвергается, а не дочитывается. Раздел 5.1 RFC 8446
 *    запрещает и дробить извещение между записями, и слать в одной записи несколько:
 *    запись вида ALERT иной длины сложена не по правилам, и починить её нечем.
 *
 *  4. Название описания выводится из текста стандарта, а не переводится. Название и есть тот
 *    признак, по которому извещение сличается с журналом встречной стороны, а перевод у всякой
 *    стороны выйдет свой.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <alert/alert.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;
	/**
	 * Пространство имён модуля
	 */
	using namespace nts::alert;

	/**
	 * @brief Функция проверки известности уровня извещения
	 *
	 * @param level проверяемый уровень извещения
	 * @return      признак того, что уровень определён протоколом
	 *
	 */
	static constexpr bool __nts_suitable__(const level_t level) noexcept {
		/**
		 * Определяем уровень извещения
		 */
		switch(static_cast <uint8_t> (level)){
			// Если уровень извещения установлен как фатальная ошибка
			case static_cast <uint8_t> (level_t::FATAL):
			// Если уровень извещения установлен как предупреждение
			case static_cast <uint8_t> (level_t::WARNING):
				// Выводим признак известности уровня извещения
				return true;
		}
		// Выводим признак того, что уровень извещения неизвестен
		return false;
	}
};

/**
 * @brief Функция разбора извещения
 *
 * @param data   разбираемая область байтов
 * @param result извещение, в которое помещается итог разбора
 * @return       отказ разбора извещения
 *
 */
alert::error_t nts::alert::parse(const view_t & data, alert_t & result) noexcept {
	// Если разбираемая область байтов не передана
	if((data.data == nullptr) || (data.size < ALERT_LENGTH))
		// Выводим отказ о том, что данных для целого извещения не набралось
		return error_t::HUNGRY;
	// Если в области байтов лежит больше одного извещения
	if(data.size > ALERT_LENGTH)
		// Выводим отказ о длине извещения
		return error_t::LENGTH;
	// Получаем уровень извещения
	const level_t level = static_cast <level_t> (data.data[0]);
	/**
	 * Раздел 6 RFC 8446: уровень извещения в TLS 1.3 значения не имеет и может быть
	 * безопасно пропущен - неизвестный уровень присланного описания не отменяет
	 */
	// Устанавливаем уровень извещения
	result.level = level;
	// Устанавливаем описание извещения как оно прислано
	result.description = static_cast <description_t> (data.data[1]);
	// Выводим признак успешного разбора извещения
	return error_t::NONE;
}
/**
 * @brief Функция записи извещения
 *
 * @param alert  записываемое извещение
 * @param result место, в которое помещается записанное извещение
 * @return       отказ записи извещения
 *
 */
alert::error_t nts::alert::build(const alert_t & alert, uint8_t * result) noexcept {
	// Если место для записи извещения не передано
	if(result == nullptr)
		// Выводим отказ о непереданном месте записи
		return error_t::EMPTY;
	// Если уровень извещения протоколом не определён
	if(!::__nts_suitable__(alert.level))
		// Выводим отказ об уровне извещения
		return error_t::LEVEL;
	// Записываем уровень извещения
	result[0] = static_cast <uint8_t> (alert.level);
	// Записываем описание извещения
	result[1] = static_cast <uint8_t> (alert.description);
	// Выводим признак успешной записи извещения
	return error_t::NONE;
}
/**
 * @brief Функция проверки известности описания извещения
 *
 * @param description проверяемое описание извещения
 * @return            признак того, что описание определено протоколом
 *
 */
bool nts::alert::known(const description_t description) noexcept {
	/**
	 * Определяем описание извещения
	 */
	switch(static_cast <uint8_t> (description)){
		// Если извещение — проверка целостности записи не прошла (bad_record_mac)
		case static_cast <uint8_t> (description_t::MAC):
		// Если извещение — опознаватель заранее разделённого ключа неизвестен (unknown_psk_identity)
		case static_cast <uint8_t> (description_t::PSK):
		// Если извещение — запрошенное имя стороне неизвестно (unrecognized_name)
		case static_cast <uint8_t> (description_t::NAME):
		// Если извещение — сторона завершила передачу данных (close_notify)
		case static_cast <uint8_t> (description_t::CLOSE):
		// Если извещение — ответ о состоянии сертификата негоден либо сертификат отозван (bad_certificate_status_response)
		case static_cast <uint8_t> (description_t::STATUS):
		// Если извещение — доступ по предъявленной подлинности запрещён (access_denied)
		case static_cast <uint8_t> (description_t::ACCESS):
		// Если извещение — сообщение разобрать не удалось (decode_error)
		case static_cast <uint8_t> (description_t::DECODE):
		// Если извещение — проверка подписи или обмена ключами не прошла (decrypt_error)
		case static_cast <uint8_t> (description_t::DECRYPT):
		// Если извещение — издание протокола не поддерживается (protocol_version)
		case static_cast <uint8_t> (description_t::VERSION):
		// Если извещение — сертификат испорчен (bad_certificate)
		case static_cast <uint8_t> (description_t::BADCERT):
		// Если извещение — сертификат отозван издателем (certificate_revoked)
		case static_cast <uint8_t> (description_t::REVOKED):
		// Если извещение — срок действия сертификата истёк (certificate_expired)
		case static_cast <uint8_t> (description_t::EXPIRED):
		// Если извещение — обязательное расширение в сообщении отсутствует (missing_extension)
		case static_cast <uint8_t> (description_t::MISSING):
		// Если извещение — подлинность стороны обязательна, но не подтверждена (certificate_required)
		case static_cast <uint8_t> (description_t::REQUIRED):
		// Если извещение — ни один из предложенных протоколов не поддержан (no_application_protocol)
		case static_cast <uint8_t> (description_t::PROTOCOL):
		// Если извещение — годного сертификата у стороны не нашлось (no_certificate)
		case static_cast <uint8_t> (description_t::NOSIGNER):
		// Если извещение — длина записи превышает дозволенную (record_overflow)
		case static_cast <uint8_t> (description_t::OVERSIZE):
		// Если извещение — согласованные условия недостаточно стойки (insufficient_security)
		case static_cast <uint8_t> (description_t::SECURITY):
		// Если извещение — внутренний отказ, к встречной стороне не относящийся (internal_error)
		case static_cast <uint8_t> (description_t::INTERNAL):
		// Если извещение — сторона отступила к изданию ниже доступного (inappropriate_fallback)
		case static_cast <uint8_t> (description_t::FALLBACK):
		// Если извещение — рукопожатие прервано по причине вне протокола (user_canceled)
		case static_cast <uint8_t> (description_t::CANCELED):
		// Если извещение — значение поля вышло за дозволенные пределы (illegal_parameter)
		case static_cast <uint8_t> (description_t::PARAMETER):
		// Если извещение — издатель сертификата доверия не имеет (unknown_ca)
		case static_cast <uint8_t> (description_t::AUTHORITY):
		// Если извещение — согласовать условия связи не удалось (handshake_failure)
		case static_cast <uint8_t> (description_t::HANDSHAKE):
		// Если извещение — прислано расширение, о котором не просили (unsupported_extension)
		case static_cast <uint8_t> (description_t::EXTENSION):
		// Если извещение — получено сообщение не в свой черёд (unexpected_message)
		case static_cast <uint8_t> (description_t::UNEXPECTED):
		// Если извещение — расшифрование записи не удалось (decryption_failed)
		case static_cast <uint8_t> (description_t::DECRYPTION):
		// Если извещение — развёртывание сжатого содержимого не удалось (decompression_failure)
		case static_cast <uint8_t> (description_t::COMPRESSION):
		// Если извещение — вид сертификата не поддерживается (unsupported_certificate)
		case static_cast <uint8_t> (description_t::UNSUPPORTED):
		// Если извещение — сертификат отвергнут по неназванной причине (certificate_unknown)
		case static_cast <uint8_t> (description_t::UNKNOWNCERT):
		// Если извещение — зашифрованное приветствие ECH отвергнуто сервером, а клиент требует ECH (ech_required)
		case static_cast <uint8_t> (description_t::ECH_REQUIRED):
		// Если извещение — пересогласование связи не дозволено (no_renegotiation)
		case static_cast <uint8_t> (description_t::RENEGOTIATION):
			// Выводим признак известности описания извещения
			return true;
	}
	// Выводим признак того, что описание извещения неизвестно
	return false;
}
/**
 * @brief Функция проверки смертельности извещения
 *
 * @param alert проверяемое извещение
 * @return      признак того, что связь после извещения продолжена быть не вправе
 *
 */
bool nts::alert::fatal(const alert_t & alert) noexcept {
	/**
	 * Определяем описание извещения
	 */
	switch(static_cast <uint8_t> (alert.description)){
		// Если сторона завершила передачу данных (close_notify)
		case static_cast <uint8_t> (description_t::CLOSE):
		// Если сторона отменила рукопожатие (user_canceled)
		case static_cast <uint8_t> (description_t::CANCELED):
			// Выводим признак того, что извещение смертельным не является
			return false;
	}
	// Выводим признак смертельности извещения
	return true;
}
/**
 * @brief Функция проверки, объявлено ли описание извещения смертельным всегда
 *
 * @param description проверяемое описание
 * @return            признак описания, смертельного при любом уровне
 *
 */
bool nts::alert::grave(const description_t description) noexcept {
	/**
	 * Определяем описание извещения: перечень раздела 7.2.2 RFC 5246,
	 * раздела 8 RFC 6066, раздела 2 RFC 4279, раздела 3.2 RFC 7301 и раздела 3 RFC 7507
	 */
	switch(static_cast <uint8_t> (description)){
		// Если извещение — опознаватель заранее разделённого ключа неизвестен (unknown_psk_identity)
		case static_cast <uint8_t> (description_t::PSK):
		// Если извещение — проверка целостности записи не прошла (bad_record_mac)
		case static_cast <uint8_t> (description_t::MAC):
		// Если извещение — ответ о состоянии сертификата негоден либо сертификат отозван (bad_certificate_status_response)
		case static_cast <uint8_t> (description_t::STATUS):
		// Если извещение — доступ по предъявленной подлинности запрещён (access_denied)
		case static_cast <uint8_t> (description_t::ACCESS):
		// Если извещение — сообщение разобрать не удалось (decode_error)
		case static_cast <uint8_t> (description_t::DECODE):
		// Если извещение — издание протокола не поддерживается (protocol_version)
		case static_cast <uint8_t> (description_t::VERSION):
		// Если извещение — проверка подписи или обмена ключами не прошла (decrypt_error)
		case static_cast <uint8_t> (description_t::DECRYPT):
		// Если извещение — длина записи превышает дозволенную (record_overflow)
		case static_cast <uint8_t> (description_t::OVERSIZE):
		// Если извещение — ни один из предложенных протоколов не поддержан (no_application_protocol)
		case static_cast <uint8_t> (description_t::PROTOCOL):
		// Если извещение — согласованные условия недостаточно стойки (insufficient_security)
		case static_cast <uint8_t> (description_t::SECURITY):
		// Если извещение — внутренний отказ, к встречной стороне не относящийся (internal_error)
		case static_cast <uint8_t> (description_t::INTERNAL):
		// Если извещение — сторона отступила к изданию ниже доступного (inappropriate_fallback)
		case static_cast <uint8_t> (description_t::FALLBACK):
		// Если извещение — прислано расширение, о котором не просили (unsupported_extension)
		case static_cast <uint8_t> (description_t::EXTENSION):
		// Если извещение — согласовать условия связи не удалось (handshake_failure)
		case static_cast <uint8_t> (description_t::HANDSHAKE):
		// Если извещение — значение поля вышло за дозволенные пределы (illegal_parameter)
		case static_cast <uint8_t> (description_t::PARAMETER):
		// Если извещение — издатель сертификата доверия не имеет (unknown_ca)
		case static_cast <uint8_t> (description_t::AUTHORITY):
		// Если извещение — получено сообщение не в свой черёд (unexpected_message)
		case static_cast <uint8_t> (description_t::UNEXPECTED):
		// Если извещение — расшифрование записи не удалось (decryption_failed)
		case static_cast <uint8_t> (description_t::DECRYPTION):
		// Если извещение — развёртывание сжатого содержимого не удалось (decompression_failure)
		case static_cast <uint8_t> (description_t::COMPRESSION):
			// Выводим признак описания, смертельного всегда
			return true;
	}
	// Выводим признак описания, смертельность которого задаётся уровнем
	return false;
}
/**
 * @brief Функция получения названия описания извещения
 *
 * @param description описание извещения, название которого запрашивается
 * @return            название описания извещения из перечисления протокола
 *
 */
const char * nts::alert::name(const description_t description) noexcept {
	/**
	 * Определяем описание извещения
	 */
	switch(static_cast <uint8_t> (description)){
		// Если проверка целостности записи не прошла
		case static_cast <uint8_t> (description_t::MAC):
			// Выводим название bad_record_mac
			return "bad_record_mac";
		// Если опознаватель заранее разделённого ключа неизвестен
		case static_cast <uint8_t> (description_t::PSK):
			// Выводим название unknown_psk_identity
			return "unknown_psk_identity";
		// Если запрошенное имя стороне неизвестно
		case static_cast <uint8_t> (description_t::NAME):
			// Выводим название unrecognized_name
			return "unrecognized_name";
		// Если сторона завершила передачу данных
		case static_cast <uint8_t> (description_t::CLOSE):
			// Выводим название close_notify
			return "close_notify";
		// Если ответ о состоянии сертификата негоден либо сертификат отозван
		case static_cast <uint8_t> (description_t::STATUS):
			// Выводим название bad_certificate_status_response
			return "bad_certificate_status_response";
		// Если сообщение разобрать не удалось
		case static_cast <uint8_t> (description_t::DECODE):
			// Выводим название decode_error
			return "decode_error";
		// Если доступ по предъявленной подлинности запрещён
		case static_cast <uint8_t> (description_t::ACCESS):
			// Выводим название access_denied
			return "access_denied";
		// Если сертификат отозван издателем
		case static_cast <uint8_t> (description_t::REVOKED):
			// Выводим название certificate_revoked
			return "certificate_revoked";
		// Если срок действия сертификата истёк
		case static_cast <uint8_t> (description_t::EXPIRED):
			// Выводим название certificate_expired
			return "certificate_expired";
		// Если проверка подписи или обмена ключами не прошла
		case static_cast <uint8_t> (description_t::DECRYPT):
			// Выводим название decrypt_error
			return "decrypt_error";
		// Если издание протокола не поддерживается
		case static_cast <uint8_t> (description_t::VERSION):
			// Выводим название protocol_version
			return "protocol_version";
		// Если сертификат испорчен
		case static_cast <uint8_t> (description_t::BADCERT):
			// Выводим название bad_certificate
			return "bad_certificate";
		// Если обязательное расширение в сообщении отсутствует
		case static_cast <uint8_t> (description_t::MISSING):
			// Выводим название missing_extension
			return "missing_extension";
		// Если согласованные условия недостаточно стойки
		case static_cast <uint8_t> (description_t::SECURITY):
			// Выводим название insufficient_security
			return "insufficient_security";
		// Если это внутренний отказ, к встречной стороне не относящийся
		case static_cast <uint8_t> (description_t::INTERNAL):
			// Выводим название internal_error
			return "internal_error";
		// Если годного сертификата у стороны не нашлось
		case static_cast <uint8_t> (description_t::NOSIGNER):
			// Выводим название no_certificate_RESERVED
			return "no_certificate_RESERVED";
		// Если ни один из предложенных протоколов не поддержан
		case static_cast <uint8_t> (description_t::PROTOCOL):
			// Выводим название no_application_protocol
			return "no_application_protocol";
		// Если подлинность стороны обязательна, но не подтверждена
		case static_cast <uint8_t> (description_t::REQUIRED):
			// Выводим название certificate_required
			return "certificate_required";
		// Если длина записи превышает дозволенную
		case static_cast <uint8_t> (description_t::OVERSIZE):
			// Выводим название record_overflow
			return "record_overflow";
		// Если сторона отступила к изданию ниже доступного
		case static_cast <uint8_t> (description_t::FALLBACK):
			// Выводим название inappropriate_fallback
			return "inappropriate_fallback";
		// Если рукопожатие прервано по причине вне протокола
		case static_cast <uint8_t> (description_t::CANCELED):
			// Выводим название user_canceled
			return "user_canceled";
		// Если значение поля вышло за дозволенные пределы
		case static_cast <uint8_t> (description_t::PARAMETER):
			// Выводим название illegal_parameter
			return "illegal_parameter";
		// Если согласовать условия связи не удалось
		case static_cast <uint8_t> (description_t::HANDSHAKE):
			// Выводим название handshake_failure
			return "handshake_failure";
		// Если издатель сертификата доверия не имеет
		case static_cast <uint8_t> (description_t::AUTHORITY):
			// Выводим название unknown_ca
			return "unknown_ca";
		// Если прислано расширение, о котором не просили
		case static_cast <uint8_t> (description_t::EXTENSION):
			// Выводим название unsupported_extension
			return "unsupported_extension";
		// Если получено сообщение не в свой черёд
		case static_cast <uint8_t> (description_t::UNEXPECTED):
			// Выводим название unexpected_message
			return "unexpected_message";
		// Если расшифрование записи не удалось
		case static_cast <uint8_t> (description_t::DECRYPTION):
			// Выводим название decryption_failed_RESERVED
			return "decryption_failed_RESERVED";
		// Если сертификат отвергнут по неназванной причине
		case static_cast <uint8_t> (description_t::UNKNOWNCERT):
			// Выводим название certificate_unknown
			return "certificate_unknown";
		// Если развёртывание сжатого содержимого не удалось
		case static_cast <uint8_t> (description_t::COMPRESSION):
			// Выводим название decompression_failure_RESERVED
			return "decompression_failure_RESERVED";
		// Если вид сертификата не поддерживается
		case static_cast <uint8_t> (description_t::UNSUPPORTED):
			// Выводим название unsupported_certificate
			return "unsupported_certificate";
		// Если зашифрованное приветствие ECH отвергнуто сервером, а клиент требует ECH
		case static_cast <uint8_t> (description_t::ECH_REQUIRED):
			// Выводим название ech_required
			return "ech_required";
		// Если пересогласование связи не дозволено
		case static_cast <uint8_t> (description_t::RENEGOTIATION):
			// Выводим название no_renegotiation
			return "no_renegotiation";
	}
	// Выводим название неизвестного описания извещения
	return "unknown_alert";
}
/**
 * @brief Конструктор
 *
 */
nts::alert::Alert::Alert() noexcept : level(level_t::NONE), description(description_t::INTERNAL) {}
/**
 * @brief Конструктор
 *
 * @param level       уровень извещения
 * @param description описание извещения
 *
 */
nts::alert::Alert::Alert(const level_t level, const description_t description) noexcept : level(level), description(description) {}
