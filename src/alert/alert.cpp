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
 * 1. Неизвестное описание извещения отказом разбора не считается. Раздел 6 RFC 8446 велит
 *    принимать всякое описание и обходиться с неизвестным как со смертельным: отвергнув разбор,
 *    сторона лишила бы себя причины разрыва, о которой ей только что сообщили.
 *
 * 2. Уровень извещения разбирается как есть, даже неизвестный, а решение о разрыве связи
 *    принимается по описанию. Раздел 6 RFC 8446 объявляет уровень в издании TLS 1.3 не
 *    имеющим значения и дозволяет его пропускать: встречная сторона вправе прислать
 *    смертельный отказ под уровнем предупреждения либо под чужим уровнем, и поверив уровню,
 *    связь лишилась бы присланного ей описания. Составление своего извещения уровень сверяет.
 *
 * 3. Извещение длиной не в два байта отвергается, а не дочитывается. Раздел 5.1 RFC 8446
 *    запрещает и дробить извещение между записями, и слать в одной записи несколько:
 *    запись вида ALERT иной длины сложена не по правилам, и починить её нечем.
 *
 * 4. Название описания выводится из текста стандарта, а не переводится. Название и есть тот
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
	 * @brief Метод проверки известности уровня извещения
	 *
	 * @param level проверяемый уровень извещения
	 *
	 * @return      признак того, что уровень определён протоколом
	 *
	 */
	static bool suitable(const level_t level) noexcept {
		/**
		 * Выполняем определение уровня извещения
		 */
		switch(static_cast <uint8_t> (level)){
			// Если это один из известных уровней извещения
			case static_cast <uint8_t> (level_t::WARNING):
			case static_cast <uint8_t> (level_t::FATAL):
				// Выводим признак известности уровня извещения
				return true;
		}
		// Выводим признак того, что уровень извещения неизвестен
		return false;
	}
};

/**
 * @brief Метод разбора извещения
 *
 * @param data   разбираемая область байтов
 * @param result извещение, в которое помещается итог разбора
 *
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
 * @brief Метод записи извещения
 *
 * @param alert  записываемое извещение
 * @param result место, в которое помещается записанное извещение
 *
 * @return       отказ записи извещения
 *
 */
alert::error_t nts::alert::build(const alert_t & alert, uint8_t * result) noexcept {
	// Если место для записи извещения не передано
	if(result == nullptr)
		// Выводим отказ о непереданном месте записи
		return error_t::EMPTY;
	// Если уровень извещения протоколом не определён
	if(!suitable(alert.level))
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
 * @brief Метод проверки известности описания извещения
 *
 * @param description проверяемое описание извещения
 *
 * @return            признак того, что описание определено протоколом
 *
 */
bool nts::alert::known(const description_t description) noexcept {
	/**
	 * Выполняем определение описания извещения
	 */
	switch(static_cast <uint8_t> (description)){
		// Если это одно из известных описаний извещения
		case static_cast <uint8_t> (description_t::CLOSE):
		case static_cast <uint8_t> (description_t::UNEXPECTED):
		case static_cast <uint8_t> (description_t::MAC):
		case static_cast <uint8_t> (description_t::DECRYPTION):
		case static_cast <uint8_t> (description_t::OVERSIZE):
		case static_cast <uint8_t> (description_t::COMPRESSION):
		case static_cast <uint8_t> (description_t::HANDSHAKE):
		case static_cast <uint8_t> (description_t::NOSIGNER):
		case static_cast <uint8_t> (description_t::BADCERT):
		case static_cast <uint8_t> (description_t::UNSUPPORTED):
		case static_cast <uint8_t> (description_t::REVOKED):
		case static_cast <uint8_t> (description_t::EXPIRED):
		case static_cast <uint8_t> (description_t::UNKNOWNCERT):
		case static_cast <uint8_t> (description_t::PARAMETER):
		case static_cast <uint8_t> (description_t::AUTHORITY):
		case static_cast <uint8_t> (description_t::ACCESS):
		case static_cast <uint8_t> (description_t::DECODE):
		case static_cast <uint8_t> (description_t::DECRYPT):
		case static_cast <uint8_t> (description_t::VERSION):
		case static_cast <uint8_t> (description_t::SECURITY):
		case static_cast <uint8_t> (description_t::INTERNAL):
		case static_cast <uint8_t> (description_t::FALLBACK):
		case static_cast <uint8_t> (description_t::CANCELED):
		case static_cast <uint8_t> (description_t::MISSING):
		case static_cast <uint8_t> (description_t::EXTENSION):
		case static_cast <uint8_t> (description_t::NAME):
		case static_cast <uint8_t> (description_t::STATUS):
		case static_cast <uint8_t> (description_t::PSK):
		case static_cast <uint8_t> (description_t::REQUIRED):
		case static_cast <uint8_t> (description_t::PROTOCOL):
			// Выводим признак известности описания извещения
			return true;
	}
	// Выводим признак того, что описание извещения неизвестно
	return false;
}
/**
 * @brief Метод проверки смертельности извещения
 *
 * @param alert проверяемое извещение
 *
 * @return      признак того, что связь после извещения продолжена быть не вправе
 *
 */
bool nts::alert::fatal(const alert_t & alert) noexcept {
	/**
	 * Выполняем определение описания извещения
	 */
	switch(static_cast <uint8_t> (alert.description)){
		// Если сторона завершила передачу данных либо отменила рукопожатие
		case static_cast <uint8_t> (description_t::CLOSE):
		case static_cast <uint8_t> (description_t::CANCELED):
			// Выводим признак того, что извещение смертельным не является
			return false;
	}
	// Выводим признак смертельности извещения
	return true;
}
/**
 * @brief Метод получения названия описания извещения
 *
 * @param description описание извещения, название которого запрашивается
 *
 * @return            название описания извещения из перечисления протокола
 *
 */
const char * nts::alert::name(const description_t description) noexcept {
	/**
	 * Выполняем определение описания извещения
	 */
	switch(static_cast <uint8_t> (description)){
		// Если сторона завершила передачу данных
		case static_cast <uint8_t> (description_t::CLOSE): return "close_notify";
		// Если получено сообщение не в свой черёд
		case static_cast <uint8_t> (description_t::UNEXPECTED): return "unexpected_message";
		// Если проверка целостности записи не прошла
		case static_cast <uint8_t> (description_t::MAC): return "bad_record_mac";
		// Если расшифрование записи не удалось
		case static_cast <uint8_t> (description_t::DECRYPTION): return "decryption_failed_RESERVED";
		// Если длина записи превышает дозволенную
		case static_cast <uint8_t> (description_t::OVERSIZE): return "record_overflow";
		// Если развёртывание сжатого содержимого не удалось
		case static_cast <uint8_t> (description_t::COMPRESSION): return "decompression_failure_RESERVED";
		// Если согласовать условия связи не удалось
		case static_cast <uint8_t> (description_t::HANDSHAKE): return "handshake_failure";
		// Если годного сертификата у стороны не нашлось
		case static_cast <uint8_t> (description_t::NOSIGNER): return "no_certificate_RESERVED";
		// Если сертификат испорчен
		case static_cast <uint8_t> (description_t::BADCERT): return "bad_certificate";
		// Если вид сертификата не поддерживается
		case static_cast <uint8_t> (description_t::UNSUPPORTED): return "unsupported_certificate";
		// Если сертификат отозван издателем
		case static_cast <uint8_t> (description_t::REVOKED): return "certificate_revoked";
		// Если срок действия сертификата истёк
		case static_cast <uint8_t> (description_t::EXPIRED): return "certificate_expired";
		// Если сертификат отвергнут по неназванной причине
		case static_cast <uint8_t> (description_t::UNKNOWNCERT): return "certificate_unknown";
		// Если значение поля вышло за дозволенные пределы
		case static_cast <uint8_t> (description_t::PARAMETER): return "illegal_parameter";
		// Если издатель сертификата доверия не имеет
		case static_cast <uint8_t> (description_t::AUTHORITY): return "unknown_ca";
		// Если доступ по предъявленной подлинности запрещён
		case static_cast <uint8_t> (description_t::ACCESS): return "access_denied";
		// Если сообщение разобрать не удалось
		case static_cast <uint8_t> (description_t::DECODE): return "decode_error";
		// Если проверка подписи или обмена ключами не прошла
		case static_cast <uint8_t> (description_t::DECRYPT): return "decrypt_error";
		// Если издание протокола не поддерживается
		case static_cast <uint8_t> (description_t::VERSION): return "protocol_version";
		// Если согласованные условия недостаточно стойки
		case static_cast <uint8_t> (description_t::SECURITY): return "insufficient_security";
		// Если это внутренний отказ, к встречной стороне не относящийся
		case static_cast <uint8_t> (description_t::INTERNAL): return "internal_error";
		// Если сторона отступила к изданию ниже доступного
		case static_cast <uint8_t> (description_t::FALLBACK): return "inappropriate_fallback";
		// Если рукопожатие прервано по причине вне протокола
		case static_cast <uint8_t> (description_t::CANCELED): return "user_canceled";
		// Если обязательное расширение в сообщении отсутствует
		case static_cast <uint8_t> (description_t::MISSING): return "missing_extension";
		// Если прислано расширение, о котором не просили
		case static_cast <uint8_t> (description_t::EXTENSION): return "unsupported_extension";
		// Если запрошенное имя стороне неизвестно
		case static_cast <uint8_t> (description_t::NAME): return "unrecognized_name";
		// Если ответ о состоянии сертификата негоден либо сертификат отозван
		case static_cast <uint8_t> (description_t::STATUS): return "bad_certificate_status_response";
		// Если опознаватель заранее разделённого ключа неизвестен
		case static_cast <uint8_t> (description_t::PSK): return "unknown_psk_identity";
		// Если подлинность стороны обязательна, но не подтверждена
		case static_cast <uint8_t> (description_t::REQUIRED): return "certificate_required";
		// Если ни один из предложенных протоколов не поддержан
		case static_cast <uint8_t> (description_t::PROTOCOL): return "no_application_protocol";
	}
	// Выводим название неизвестного описания извещения
	return "unknown_alert";
}
