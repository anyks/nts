/**
 * @file adversary.hpp
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
 * @brief Общий для проверок заголовочный файл враждебного сервера протокола TLS 1.3
 *
 * @details Клиент судит сервера по сообщениям, идущим под защитой рукопожатия, и
 *          подделать их в потоке байтов нельзя: подделка не расшифруется вовсе, а
 *          отказ придёт не от того заслона, который проверяется. Враждебный сервер
 *          обходит это тем, что ведёт свою сторону сам: он выводит ключи рукопожатия
 *          по-настоящему и складывает ими сообщение, искажённое по заказу проверки.
 *
 * @note Рукопожатие здесь не доводится до конца: всякий проверяемый заслон обрывает
 *       клиента раньше подписи владения ключом, и складывать её незачем
 *
 * @note Всё содержимое лежит в безымянном пространстве имён: у всякой проверки своя
 *       программа, но правило это блюдётся и здесь - так заголовочный файл годится и
 *       для набора, собранного единой программой
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию заголовочного файла
 */
#ifndef __ANTS_TESTS_ADVERSARY__
#define __ANTS_TESTS_ADVERSARY__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <curve/parameters.hpp>
#include <hello/hello.hpp>
#include <flow/flow.hpp>
#include <record/record.hpp>
#include <message/message.hpp>
#include <session/session.hpp>
#include <protect/protect.hpp>
#include <schedule/schedule.hpp>
#include <agreement/ecdhe.hpp>
#include <x509/x509.hpp>
#include <x509/signature.hpp>
#include <math/number.hpp>
#include <sign/gost.hpp>
#include <alert/alert.hpp>
#include <cipher/mgm.hpp>
#include <cipher/magma.hpp>
#include <cipher/kuznyechik.hpp>
#include <field/field.hpp>
#include <digest/streebog.hpp>
#include <extension/extension.hpp>
#include <handshake/handshake.hpp>
#include <context/context.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * @brief Служебные объекты враждебного сервера проверок
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён проекта
	 */
	using namespace nts;
	/**
	 * @brief Искажения, вносимые враждебным сервером
	 *
	 */
	enum class distortion_t : uint8_t {
		NONE      = 0x00, // Искажение не вносится
		EXTENSION = 0x01, // Защищённые расширения несут непрошенное расширение
		CONTEXT   = 0x02, // Цепочка сертификатов несёт непустой опознаватель запроса
		EMPTINESS = 0x03, // Цепочка сертификатов не несёт ни одного сертификата
		SCHEME    = 0x04, // Подпись владения ключом объявлена неизвестной схемой
		FOREIGN   = 0x05, // Подпись владения ключом объявлена схемой чужой кривой
		LIFETIME  = 0x06, // Билет возобновления связи объявлен сроком свыше семи суток
		INTERLEAVE = 0x07, // Сообщение рукопожатия разорвано записью извещения
		COOKIE    = 0x08, // Просьба о повторе приветствия несёт метку возврата состояния
		GREETING  = 0x09, // Приветствие сервера несёт расширение не своего сообщения
		METHOD    = 0x0A, // Приветствие сервера объявляет способ сжатия, отличный от нуля
		PROPOSAL  = 0x0B, // Просьба о повторе приветствия без метки возврата состояния
		PROPOSED  = 0x0C, // Приветствие за просьбой о повторе меняет набор шифрования
		DISCORD   = 0x0D, // Приветствие клиента объявляет схемы подписи чужой кривой
		SILENT    = 0x0E, // Запрос подлинности клиента не объявляет схем подписи
		ADORNED   = 0x0F, // Запись цепочки сертификатов несёт непрошенное расширение
		FAREWELL  = 0x10, // Клиент шлёт конец упреждающих данных, которых не посылал
		AFTERCLOSE = 0x11, // Сервер шлёт прикладные данные за извещением о закрытии
		REPEATED   = 0x12, // Просьба о повторе приветствия приходит второй раз за связь
		ARCHAIC    = 0x13, // Приветствие клиента не объявляет перечня изданий протокола
		OUTDATED   = 0x14, // Приветствие клиента предлагает лишь издания до TLS 1.3
		ALIEN      = 0x15, // Приветствие клиента предлагает чужой набор шифрования
		BARE       = 0x16, // Приветствие клиента не объявляет перечня кривых обмена
		STRANGER   = 0x17, // Приветствие клиента предлагает кривую, сервером не признаваемую
		HOLLOW     = 0x18, // Приветствие клиента несёт пустую открытую часть ключа обмена
		SPEECHLESS = 0x19, // Приветствие сервера не объявляет издания протокола
		REGRESSED  = 0x1A, // Приветствие сервера объявляет издание ниже TLS 1.3
		KEYLESS    = 0x1B, // Приветствие сервера не объявляет открытой части ключа обмена
		SWAPPED    = 0x1C, // Приветствие сервера объявляет кривую, о которой не просили
		PRESUMED   = 0x1D, // Приветствие сервера выбирает ключ, клиентом не предложенный
		MODELESS   = 0x1E, // Приветствие клиента предлагает ключ без способов обмена им
		GARBLED    = 0x1F, // Приветствие клиента несёт негодные способы обмена ключом
		SPURIOUS   = 0x20, // Приветствие клиента несёт негодное предложение ключа
		MANGLED    = 0x21, // Защищённые расширения сервера несут негодное тело
		TATTERED   = 0x22, // Билет возобновления связи несёт негодное тело
		SCRAMBLED  = 0x23, // Смена ключевого материала несёт негодное тело
		MALVERSION = 0x24, // Приветствие клиента несёт негодный перечень изданий
		MALSHARE   = 0x25, // Приветствие клиента несёт негодный перечень долей обмена
		MALGROUPS  = 0x26, // Приветствие клиента несёт негодный перечень кривых
		MALCURVES  = 0x27, // То же, но доли обмена приветствием не объявлены вовсе
		MALNAME    = 0x28, // Приветствие клиента несёт негодное имя запрашиваемого узла
		MALPROTOCOL = 0x29, // Приветствие клиента несёт негодный перечень протоколов
		ODDSUITE   = 0x2A, // Приветствие сервера выбирает набор шифрования вне предложения
		PICKEDEARLY = 0x2B, // Просьба о повторе выбирает заранее разделённый ключ
		LATECOOKIE = 0x2C, // Приветствие сервера несёт метку возврата состояния
		MALSELECT  = 0x2D, // Просьба о повторе несёт негодную выбранную кривую
		MALEDITION = 0x2E, // Приветствие сервера несёт негодное издание протокола
		MALCHOSEN  = 0x2F, // Приветствие сервера несёт негодный выбор ключа
		MALSHARING = 0x30, // Приветствие сервера несёт негодную открытую часть ключа
		TWICE      = 0x31, // Приветствие клиента идёт дважды одною записью
		DOUBLED    = 0x32, // Приветствие сервера идёт дважды одною записью
		TWINNED    = 0x33, // Защищённые расширения сервера идут дважды
		MALALPN    = 0x34, // Защищённые расширения несут негодный прикладной протокол
		MALADVANCE = 0x35, // Билет несёт негодный предел упреждающих данных
		UNSETTLED  = 0x36, // Доля обмена идёт по кривой, сервером не признаваемой
		MALCOOKIE  = 0x37, // Приветствие клиента несёт негодную метку возврата состояния
		RECURRENT  = 0x38, // За приветствием сервера тою же записью идёт просьба о повторе
		LINGERING  = 0x39, // Конец упреждающих данных несёт тело, которого ему не положено
		MISAGED    = 0x3A, // Возраст билета объявлен разошедшимся с наблюдаемым
		UNOFFERED  = 0x3B, // Приветствие сервера выбирает ключ у клиента, его не предлагавшего
		WORDLESS   = 0x3C, // Приветствие клиента не объявляет схем подписи вовсе
		MISPLACED  = 0x3D, // Защищённые расширения несут расширение, им не положенное
		OUTPLACED  = 0x3E, // Билет возобновления связи несёт расширение, ему не положенное
		OFFPLACED  = 0x3F, // Запрос подлинности несёт расширение, ему не положенное
		VACANT     = 0x40, // Защищённая запись рукопожатия идёт с пустым содержимым
		RETROGRADE = 0x41, // Просьба о повторе приветствия объявляет издание ниже TLS 1.3
		LENGTHY    = 0x42, // Подпись владения ключом объявлена непомерной длины
		MALSIGN    = 0x43, // Подпись владения ключом испорчена при годной её длине
		MALFINISH  = 0x44, // Завершение рукопожатия несёт испорченную имитовставку
		MISORDER   = 0x45, // Предложение ключа идёт не последним расширением приветствия
		OFFCURVE   = 0x46, // Приветствие сервера несёт долю обмена вне кривой
		OFFPOINT   = 0x47, // Приветствие клиента несёт долю обмена вне кривой
		SYNTHETIC  = 0x48, // За приветствием сервера идёт сообщение поддельного вида
		MALSCHEMES = 0x49, // Приветствие клиента несёт негодные схемы подписи
		MALREQUEST = 0x4A, // Запрос подлинности несёт перечень расширений, оборванный на виде
		OVERREQUEST = 0x4B, // Запрос подлинности несёт лишний байт за своим телом
		MALREQSCHEMES = 0x4C, // Запрос подлинности несёт негодный перечень схем подписи
		MALCHAIN   = 0x4D, // Цепочка сертификатов несёт негодное тело
		MALVERIFY  = 0x4E, // Подпись владения ключом несёт негодное тело
		GARBAGELEAF = 0x4F, // Цепочка сертификатов несёт запись, сертификатом не являющуюся
		ODDSIGN    = 0x50, // Подпись владения ключом нечётной длины при годном объявлении
		ALIENTYPE  = 0x51, // Защищённая запись несёт содержимое неведомого вида
		UNKNOWNPSK = 0x52, // Приветствие клиента предлагает неведомый серверу заранее разделённый ключ
		ALIENLEAF  = 0x53, // Цепочка сертификатов несёт лист с чужим алгоритмом ключа
		UNATTESTED = 0x54, // Завершение сервера без сертификата в полном рукопожатии
		SPANNING   = 0x55, // Запись приветствия сервера несёт хвост следующего сообщения
		UNPICKED   = 0x56, // Защищённые расширения объявляют упреждение без выбранного ключа
		UNPROVEN   = 0x57, // Сертификат клиента без подписи владения ключом
		ENDLESS    = 0x58, // Завершение клиента ключами упреждения без конца упреждающих данных
		OVERGROWN  = 0x59, // Сервер шлёт по установленной связи сообщение рукопожатия непомерной длины
		IMPOSTOR   = 0x5A  // Сервер шлёт по установленной связи цепочку сертификатов заново
	};
	/**
	 * @brief Заранее назначенное случайное значение просьбы о повторе приветствия
	 *
	 * @note Раздел 4.1.3 RFC 8446 объявляет просьбу о повторе именно этим значением
	 *
	 */
	static const uint8_t RETRY[32] = {
		0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
		0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
		0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
		0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
	};
	/**
	 * @brief Метод составления защищённой записи с пустым содержимым
	 *
	 * @details Раздел 5.4 RFC 8446 запрещает отправлять записи рукопожатия и извещений
	 *          с пустым содержимым, и своя защита записей такую запись составить не
	 *          даёт. Оттого враждебная сторона складывает её сама, по тем же правилам:
	 *          ключ записи берётся построением TLSTREE, одноразовое значение - сложением
	 *          вектора замены с порядковым номером, а открытым текстом идёт единственный
	 *          байт истинного вида содержимого, за которым не стоит ничего
	 *
	 * @param suite    набор шифрования направления связи
	 * @param key      корневой ключ направления связи
	 * @param vector   вектор замены направления связи
	 * @param sequence порядковый номер составляемой записи
	 * @param inner    истинный вид содержимого составляемой записи
	 * @param result   накопитель, в конец которого дописывается защищённая запись
	 *
	 * @return         признак успешности составления защищённой записи
	 *
	 */
	bool hollow(const protect::suite_t suite, const view_t & key, const view_t & vector, const uint64_t sequence, const record::type_t inner, std::vector <uint8_t> & result, const size_t filler = 0) noexcept {
		// Получаем длину блока базового шифра набора
		const size_t size = protect::block(suite);
		// Если набор шифрования неизвестен
		if(size == 0)
			// Выводим отказ составления защищённой записи
			return false;
		// Место, в которое помещается ключ составляемой записи
		uint8_t item[protect::PROTECT_KEY];
		// Если ключ записи выработать не удалось
		if(!protect::tree(suite, key, sequence, item))
			// Выводим отказ составления защищённой записи
			return false;
		// Базовые шифры, из которых выбирается шифр набора
		cipher::magma_t magma;
		// Базовый шифр «Кузнечик» набора шифрования
		cipher::kuznyechik_t kuznyechik;
		// Признак успешности установки ключа базового шифра
		bool ok = ((size == 8) ? magma.key(view_t(item, sizeof(item))) : kuznyechik.key(view_t(item, sizeof(item))));
		// Выполняем затирание ключа составляемой записи
		::memset(item, 0, sizeof(item));
		// Если ключ базового шифра установить не удалось
		if(!ok)
			// Выводим отказ составления защищённой записи
			return false;
		// Описание базового шифра составляемой записи
		cipher::block_t block = ((size == 8) ? cipher::block_t(magma) : cipher::block_t(kuznyechik));
		// Место, в которое помещается одноразовое значение записи
		uint8_t nonce[protect::PROTECT_VECTOR];
		// Записываем вектор замены направления связи
		::memcpy(nonce, vector.data, size);
		/**
		 * Выполняем сложение вектора замены с порядковым номером записи
		 */
		for(size_t i = 0; i < 8; i++)
			// Складываем очередной байт номера с байтом вектора замены
			nonce[size - 1 - i] ^= static_cast <uint8_t> ((sequence >> (i * 8)) & 0xFF);
		// Гасим старший разряд одноразового значения, занятый самим режимом
		nonce[0] = static_cast <uint8_t> (nonce[0] & 0x7F);
		// Объект режима шифрования с проверкой целостности
		cipher::galois_t galois;
		// Если режим шифрования запустить не удалось
		if(!galois.start(block, view_t(nonce, size), size))
			// Выводим отказ составления защищённой записи
			return false;
		// Заголовок составляемой защищённой записи
		record::header_t header;
		// Устанавливаем вид содержимого защищённой записи
		header.type = record::type_t::APPLICATION;
		// Устанавливаем издание протокола защищённой записи
		header.version = record::version_t::TLS12;
		// Устанавливаем длину содержимого защищённой записи
		header.size = (filler + 1 + size);
		// Место, в которое записывается заголовок защищённой записи
		uint8_t associated[record::RECORD_HEADER];
		// Если заголовок защищённой записи составить не удалось
		if(record::build(header, associated) != record::error_t::NONE)
			// Выводим отказ составления защищённой записи
			return false;
		// Открытый текст составляемой записи в один байт истинного вида содержимого
		std::vector <uint8_t> plain(filler, 0x00); plain.push_back(static_cast <uint8_t> (inner));
		// Место, в которое помещаются шифртекст и метка целостности записи
		std::vector <uint8_t> sealed(plain.size() + protect::PROTECT_VECTOR);
		// Если наложить шифрование с проверкой целостности не удалось
		if(!galois.encrypt(view_t(associated, record::RECORD_HEADER), view_t(plain.data(), plain.size()), sealed.data(), (sealed.data() + plain.size())))
			// Выводим отказ составления защищённой записи
			return false;
		// Складываем заголовок защищённой записи в накопитель
		result.insert(result.end(), associated, associated + record::RECORD_HEADER);
		// Складываем шифртекст и метку целостности в накопитель
		result.insert(result.end(), sealed.data(), sealed.data() + plain.size() + size);
		// Выводим успешность составления защищённой записи
		return true;
	}
	/**
	 * @brief Метод отправки сообщения рукопожатия враждебным сервером
	 *
	 * @param protection защита записей враждебного сервера
	 * @param transcript переписка рукопожатия враждебного сервера
	 * @param type       вид отправляемого сообщения рукопожатия
	 * @param body       тело отправляемого сообщения рукопожатия
	 * @param result     накопитель, в который складывается защищённая запись
	 *
	 * @return           признак успешности отправки сообщения рукопожатия
	 *
	 */
	bool deliver(protect::protection_t & protection, session::transcript_t & transcript, const handshake::type_t type, const view_t & body, vector <uint8_t> & result) noexcept {
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если сообщение рукопожатия составить не удалось
		if(writer.push(type, body) != handshake::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Если сообщение в переписку рукопожатия добавить не удалось
		if(transcript.update(writer.data()) != session::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Накопитель, в который складывается защищённая запись
		vector <uint8_t> sealed;
		// Если наложить защиту на сообщение рукопожатия не удалось
		if(protection.seal(record::type_t::HANDSHAKE, writer.data(), sealed) != protect::error_t::NONE)
			// Выводим отказ отправки сообщения рукопожатия
			return false;
		// Складываем защищённую запись в накопитель ответа
		result.insert(result.end(), sealed.begin(), sealed.end());
		// Выводим успешность отправки сообщения рукопожатия
		return true;
	}
	/**
	 * @brief Метод выработки подписи владения ключом враждебного сервера
	 *
	 * @param credential подлинность подписывающей стороны
	 * @param transcript переписка рукопожатия подписывающей стороны
	 * @param server     признак того, что подпись кладёт сторона сервера
	 * @param result     накопитель, в который складывается тело подписи
	 *
	 * @return           признак успешности выработки подписи владения ключом
	 *
	 */
	bool possession(const context::credential_t & credential, const session::transcript_t & transcript, const bool server, vector <uint8_t> & result, const char * override = nullptr) noexcept {
		// Объект разбора сертификата враждебного сервера
		x509::certificate_t leaf;
		// Если сертификат враждебного сервера разобрать не удалось
		if(leaf.parse(view_t(credential.chain[0].data(), credential.chain[0].size())) != x509::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Опознаватель набора параметров кривой своего ключа
		string oid;
		// Если опознаватель набора параметров кривой извлечь не удалось
		/**
		 * Кривая подписи берётся из листа, а при переопределении - из довода: лист с
		 * чужим алгоритмом ключа своей кривой не выдаёт, тогда как подписать волну им
		 * всё же надо - клиент обязан отвергнуть лист сам, а не по отказу оснастки
		 */
		if(override != nullptr)
			oid = override;
		else if(x509::identifier(leaf.key(), oid) != x509::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Схема подписи владения ключом враждебного сервера
		extension::scheme_t chosen = extension::scheme_t::NONE;
		// Схемы подписи, известные протоколу
		const extension::scheme_t schemes[] = {
			extension::scheme_t::S256A, extension::scheme_t::S256B,
			extension::scheme_t::S256C, extension::scheme_t::S256D,
			extension::scheme_t::S512A, extension::scheme_t::S512B,
			extension::scheme_t::S512C
		};
		/**
		 * Выполняем перебор схем подписи, известных протоколу
		 */
		for(size_t i = 0; (i < (sizeof(schemes) / sizeof(extension::scheme_t))) && (chosen == extension::scheme_t::NONE); i++){
			// Получаем опознаватель кривой очередной схемы подписи
			const char * item = extension::curve(schemes[i]);
			// Если опознаватель кривой схемы совпал с искомым
			if((item != nullptr) && (oid.compare(item) == 0))
				// Запоминаем схему подписи владения ключом
				chosen = schemes[i];
		}
		// Если схему подписи подобрать не удалось
		if(chosen == extension::scheme_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Эллиптическая кривая подписи владения ключом
		curve::curve_t signing;
		// Если кривую своего ключа завести не удалось
		if((override != nullptr) ? !curve::parameters(oid, signing) : (x509::parameters(leaf.key(), signing) != x509::error_t::NONE))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t hash[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(hash) != session::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Накопитель, в который складывается подписываемое содержимое
		vector <uint8_t> content;
		// Если подписываемое содержимое составить не удалось
		if(message::content(view_t(hash, sizeof(hash)), server, content) != message::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается хеш подписываемого содержимого
		uint8_t digest[64];
		// Определяем длину хеша подписываемого содержимого
		const digest::type_t kind = ((signing.size() == 32) ? digest::type_t::SHORT : digest::type_t::LONG);
		// Если хеш подписываемого содержимого выработать не удалось
		if(!digest::streebog(kind, view_t(content.data(), content.size()), digest, signing.size(), digest::order_t::VECTOR))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если эллиптическую кривую подписи установить не удалось
		if(!gost.start(signing))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Если секретный ключ враждебного сервера установить не удалось
		if(!gost.secret(view_t(credential.secret.data(), credential.secret.size())))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается выработанная подпись владения ключом
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Если подпись владения ключом выработать не удалось
		if(!gost.make(view_t(digest, signing.size()), signature))
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Место, в которое помещается подпись в записи протокола
		uint8_t reversed[math::NUMBER_SIZE * 2];
		// Если запись подписи развернуть не удалось
		if(message::reverse(view_t(signature, gost.size()), reversed) != message::error_t::NONE)
			// Выводим отказ выработки подписи владения ключом
			return false;
		// Составляемое сообщение подписи владения ключом
		message::verify_t verify;
		// Устанавливаем схему подписи владения ключом
		verify.scheme = chosen;
		// Устанавливаем значение подписи владения ключом
		verify.signature = view_t(reversed, gost.size());
		// Выводим итог составления тела подписи владения ключом
		return (message::build(verify, result) == message::error_t::NONE);
	}
	/**
	 * @brief Метод ответа враждебного сервера на приветствие клиента
	 *
	 * @param client     связь стороны клиента
	 * @param distortion искажение, вносимое враждебным сервером
	 * @param credential подлинность враждебного сервера, нужная искажению подписи
	 *
	 * @return           признак успешности ответа враждебного сервера
	 *
	 * @note Итог отвечает лишь за то, что ответ составлен и подан клиенту: суждение
	 *       о заслоне снимается с самого клиента
	 *
	 */
	bool adversary(client::context_t & client, const distortion_t distortion, const context::credential_t * credential = nullptr) noexcept {
		// Получаем байты, отправляемые клиентом серверу
		const view_t sending = client.output();
		// Если клиент серверу ничего не отправил
		if(sending.size == 0)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Выполняем перенос отправленных клиентом байтов
		const vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя клиента
		client.consume(wire.size());
		// Объект сборщика принимаемых записей связи
		record::reader_t records;
		// Если принятые байты сборщику записей подать не удалось
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Заголовок принятой записи связи
		record::header_t header;
		// Содержимое принятой записи связи
		view_t payload;
		// Если запись приветствия клиента прочитать не удалось
		if(records.next(header, payload) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект сборщика принимаемых сообщений рукопожатия
		handshake::reader_t messages;
		// Если содержимое записи сборщику сообщений подать не удалось
		if(messages.push(payload) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Заголовок принятого сообщения рукопожатия
		handshake::header_t message;
		// Тело принятого сообщения рукопожатия
		view_t body;
		// Если сообщение приветствия клиента прочитать не удалось
		if(messages.next(message, body) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Если принято не приветствие клиента
		if(message.type != handshake::type_t::CLIENT)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Разбираемое приветствие клиента
		hello::client_t greeting;
		// Если приветствие клиента разобрать не удалось
		if(hello::parse(body, greeting) != hello::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Разыскиваем расширение открытых частей ключей обмена клиента
		const hello::extension_t * extension = hello::extension(greeting.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если открытых частей ключей обмена приветствие не несёт
		if((extension == nullptr) || greeting.suites.empty())
			// Выводим отказ ответа враждебного сервера
			return false;
		// Открытые части ключей обмена, предложенные клиентом
		vector <extension::share_t> shares;
		// Если открытые части ключей обмена разобрать не удалось
		if((extension::shares(extension->data, shares) != extension::error_t::NONE) || shares.empty())
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем опознаватель набора параметров кривой обмена ключами
		const char * oid = extension::curve(shares[0].group);
		// Объект кривой обмена мимолётными ключами
		curve::curve_t elliptic;
		// Если кривую обмена мимолётными ключами завести не удалось
		if((oid == nullptr) || !curve::parameters(oid, elliptic))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Секретный мимолётный ключ враждебного сервера
		vector <uint8_t> secret(elliptic.size(), 0);
		// Открытый мимолётный ключ враждебного сервера
		vector <uint8_t> opened(elliptic.size() * 2, 0);
		// Если мимолётную пару ключей враждебного сервера выработать не удалось
		if(!agreement::generate(elliptic, secret.data(), opened.data()))
			// Выводим отказ ответа враждебного сервера
			return false;
		/**
		 * Искажением OFFCURVE доля обмена портится ПОСЛЕ выработки: длина её и кривая
		 * остаются годными, а точка сходит с кривой. Тем и проверяется сличение точки
		 * с уравнением кривой при выработке общего значения - негодное ТЕЛО доли
		 * отвергается много раньше, разбором расширения
		 */
		if(distortion == distortion_t::OFFCURVE)
			// Портим первый байт первой координаты доли обмена
			opened[0] = static_cast <uint8_t> (opened[0] ^ 0x01);
		// Объект переписки рукопожатия враждебного сервера
		session::transcript_t transcript;
		// Заводим переписку рукопожатия враждебного сервера
		transcript.start();
		// Если приветствие клиента в переписку добавить не удалось
		if(transcript.update(messages.message()) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Составляемое приветствие враждебного сервера
		hello::server_t answer;
		// Устанавливаем версию протокола, доставшуюся от предыдущих изданий
		answer.version = 0x0303;
		// Устанавливаем опознаватель связи, повторяемый за приветствием клиента
		answer.session = greeting.session;
		/**
		 * Набор шифрования берётся первым из предложенных клиентом, а искажением
		 * PROPOSED - вторым: им враждебный сервер меняет набор между просьбой о
		 * повторе приветствия и самим приветствием
		 */
		answer.suite = ((distortion == distortion_t::ODDSUITE) ? 0x1301 :
			(((distortion == distortion_t::PROPOSED) && (greeting.suites.size() > 1)) ? greeting.suites[1] : greeting.suites[0]));
		// Устанавливаем выбранный способ сжатия
		answer.method = ((distortion == distortion_t::METHOD) ? 0x01 : 0x00);
		/**
		 * Выполняем набивку случайного значения приветствия враждебного сервера
		 */
		for(size_t i = 0; i < sizeof(answer.random); i++)
			// Записываем очередной байт случайного значения приветствия
			answer.random[i] = static_cast <uint8_t> (0x10 + i);
		// Накопители, в которых лежат тела расширений приветствия
		vector <uint8_t> version, share, elected;
		/**
		 * Негодное тело расширения: единственный байт объявляет длину свыше
		 * собственного размера тела, и разбору оно не поддаётся
		 */
		const vector <uint8_t> spoiled = {0xFF};
		// Если издание протокола составить не удалось
		if(extension::version((((distortion == distortion_t::REGRESSED) || (distortion == distortion_t::RETROGRADE)) ? 0x0303 : 0x0304), version) != extension::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Открытая часть ключа обмена враждебного сервера
		/**
		 * Кривая объявляемой доли: искажением SWAPPED объявляется кривая, о которой
		 * клиент не просил, тогда как байты ключа остаются от кривой настоящей
		 */
		const extension::share_t item(((distortion == distortion_t::SWAPPED) ? extension::group_t::GC256A : shares[0].group), view_t(opened.data(), opened.size()));
		// Если открытую часть ключа обмена составить не удалось
		if(extension::share(item, share) != extension::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Если издание протокола приветствием объявляется
		if(distortion != distortion_t::SPEECHLESS)
			// Добавляем расширение издания протокола
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS),
				((distortion == distortion_t::MALEDITION) ? view_t(spoiled.data(), spoiled.size()) : view_t(version.data(), version.size()))));
		// Накопитель, в котором лежит тело расширения просьбы о повторе
		vector <uint8_t> selected;
		// Метка возврата состояния, объявляемая просьбой о повторе
		const vector <uint8_t> label = {0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
		// Если враждебный сервер просит повтора приветствия
		if((distortion == distortion_t::COOKIE) || (distortion == distortion_t::PROPOSAL) || (distortion == distortion_t::REPEATED) ||
		   (distortion == distortion_t::PICKEDEARLY) || (distortion == distortion_t::MALSELECT) ||
		   (distortion == distortion_t::RETROGRADE)){
			// Переносим случайное значение просьбы о повторе приветствия
			::memcpy(answer.random, RETRY, sizeof(RETRY));
			/**
			 * Просить повтора вправе лишь на кривой, которую клиент предложил и ключа
			 * по которой ещё не прислал: берём вторую из предложенных
			 */
			/**
			 * Искажением REPEATED враждебный сервер просит повтора второй раз за связь,
			 * и звать он обязан кривую, отличную от той, о которой просил впервые:
			 * иначе связь оборвётся заслоном просьбы о кривой с уже отправленным ключом,
			 * а проверяется здесь заслон самой повторности просьбы
			 */
			if(extension::selected(((distortion == distortion_t::REPEATED) ? extension::group_t::GC256B : extension::group_t::GC512A), selected) != extension::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Добавляем расширение выбранной кривой обмена ключами
			answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE),
				((distortion == distortion_t::MALSELECT) ? view_t(spoiled.data(), spoiled.size()) : view_t(selected.data(), selected.size()))));
			// Если просьба о повторе выбирает заранее разделённый ключ клиента
			if(distortion == distortion_t::PICKEDEARLY){
				// Если выбор заранее разделённого ключа составить не удалось
				if(extension::chosen(0, elected) != extension::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Добавляем расширение выбранного заранее разделённого ключа
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(elected.data(), elected.size())));
			}
			// Если просьба о повторе объявляет метку возврата состояния сервера
			if(distortion == distortion_t::COOKIE)
				// Добавляем расширение метки возврата состояния сервера
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
		// Если враждебный сервер отвечает самим приветствием
		} else {
			// Если открытая часть ключа обмена приветствием объявляется
			if(distortion != distortion_t::KEYLESS)
				// Добавляем расширение открытой части ключа обмена
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE),
					((distortion == distortion_t::MALSHARING) ? view_t(spoiled.data(), spoiled.size()) : view_t(share.data(), share.size()))));
			// Если приветствие сервера несёт метку возврата состояния
			if(distortion == distortion_t::LATECOOKIE)
				// Добавляем расширение метки возврата состояния сервера
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(label.data(), label.size())));
			// Если приветствие сервера несёт негодный выбор заранее разделённого ключа
			if(distortion == distortion_t::MALCHOSEN)
				// Добавляем расширение выбранного заранее разделённого ключа
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(spoiled.data(), spoiled.size())));
			/**
			 * Искажением UNOFFERED сервер выбирает ПЕРВЫЙ заранее разделённый ключ у
			 * клиента, не предлагавшего ни одного: место выбранного ключа и наличие
			 * самого предложения сверяются РАЗНЫМИ половинами заслона клиента
			 */
			if(distortion == distortion_t::UNOFFERED){
				// Если расширение выбранного заранее разделённого ключа составить не удалось
				if(extension::chosen(0, elected) != extension::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Добавляем расширение выбранного заранее разделённого ключа
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(elected.data(), elected.size())));
			}
			// Если приветствие сервера выбирает заранее разделённый ключ клиента
			if(distortion == distortion_t::PRESUMED){
				/**
				 * Клиент предлагает единственный ключ, и место первое: всякое иное
				 * есть выбор того, чего он не предлагал вовсе
				 */
				if(extension::chosen(1, elected) != extension::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Добавляем расширение выбранного заранее разделённого ключа
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(elected.data(), elected.size())));
			}
			// Если приветствие сервера несёт расширение не своего сообщения
			if(distortion == distortion_t::GREETING)
				// Добавляем расширение, приветствию сервера не положенное
				answer.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(nullptr, 0)));
		}
		// Накопитель, в который складывается тело приветствия сервера
		vector <uint8_t> greeted;
		// Если тело приветствия враждебного сервера составить не удалось
		if(hello::build(answer, greeted) != hello::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие враждебного сервера составить не удалось
		if(writer.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())) != handshake::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		/**
		 * Искажением DOUBLED приветствие идёт дважды, и непременно одною записью:
		 * приветствием сервера пора ключей сменяется, и вторая запись открытой уже
		 * не разобралась бы вовсе - заслон проверялся бы не тот
		 */
		if(distortion == distortion_t::DOUBLED){
			// Если повторное приветствие враждебного сервера составить не удалось
			if(writer.push(handshake::type_t::SERVER, view_t(greeted.data(), greeted.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		/**
		 * Искажением RECURRENT за приветствием сервера тою же записью идёт просьба о
		 * повторе: приветствием пора рукопожатия уже прошла, и просьба приходит
		 * тогда, когда просить о повторе поздно
		 */
		/**
		 * Искажением SYNTHETIC за приветствием сервера идёт сообщение вида
		 * message_hash: вид этот стандартом заведён для ПОДМЕНЫ первого приветствия в
		 * переписке рукопожатия и по связи идти не вправе вовсе, хотя сборщик
		 * сообщений его и признаёт
		 */
		if(distortion == distortion_t::SYNTHETIC){
			// Тело поддельного сообщения длиною в хеш переписки
			const vector <uint8_t> forged(32, 0x77);
			// Если поддельное сообщение составить не удалось
			if(writer.push(handshake::type_t::DIGEST, view_t(forged.data(), forged.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		if(distortion == distortion_t::RECURRENT){
			// Составляемая просьба враждебного сервера о повторе приветствия
			hello::server_t asking = answer;
			// Переносим случайное значение просьбы о повторе приветствия
			::memcpy(asking.random, RETRY, sizeof(RETRY));
			// Выполняем сброс расширений составляемой просьбы о повторе
			asking.extensions.clear();
			// Добавляем расширение издания протокола
			asking.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(version.data(), version.size())));
			// Если выбранную просьбою кривую обмена ключами составить не удалось
			if(extension::selected(extension::group_t::GC512A, selected) != extension::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Добавляем расширение выбранной кривой обмена ключами
			asking.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(selected.data(), selected.size())));
			// Накопитель, в который складывается тело просьбы о повторе
			vector <uint8_t> pleaded;
			// Если тело просьбы о повторе составить не удалось
			if(hello::build(asking, pleaded) != hello::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если просьбу о повторе враждебного сервера составить не удалось
			if(writer.push(handshake::type_t::SERVER, view_t(pleaded.data(), pleaded.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Получаем составленное приветствие враждебного сервера
		const view_t greeter = writer.data();
		// Если приветствие сервера в переписку добавить не удалось
		if(transcript.update(greeter) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если приветствие враждебного сервера на записи нарезать не удалось
		// Содержимое записи приветствия сервера
		vector <uint8_t> spanned(greeter.data, greeter.data + greeter.size);
		/**
		 * Искажением SPANNING за приветствием в той же записи идёт начало следующего
		 * сообщения: раздел 5.1 RFC 8446 велит сообщению перед сменой ключей кончаться
		 * на границе записи
		 */
		if(distortion == distortion_t::SPANNING){
			// Начало следующего сообщения рукопожатия: вид и длина без тела
			const uint8_t spanning[4] = {0x08, 0x00, 0x00, 0x10};
			// Дописываем начало следующего сообщения к записи
			spanned.insert(spanned.end(), spanning, spanning + sizeof(spanning));
		}
		// Если запись приветствия сервера составить не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, view_t(spanned.data(), spanned.size())) != record::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем нарезанные записи приветствия враждебного сервера
		const view_t plaintext = plain.data();
		// Накопитель, в который складывается ответ враждебного сервера
		vector <uint8_t> answered(plaintext.data, plaintext.data + plaintext.size);
		// Если враждебный сервер искажает само приветствие
		if((distortion == distortion_t::COOKIE) || (distortion == distortion_t::GREETING) ||
		   (distortion == distortion_t::METHOD) || (distortion == distortion_t::PROPOSAL) ||
		   (distortion == distortion_t::PROPOSED) || (distortion == distortion_t::REPEATED) ||
		   (distortion == distortion_t::SPEECHLESS) || (distortion == distortion_t::REGRESSED) ||
		   (distortion == distortion_t::KEYLESS) || (distortion == distortion_t::SWAPPED) ||
		   (distortion == distortion_t::PRESUMED) || (distortion == distortion_t::ODDSUITE) ||
		   (distortion == distortion_t::PICKEDEARLY) || (distortion == distortion_t::LATECOOKIE) ||
		   (distortion == distortion_t::MALSELECT) || (distortion == distortion_t::MALEDITION) ||
		   (distortion == distortion_t::MALCHOSEN) || (distortion == distortion_t::MALSHARING) ||
		   (distortion == distortion_t::DOUBLED) || (distortion == distortion_t::RECURRENT)){
			// Выполняем подачу приветствия враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		// Место, в которое помещается общее значение обмена мимолётными ключами
		uint8_t common[64];
		// Если общее значение обмена мимолётными ключами выработать не удалось
		if(!agreement::ecdhe(elliptic, view_t(secret.data(), secret.size()), shares[0].key, common))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t digest[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект значений расписания ключей враждебного сервера
		session::secrets_t secrets;
		// Если начальную ступень расписания ключей завести не удалось
		if(secrets.start(view_t(nullptr, 0)) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Если ступень рукопожатия расписания ключей вывести не удалось
		if(secrets.handshake(view_t(common, elliptic.size()), view_t(digest, sizeof(digest))) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем набор шифрования, выбранный враждебным сервером
		const protect::suite_t suite = static_cast <protect::suite_t> (answer.suite);
		// Корневой ключ направления связи враждебного сервера
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи враждебного сервера
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи вывести не удалось
		if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Объект защиты записей враждебного сервера
		protect::protection_t protection;
		// Если ключевой материал направления связи установить не удалось
		if(!protection.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ ответа враждебного сервера
			return false;
		// Перечень расширений, объявляемых враждебным сервером
		vector <hello::extension_t> items;
		// Если защищённые расширения несут негодный прикладной протокол
		if(distortion == distortion_t::MALALPN)
			// Добавляем расширение прикладного протокола с негодным телом
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(spoiled.data(), spoiled.size())));
		// Если защищённые расширения несут непрошенное расширение
		/**
		 * Расширение берётся такое, какое защищённым расширениям положено, а клиентом
		 * не предлагалось: заслон непрошенного расширения проверяется тогда САМ по
		 * себе. Расширение, защищённым расширениям не положенное вовсе, задело бы
		 * прежде него заслон места расширения, и о непрошенном не сказало бы ничего
		 */
		if(distortion == distortion_t::EXTENSION)
			// Добавляем расширение прикладных протоколов, клиентом не предлагавшееся
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(nullptr, 0)));
		/**
		 * Искажением MISPLACED защищённые расширения несут расширение, им не
		 * положенное: способы обмена заранее разделённым ключом раздел 4.2 RFC 8446
		 * кладёт одному лишь приветствию клиента
		 */
		if(distortion == distortion_t::MISPLACED)
			// Добавляем расширение способов обмена заранее разделённым ключом
			items.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(nullptr, 0)));
		// Объект составителя перечня расширений сообщения
		field::builder_t fields;
		// Если перечень расширений открыть не удалось
		if(fields.open(2) != field::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		/**
		 * Выполняем перебор расширений, объявляемых враждебным сервером
		 */
		for(size_t i = 0; i < items.size(); i++){
			// Если вид расширения записать не удалось
			if(fields.number(items[i].type, 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения открыть не удалось
			if(fields.open(2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения записать не удалось
			if((items[i].data.size > 0) && (fields.bytes(items[i].data) != field::error_t::NONE))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения закрыть не удалось
			if(fields.close() != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Если перечень расширений закрыть не удалось
		if(fields.close() != field::error_t::NONE)
			// Выводим отказ ответа враждебного сервера
			return false;
		// Получаем составленный перечень расширений
		const view_t list = fields.data();
		// Накопитель, в который складывается тело защищённых расширений сервера
		const vector <uint8_t> extensions(list.data, list.data + list.size);
		// Если враждебный сервер рвёт сообщение рукопожатия чужой записью
		if(distortion == distortion_t::INTERLEAVE){
			// Объект составителя защищённых расширений враждебного сервера
			handshake::writer_t divided;
			// Если защищённые расширения враждебного сервера составить не удалось
			if(divided.push(handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Получаем составленное сообщение защищённых расширений
			const view_t whole = divided.data();
			// Если сообщение защищённых расширений разрывать не на чем
			if(whole.size < 4)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается первая половина сообщения
			vector <uint8_t> leading;
			// Если наложить защиту на первую половину сообщения не удалось
			if(protection.seal(record::type_t::HANDSHAKE, view_t(whole.data, 2), leading) != protect::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Складываем защищённую запись в ответ враждебного сервера
			answered.insert(answered.end(), leading.begin(), leading.end());
			// Составляемое извещение, разрывающее сообщение рукопожатия
			alert::alert_t notice;
			// Устанавливаем уровень составляемого извещения
			notice.level = alert::level_t::WARNING;
			/**
			 * Извещение берётся несмертельным нарочно: смертельное оборвало бы связь
			 * само по себе, и заслон разрыва проверен бы не был
			 */
			notice.description = alert::description_t::CANCELED;
			// Место, в которое складывается тело составляемого извещения
			uint8_t noticed[2];
			// Если тело извещения составить не удалось
			if(alert::build(notice, noticed) != alert::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается запись извещения
			vector <uint8_t> noticing;
			// Если наложить защиту на извещение не удалось
			if(protection.seal(record::type_t::ALERT, view_t(noticed, sizeof(noticed)), noticing) != protect::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Складываем защищённую запись в ответ враждебного сервера
			answered.insert(answered.end(), noticing.begin(), noticing.end());
			// Выполняем подачу ответа враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		/**
		 * Тело защищённых расширений: искажением MANGLED оно объявляет длину перечня
		 * свыше собственного размера, и разбору не поддаётся
		 */
		const vector <uint8_t> mangled = {0xFF, 0xFF};
		/**
		 * Искажением UNPICKED защищённые расширения объявляют приём упреждающих данных,
		 * хотя приветствие сервера заранее разделённого ключа не выбрало
		 */
		const vector <uint8_t> unpicked = {0x00, 0x04, 0x00, 0x2A, 0x00, 0x00};
		// Если защищённые расширения враждебного сервера отправить не удалось
		if(!deliver(protection, transcript, handshake::type_t::EXTENSIONS,
			((distortion == distortion_t::MANGLED) ? view_t(mangled.data(), mangled.size()) : ((distortion == distortion_t::UNPICKED) ? view_t(unpicked.data(), unpicked.size()) : view_t(extensions.data(), extensions.size()))), answered))
			// Выводим отказ ответа враждебного сервера
			return false;
		/**
		 * Искажением TWINNED защищённые расширения идут вторым разом: поры ключей они
		 * не сменяют, оттого вторая запись вскрывается и до заслона черёда доходит
		 */
		if(distortion == distortion_t::TWINNED){
			// Если повторные защищённые расширения отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::EXTENSIONS, view_t(extensions.data(), extensions.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем подачу ответа враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		/**
		 * Искажением OFFPLACED запрос подлинности несёт расширение, ему не положенное:
		 * раздел 4.2 RFC 8446 кладёт запросу из признаваемых движком расширений одни
		 * лишь схемы подписи. Сами схемы подписи запрос несёт годными, ибо заслон их
		 * отсутствия лежит позже и негодным местом проверялся бы не тот заслон
		 */
		if(distortion == distortion_t::OFFPLACED){
			// Объект составителя тела запроса подлинности клиента
			field::builder_t builder;
			// Если пустой опознаватель запроса записать не удалось
			if(builder.number(0, 1) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается тело расширения схем подписи
			vector <uint8_t> schemes;
			// Если перечень схем подписи составить не удалось
			if(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::S256A}, schemes) != extension::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если перечень расширений запроса открыть не удалось
			if(builder.open(2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если вид расширения схем подписи записать не удалось
			if(builder.number(static_cast <uint32_t> (extension::type_t::SCHEMES), 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения схем подписи открыть не удалось
			if(builder.open(2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения схем подписи записать не удалось
			if(builder.bytes(view_t(schemes.data(), schemes.size())) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если тело расширения схем подписи закрыть не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если вид расширения открытой части ключа обмена записать не удалось
			if(builder.number(static_cast <uint32_t> (extension::type_t::SHARE), 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если пустое тело расширения открытой части ключа записать не удалось
			if(builder.number(0, 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если перечень расширений запроса закрыть не удалось
			if(builder.close() != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если запрос подлинности враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::REQUEST, builder.data(), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем подачу ответа враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		// Если враждебный сервер шлёт запрос подлинности без схем подписи
		if((distortion == distortion_t::MALREQUEST) || (distortion == distortion_t::OVERREQUEST) ||
		   (distortion == distortion_t::MALREQSCHEMES)){
			// Тело запроса подлинности с негодным перечнем расширений
			std::vector <uint8_t> request;
			// Если перечень расширений оборван на виде расширения
			if(distortion == distortion_t::MALREQUEST)
				request = {0x00, 0x00, 0x01, 0x00};
			// Если за телом запроса идёт лишний байт
			else if(distortion == distortion_t::OVERREQUEST)
				request = {0x00, 0x00, 0x00, 0x00};
			// Если перечень схем подписи негоден: длина перечня нечётна
			else request = {0x00, 0x00, 0x07, 0x00, 0x0D, 0x00, 0x03, 0x00, 0x01, 0x08};
			if(!deliver(protection, transcript, handshake::type_t::REQUEST, view_t(request.data(), request.size()), answered))
				return false;
			client.push(view_t(answered.data(), answered.size()));
			return true;
		}
		if(distortion == distortion_t::SILENT){
			// Объект составителя тела запроса подлинности клиента
			field::builder_t builder;
			// Если пустой опознаватель запроса записать не удалось
			if(builder.number(0, 1) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если пустой перечень расширений запроса записать не удалось
			if(builder.number(0, 2) != field::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Получаем составленное тело запроса подлинности клиента
			const view_t request = builder.data();
			// Если запрос подлинности враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::REQUEST, request, answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем подачу ответа враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Выводим успешность ответа враждебного сервера
			return true;
		}
		// Опознаватель запроса подлинности, набиваемый враждебным сервером
		const uint8_t identifier[] = {0x0A, 0x0B, 0x0C, 0x0D};
		// Если враждебный сервер искажает цепочку сертификатов
		if((distortion == distortion_t::CONTEXT) || (distortion == distortion_t::EMPTINESS) || (distortion == distortion_t::ADORNED)){
			// Составляемая цепочка сертификатов враждебного сервера
			message::certificate_t certificate;
			// Если запись цепочки несёт расширение, клиентом не предлагавшееся
			if(distortion == distortion_t::ADORNED){
				// Запись цепочки сертификатов враждебного сервера
				message::entry_t entry;
				// Устанавливаем тело сертификата записи цепочки
				entry.data = view_t(identifier, sizeof(identifier));
				/**
				 * Расширение запроса состояния сертификата клиент приветствием не
				 * предлагает: раздел 4.4.2 RFC 8446 велит ему на нём оборваться
				 */
				entry.extensions.push_back(hello::extension_t(0x0005, view_t(nullptr, 0)));
				// Добавляем запись в цепочку сертификатов
				certificate.entries.push_back(entry);
			}
			// Если цепочка сертификатов несёт непустой опознаватель запроса
			if(distortion == distortion_t::CONTEXT){
				// Устанавливаем непустой опознаватель запроса подлинности
				certificate.context = view_t(identifier, sizeof(identifier));
				// Запись цепочки сертификатов враждебного сервера
				message::entry_t entry;
				// Устанавливаем тело сертификата записи цепочки
				entry.data = view_t(identifier, sizeof(identifier));
				// Добавляем запись в цепочку сертификатов
				certificate.entries.push_back(entry);
			}
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если цепочку сертификатов враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
		// Если враждебный сервер доводит рукопожатие до подписи владения ключом
		} else if((distortion == distortion_t::SCHEME) || (distortion == distortion_t::FOREIGN) ||
		          (distortion == distortion_t::LIFETIME) || (distortion == distortion_t::AFTERCLOSE) ||
		          (distortion == distortion_t::TATTERED) || (distortion == distortion_t::SCRAMBLED) ||
		          (distortion == distortion_t::MALADVANCE) || (distortion == distortion_t::OUTPLACED) ||
		          (distortion == distortion_t::LENGTHY) || (distortion == distortion_t::MALSIGN) ||
		          (distortion == distortion_t::MALFINISH) || (distortion == distortion_t::MALCHAIN) ||
		          (distortion == distortion_t::MALVERIFY) || (distortion == distortion_t::GARBAGELEAF) ||
		          (distortion == distortion_t::ODDSIGN) || (distortion == distortion_t::ALIENLEAF) ||
		          (distortion == distortion_t::VACANT) || (distortion == distortion_t::ALIENTYPE) ||
		          (distortion == distortion_t::OVERGROWN) || (distortion == distortion_t::IMPOSTOR)) {
			// Если подлинность враждебного сервера проверкой не задана
			if((credential == nullptr) || credential->chain.empty())
				// Выводим отказ ответа враждебного сервера
				return false;
			// Составляемая цепочка сертификатов враждебного сервера
			message::certificate_t certificate;
			// Запись цепочки сертификатов враждебного сервера
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			// Запись, сертификатом не являющаяся: разбор её обязан отвергнуть лист
			const std::vector <uint8_t> garbage(64, 0x41);
			entry.data = ((distortion == distortion_t::GARBAGELEAF) ? view_t(garbage.data(), garbage.size()) : view_t(credential->chain[0].data(), credential->chain[0].size()));
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если цепочку сертификатов враждебного сервера отправить не удалось
			// Если цепочка сертификатов несёт негодное тело: перечень расширений записи оборван
			if(distortion == distortion_t::MALCHAIN)
				chain = {0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x01, 0x30, 0x00, 0x01, 0x00};
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Накопитель, в который складывается тело подписи владения ключом
			vector <uint8_t> witnessed;
			// Если враждебный сервер искажает схему подписи владения ключом
			if((distortion == distortion_t::SCHEME) || (distortion == distortion_t::FOREIGN)){
				// Составляемая подпись владения ключом враждебного сервера
				message::verify_t witness;
				/**
				 * Схема подписи объявляется либо неизвестной вовсе, либо известной, но
				 * положенной чужой кривой: сама подпись при этом не важна, ибо заслон
				 * схемы стоит прежде её проверки
				 */
				witness.scheme = ((distortion == distortion_t::SCHEME) ? static_cast <extension::scheme_t> (0x0403) : extension::scheme_t::S512A);
				// Место, в которое кладётся ничего не значащая запись подписи
				const vector <uint8_t> nothing(64, 0x5A);
				// Устанавливаем запись подписи владения ключом
				witness.signature = view_t(nothing.data(), nothing.size());
				// Если тело подписи владения ключом составить не удалось
				if(message::build(witness, witnessed) != message::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
			// Если враждебный сервер подписывает владение ключом по-настоящему
			} else if(!possession(* credential, transcript, true, witnessed, ((distortion == distortion_t::ALIENLEAF) ? "1.2.643.2.2.35.1" : nullptr)))
				// Выводим отказ ответа враждебного сервера
				return false;
			/**
			 * Искажением LENGTHY подпись объявляется непомерной длины при годной схеме:
			 * схема берётся у настоящей подписи, дабы заслон схемы её пропустил и дело
			 * дошло до разворота записи подписи
			 */
			/**
			 * Искажением MALSIGN портится сама подпись при годных её схеме и длине:
			 * раздел 4.4.3 RFC 8446 велит рвать связь извещением decrypt_error
			 */
			// Если подпись владения ключом несёт негодное тело: значение подписи пусто
			if(distortion == distortion_t::MALVERIFY)
				witnessed = {0x08, 0x04, 0x00, 0x00};
			// Если подпись владения ключом нечётной длины при годном объявлении
			if(distortion == distortion_t::ODDSIGN){
				message::verify_t witness;
				if(message::parse(view_t(witnessed.data(), witnessed.size()), witness) != message::error_t::NONE)
					return false;
				const std::vector <uint8_t> odd(63, 0x5A);
				witness.signature = view_t(odd.data(), odd.size());
				witnessed.clear();
				if(message::build(witness, witnessed) != message::error_t::NONE)
					return false;
			}
			if((distortion == distortion_t::MALSIGN) && (witnessed.size() > 0))
				// Портим последний байт записи подписи владения ключом
				witnessed[witnessed.size() - 1] = static_cast <uint8_t> (witnessed[witnessed.size() - 1] ^ 0x01);
			if(distortion == distortion_t::LENGTHY){
				// Разбираемая настоящая подпись владения ключом
				message::verify_t witness;
				// Если настоящую подпись владения ключом разобрать не удалось
				if(message::parse(view_t(witnessed.data(), witnessed.size()), witness) != message::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Место, в которое кладётся ничего не значащая запись подписи
				const vector <uint8_t> lengthy(4096, 0x5A);
				// Устанавливаем непомерную запись подписи владения ключом
				witness.signature = view_t(lengthy.data(), lengthy.size());
				// Выполняем сброс накопителя подписи владения ключом
				witnessed.clear();
				// Если тело подписи владения ключом составить не удалось
				if(message::build(witness, witnessed) != message::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
			}
			// Если подпись владения ключом враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::VERIFY, view_t(witnessed.data(), witnessed.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
		}
		// Если враждебный сервер доводит рукопожатие до билета возобновления связи
		if((distortion == distortion_t::LIFETIME) || (distortion == distortion_t::AFTERCLOSE) ||
		   (distortion == distortion_t::TATTERED) || (distortion == distortion_t::SCRAMBLED) ||
		   (distortion == distortion_t::MALADVANCE) || (distortion == distortion_t::OUTPLACED) ||
		   (distortion == distortion_t::VACANT) || (distortion == distortion_t::MALFINISH) ||
		   (distortion == distortion_t::ALIENTYPE) || (distortion == distortion_t::UNATTESTED) ||
		   (distortion == distortion_t::OVERGROWN) || (distortion == distortion_t::IMPOSTOR)){
			// Место, в которое помещается ключ завершения рукопожатия сервера
			uint8_t completion[schedule::SCHEDULE_SECRET];
			// Если ключ завершения рукопожатия вывести не удалось
			if(secrets.finished(session::side_t::SERVER, completion) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Корневой ключ направления связи клиента
			uint8_t material[protect::PROTECT_KEY];
			// Вектор замены направления связи клиента
			uint8_t element[protect::PROTECT_VECTOR];
			/**
			 * Ключи рукопожатия клиента снимаются заранее: переход к ступени
			 * прикладных данных значения направлений связи переписывает
			 */
			if(secrets.material(session::side_t::CLIENT, suite, material, element) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Объект защиты записей, принимаемых от клиента
			protect::protection_t incoming;
			// Если ключевой материал направления связи клиента установить не удалось
			if(!incoming.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Место, в которое помещается хеш переписки рукопожатия
			uint8_t hash[schedule::SCHEDULE_SECRET];
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Место, в которое помещается завершение рукопожатия сервером
			uint8_t completed[32];
			// Если завершение рукопожатия выработать не удалось
			if(message::finished(view_t(completion, sizeof(completion)), view_t(hash, sizeof(hash)), completed) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			/**
			 * Искажением MALFINISH портится имитовставка завершения рукопожатия:
			 * раздел 4.4.4 RFC 8446 велит рвать связь извещением decrypt_error
			 */
			if(distortion == distortion_t::MALFINISH)
				// Портим последний байт имитовставки завершения рукопожатия
				completed[sizeof(completed) - 1] = static_cast <uint8_t> (completed[sizeof(completed) - 1] ^ 0x01);
			// Если завершение рукопожатия враждебного сервера отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::FINISHED, view_t(completed, sizeof(completed)), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если ступень прикладных данных расписания ключей вывести не удалось
			if(secrets.application(view_t(hash, sizeof(hash))) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если ключевой материал прикладных данных сервера вывести не удалось
			if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Объект защиты записей прикладных данных враждебного сервера
			protect::protection_t outgoing;
			// Если ключевой материал прикладных данных установить не удалось
			if(!outgoing.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем подачу рукопожатия враждебного сервера клиенту
			client.push(view_t(answered.data(), answered.size()));
			// Получаем байты, отправленные клиентом в ответ
			const view_t completing = client.output();
			// Если клиент рукопожатие не договорил
			if(completing.size == 0)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Выполняем перенос отправленных клиентом байтов
			const vector <uint8_t> stream(completing.data, completing.data + completing.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(stream.size());
			// Объект сборщика записей, принятых от клиента
			record::reader_t taken;
			// Если принятые байты сборщику записей подать не удалось
			if(taken.push(view_t(stream.data(), stream.size())) != record::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			/**
			 * Выполняем перебор записей, принятых от клиента
			 */
			while(taken.pending() > 0){
				// Заголовок очередной принятой записи
				record::header_t taking;
				// Содержимое очередной принятой записи
				view_t sealed;
				// Если очередную запись прочитать не удалось
				if(taken.next(taking, sealed) != record::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Вид содержимого, вскрытого из принятой записи
				record::type_t kind = record::type_t::NONE;
				// Накопитель, в который складывается вскрытое содержимое
				vector <uint8_t> opened;
				// Если снять защиту с принятой записи не удалось
				if(incoming.open(taking, sealed, kind, opened) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Если вскрытое содержимое сообщением рукопожатия не является
				if(kind != record::type_t::HANDSHAKE)
					// Переходим к следующей принятой записи
					continue;
				// Объект сборщика сообщений, принятых от клиента
				handshake::reader_t taker;
				// Если вскрытое содержимое сборщику сообщений подать не удалось
				if(taker.push(view_t(opened.data(), opened.size())) != handshake::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Заголовок очередного принятого сообщения рукопожатия
				handshake::header_t taken_header;
				// Тело очередного принятого сообщения рукопожатия
				view_t taken_body;
				/**
				 * Выполняем перебор сообщений рукопожатия, принятых от клиента
				 */
				while(taker.next(taken_header, taken_body) == handshake::error_t::NONE){
					// Если сообщение в переписку рукопожатия добавить не удалось
					if(transcript.update(taker.message()) != session::error_t::NONE)
						// Выводим отказ ответа враждебного сервера
						return false;
				}
			}
			// Если хеш переписки рукопожатия получить не удалось
			if(transcript.digest(hash) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если значение возобновления связи вывести не удалось
			if(secrets.resumption(view_t(hash, sizeof(hash))) != session::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если враждебный сервер выдаёт билет возобновления связи
			if((distortion == distortion_t::LIFETIME) || (distortion == distortion_t::TATTERED) ||
			   (distortion == distortion_t::MALADVANCE) || (distortion == distortion_t::OUTPLACED)){
			// Составляемый билет возобновления связи враждебного сервера
			message::ticket_t ticket;
			/**
			 * Срок билета объявляется свыше семи суток: раздел 4.6.1 RFC 8446 кладёт
			 * сроку билета именно этот предел. Искажением MALADVANCE срок берётся
			 * годным нарочно: заслон срока лежит раньше заслона предела упреждения,
			 * и негодным сроком проверялся бы не тот заслон
			 */
			ticket.lifetime = (((distortion == distortion_t::MALADVANCE) || (distortion == distortion_t::OUTPLACED)) ? 3600 : 604801);
			// Устанавливаем добавку к возрасту составляемого билета
			ticket.age = 0;
			// Неповторимое значение составляемого билета
			const uint8_t nonce[4] = {0x00, 0x00, 0x00, 0x00};
			// Устанавливаем неповторимое значение составляемого билета
			ticket.nonce = view_t(nonce, sizeof(nonce));
			// Устанавливаем тело составляемого билета
			ticket.data = view_t(identifier, sizeof(identifier));
			/**
			 * Искажением OUTPLACED билет несёт расширение, ему не положенное: раздел
			 * 4.2 RFC 8446 кладёт билету одно лишь расширение предела упреждающих
			 * данных. Срок билета берётся годным нарочно, как и у MALADVANCE
			 */
			if(distortion == distortion_t::OUTPLACED)
				// Добавляем расширение открытой части ключа обмена, билету не положенное
				ticket.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(nullptr, 0)));
			// Если билет несёт негодный предел упреждающих данных
			if(distortion == distortion_t::MALADVANCE)
				// Добавляем расширение предела упреждающих данных с негодным телом
				ticket.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(spoiled.data(), spoiled.size())));
			// Накопитель, в который складывается тело билета возобновления связи
			vector <uint8_t> issued;
			// Если тело билета возобновления связи составить не удалось
			if(message::build(ticket, issued) != message::error_t::NONE)
				// Выводим отказ ответа враждебного сервера
				return false;
			// Если враждебный сервер выдаёт билет с негодным телом
			if(distortion == distortion_t::TATTERED)
				// Устанавливаем негодное тело билета возобновления связи
				issued = {0x00, 0x00};
			// Выполняем сброс накопителя ответа враждебного сервера
			answered.clear();
			// Если билет возобновления связи отправить не удалось
			if(!deliver(outgoing, transcript, handshake::type_t::TICKET, view_t(issued.data(), issued.size()), answered))
				// Выводим отказ ответа враждебного сервера
				return false;
			}
			// Если враждебный сервер шлёт негодную смену ключевого материала
			if(distortion == distortion_t::SCRAMBLED){
				/**
				 * Раздел 4.6.3 RFC 8446 кладёт смене ключевого материала тело в один
				 * байт: пустое тело разбору не поддаётся
				 */
				answered.clear();
				// Если смену ключевого материала отправить не удалось
				if(!deliver(outgoing, transcript, handshake::type_t::UPDATE, view_t(nullptr, 0), answered))
					// Выводим отказ ответа враждебного сервера
					return false;
			}
			// Если враждебный сервер шлёт защищённую запись с пустым содержимым
			if(distortion == distortion_t::ALIENTYPE){
			answered.clear();
			// Запись с содержимым в один байт и неведомым видом 0x2A: до разбора вида она доходит
			if(!hollow(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite)), outgoing.sequence(), static_cast <record::type_t> (0x2A), answered, 1))
				return false;
		}
		if(distortion == distortion_t::VACANT){
				// Выполняем сброс накопителя ответа враждебного сервера
				answered.clear();
				/**
				 * Раздел 5.4 RFC 8446 велит рвать связь по записи рукопожатия с пустым
				 * содержимым: своя защита записей такую составить не даёт, оттого
				 * враждебный сервер складывает её сам
				 */
				if(!hollow(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite)), outgoing.sequence(), record::type_t::HANDSHAKE, answered))
					// Выводим отказ ответа враждебного сервера
					return false;
			}
			// Если враждебный сервер шлёт прикладные данные за извещением о закрытии
			if(distortion == distortion_t::AFTERCLOSE){
				// Извещение о завершении передачи данных враждебным сервером
				alert::alert_t notice;
				// Устанавливаем уровень извещения о завершении передачи
				notice.level = alert::level_t::WARNING;
				// Устанавливаем описание извещения о завершении передачи
				notice.description = alert::description_t::CLOSE;
				// Место, в которое складывается тело составляемого извещения
				uint8_t noticed[2];
				// Если тело извещения составить не удалось
				if(alert::build(notice, noticed) != alert::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Выполняем сброс накопителя ответа враждебного сервера
				answered.clear();
				// Накопитель, в который складывается запись извещения о закрытии
				vector <uint8_t> closing;
				// Если наложить защиту на извещение о закрытии не удалось
				if(outgoing.seal(record::type_t::ALERT, view_t(noticed, sizeof(noticed)), closing) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Складываем защищённую запись извещения в ответ враждебного сервера
				answered.insert(answered.end(), closing.begin(), closing.end());
				// Прикладные данные, посылаемые вслед за извещением о закрытии
				const uint8_t trailing[] = {0xDE, 0xAD, 0xBE, 0xEF};
				// Накопитель, в который складывается запись прикладных данных
				vector <uint8_t> tailing;
				// Если наложить защиту на прикладные данные не удалось
				if(outgoing.seal(record::type_t::APPLICATION, view_t(trailing, sizeof(trailing)), tailing) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Складываем защищённую запись данных в ответ враждебного сервера
				answered.insert(answered.end(), tailing.begin(), tailing.end());
			}
			// Если враждебный сервер шлёт сообщение рукопожатия непомерной длины
			if(distortion == distortion_t::OVERGROWN){
				/**
				 * Обвязка билета возобновления с телом в мегабайт: после установления
				 * связи сообщения рукопожатия шире билета не ходят, и связь обязана
				 * оборваться по одной обвязке, не дожидаясь набора тела
				 */
				const uint8_t bloated[] = {0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
				// Выполняем сброс накопителя ответа враждебного сервера
				answered.clear();
				// Накопитель, в который складывается запись непомерного сообщения
				vector <uint8_t> swollen;
				// Если наложить защиту на непомерное сообщение не удалось
				if(outgoing.seal(record::type_t::HANDSHAKE, view_t(bloated, sizeof(bloated)), swollen) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Складываем защищённую запись непомерного сообщения в ответ враждебного сервера
				answered.insert(answered.end(), swollen.begin(), swollen.end());
			}
			// Если враждебный сервер шлёт цепочку сертификатов по установленной связи
			if(distortion == distortion_t::IMPOSTOR){
				/**
				 * Пустая цепочка сертификатов после установления связи: сообщение
				 * само по себе законное, но не в свой черёд - подмена принятой цепочки
				 * по установленной связи отвергается до разбора тела
				 */
				const uint8_t chain[] = {0x0B, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00};
				// Выполняем сброс накопителя ответа враждебного сервера
				answered.clear();
				// Накопитель, в который складывается запись повторной цепочки
				vector <uint8_t> repeated;
				// Если наложить защиту на повторную цепочку не удалось
				if(outgoing.seal(record::type_t::HANDSHAKE, view_t(chain, sizeof(chain)), repeated) != protect::error_t::NONE)
					// Выводим отказ ответа враждебного сервера
					return false;
				// Складываем защищённую запись повторной цепочки в ответ враждебного сервера
				answered.insert(answered.end(), repeated.begin(), repeated.end());
			}
		}
		// Выполняем подачу ответа враждебного сервера клиенту
		client.push(view_t(answered.data(), answered.size()));
		// Выводим успешность ответа враждебного сервера
		return true;
	}
	/**
	 * @brief Метод возобновления связи враждебным клиентом с упреждающими данными
	 *
	 * @param server     связь стороны сервера
	 * @param ticket     билет возобновления связи, принятый прошлой связью
	 * @param distortion искажение, вносимое враждебным клиентом
	 *
	 * @return           признак успешности подачи упреждающих данных
	 *
	 * @details Приветствие складывается своё, привязка билета вырабатывается
	 *          по-настоящему, и ключи упреждающих данных выводятся из билета - иначе
	 *          сервер упреждения не примет и заслоны за ним останутся непроверенными
	 *
	 */
	bool precursor(server::context_t & server, const context::ticket_t & ticket, const distortion_t distortion) noexcept {
		// Кривая обмена ключами враждебного клиента
		const extension::group_t group = extension::group_t::GC256B;
		// Получаем опознаватель набора параметров кривой обмена ключами
		const char * oid = extension::curve(group);
		// Объект кривой обмена мимолётными ключами
		curve::curve_t elliptic;
		// Если кривую обмена мимолётными ключами завести не удалось
		if((oid == nullptr) || !curve::parameters(oid, elliptic))
			// Выводим отказ подачи упреждающих данных
			return false;
		// Секретный мимолётный ключ враждебного клиента
		vector <uint8_t> secret(elliptic.size(), 0);
		// Открытый мимолётный ключ враждебного клиента
		vector <uint8_t> opened(elliptic.size() * 2, 0);
		// Если мимолётную пару ключей враждебного клиента выработать не удалось
		if(!agreement::generate(elliptic, secret.data(), opened.data()))
			// Выводим отказ подачи упреждающих данных
			return false;
		// Составляемое приветствие враждебного клиента
		hello::client_t greeting;
		// Устанавливаем издание протокола, доставшееся от предыдущих изданий
		greeting.version = 0x0303;
		// Устанавливаем опознаватель связи приветствия
		greeting.session.assign(hello::HELLO_SESSION, 0x55);
		// Устанавливаем предлагаемый набор шифрования набором билета
		greeting.suites.push_back(static_cast <uint16_t> (ticket.suite));
		// Устанавливаем перечень способов сжатия
		greeting.methods.assign(1, 0x00);
		/**
		 * Выполняем набивку случайного значения приветствия
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт случайного значения приветствия
			greeting.random[i] = static_cast <uint8_t> (0x60 + i);
		// Накопители, в которых лежат тела расширений приветствия
		vector <vector <uint8_t>> bodies(6);
		// Если перечень изданий протокола составить не удалось
		if(extension::versions(vector <uint16_t> (1, 0x0304), bodies[0]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Добавляем расширение перечня изданий протокола
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS), view_t(bodies[0].data(), bodies[0].size())));
		// Если перечень кривых обмена ключами составить не удалось
		if(extension::groups(vector <extension::group_t> (1, group), bodies[1]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Добавляем расширение перечня кривых обмена ключами
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS), view_t(bodies[1].data(), bodies[1].size())));
		// Если перечень схем подписи составить не удалось
		if(extension::schemes(vector <extension::scheme_t> {extension::scheme_t::S256B}, bodies[2]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Добавляем расширение перечня схем подписи
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES), view_t(bodies[2].data(), bodies[2].size())));
		// Если перечень открытых частей ключей обмена составить не удалось
		if(extension::shares(vector <extension::share_t> (1, extension::share_t(group, view_t(opened.data(), opened.size()))), bodies[3]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Добавляем расширение открытых частей ключей обмена
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE), view_t(bodies[3].data(), bodies[3].size())));
		// Если способы обмена заранее разделённым ключом составить не удалось
		if(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, bodies[4]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Добавляем расширение способов обмена заранее разделённым ключом
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(bodies[4].data(), bodies[4].size())));
		/**
		 * Расширение упреждающих данных пусто: раздел 4.2.10 RFC 8446 велит объявлять
		 * им лишь само намерение, а предел объявлен билетом
		 */
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::EARLY), view_t(nullptr, 0)));
		// Место, в которое помещается пустая привязка предъявляемого билета
		uint8_t empty[schedule::SCHEDULE_SECRET];
		// Выполняем обнуление привязки предъявляемого билета
		::memset(empty, 0, sizeof(empty));
		// Опознаватель предъявляемого билета возобновления связи
		/**
		 * Возраст билета: искажением MISAGED он объявляется разошедшимся с наблюдаемым
		 * на час, тогда как окно расхождения - десять секунд
		 */
		const extension::identity_t identity(view_t(ticket.identity.data(), ticket.identity.size()),
			((distortion == distortion_t::MISAGED) ? static_cast <uint32_t> (ticket.age + 3600000) : ticket.age));
		// Если предложение заранее разделённых ключей составить не удалось
		if(extension::identities(vector <extension::identity_t> {identity}, vector <view_t> {view_t(empty, sizeof(empty))}, bodies[5]) != extension::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		/**
		 * Расширение заранее разделённых ключей идёт последним: привязка покрывает
		 * всё, что идёт до неё, и место ей раздел 4.2.11 RFC 8446 кладёт в конец
		 */
		greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(bodies[5].data(), bodies[5].size())));
		// Накопитель, в который складывается тело приветствия клиента
		vector <uint8_t> body;
		// Если тело приветствия враждебного клиента составить не удалось
		if(hello::build(greeting, body) != hello::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие враждебного клиента составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Получаем составленное приветствие враждебного клиента
		const view_t made = writer.data();
		// Накопитель, в котором приветствие правится привязкой билета
		vector <uint8_t> message(made.data, made.data + made.size);
		/**
		 * Приветствие усекается перед перечнем привязок: два байта длины перечня, байт
		 * длины привязки и сама привязка себя же покрывать не вправе
		 */
		const size_t truncation = (message.size() - (sizeof(empty) + 3));
		// Объект переписки рукопожатия враждебного клиента
		session::transcript_t transcript;
		// Заводим переписку рукопожатия враждебного клиента
		transcript.start();
		// Место, в которое помещается хеш усечённого приветствия
		uint8_t digest[schedule::SCHEDULE_SECRET];
		// Если хеш усечённого приветствия получить не удалось
		if(transcript.digest(view_t(message.data(), truncation), digest) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Объект значений расписания ключей враждебного клиента
		session::secrets_t secrets;
		// Если начальную ступень расписания ключей завести не удалось
		if(secrets.start(view_t(ticket.secret.data(), ticket.secret.size())) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Если привязку предъявляемого билета выработать не удалось
		if(secrets.binder(view_t(digest, sizeof(digest)), message.data() + (message.size() - sizeof(empty))) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Если приветствие в переписку рукопожатия добавить не удалось
		if(transcript.update(view_t(message.data(), message.size())) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Если значение упреждающих данных вывести не удалось
		if(secrets.early(view_t(digest, sizeof(digest))) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Значение упреждающих данных связи
		uint8_t traffic[schedule::SCHEDULE_SECRET];
		// Если значение упреждающих данных получить не удалось
		if(secrets.early(traffic) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Место, в которое помещается корневой ключ упреждающих данных
		uint8_t material[protect::PROTECT_KEY];
		// Место, в которое помещается вектор замены упреждающих данных
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал упреждающих данных вывести не удалось
		if(session::material(view_t(traffic, sizeof(traffic)), ticket.suite, material, element) != session::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Объект защиты упреждающих данных враждебного клиента
		protect::protection_t protection;
		// Если ключевой материал упреждающих данных установить не удалось
		if(!protection.start(ticket.suite, view_t(material, sizeof(material)), view_t(element, protect::block(ticket.suite))))
			// Выводим отказ подачи упреждающих данных
			return false;
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если приветствие враждебного клиента на записи нарезать не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, view_t(message.data(), message.size())) != record::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Получаем нарезанные записи приветствия враждебного клиента
		const view_t plaintext = plain.data();
		// Накопитель, в который складывается подача враждебного клиента
		vector <uint8_t> answered(plaintext.data, plaintext.data + plaintext.size);
		/**
		 * Упреждающие данные идут перед концом своим: без них отказ приёма неотличим
		 * от приёма, ибо сервер отвергнутые записи пропускает молча, как и велено
		 */
		const uint8_t advancing[8] = {0x41, 0x4E, 0x54, 0x53, 0x2D, 0x30, 0x52, 0x54};
		// Накопитель, в который складывается запись упреждающих данных
		vector <uint8_t> advanced;
		// Если наложить защиту на упреждающие данные не удалось
		if(protection.seal(record::type_t::APPLICATION, view_t(advancing, sizeof(advancing)), advanced) != protect::error_t::NONE)
			// Выводим отказ подачи упреждающих данных
			return false;
		// Складываем защищённую запись в подачу враждебного клиента
		answered.insert(answered.end(), advanced.begin(), advanced.end());
		// Объект составителя конца упреждающих данных
		/**
		 * Искажением ENDLESS конец упреждающих данных не посылается вовсе, а ключами
		 * упреждения уходит завершение рукопожатия: раздел 4.5 RFC 8446 велит серверу
		 * ждать конца упреждения прежде всякого иного сообщения
		 */
		if(distortion == distortion_t::ENDLESS){
			// Объект составителя подложного завершения рукопожатия
			handshake::writer_t finishing;
			// Тело подложного завершения рукопожатия
			const vector <uint8_t> forged(32, 0x5A);
			// Если подложное завершение составить не удалось
			if(finishing.push(handshake::type_t::FINISHED, view_t(forged.data(), forged.size())) != handshake::error_t::NONE)
				// Выводим отказ ответа враждебного клиента
				return false;
			// Защищённая запись подложного завершения
			vector <uint8_t> sealed;
			// Если наложить защиту упреждения на завершение не удалось
			if(protection.seal(record::type_t::HANDSHAKE, finishing.data(), sealed) != protect::error_t::NONE)
				// Выводим отказ ответа враждебного клиента
				return false;
			// Дописываем подложное завершение к ответу
			answered.insert(answered.end(), sealed.begin(), sealed.end());
		// Иначе упреждающие данные кончаются по правилам
		} else {
			handshake::writer_t ending;
			/**
			 * Раздел 4.5 RFC 8446 кладёт концу упреждающих данных пустое тело: искажением
			 * LINGERING он несёт байт, которого ему не положено
			 */
			const uint8_t trailing[1] = {0x00};
			// Если конец упреждающих данных составить не удалось
			if(ending.push(handshake::type_t::EARLY, ((distortion == distortion_t::LINGERING) ? view_t(trailing, sizeof(trailing)) : view_t(nullptr, 0))) != handshake::error_t::NONE)
				// Выводим отказ подачи упреждающих данных
				return false;
			// Накопитель, в который складывается запись конца упреждающих данных
			vector <uint8_t> sealed;
			// Если наложить защиту на конец упреждающих данных не удалось
			if(protection.seal(record::type_t::HANDSHAKE, ending.data(), sealed) != protect::error_t::NONE)
				// Выводим отказ подачи упреждающих данных
				return false;
			// Складываем защищённую запись в подачу враждебного клиента
			answered.insert(answered.end(), sealed.begin(), sealed.end());
		}
		/**
		 * Итог подачи не сличается: обрыв связи сервером и есть проверяемое, и отказом
		 * оснастки он не является
		 */
		(void) server.push(view_t(answered.data(), answered.size()));
		// Выводим успешность подачи упреждающих данных
		return true;
	}
	/**
	 * @brief Метод рукопожатия враждебного клиента с сервером
	 *
	 * @param server     связь стороны сервера
	 * @param distortion искажение, вносимое враждебным клиентом
	 * @param credential подлинность враждебного клиента
	 *
	 * @return           признак успешности рукопожатия враждебного клиента
	 *
	 * @details Зеркало враждебного сервера: приветствие складывается своё, ключи
	 *          рукопожатия выводятся по-настоящему, и подделывается уже то, что идёт
	 *          под их защитой, - иначе заслоны сервера за приветствием не проверить.
	 *
	 * @note Итог отвечает лишь за то, что рукопожатие составлено и подано серверу:
	 *       суждение о заслоне снимается с самого сервера
	 *
	 */
	bool intruder(server::context_t & server, const distortion_t distortion, const context::credential_t * credential = nullptr) noexcept {
		/**
		 * Кривая обмена ключами враждебного клиента: искажениями BARE и STRANGER
		 * берётся кривая, в перечень сервера по умолчанию не входящая, - без этого
		 * доля клиента сервером опознаётся и заслоны выбора кривой остаются в стороне
		 */
		const extension::group_t group = (((distortion == distortion_t::BARE) ||
			(distortion == distortion_t::STRANGER) || (distortion == distortion_t::UNSETTLED)) ?
			extension::group_t::GC256C : extension::group_t::GC256B);
		/**
		 * Перечень кривых, объявляемый враждебным клиентом: искажением UNSETTLED он
		 * несёт обе - и ту, по которой идёт доля, и общую с сервером. Обе нужны:
		 * доля вне объявленного перечня отвергается заслоном раньше, а без общей
		 * кривой сервер оборвал бы связь вместо просьбы о повторе. Тем он и
		 * понуждается просить повтора - общая кривая есть, а доли по ней нет
		 */
		const vector <extension::group_t> declared = ((distortion == distortion_t::UNSETTLED) ?
			vector <extension::group_t> {extension::group_t::GC256C, extension::group_t::GC256B} :
			vector <extension::group_t> {group});
		// Получаем опознаватель набора параметров кривой обмена ключами
		const char * oid = extension::curve(group);
		// Объект кривой обмена мимолётными ключами
		curve::curve_t elliptic;
		// Если кривую обмена мимолётными ключами завести не удалось
		if((oid == nullptr) || !curve::parameters(oid, elliptic))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Секретный мимолётный ключ враждебного клиента
		vector <uint8_t> secret(elliptic.size(), 0);
		// Открытый мимолётный ключ враждебного клиента
		vector <uint8_t> opened(elliptic.size() * 2, 0);
		// Если мимолётную пару ключей враждебного клиента выработать не удалось
		if(!agreement::generate(elliptic, secret.data(), opened.data()))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Искажением OFFPOINT доля обмена портится ПОСЛЕ выработки: длина её и кривая
		 * остаются годными, а точка сходит с кривой. Тем и проверяется сличение точки
		 * с уравнением кривой при выработке общего значения - негодное ТЕЛО доли
		 * отвергается много раньше, разбором расширения
		 */
		if(distortion == distortion_t::OFFPOINT)
			// Портим первый байт первой координаты доли обмена
			opened[0] = static_cast <uint8_t> (opened[0] ^ 0x01);
		// Составляемое приветствие враждебного клиента
		hello::client_t greeting;
		// Устанавливаем издание протокола, доставшееся от предыдущих изданий
		greeting.version = 0x0303;
		// Устанавливаем опознаватель связи приветствия
		greeting.session.assign(hello::HELLO_SESSION, 0x33);
		/**
		 * Предлагаемый набор шифрования: искажением ALIEN предлагается набор чужой,
		 * общего с сервером у сторон не находится вовсе
		 */
		greeting.suites.push_back((distortion == distortion_t::ALIEN) ? 0x1301 : static_cast <uint16_t> (protect::suite_t::MAGMA_MGM_L));
		// Устанавливаем перечень способов сжатия
		greeting.methods.assign(1, 0x00);
		/**
		 * Выполняем набивку случайного значения приветствия
		 */
		for(size_t i = 0; i < hello::HELLO_RANDOM; i++)
			// Записываем очередной байт случайного значения приветствия
			greeting.random[i] = static_cast <uint8_t> (0x40 + i);
		// Накопители, в которых лежат тела расширений приветствия
		vector <vector <uint8_t>> bodies(6);
		/**
		 * Негодное тело расширения: единственный байт объявляет длину перечня в
		 * двести пятьдесят пять байтов, каковых за ним не идёт вовсе
		 */
		const vector <uint8_t> spoiled = {0xFF};
		/**
		 * Перечень изданий протокола: искажением OUTDATED предлагается лишь издание
		 * предыдущее, а искажением ARCHAIC расширение не объявляется вовсе
		 */
		if(extension::versions(vector <uint16_t> (1, ((distortion == distortion_t::OUTDATED) ? 0x0303 : 0x0304)), bodies[0]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если перечень изданий протокола приветствием объявляется
		if(distortion != distortion_t::ARCHAIC)
			// Добавляем расширение перечня изданий протокола
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::VERSIONS),
				((distortion == distortion_t::MALVERSION) ? view_t(spoiled.data(), spoiled.size()) : view_t(bodies[0].data(), bodies[0].size()))));
		// Если перечень кривых обмена ключами составить не удалось
		if(extension::groups(declared, bodies[1]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если перечень кривых обмена ключами приветствием объявляется
		if(distortion != distortion_t::BARE){
			// Признак того, что перечень кривых объявляется негодным
			const bool spoil = ((distortion == distortion_t::MALGROUPS) || (distortion == distortion_t::MALCURVES));
			// Добавляем расширение перечня кривых обмена ключами
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::GROUPS),
				(spoil ? view_t(spoiled.data(), spoiled.size()) : view_t(bodies[1].data(), bodies[1].size()))));
		}
		/**
		 * Схемы подписи, предлагаемые враждебным клиентом: искажением DISCORD в
		 * перечне остаются одни схемы длинной кривой, тогда как сертификат сервера
		 * выдан на короткой
		 */
		const vector <extension::scheme_t> schemes = ((distortion == distortion_t::DISCORD) ?
			vector <extension::scheme_t> {
				extension::scheme_t::S512A, extension::scheme_t::S512B,
				extension::scheme_t::S512C
			} :
			vector <extension::scheme_t> {
				extension::scheme_t::S256A, extension::scheme_t::S256B,
				extension::scheme_t::S256C, extension::scheme_t::S256D,
				extension::scheme_t::S512A, extension::scheme_t::S512B,
				extension::scheme_t::S512C
			}
		);
		// Если перечень схем подписи составить не удалось
		if(extension::schemes(schemes, bodies[2]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Искажением WORDLESS расширение схем подписи не объявляется вовсе: раздел 9.2
		 * RFC 8446 велит клиенту объявлять их всякий раз, когда сервер подтверждает
		 * подлинность сертификатом, а возобновление ключом сертификата не требует
		 */
		/**
		 * Искажением MALSCHEMES перечень схем подписи несёт негодное тело: сам он
		 * приветствием объявлен, а разбору не поддаётся
		 */
		if(distortion != distortion_t::WORDLESS)
			// Добавляем расширение перечня схем подписи
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SCHEMES),
				((distortion == distortion_t::MALSCHEMES) ? view_t(spoiled.data(), spoiled.size()) : view_t(bodies[2].data(), bodies[2].size()))));
		// Если перечень открытых частей ключей обмена составить не удалось
		if(extension::shares(vector <extension::share_t> (1, extension::share_t(group, ((distortion == distortion_t::HOLLOW) ? view_t(nullptr, 0) : view_t(opened.data(), opened.size())))), bodies[3]) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Доли обмена ключами: искажением MALCURVES расширение не объявляется вовсе,
		 * ибо заслон негодного перечня кривых при опознанной доле лежит раньше того,
		 * что проверяется, - разбор кривых идёт тогда иной ветвью
		 */
		if(distortion != distortion_t::MALCURVES)
			// Добавляем расширение открытых частей ключей обмена
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SHARE),
				((distortion == distortion_t::MALSHARE) ? view_t(spoiled.data(), spoiled.size()) : view_t(bodies[3].data(), bodies[3].size()))));
		// Если приветствие клиента несёт негодную метку возврата состояния
		if(distortion == distortion_t::MALCOOKIE)
			// Добавляем расширение метки возврата состояния сервера
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::COOKIE), view_t(spoiled.data(), spoiled.size())));
		// Если приветствие клиента несёт негодное имя запрашиваемого узла
		if(distortion == distortion_t::MALNAME)
			// Добавляем расширение имени запрашиваемого узла
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(spoiled.data(), spoiled.size())));
		// Если приветствие клиента несёт негодный перечень прикладных протоколов
		if(distortion == distortion_t::MALPROTOCOL)
			// Добавляем расширение перечня прикладных протоколов
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::PROTOCOLS), view_t(spoiled.data(), spoiled.size())));
		/**
		 * Предложение заранее разделённого ключа: сами байты предложения разбору
		 * подлежат не всегда, ибо заслоны способов обмена стоят до него. Оттого
		 * искажениями MODELESS и GARBLED тело предложения годным быть не обязано
		 */
		if((distortion == distortion_t::MODELESS) || (distortion == distortion_t::GARBLED) ||
		   (distortion == distortion_t::SPURIOUS) || (distortion == distortion_t::MISORDER)){
			// Устанавливаем негодное тело предложения заранее разделённого ключа
			bodies[4] = {0x00, 0x05};
			// Если способы обмена заранее разделённым ключом приветствием объявляются
			if(distortion != distortion_t::MODELESS){
				/**
				 * Способы обмена: искажением GARBLED тело их негодно, а искажением
				 * SPURIOUS годно и несёт обмен с обновлением мимолётных ключей
				 */
				if(distortion == distortion_t::GARBLED)
					// Устанавливаем негодное тело способов обмена ключом
					bodies[5] = {0x05};
				// Если годные способы обмена ключом составить не удалось
				else if(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, bodies[5]) != extension::error_t::NONE)
					// Выводим отказ рукопожатия враждебного клиента
					return false;
				// Добавляем расширение способов обмена заранее разделённым ключом
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(bodies[5].data(), bodies[5].size())));
			}
			/**
			 * Предложение ключа идёт последним расширением приветствия: раздел 4.2.11
			 * RFC 8446 иного места ему не отводит, ибо привязки считаются по всему
			 * приветствию до него
			 */
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(bodies[4].data(), bodies[4].size())));
			/**
			 * Искажением MISORDER за предложением ключа идёт ещё одно расширение:
			 * раздел 4.2.11 RFC 8446 велит серверу сверять место предложения и
			 * отвечать извещением illegal_parameter, когда оно не последнее
			 */
			if(distortion == distortion_t::MISORDER)
				// Добавляем расширение имени сервера за предложением ключа
				greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::NAME), view_t(bodies[0].data(), bodies[0].size())));
		}
		/**
		 * Неведомый серверу заранее разделённый ключ: предложение собрано по всем
		 * правилам - способы обмена, опознаватель, привязка, - и стоит последним, как
		 * велит раздел 4.2.11 RFC 8446. Сервер вправе его не признать и продолжить
		 * полным рукопожатием: неведомый опознаватель - не отказ, а отсутствие совпадения
		 */
		if(distortion == distortion_t::UNKNOWNPSK){
			if(extension::modes(vector <extension::regime_t> {extension::regime_t::SHARED}, bodies[5]) != extension::error_t::NONE)
				return false;
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::MODES), view_t(bodies[5].data(), bodies[5].size())));
			const std::vector <uint8_t> unknown(8, 0x5A);
			const std::vector <uint8_t> binder(32, 0xA5);
			const extension::identity_t identity(view_t(unknown.data(), unknown.size()), 0);
			if(extension::identities(vector <extension::identity_t> {identity}, vector <view_t> {view_t(binder.data(), binder.size())}, bodies[4]) != extension::error_t::NONE)
				return false;
			greeting.extensions.push_back(hello::extension_t(static_cast <uint16_t> (extension::type_t::SECRET), view_t(bodies[4].data(), bodies[4].size())));
		}
		// Накопитель, в который складывается тело приветствия клиента
		vector <uint8_t> body;
		// Признак того, что приветствие клиента идёт дважды одною записью
		const bool twice = (distortion == distortion_t::TWICE);
		// Если тело приветствия враждебного клиента составить не удалось
		if(hello::build(greeting, body) != hello::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект составителя отправляемых сообщений рукопожатия
		handshake::writer_t writer;
		// Если приветствие враждебного клиента составить не удалось
		if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Искажением TWICE приветствие идёт дважды, и непременно одною записью: за
		 * первым приветствием сервер отвечает своим, и вторая запись пришлась бы уже
		 * на иную пору ключей
		 */
		if(twice){
			// Если повторное приветствие враждебного клиента составить не удалось
			if(writer.push(handshake::type_t::CLIENT, view_t(body.data(), body.size())) != handshake::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
		}
		// Объект переписки рукопожатия враждебного клиента
		session::transcript_t transcript;
		// Заводим переписку рукопожатия враждебного клиента
		transcript.start();
		// Если приветствие клиента в переписку добавить не удалось
		if(transcript.update(writer.data()) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект нарезчика отправляемых записей
		record::writer_t plain;
		// Если приветствие враждебного клиента на записи нарезать не удалось
		if(plain.push(record::type_t::HANDSHAKE, record::version_t::TLS12, writer.data()) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем подачу приветствия враждебного клиента серверу
		if(server.push(plain.data()) != context::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Получаем байты, отправленные сервером в ответ
		const view_t sending = server.output();
		// Если сервер приветствию не ответил
		if(sending.size == 0)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем перенос отправленных сервером байтов
		const vector <uint8_t> wire(sending.data, sending.data + sending.size);
		// Снимаем отправленные байты с накопителя сервера
		server.consume(wire.size());
		// Объект сборщика записей, принятых от сервера
		record::reader_t records;
		// Если принятые байты сборщику записей подать не удалось
		if(records.push(view_t(wire.data(), wire.size())) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Заголовок записи приветствия сервера
		record::header_t header;
		// Содержимое записи приветствия сервера
		view_t payload;
		// Если запись приветствия сервера прочитать не удалось
		if(records.next(header, payload) != record::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект сборщика принимаемых сообщений рукопожатия
		handshake::reader_t messages;
		// Если содержимое записи сборщику сообщений подать не удалось
		if(messages.push(payload) != handshake::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Заголовок принятого сообщения рукопожатия
		handshake::header_t message;
		// Тело принятого сообщения рукопожатия
		view_t taken;
		// Если приветствие сервера прочитать не удалось
		if((messages.next(message, taken) != handshake::error_t::NONE) || (message.type != handshake::type_t::SERVER))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если приветствие сервера в переписку добавить не удалось
		if(transcript.update(messages.message()) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Разбираемое приветствие сервера
		hello::server_t answer;
		// Если приветствие сервера разобрать не удалось
		if(hello::parse(taken, answer) != hello::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Искажением UNSETTLED сервер отвечает просьбою о повторе приветствия, и
		 * враждебный клиент повторяет прежнее - то же, без доли по общей кривой.
		 * Повтор этот сервер обязан оборвать: просить дважды он не вправе, а годной
		 * доли ему так и не прислали
		 */
		if((distortion == distortion_t::UNSETTLED) && hello::retry(answer)){
			/**
			 * Итог подачи здесь не сличается: обрыв связи сервером и есть ожидаемое,
			 * и отказом оснастки он не является
			 */
			(void) server.push(plain.data());
			// Выводим успешность рукопожатия враждебного клиента
			return true;
		}
		// Разыскиваем расширение открытой части ключа обмена сервера
		const hello::extension_t * extension = hello::extension(answer.extensions, static_cast <uint16_t> (extension::type_t::SHARE));
		// Если открытой части ключа обмена приветствие сервера не несёт
		if(extension == nullptr)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Открытая часть ключа обмена, присланная сервером
		extension::share_t share(extension::group_t::NONE, view_t(nullptr, 0));
		// Если открытую часть ключа обмена разобрать не удалось
		if(extension::share(extension->data, share) != extension::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается общее значение обмена мимолётными ключами
		uint8_t common[64];
		// Если общее значение обмена мимолётными ключами выработать не удалось
		if(!agreement::ecdhe(elliptic, view_t(secret.data(), secret.size()), share.key, common))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t digest[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(digest) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект значений расписания ключей враждебного клиента
		session::secrets_t secrets;
		// Если начальную ступень расписания ключей завести не удалось
		if(secrets.start(view_t(nullptr, 0)) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если ступень рукопожатия расписания ключей вывести не удалось
		if(secrets.handshake(view_t(common, elliptic.size()), view_t(digest, sizeof(digest))) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Получаем набор шифрования, выбранный сервером
		const protect::suite_t suite = static_cast <protect::suite_t> (answer.suite);
		// Место, в которое помещается ключ завершения рукопожатия клиента
		uint8_t completion[schedule::SCHEDULE_SECRET];
		// Если ключ завершения рукопожатия вывести не удалось
		if(secrets.finished(session::side_t::CLIENT, completion) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Корневой ключ направления связи
		uint8_t material[protect::PROTECT_KEY];
		// Вектор замены направления связи
		uint8_t element[protect::PROTECT_VECTOR];
		// Если ключевой материал направления связи сервера вывести не удалось
		if(secrets.material(session::side_t::SERVER, suite, material, element) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект защиты записей, принимаемых от сервера
		protect::protection_t incoming;
		// Если ключевой материал направления связи сервера установить не удалось
		if(!incoming.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		/**
		 * Выполняем перебор записей рукопожатия, принятых от сервера
		 */
		while(records.pending() > 0){
			// Заголовок очередной принятой записи
			record::header_t taking;
			// Содержимое очередной принятой записи
			view_t sealed;
			// Если очередную запись прочитать не удалось
			if(records.next(taking, sealed) != record::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Вид содержимого, вскрытого из принятой записи
			record::type_t kind = record::type_t::NONE;
			// Накопитель, в который складывается вскрытое содержимое
			vector <uint8_t> unsealed;
			// Если снять защиту с принятой записи не удалось
			if(incoming.open(taking, sealed, kind, unsealed) != protect::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если вскрытое содержимое сообщением рукопожатия не является
			if(kind != record::type_t::HANDSHAKE)
				// Переходим к следующей принятой записи
				continue;
			// Объект сборщика сообщений, принятых от сервера
			handshake::reader_t taker;
			// Если вскрытое содержимое сборщику сообщений подать не удалось
			if(taker.push(view_t(unsealed.data(), unsealed.size())) != handshake::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Заголовок очередного принятого сообщения рукопожатия
			handshake::header_t item;
			// Тело очередного принятого сообщения рукопожатия
			view_t content;
			/**
			 * Выполняем перебор сообщений рукопожатия, принятых от сервера
			 */
			while(taker.next(item, content) == handshake::error_t::NONE){
				// Если сообщение в переписку рукопожатия добавить не удалось
				if(transcript.update(taker.message()) != session::error_t::NONE)
					// Выводим отказ рукопожатия враждебного клиента
					return false;
			}
		}
		// Если ключевой материал направления связи клиента вывести не удалось
		if(secrets.material(session::side_t::CLIENT, suite, material, element) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Объект защиты записей враждебного клиента
		protect::protection_t protection;
		// Если ключевой материал направления связи клиента установить не удалось
		if(!protection.start(suite, view_t(material, sizeof(material)), view_t(element, protect::block(suite))))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Накопитель, в который складывается ответ враждебного клиента
		vector <uint8_t> answered;
		// Если враждебный клиент шлёт конец упреждающих данных, которых не посылал
		if(distortion == distortion_t::FAREWELL){
			// Если конец упреждающих данных враждебного клиента отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::EARLY, view_t(nullptr, 0), answered))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Выполняем подачу ответа враждебного клиента серверу
			server.push(view_t(answered.data(), answered.size()));
			// Выводим успешность рукопожатия враждебного клиента
			return true;
		}
		// Если враждебный клиент предъявляет свою подлинность
		if(distortion == distortion_t::CONTEXT){
			// Если подлинность враждебного клиента проверкой не задана
			if((credential == nullptr) || credential->chain.empty())
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Составляемая цепочка сертификатов враждебного клиента
			message::certificate_t certificate;
			// Опознаватель запроса подлинности, набиваемый враждебным клиентом
			const uint8_t identifier[] = {0x0A, 0x0B, 0x0C, 0x0D};
			/**
			 * Раздел 4.4.2 RFC 8446 велит клиенту повторять опознаватель запроса,
			 * присланный сервером, а сервер шлёт его пустым: опознаватель, взятый
			 * с потолка, отвечает не тому запросу, который был сделан
			 */
			certificate.context = view_t(identifier, sizeof(identifier));
			// Запись цепочки сертификатов враждебного клиента
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			entry.data = view_t(credential->chain[0].data(), credential->chain[0].size());
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
			// Накопитель, в который складывается тело цепочки сертификатов
			vector <uint8_t> chain;
			// Если тело цепочки сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если цепочку сертификатов враждебного клиента отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Накопитель, в который складывается тело подписи владения ключом
			vector <uint8_t> witnessed;
			// Если подпись владения ключом враждебного клиента выработать не удалось
			if(!possession(* credential, transcript, false, witnessed))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
			// Если подпись владения ключом враждебного клиента отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::VERIFY, view_t(witnessed.data(), witnessed.size()), answered))
				// Выводим отказ рукопожатия враждебного клиента
				return false;
		}
		/**
		 * Искажением UNPROVEN клиент предъявляет сертификат без подписи владения
		 * ключом: раздел 4.4.3 RFC 8446 велит подписи идти сразу за сертификатом
		 */
		if(distortion == distortion_t::UNPROVEN){
			// Если подлинность враждебного клиента проверкой не задана
			if((credential == nullptr) || credential->chain.empty())
				// Выводим отказ ответа враждебного клиента
				return false;
			// Составляемая цепочка сертификатов враждебного клиента
			message::certificate_t certificate;
			// Запись цепочки сертификатов
			message::entry_t entry;
			// Устанавливаем тело сертификата записи цепочки
			entry.data = view_t(credential->chain[0].data(), credential->chain[0].size());
			// Добавляем запись в цепочку сертификатов
			certificate.entries.push_back(entry);
			// Составленная цепочка сертификатов
			vector <uint8_t> chain;
			// Если цепочку сертификатов составить не удалось
			if(message::build(certificate, chain) != message::error_t::NONE)
				// Выводим отказ ответа враждебного клиента
				return false;
			// Если цепочку сертификатов отправить не удалось
			if(!deliver(protection, transcript, handshake::type_t::CERTIFICATE, view_t(chain.data(), chain.size()), answered))
				// Выводим отказ ответа враждебного клиента
				return false;
		}
		// Место, в которое помещается хеш переписки рукопожатия
		uint8_t hash[schedule::SCHEDULE_SECRET];
		// Если хеш переписки рукопожатия получить не удалось
		if(transcript.digest(hash) != session::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Место, в которое помещается завершение рукопожатия клиентом
		uint8_t completed[32];
		// Если завершение рукопожатия выработать не удалось
		if(message::finished(view_t(completion, sizeof(completion)), view_t(hash, sizeof(hash)), completed) != message::error_t::NONE)
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Если завершение рукопожатия враждебного клиента отправить не удалось
		if(!deliver(protection, transcript, handshake::type_t::FINISHED, view_t(completed, sizeof(completed)), answered))
			// Выводим отказ рукопожатия враждебного клиента
			return false;
		// Выполняем подачу ответа враждебного клиента серверу
		server.push(view_t(answered.data(), answered.size()));
		// Выводим успешность рукопожатия враждебного клиента
		return true;
	}
};

#endif // __ANTS_TESTS_ADVERSARY__
