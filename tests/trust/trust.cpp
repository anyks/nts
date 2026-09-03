/**
 * @file trust.cpp
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
 * @brief Исходный файл проверок модуля доверия цепочке сертификатов
 *
 * @note Сертификаты вырабатываются самими проверками: цепочка нужна разной - и годная, и
 *       испорченная всеми теми способами, по которым доверие ей и отказывается
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <asn1/asn1.hpp>
#include <sign/gost.hpp>
#include <trust/trust.hpp>
#include <entropy/entropy.hpp>
#include <digest/streebog.hpp>
#include <curve/parameters.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Служебные объекты проверок
 *
 */
namespace {
	/**
	 * @brief Ключевая пара стороны сертификата
	 *
	 */
	typedef struct Keys {
		// Секретный ключ стороны сертификата
		vector <uint8_t> secret;
		// Запись открытого ключа стороны сертификата
		vector <uint8_t> opened;
	} keys_t;

	/**
	 * Тело расширения, записью ASN.1 не являющееся: метка набора значений объявляет
	 * длину, за которою содержимого не набирается
	 */
	const uint8_t SPOILED[3] = {0x30, 0x7F, 0x00};

	/**
	 * Разряды порчи тел объявляемых расширений: расширения объявляются по отдельности,
	 * и порча их по отдельности же нужна - заслон разбора одного расширения стоит за
	 * заслоном другого и порчею обоих разом не задевается
	 */
	enum : uint8_t {
		SPOIL_CONSTRAINTS  = 0x01, // Порча тела основных ограничений сертификата
		SPOIL_USAGE        = 0x02, // Порча тела назначения открытого ключа
		SPOIL_ALTERNATIVES = 0x04  // Порча тела дополнительных имён владельца
	};

	/**
	 * @brief Настройки вырабатываемого сертификата
	 *
	 */
	typedef struct Options {
		// Признак права издавать другие сертификаты
		bool authority;
		// Признак объявления основных ограничений сертификата
		bool constraints;
		// Признак объявления назначения открытого ключа
		bool usage;
		// Признак объявления права подписывать другие сертификаты
		bool signing;
		/**
		 * Признак порчи тела объявляемых расширений: тело расширения несёт запись
		 * ASN.1 внутри строки байтов, и запись эта приходит извне наравне со всем
		 * прочим - разбор её отказать вправе
		 */
		uint8_t spoiled;
		/**
		 * Признак отказа от записи имени владельца вовсе: сертификат, не объявивший
		 * ни общего имени, ни дополнительных имён, ни одному имени узла не отвечает
		 */
		bool unnamed;
		// Предел числа звеньев цепочки под сертификатом
		int64_t depth;
		// Начало срока действия сертификата
		int64_t before;
		// Окончание срока действия сертификата
		int64_t after;
		// Дополнительное доменное имя владельца сертификата
		string alternative;
		/**
		 * @brief Конструктор
		 *
		 */
		Options() noexcept :
		 authority(false), constraints(true), usage(true), signing(true), spoiled(0), unnamed(false),
		 depth(-1), before(1767225600), after(2082758400) {}
	} options_t;

	/**
	 * @brief Метод выработки ключевой пары стороны сертификата
	 *
	 * @param result ключевая пара, в которую помещается итог выработки
	 *
	 * @return       признак успешности выработки ключевой пары
	 *
	 */
	bool generate(keys_t & result) noexcept {
		// Эллиптическая кривая ключа стороны сертификата
		curve::curve_t curve;
		// Если кривую ключа стороны завести не удалось
		if(!curve::parameters("1.2.643.2.2.35.1", curve))
			// Выводим отказ выработки ключевой пары
			return false;
		// Секретный ключ стороны сертификата
		math::number_t number;
		// Если секретный ключ стороны выработать не удалось
		if(!entropy::number(curve.order(), number) || curve.order().zero(number))
			// Выводим отказ выработки ключевой пары
			return false;
		// Занимаем место под секретный ключ стороны
		result.secret.assign(curve.size(), 0);
		// Если секретный ключ стороны записать не удалось
		if(!curve.order().store(number, result.secret.data(), curve.size()))
			// Выводим отказ выработки ключевой пары
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если эллиптическую кривую подписи установить не удалось
		if(!gost.start(curve))
			// Выводим отказ выработки ключевой пары
			return false;
		// Если секретный ключ подписи установить не удалось
		if(!gost.secret(view_t(result.secret.data(), result.secret.size())))
			// Выводим отказ выработки ключевой пары
			return false;
		// Места, в которые помещаются координаты открытого ключа
		uint8_t x[32], y[32];
		// Если открытый ключ стороны получить не удалось
		if(!gost.key(x, y, curve.size()))
			// Выводим отказ выработки ключевой пары
			return false;
		// Занимаем место под запись открытого ключа стороны
		result.opened.assign(curve.size() * 2, 0);
		/**
		 * Выполняем разворот записи координат: раздел 4 RFC 9215 велит записывать их в
		 * сертификат от младшего байта к старшему
		 */
		for(size_t i = 0; i < curve.size(); i++){
			// Переносим очередной байт первой координаты
			result.opened[i] = x[curve.size() - i - 1];
			// Переносим очередной байт второй координаты
			result.opened[curve.size() + i] = y[curve.size() - i - 1];
		}
		// Выводим успешность выработки ключевой пары
		return true;
	}
	/**
	 * @brief Метод составления записи имени стороны сертификата
	 *
	 * @param writer составитель записи сертификата
	 * @param name   записываемое имя стороны сертификата
	 *
	 * @return       признак успешности составления записи имени
	 *
	 */
	bool title(asn1::writer_t & writer, const string & name) noexcept {
		// Открываем набор записей имени стороны сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи имени
			return false;
		// Открываем множество свойств имени стороны
		if(!writer.open(asn1::tag_t::SET))
			// Выводим отказ составления записи имени
			return false;
		// Открываем набор записи свойства имени
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи имени
			return false;
		// Записываем опознаватель свойства общего имени
		if(!writer.oid("2.5.4.3"))
			// Выводим отказ составления записи имени
			return false;
		// Записываем значение общего имени стороны
		if(!writer.text(asn1::tag_t::UTF8_STRING, name))
			// Выводим отказ составления записи имени
			return false;
		// Закрываем набор записи свойства имени
		if(!writer.close())
			// Выводим отказ составления записи имени
			return false;
		// Закрываем множество свойств имени стороны
		if(!writer.close())
			// Выводим отказ составления записи имени
			return false;
		// Выводим итог закрытия набора записей имени стороны
		return writer.close();
	}
	/**
	 * @brief Метод составления расширений сертификата
	 *
	 * @param writer  составитель записи сертификата
	 * @param options настройки вырабатываемого сертификата
	 *
	 * @return        признак успешности составления расширений
	 *
	 */
	bool extensions(asn1::writer_t & writer, const options_t & options) noexcept {
		// Открываем запись расширений сертификата
		if(!writer.open(asn1::cls_t::CONTEXT, 3))
			// Выводим отказ составления расширений
			return false;
		// Открываем набор расширений сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления расширений
			return false;
		// Если основные ограничения сертификата объявляются
		if(options.constraints){
			// Составитель записи основных ограничений сертификата
			asn1::writer_t item;
			// Открываем набор записи основных ограничений
			if(!item.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ составления расширений
				return false;
			// Записываем признак права издавать другие сертификаты
			if(options.authority && !item.boolean(true))
				// Выводим отказ составления расширений
				return false;
			// Записываем предел числа звеньев цепочки под сертификатом
			if((options.depth >= 0) && !item.integer(options.depth))
				// Выводим отказ составления расширений
				return false;
			// Закрываем набор записи основных ограничений
			if(!item.close())
				// Выводим отказ составления расширений
				return false;
			// Открываем набор записи расширения сертификата
			if(!writer.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ составления расширений
				return false;
			// Записываем опознаватель расширения основных ограничений
			if(!writer.oid("2.5.29.19"))
				// Выводим отказ составления расширений
				return false;
			// Записываем значение расширения основных ограничений
			if(!writer.octets(((options.spoiled & SPOIL_CONSTRAINTS) != 0) ? view_t(SPOILED, sizeof(SPOILED)) : item.data()))
				// Выводим отказ составления расширений
				return false;
			// Закрываем набор записи расширения сертификата
			if(!writer.close())
				// Выводим отказ составления расширений
				return false;
		}
		// Если назначение открытого ключа объявляется
		if(options.usage){
			// Разряды назначения открытого ключа сертификата
			/**
			 * Раздел 4.2.1.3 RFC 5280 отводит праву подписывать другие сертификаты
			 * пятый разряд назначения ключа. Признак объявления его заведён отдельно
			 * от права издавать сертификаты: основные ограничения и назначение ключа
			 * объявляются разными расширениями и разойтись между собою вправе
			 */
			const uint8_t bits[1] = {static_cast <uint8_t> ((options.authority && options.signing) ? 0x04 : 0x80)};
			// Составитель записи назначения открытого ключа
			asn1::writer_t item;
			// Записываем разряды назначения открытого ключа
			if(!item.bits(view_t(bits, sizeof(bits)), ((options.authority && options.signing) ? 2 : 7)))
				// Выводим отказ составления расширений
				return false;
			// Открываем набор записи расширения сертификата
			if(!writer.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ составления расширений
				return false;
			// Записываем опознаватель расширения назначения ключа
			if(!writer.oid("2.5.29.15"))
				// Выводим отказ составления расширений
				return false;
			// Записываем значение расширения назначения ключа
			if(!writer.octets(((options.spoiled & SPOIL_USAGE) != 0) ? view_t(SPOILED, sizeof(SPOILED)) : item.data()))
				// Выводим отказ составления расширений
				return false;
			// Закрываем набор записи расширения сертификата
			if(!writer.close())
				// Выводим отказ составления расширений
				return false;
		}
		// Если дополнительное имя владельца объявляется
		if(!options.alternative.empty()){
			// Составитель записи дополнительных имён владельца
			asn1::writer_t item;
			// Открываем набор записи дополнительных имён
			if(!item.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ составления расширений
				return false;
			// Получаем записываемое доменное имя владельца
			const view_t name(reinterpret_cast <const uint8_t *> (options.alternative.data()), options.alternative.size());
			// Записываем доменное имя владельца сертификата
			if(!item.element(asn1::cls_t::CONTEXT, false, 2, name))
				// Выводим отказ составления расширений
				return false;
			// Закрываем набор записи дополнительных имён
			if(!item.close())
				// Выводим отказ составления расширений
				return false;
			// Открываем набор записи расширения сертификата
			if(!writer.open(asn1::tag_t::SEQUENCE))
				// Выводим отказ составления расширений
				return false;
			// Записываем опознаватель расширения дополнительных имён
			if(!writer.oid("2.5.29.17"))
				// Выводим отказ составления расширений
				return false;
			// Записываем значение расширения дополнительных имён
			if(!writer.octets(((options.spoiled & SPOIL_ALTERNATIVES) != 0) ? view_t(SPOILED, sizeof(SPOILED)) : item.data()))
				// Выводим отказ составления расширений
				return false;
			// Закрываем набор записи расширения сертификата
			if(!writer.close())
				// Выводим отказ составления расширений
				return false;
		}
		// Закрываем набор расширений сертификата
		if(!writer.close())
			// Выводим отказ составления расширений
			return false;
		// Выводим итог закрытия записи расширений сертификата
		return writer.close();
	}
	/**
	 * @brief Метод выработки сертификата стороны связи
	 *
	 * @param subject имя владельца вырабатываемого сертификата
	 * @param issuer  имя издателя вырабатываемого сертификата
	 * @param keys    ключевая пара владельца сертификата
	 * @param signer  секретный ключ издателя сертификата
	 * @param options настройки вырабатываемого сертификата
	 * @param result  запись, в которую помещается сертификат
	 *
	 * @return        признак успешности выработки сертификата
	 *
	 */
	bool make(const string & subject, const string & issuer, const keys_t & keys, const vector <uint8_t> & signer, const options_t & options, vector <uint8_t> & result) noexcept {
		// Эллиптическая кривая подписи сертификата
		curve::curve_t curve;
		// Если кривую подписи сертификата завести не удалось
		if(!curve::parameters("1.2.643.2.2.35.1", curve))
			// Выводим отказ выработки сертификата
			return false;
		// Составитель записи открытого ключа владельца
		asn1::writer_t key;
		// Если запись открытого ключа составить не удалось
		if(!key.octets(view_t(keys.opened.data(), keys.opened.size())))
			// Выводим отказ выработки сертификата
			return false;
		// Составитель тела вырабатываемого сертификата
		asn1::writer_t body;
		// Открываем набор записей тела сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем запись издания сертификата
		if(!body.open(asn1::cls_t::CONTEXT, 0))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем издание сертификата
		if(!body.integer(2))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем запись издания сертификата
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Записываем порядковый номер сертификата
		if(!body.integer(1))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор записи алгоритма подписи сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем опознаватель алгоритма подписи сертификата
		if(!body.oid("1.2.643.7.1.1.3.2"))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записи алгоритма подписи сертификата
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Если имя издателя сертификата записать не удалось
		if(!title(body, issuer))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор записи срока действия сертификата
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем начало срока действия сертификата
		if(!body.time(asn1::tag_t::UTC_TIME, options.before))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем окончание срока действия сертификата
		if(!body.time(asn1::tag_t::UTC_TIME, options.after))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записи срока действия сертификата
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Если имя владельца сертификата записать не удалось
		if(!(options.unnamed ? (body.open(asn1::tag_t::SEQUENCE) && body.close()) : title(body, subject)))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор сведений об открытом ключе
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор записи алгоритма открытого ключа
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем опознаватель алгоритма открытого ключа
		if(!body.oid("1.2.643.7.1.1.1.1"))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор настроек алгоритма открытого ключа
		if(!body.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем опознаватель набора параметров кривой
		if(!body.oid("1.2.643.2.2.35.1"))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор настроек алгоритма открытого ключа
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записи алгоритма открытого ключа
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Записываем разряды открытого ключа владельца сертификата
		if(!body.bits(key.data()))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор сведений об открытом ключе
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Если расширения сертификата составить не удалось
		if(!extensions(body, options))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записей тела сертификата
		if(!body.close())
			// Выводим отказ выработки сертификата
			return false;
		// Получаем составленное тело сертификата
		const view_t tbs = body.data();
		// Место, в которое помещается хеш тела сертификата
		uint8_t hash[32];
		// Если хеш тела сертификата выработать не удалось
		if(!digest::streebog(digest::type_t::SHORT, tbs, hash, sizeof(hash), digest::order_t::VECTOR))
			// Выводим отказ выработки сертификата
			return false;
		// Объект модуля электронной подписи
		sign::gost_t gost;
		// Если эллиптическую кривую подписи установить не удалось
		if(!gost.start(curve))
			// Выводим отказ выработки сертификата
			return false;
		// Получаем секретный ключ, которым подписывается сертификат
		const vector <uint8_t> & secret = (signer.empty() ? keys.secret : signer);
		// Если секретный ключ издателя установить не удалось
		if(!gost.secret(view_t(secret.data(), secret.size())))
			// Выводим отказ выработки сертификата
			return false;
		// Место, в которое помещается подпись тела сертификата
		uint8_t signature[math::NUMBER_SIZE * 2];
		// Если подпись тела сертификата выработать не удалось
		if(!gost.make(view_t(hash, sizeof(hash)), signature))
			// Выводим отказ выработки сертификата
			return false;
		// Место, в которое помещается подпись в записи сертификата
		uint8_t reversed[64];
		/**
		 * Выполняем перестановку частей подписи: раздел 2 RFC 9215 велит записывать в
		 * сертификат сперва число s, а затем число r
		 */
		::memcpy(reversed, signature + curve.size(), curve.size());
		// Переносим вторую часть подписи сертификата
		::memcpy(reversed + curve.size(), signature, curve.size());
		// Разборщик составленного тела сертификата
		asn1::Reader reader(tbs);
		// Разбираемый элемент тела сертификата
		asn1::element_t item;
		// Если составленное тело сертификата разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим отказ выработки сертификата
			return false;
		// Составитель записи вырабатываемого сертификата
		asn1::writer_t writer;
		// Открываем набор записей сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем тело вырабатываемого сертификата
		if(!writer.element(asn1::cls_t::UNIVERSAL, true, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), item.content))
			// Выводим отказ выработки сертификата
			return false;
		// Открываем набор записи алгоритма подписи сертификата
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ выработки сертификата
			return false;
		// Записываем опознаватель алгоритма подписи сертификата
		if(!writer.oid("1.2.643.7.1.1.3.2"))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записи алгоритма подписи сертификата
		if(!writer.close())
			// Выводим отказ выработки сертификата
			return false;
		// Записываем подпись тела сертификата
		if(!writer.bits(view_t(reversed, curve.size() * 2)))
			// Выводим отказ выработки сертификата
			return false;
		// Закрываем набор записей сертификата
		if(!writer.close())
			// Выводим отказ выработки сертификата
			return false;
		// Получаем составленную запись сертификата
		const view_t data = writer.data();
		// Выполняем перенос составленной записи сертификата
		result.assign(data.data, data.data + data.size);
		// Выводим успешность выработки сертификата
		return true;
	}
	/**
	 * @brief Миг проверки цепочки сертификатов
	 *
	 */
	static const int64_t MOMENT = 1800000000;
};

/**
 * Проверка доверия годной цепочке сертификатов
 */
TEST(TrustTest, Chain){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата издателя
	options_t options;
	// Устанавливаем право издавать другие сертификаты
	options.authority = true;
	// Запись сертификата издателя цепочки
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), options, root));
	// Настройки сертификата владельца
	options_t settings;
	// Устанавливаем дополнительное доменное имя владельца
	settings.alternative = "anyks.com";
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного издателем
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, settings, leaf));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата издателя в запас доверенных
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Проверяем число доверенных сертификатов запаса
	ASSERT_EQ(store.size(), static_cast <size_t> (1));
	// Проверяемая цепочка сертификатов
	const vector <vector <uint8_t>> chain = {leaf};
	// Проверяем доверие цепочке сертификатов
	ASSERT_EQ(trust::verify(chain, store, MOMENT), trust::error_t::NONE);
	// Проверяемая цепочка сертификатов вместе с издателем
	const vector <vector <uint8_t>> full = {leaf, root};
	// Проверяем доверие цепочке сертификатов вместе с издателем
	ASSERT_EQ(trust::verify(full, store, MOMENT), trust::error_t::NONE);
	// Проверяем сличение имени узла с именами сертификата
	ASSERT_EQ(trust::belongs(view_t(leaf.data(), leaf.size()), "anyks.com"), trust::error_t::NONE);
	// Проверяем сличение имени узла без учёта регистра
	ASSERT_EQ(trust::belongs(view_t(leaf.data(), leaf.size()), "ANYKS.com"), trust::error_t::NONE);
	// Проверяем отказ сличения чужого имени узла
	ASSERT_EQ(trust::belongs(view_t(leaf.data(), leaf.size()), "example.com"), trust::error_t::NAME);
}

/**
 * Проверка отвержения цепочки без доверенного издателя
 */
TEST(TrustTest, Authority){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата издателя
	options_t options;
	// Устанавливаем право издавать другие сертификаты
	options.authority = true;
	// Запись сертификата издателя цепочки
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), options, root));
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного издателем
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, options_t (), leaf));
	// Пустой запас доверенных сертификатов
	trust::store_t store;
	// Проверяемая цепочка сертификатов
	const vector <vector <uint8_t>> chain = {leaf};
	// Проверяем отказ доверия цепочке при пустом запасе доверенных
	ASSERT_EQ(trust::verify(chain, store, MOMENT), trust::error_t::AUTHORITY);
	// Ключевая пара чужого издателя
	keys_t alien;
	// Выполняем выработку ключевой пары чужого издателя
	ASSERT_TRUE(generate(alien));
	// Запись сертификата чужого издателя
	vector <uint8_t> foreign;
	// Выполняем выработку самоподписанного сертификата чужого издателя
	ASSERT_TRUE(make("alien root", "alien root", alien, vector <uint8_t> (), options, foreign));
	// Выполняем добавление чужого сертификата в запас доверенных
	ASSERT_TRUE(store.add(view_t(foreign.data(), foreign.size())));
	// Проверяем отказ доверия цепочке чужого издателя
	ASSERT_EQ(trust::verify(chain, store, MOMENT), trust::error_t::AUTHORITY);
	// Проверяем доверие самому сертификату издателя, лежащему в запасе
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {foreign}, store, MOMENT), trust::error_t::NONE);
}

/**
 * Проверка отвержения цепочки с испорченным звеном
 */
TEST(TrustTest, Reject){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата издателя
	options_t options;
	// Устанавливаем право издавать другие сертификаты
	options.authority = true;
	// Запись сертификата издателя цепочки
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), options, root));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата издателя в запас доверенных
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Настройки сертификата с истёкшим сроком действия
	options_t expired;
	// Устанавливаем начало срока действия сертификата
	expired.before = 1600000000;
	// Устанавливаем окончание срока действия сертификата
	expired.after = 1700000000;
	// Запись сертификата с истёкшим сроком действия
	vector <uint8_t> outdated;
	// Выполняем выработку сертификата с истёкшим сроком действия
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, expired, outdated));
	// Проверяем отказ доверия сертификату с истёкшим сроком действия
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {outdated}, store, MOMENT), trust::error_t::EXPIRED);
	/**
	 * Срок действия имеет две границы, и обе отвергают сертификат по отдельности:
	 * сертификат, чей срок ещё не наступил, негоден ровно так же, как истёкший
	 */
	options_t upcoming;
	// Устанавливаем начало срока действия сертификата позже проверяемого мига
	upcoming.before = 1900000000;
	// Устанавливаем окончание срока действия сертификата
	upcoming.after = 2000000000;
	// Запись сертификата, срок действия которого ещё не наступил
	vector <uint8_t> premature;
	// Выполняем выработку сертификата с ненаступившим сроком действия
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, upcoming, premature));
	// Проверяем отказ доверия сертификату с ненаступившим сроком действия
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {premature}, store, MOMENT), trust::error_t::EXPIRED);
	// Запись сертификата, изданного не тем издателем
	vector <uint8_t> alien;
	// Выполняем выработку сертификата с чужим именем издателя
	ASSERT_TRUE(make("anyks.com", "alien root", subject, issuer.secret, options_t (), alien));
	// Проверяем отказ доверия цепочке с разошедшимся издателем
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {alien, root}, store, MOMENT), trust::error_t::ISSUER);
	// Запись сертификата, подписанного чужим ключом
	vector <uint8_t> forged;
	// Выполняем выработку сертификата, подписанного ключом владельца
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, subject.secret, options_t (), forged));
	// Проверяем отказ доверия сертификату с несошедшейся подписью
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {forged}, store, MOMENT), trust::error_t::AUTHORITY);
	// Проверяем отказ доверия пустой цепочке сертификатов
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> (), store, MOMENT), trust::error_t::EMPTY);
	// Испорченная запись сертификата владельца
	vector <uint8_t> corrupted = root;
	// Портим запись сертификата владельца
	corrupted[corrupted.size() / 2] ^= 0xFF;
	// Проверяем отказ доверия испорченной записи сертификата
	ASSERT_NE(trust::verify(vector <vector <uint8_t>> {corrupted}, store, MOMENT), trust::error_t::NONE);
	// Проверяем отказ добавления испорченной записи в запас доверенных
	ASSERT_FALSE(store.add(view_t(corrupted.data(), 4)));
	/**
	 * Непереданная запись при заявленной длине - оплошность потребителя. Переданность
	 * и длина сверяются РАЗНЫМИ половинами условия, и всякая отвергает запись в
	 * одиночку
	 */
	ASSERT_FALSE(store.add(view_t(nullptr, root.size())));
	// Проверяем отказ добавления записи нулевой длины в запас доверенных
	ASSERT_FALSE(store.add(view_t(root.data(), 0)));
	// Запись самоподписанного сертификата постороннего издателя
	vector <uint8_t> outsider;
	/**
	 * Запас сличается с цепочкой сперва по длине записи, и совпадение длин при
	 * расхождении содержимого доверием обернуться не вправе. Длина записи гуляет от
	 * вида подписи, оттого посторонний сертификат вырабатывается до совпадения длин
	 */
	for(size_t i = 0; (i < 32) && (outsider.size() != root.size()); i++){
		// Ключевая пара постороннего издателя, доверием не объявленного
		keys_t stranger;
		// Выполняем выработку ключевой пары постороннего издателя
		ASSERT_TRUE(generate(stranger));
		// Выполняем выработку самоподписанного сертификата постороннего издателя
		ASSERT_TRUE(make("anyks main", "anyks main", stranger, vector <uint8_t> (), options, outsider));
	}
	// Проверяем совпадение длин записей доверенного и постороннего издателей
	ASSERT_EQ(outsider.size(), root.size());
	// Проверяем отказ доверия самоподписанному сертификату постороннего издателя
	ASSERT_NE(trust::verify(vector <vector <uint8_t>> {outsider}, store, MOMENT), trust::error_t::NONE);
}

/**
 * Проверка доверия издателю без объявленного назначения ключа
 */
TEST(TrustTest, Unstated){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата издателя с правом издавать сертификаты
	options_t options;
	// Объявляем принадлежность издателя удостоверяющему центру
	options.authority = true;
	// Отменяем объявление назначения открытого ключа сертификата
	options.usage = false;
	// Запись сертификата издателя цепочки
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), options, root));
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного издателем
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, options_t (), leaf));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата издателя в запас доверенных
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	/**
	 * Раздел 4.2.1.3 RFC 5280 кладёт назначение открытого ключа расширением
	 * необязательным: не объявив его, издатель ничего себе не запретил, и права
	 * издавать сертификаты, данного основными ограничениями, оно не отменяет
	 */
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, root}, store, MOMENT), trust::error_t::NONE);
}

/**
 * Проверка права издавать другие сертификаты
 */
TEST(TrustTest, Constraint){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата издателя без права издавать сертификаты
	options_t options;
	// Запись сертификата издателя цепочки
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), options, root));
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного издателем
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, options_t (), leaf));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата издателя в запас доверенных
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	/**
	 * Сертификат без права издавать другие сертификаты издателем цепочки быть не
	 * вправе: доверие ему объявлено, а вот подписанному им - нет
	 */
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf}, store, MOMENT), trust::error_t::AUTHORITY);
	// Проверяем отказ доверия цепочке с издателем без права издавать
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, root}, store, MOMENT), trust::error_t::CONSTRAINT);
	// Настройки сертификата издателя без объявленных ограничений
	options_t silent;
	// Отменяем объявление основных ограничений сертификата
	silent.constraints = false;
	// Запись сертификата издателя без объявленных ограничений
	vector <uint8_t> quiet;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("quiet root", "quiet root", issuer, vector <uint8_t> (), silent, quiet));
	// Запись сертификата владельца, изданного молчаливым издателем
	vector <uint8_t> issued;
	// Выполняем выработку сертификата владельца
	ASSERT_TRUE(make("anyks.com", "quiet root", subject, issuer.secret, options_t (), issued));
	/**
	 * Отсутствие расширения умолчанием в пользу издателя не считается: раздел
	 * 4.2.1.9 RFC 5280 велит объявлять право издавать сертификаты явно
	 */
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {issued, quiet}, store, MOMENT), trust::error_t::CONSTRAINT);
}

/**
 * Проверка сличения имени узла со звёздочкой
 */
TEST(TrustTest, Wildcard){
	// Ключевая пара владельца сертификата
	keys_t subject;
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Настройки сертификата владельца
	options_t options;
	// Устанавливаем дополнительное доменное имя владельца со звёздочкой
	options.alternative = "*.anyks.com";
	// Запись сертификата владельца
	vector <uint8_t> leaf;
	// Выполняем выработку самоподписанного сертификата владельца
	ASSERT_TRUE(make("anyks.com", "anyks.com", subject, vector <uint8_t> (), options, leaf));
	// Получаем запись сличаемого сертификата
	const view_t certificate(leaf.data(), leaf.size());
	// Проверяем сличение имени узла со звёздочкой
	ASSERT_EQ(trust::belongs(certificate, "www.anyks.com"), trust::error_t::NONE);
	/**
	 * Звёздочка отвечает лишь одной части имени: без этого правила имя вида
	 * «*.anyks.com» отвечало бы и узлу «www.dev.anyks.com»
	 */
	ASSERT_EQ(trust::belongs(certificate, "www.dev.anyks.com"), trust::error_t::NAME);
	// Проверяем отказ сличения имени самой области с именем со звёздочкой
	ASSERT_EQ(trust::belongs(certificate, "anyks.com"), trust::error_t::NAME);
	// Проверяем отказ сличения пустого имени узла
	ASSERT_EQ(trust::belongs(certificate, ""), trust::error_t::NAME);
	// Настройки сертификата без дополнительных имён владельца
	options_t settings;
	// Запись сертификата без дополнительных имён владельца
	vector <uint8_t> common;
	// Выполняем выработку самоподписанного сертификата владельца
	ASSERT_TRUE(make("anyks.com", "anyks.com", subject, vector <uint8_t> (), settings, common));
	/**
	 * Общее имя владельца берётся лишь тогда, когда дополнительных имён нет вовсе:
	 * раздел 6.4.4 RFC 6125
	 */
	ASSERT_EQ(trust::belongs(view_t(common.data(), common.size()), "anyks.com"), trust::error_t::NONE);
	// Проверяем отказ сличения чужого имени узла с общим именем владельца
	ASSERT_EQ(trust::belongs(view_t(common.data(), common.size()), "example.com"), trust::error_t::NAME);
	// Запись сертификата с пустым общим именем владельца
	vector <uint8_t> nameless;
	// Выполняем выработку сертификата с пустым общим именем владельца
	ASSERT_TRUE(make("", "anyks.com", subject, vector <uint8_t> (), settings, nameless));
	/**
	 * Пустое имя сертификата не отвечает никакому имени узла: имя сертификата и имя
	 * узла сверяются РАЗНЫМИ половинами условия, и всякая отвергает сличение в
	 * одиночку
	 */
	ASSERT_EQ(trust::belongs(view_t(nameless.data(), nameless.size()), "anyks.com"), trust::error_t::NAME);
}

/**
 * Проверка предела числа звеньев цепочки сертификатов
 */
TEST(TrustTest, Deepness){
	// Ключевые пары корня, промежуточного звена и владельца цепочки
	keys_t root, middle, subject;
	// Выполняем выработку ключевой пары корня цепочки
	ASSERT_TRUE(generate(root));
	// Выполняем выработку ключевой пары промежуточного звена
	ASSERT_TRUE(generate(middle));
	// Выполняем выработку ключевой пары владельца цепочки
	ASSERT_TRUE(generate(subject));
	/**
	 * Раздел 4.2.1.9 RFC 5280: предел числа звеньев считает промежуточные звенья под
	 * сертификатом, и ноль его значит, что издавать корень вправе один лишь
	 * сертификат владельца, но никак не другой удостоверяющий центр
	 */
	options_t strict;
	// Наделяем корень правом издавать другие сертификаты
	strict.authority = true;
	// Объявляем пределом числа звеньев цепочки ноль
	strict.depth = 0;
	// Запись сертификата корня цепочки
	vector <uint8_t> anchor;
	// Выполняем выработку самоподписанного сертификата корня цепочки
	ASSERT_TRUE(make("strict root", "strict root", root, vector <uint8_t> (), strict, anchor));
	// Настройки промежуточного звена цепочки
	options_t authorized;
	// Наделяем промежуточное звено правом издавать другие сертификаты
	authorized.authority = true;
	// Запись сертификата промежуточного звена цепочки
	vector <uint8_t> intermediate;
	// Выполняем выработку сертификата промежуточного звена, изданного корнем
	ASSERT_TRUE(make("strict middle", "strict root", middle, root.secret, authorized, intermediate));
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного промежуточным звеном
	ASSERT_TRUE(make("anyks.com", "strict middle", subject, middle.secret, options_t (), leaf));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата корня в запас доверенных
	ASSERT_TRUE(store.add(view_t(anchor.data(), anchor.size())));
	// Проверяем отказ доверия цепочке, вышедшей за предел числа звеньев
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, intermediate, anchor}, store, MOMENT), trust::error_t::CONSTRAINT);
	// Запись сертификата владельца, изданного корнем напрямую
	vector <uint8_t> direct;
	// Выполняем выработку сертификата владельца, изданного корнем
	ASSERT_TRUE(make("anyks.com", "strict root", subject, root.secret, options_t (), direct));
	// Проверяем доверие цепочке, в предел числа звеньев уложившейся
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {direct, anchor}, store, MOMENT), trust::error_t::NONE);
	// Настройки корня цепочки, дозволяющего одно промежуточное звено
	options_t lenient;
	// Наделяем корень правом издавать другие сертификаты
	lenient.authority = true;
	// Объявляем пределом числа звеньев цепочки единицу
	lenient.depth = 1;
	// Запись сертификата корня, дозволяющего промежуточное звено
	vector <uint8_t> spacious;
	// Выполняем выработку самоподписанного сертификата корня цепочки
	ASSERT_TRUE(make("lenient root", "lenient root", root, vector <uint8_t> (), lenient, spacious));
	// Запись сертификата промежуточного звена под просторным корнем
	vector <uint8_t> linked;
	// Выполняем выработку сертификата промежуточного звена
	ASSERT_TRUE(make("lenient middle", "lenient root", middle, root.secret, authorized, linked));
	// Запись сертификата владельца под просторным корнем
	vector <uint8_t> issued;
	// Выполняем выработку сертификата владельца
	ASSERT_TRUE(make("anyks.com", "lenient middle", subject, middle.secret, options_t (), issued));
	// Выполняем добавление просторного корня в запас доверенных
	ASSERT_TRUE(store.add(view_t(spacious.data(), spacious.size())));
	// Проверяем доверие цепочке, в дозволенное промежуточное звено уложившейся
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {issued, linked, spacious}, store, MOMENT), trust::error_t::NONE);
}

/**
 * @brief Проверка сверки звеньев цепочки сертификатов между собою
 *
 * @note Цепочка длиною в одно звено сверки звеньев не задевает вовсе: проверки её
 *       стерегли лишь связь сертификата с запасом доверенных, а сама цепочка
 *       оставалась непроверенной
 *
 */
TEST(TrustTest, Interlinked){
	// Ключевые пары корня, промежуточного звена, владельца и постороннего
	keys_t root, middle, subject, stranger;
	// Выполняем выработку ключевой пары корня цепочки
	ASSERT_TRUE(generate(root));
	// Выполняем выработку ключевой пары промежуточного звена
	ASSERT_TRUE(generate(middle));
	// Выполняем выработку ключевой пары владельца цепочки
	ASSERT_TRUE(generate(subject));
	// Выполняем выработку ключевой пары постороннего издателя
	ASSERT_TRUE(generate(stranger));
	// Настройки сертификата, наделённого правом издавать другие сертификаты
	options_t authorized;
	// Наделяем сертификат правом издавать другие сертификаты
	authorized.authority = true;
	// Запись сертификата корня цепочки
	vector <uint8_t> anchor;
	// Выполняем выработку самоподписанного сертификата корня цепочки
	ASSERT_TRUE(make("chain root", "chain root", root, vector <uint8_t> (), authorized, anchor));
	// Запись сертификата промежуточного звена цепочки
	vector <uint8_t> intermediate;
	// Выполняем выработку сертификата промежуточного звена, изданного корнем
	ASSERT_TRUE(make("chain middle", "chain root", middle, root.secret, authorized, intermediate));
	// Запись сертификата владельца цепочки
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного промежуточным звеном
	ASSERT_TRUE(make("anyks.com", "chain middle", subject, middle.secret, options_t (), leaf));
	// Запас доверенных сертификатов
	trust::store_t store;
	// Выполняем добавление сертификата корня в запас доверенных
	ASSERT_TRUE(store.add(view_t(anchor.data(), anchor.size())));
	// Проверяем доверие цепочке из трёх звеньев
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, intermediate, anchor}, store, MOMENT), trust::error_t::NONE);
	/**
	 * Подпись всякого звена сверяется ключом звена над ним: промежуточное звено,
	 * подписанное посторонним ключом, доверием обернуться не вправе, хотя бы имя
	 * издателя у него и сходилось с именем корня
	 */
	vector <uint8_t> forged;
	// Выполняем выработку промежуточного звена, подписанного посторонним ключом
	ASSERT_TRUE(make("chain middle", "chain root", middle, stranger.secret, authorized, forged));
	// Проверяем отказ доверия цепочке с несошедшейся подписью промежуточного звена
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, forged, anchor}, store, MOMENT), trust::error_t::SIGNATURE);
	/**
	 * Имя издателя всякого звена сверяется с именем владельца звена над ним: разрыв
	 * имён посреди цепочки означает цепочку, звеньями не связанную
	 */
	vector <uint8_t> renamed;
	// Выполняем выработку промежуточного звена с чужим именем владельца
	ASSERT_TRUE(make("other middle", "chain root", middle, root.secret, authorized, renamed));
	// Проверяем отказ доверия цепочке с разошедшимися именами звеньев
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, renamed, anchor}, store, MOMENT), trust::error_t::ISSUER);
	/**
	 * Раздел 4.2.1.3 RFC 5280 велит издателю нести право подписывать другие
	 * сертификаты. Право это объявляется назначением ключа, отдельным расширением
	 * от основных ограничений, и одних лишь ограничений издателю мало
	 */
	options_t unsigning;
	// Наделяем сертификат правом издавать другие сертификаты
	unsigning.authority = true;
	// Снимаем с сертификата право подписывать другие сертификаты
	unsigning.signing = false;
	// Ключевая пара корня, не вправе подписывать другие сертификаты
	keys_t barren;
	// Выполняем выработку ключевой пары корня без права подписи
	ASSERT_TRUE(generate(barren));
	// Запись сертификата корня, не вправе подписывать другие сертификаты
	vector <uint8_t> unsigned_;
	// Выполняем выработку корня без права подписывать другие сертификаты
	ASSERT_TRUE(make("barren root", "barren root", barren, vector <uint8_t> (), unsigning, unsigned_));
	// Запись сертификата владельца, изданного корнем без права подписи
	vector <uint8_t> issued;
	// Выполняем выработку сертификата владельца, изданного таким корнем
	ASSERT_TRUE(make("anyks.com", "barren root", subject, barren.secret, options_t (), issued));
	// Запас доверенных сертификатов, несущий корень без права подписи
	trust::store_t barrens;
	// Выполняем добавление корня без права подписи в запас доверенных
	ASSERT_TRUE(barrens.add(view_t(unsigned_.data(), unsigned_.size())));
	/**
	 * Отказ приходит отсутствием издателя в запасе, а не нарушением ограничений:
	 * сертификат без права подписывать другие в издатели не берётся вовсе, и
	 * запас доверенных отвечает так, будто издателя в нём нет
	 */
	ASSERT_EQ(trust::verify(vector <vector <uint8_t>> {issued}, barrens, MOMENT), trust::error_t::AUTHORITY);
	/**
	 * Длина цепочки ограничена сверху: цепочка длиннее дозволенной отвергается до
	 * всякого её разбора, ибо разбор такой цепочки - это уже работа впустую
	 */
	vector <vector <uint8_t>> lengthy;
	/**
	 * Выполняем набор цепочки длиннее дозволенной
	 */
	for(size_t i = 0; i <= trust::TRUST_DEPTH; i++)
		// Добавляем в цепочку очередное её звено
		lengthy.push_back(leaf);
	// Проверяем отказ доверия цепочке длиннее дозволенной
	ASSERT_EQ(trust::verify(lengthy, store, MOMENT), trust::error_t::DEPTH);
}

/**
 * @brief Проверка сличения имени узла с именами сертификата
 *
 */
TEST(TrustTest, Belonging){
	// Ключевые пары издателя и владельца сертификатов
	keys_t issuer, subject;
	// Выполняем выработку ключевой пары издателя
	ASSERT_TRUE(generate(issuer));
	// Выполняем выработку ключевой пары владельца
	ASSERT_TRUE(generate(subject));
	// Запись сертификата, разобрать которую нельзя вовсе
	const vector <uint8_t> garbage(64, 0x41);
	// Проверяем отказ сличения имени узла с неразбираемой записью
	EXPECT_EQ(trust::belongs(view_t(garbage.data(), garbage.size()), "anyks.com"), trust::error_t::PARSE);
	/**
	 * Тело расширения дополнительных имён несёт запись ASN.1 внутри строки байтов, и
	 * запись эта приходит извне: разбор её отказать вправе
	 */
	options_t spoiled;
	// Портим тело объявляемых расширений сертификата
	spoiled.spoiled = SPOIL_ALTERNATIVES;
	// Устанавливаем дополнительное доменное имя владельца сертификата
	spoiled.alternative = "anyks.com";
	// Запись сертификата с порченым телом расширений
	vector <uint8_t> broken;
	// Выполняем выработку сертификата с порченым телом расширений
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, spoiled, broken));
	// Проверяем отказ сличения имени узла при порченом расширении имён
	EXPECT_EQ(trust::belongs(view_t(broken.data(), broken.size()), "anyks.com"), trust::error_t::PARSE);
	/**
	 * Звёздочка отвечает лишь одной части имени узла: имя, из одной части и
	 * состоящее, ей не отвечает вовсе, иначе имя вида «*.com» отвечало бы всякому
	 * узлу верхней области имён
	 */
	options_t wildcard;
	// Устанавливаем дополнительное имя владельца со звёздочкой
	wildcard.alternative = "*.anyks.com";
	// Запись сертификата с именем владельца со звёздочкой
	vector <uint8_t> covered;
	// Выполняем выработку сертификата с именем владельца со звёздочкой
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, wildcard, covered));
	// Проверяем схождение имени узла из двух частей с именем со звёздочкой
	EXPECT_EQ(trust::belongs(view_t(covered.data(), covered.size()), "www.anyks.com"), trust::error_t::NONE);
	// Проверяем несовпадение имени узла из одной части с именем со звёздочкой
	EXPECT_EQ(trust::belongs(view_t(covered.data(), covered.size()), "localhost"), trust::error_t::NAME);
	// Проверяем отказ сличения непереданного имени узла
	EXPECT_EQ(trust::belongs(view_t(covered.data(), covered.size()), ""), trust::error_t::NAME);
	/**
	 * Сертификат, не объявивший ни дополнительных имён, ни общего имени владельца,
	 * ни одному имени узла не отвечает: сличать нечего
	 */
	options_t nameless;
	// Отказываемся от записи имени владельца сертификата вовсе
	nameless.unnamed = true;
	// Запись сертификата без имени владельца вовсе
	vector <uint8_t> anonymous;
	// Выполняем выработку сертификата без имени владельца
	ASSERT_TRUE(make("", "anyks root", subject, issuer.secret, nameless, anonymous));
	// Проверяем отказ сличения имени узла с сертификатом без имён владельца
	EXPECT_EQ(trust::belongs(view_t(anonymous.data(), anonymous.size()), "anyks.com"), trust::error_t::NAME);
	/**
	 * Запас доверенных выдаёт записи по номеру, и номер за его пределами отвечает
	 * пустою записью, а не выходом за поданную область байтов
	 */
	trust::store_t store;
	// Проверяем пустоту записи, запрошенной у пустого запаса доверенных
	EXPECT_EQ(store.get(0).data, nullptr);
	// Настройки сертификата издателя цепочки
	options_t authorized;
	// Наделяем сертификат правом издавать другие сертификаты
	authorized.authority = true;
	// Запись самоподписанного сертификата издателя
	vector <uint8_t> root;
	// Выполняем выработку самоподписанного сертификата издателя
	ASSERT_TRUE(make("anyks root", "anyks root", issuer, vector <uint8_t> (), authorized, root));
	// Выполняем добавление сертификата издателя в запас доверенных
	ASSERT_TRUE(store.add(view_t(root.data(), root.size())));
	// Проверяем выдачу записи первого сертификата запаса доверенных
	EXPECT_EQ(store.get(0).size, root.size());
	// Проверяем пустоту записи, запрошенной за пределами запаса доверенных
	EXPECT_EQ(store.get(1).data, nullptr);
	/**
	 * Всякое звено цепочки разбирается до сверки: звено, разобрать которое нельзя,
	 * отвергает цепочку целиком
	 */
	vector <uint8_t> leaf;
	// Выполняем выработку сертификата владельца, изданного издателем
	ASSERT_TRUE(make("anyks.com", "anyks root", subject, issuer.secret, options_t (), leaf));
	// Проверяем отказ доверия цепочке с неразбираемым звеном
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {leaf, garbage}, store, MOMENT), trust::error_t::PARSE);
	/**
	 * Тело основных ограничений издателя разбирается наравне со всем прочим: порча
	 * его лишает издателя права издавать другие сертификаты
	 */
	options_t damaged;
	// Наделяем сертификат правом издавать другие сертификаты
	damaged.authority = true;
	// Портим тело объявляемых расширений сертификата
	damaged.spoiled = SPOIL_CONSTRAINTS;
	// Ключевая пара издателя с порченым телом расширений
	keys_t spoiler;
	// Выполняем выработку ключевой пары издателя с порченым телом расширений
	ASSERT_TRUE(generate(spoiler));
	// Запись самоподписанного сертификата издателя с порченым телом расширений
	vector <uint8_t> ruined;
	// Выполняем выработку издателя с порченым телом расширений
	ASSERT_TRUE(make("ruined root", "ruined root", spoiler, vector <uint8_t> (), damaged, ruined));
	// Запас доверенных, несущий издателя с порченым телом расширений
	trust::store_t ruins;
	// Выполняем добавление издателя с порченым телом расширений в запас
	ASSERT_TRUE(ruins.add(view_t(ruined.data(), ruined.size())));
	// Запись сертификата владельца, изданного издателем с порченым телом расширений
	vector <uint8_t> issued;
	// Выполняем выработку сертификата владельца, изданного таким издателем
	ASSERT_TRUE(make("anyks.com", "ruined root", subject, spoiler.secret, options_t (), issued));
	// Проверяем отказ доверия сертификату, изданному издателем с порченым расширением
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {issued}, ruins, MOMENT), trust::error_t::AUTHORITY);
	/**
	 * Назначение открытого ключа объявляется расширением, отдельным от основных
	 * ограничений: порча тела его задевает свой заслон, а не заслон ограничений,
	 * и порчею обоих разом он не задевается вовсе
	 */
	options_t misused;
	// Наделяем сертификат правом издавать другие сертификаты
	misused.authority = true;
	// Портим тело назначения открытого ключа сертификата
	misused.spoiled = SPOIL_USAGE;
	// Ключевая пара издателя с порченым назначением ключа
	keys_t misuser;
	// Выполняем выработку ключевой пары издателя с порченым назначением ключа
	ASSERT_TRUE(generate(misuser));
	// Запись самоподписанного издателя с порченым назначением ключа
	vector <uint8_t> misuse;
	// Выполняем выработку издателя с порченым назначением ключа
	ASSERT_TRUE(make("misused root", "misused root", misuser, vector <uint8_t> (), misused, misuse));
	// Запас доверенных, несущий издателя с порченым назначением ключа
	trust::store_t misuses;
	// Выполняем добавление издателя с порченым назначением ключа в запас
	ASSERT_TRUE(misuses.add(view_t(misuse.data(), misuse.size())));
	// Запись сертификата владельца, изданного таким издателем
	vector <uint8_t> granted;
	// Выполняем выработку сертификата владельца, изданного таким издателем
	ASSERT_TRUE(make("anyks.com", "misused root", subject, misuser.secret, options_t (), granted));
	// Проверяем отказ доверия сертификату, изданному издателем с порченым назначением
	EXPECT_EQ(trust::verify(vector <vector <uint8_t>> {granted}, misuses, MOMENT), trust::error_t::AUTHORITY);
}
