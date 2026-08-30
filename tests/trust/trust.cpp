/**
 * @file trust.cpp
 * @date 2026-08-30
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
using namespace anyks;

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
		 authority(false), constraints(true), usage(true),
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
			if(!writer.octets(item.data()))
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
			const uint8_t bits[1] = {static_cast <uint8_t> (options.authority ? 0x04 : 0x80)};
			// Составитель записи назначения открытого ключа
			asn1::writer_t item;
			// Записываем разряды назначения открытого ключа
			if(!item.bits(view_t(bits, sizeof(bits)), (options.authority ? 2 : 7)))
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
			if(!writer.octets(item.data()))
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
			if(!writer.octets(item.data()))
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
		if(!title(body, subject))
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
}
