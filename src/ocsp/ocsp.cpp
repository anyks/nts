/**
 * @file ocsp.cpp
 * @date 2026-09-04
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
 * @brief Реализация модуля состояния сертификата по RFC 6960
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <string>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <ocsp/ocsp.hpp>
#include <x509/signature.hpp>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
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
	using namespace nts::ocsp;

	/**
	 * Опознаватель вида основного ответа id-pkix-ocsp-basic
	 */
	static const char * BASIC = "1.3.6.1.5.5.7.48.1.1";
	/**
	 * Опознаватель расширения неповторимого значения id-pkix-ocsp-nonce
	 */
	static const char * NONCE = "1.3.6.1.5.5.7.48.1.2";
	/**
	 * Опознаватель способа доступа к ответчику id-ad-ocsp
	 */
	static const char * ACCESS = "1.3.6.1.5.5.7.48.1";
	/**
	 * Опознаватель расширения сведений о доступе к издателю
	 */
	static const char * AUTHORITY = "1.3.6.1.5.5.7.1.1";
	/**
	 * Опознаватель расширения расширенного назначения ключа
	 */
	static const char * PURPOSE = "2.5.29.37";
	/**
	 * Опознаватель назначения ключа id-kp-OCSPSigning
	 */
	static const char * SIGNING = "1.3.6.1.5.5.7.3.9";
	/**
	 * Номер метки перечисления ENUMERATED: в перечне меток модуля ASN.1 её нет,
	 * ибо нигде, кроме исхода ответа OCSP, она в библиотеке не встречается
	 */
	static constexpr uint32_t ENUMERATED = 0x0A;
	/**
	 * Длина хеша SHA-1, которым назван ответчик по ключу: раздел 4.2.1 RFC 6960
	 */
	static constexpr size_t KEY_HASH = 20;

	/**
	 * @brief Описание алгоритма хеша опознавателя сертификата
	 *
	 */
	typedef struct Hash {
		// Опознаватель алгоритма хеша
		const char * oid;
		// Алгоритм хеша
		digest::hash_t algorithm;
		// Признак записи настроек алгоритма пустым значением NULL
		bool nothing;
	} hash_t;

	/**
	 * Алгоритмы хеша, признаваемые опознавателем сертификата: раздел 4.1.1 RFC 6960
	 * велит принимать SHA-1 всякому, RFC 6277 добавляет SHA-2, а RFC 9215 - «Стрибог»
	 */
	static const hash_t HASHES[] = {
		// SHA-1
		{"1.3.14.3.2.26", digest::hash_t::SHA1, true},
		// SHA-224
		{"2.16.840.1.101.3.4.2.4", digest::hash_t::SHA224, true},
		// SHA-256
		{"2.16.840.1.101.3.4.2.1", digest::hash_t::SHA256, true},
		// SHA-384
		{"2.16.840.1.101.3.4.2.2", digest::hash_t::SHA384, true},
		// SHA-512
		{"2.16.840.1.101.3.4.2.3", digest::hash_t::SHA512, true},
		// «Стрибог» 256 разрядов
		{"1.2.643.7.1.1.2.2", digest::hash_t::STREEBOG256, false},
		// «Стрибог» 512 разрядов
		{"1.2.643.7.1.1.2.3", digest::hash_t::STREEBOG512, false}
	};

	/**
	 * @brief Функция розыска описания алгоритма хеша по опознавателю
	 *
	 * @param oid опознаватель алгоритма хеша
	 * @return    описание алгоритма хеша либо nullptr
	 *
	 */
	static const hash_t * lookup(const string & oid) noexcept {
		/**
		 * Выполняем перебор признаваемых алгоритмов хеша
		 */
		for(size_t i = 0; i < (sizeof(HASHES) / sizeof(hash_t)); i++){
			// Если опознаватель алгоритма сошёлся
			if(oid.compare(HASHES[i].oid) == 0)
				// Выводим описание алгоритма хеша
				return &HASHES[i];
		}
		// Выводим отсутствие описания
		return nullptr;
	}
	/**
	 * @brief Функция розыска описания алгоритма хеша по алгоритму
	 *
	 * @param algorithm алгоритм хеша
	 * @return          описание алгоритма хеша либо nullptr
	 *
	 */
	static const hash_t * lookup(const digest::hash_t algorithm) noexcept {
		/**
		 * Выполняем перебор признаваемых алгоритмов хеша
		 */
		for(size_t i = 0; i < (sizeof(HASHES) / sizeof(hash_t)); i++){
			// Если алгоритм хеша сошёлся
			if(HASHES[i].algorithm == algorithm)
				// Выводим описание алгоритма хеша
				return &HASHES[i];
		}
		// Выводим отсутствие описания
		return nullptr;
	}
	/**
	 * @brief Функция перевода отказа модуля ASN.1 в отказ модуля
	 *
	 * @param error отказ модуля ASN.1
	 * @return      отказ модуля
	 *
	 */
	static ocsp::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля, отвечающий отказу модуля ASN.1
		return ((error == asn1::error_t::MEMORY) ? ocsp::error_t::MEMORY : ocsp::error_t::ENCODING);
	}
	/**
	 * @brief Функция проверки признаков элемента записи
	 *
	 * @param element     проверяемый элемент записи
	 * @param cls         ожидаемый класс метки
	 * @param constructed ожидаемый вид метки
	 * @param tag         ожидаемый номер метки
	 * @return            признак того, что элемент отвечает ожиданию
	 *
	 */
	static bool alike(const asn1::element_t & element, const asn1::cls_t cls, const bool constructed, const uint32_t tag) noexcept {
		// Выводим признак соответствия элемента ожиданию
		return ((element.cls == cls) && (element.constructed == constructed) && (element.tag == tag));
	}
	/**
	 * @brief Функция разбора опознавателя алгоритма
	 *
	 * @param element элемент записи опознавателя алгоритма
	 * @param oid     строка, в которую помещается опознаватель алгоритма
	 * @param params  просмотр, в который помещается запись настроек алгоритма
	 * @return        причина отказа либо ocsp::error_t::NONE
	 *
	 */
	static ocsp::error_t algorithm(const asn1::element_t & element, string & oid, view_t & params) noexcept {
		// Если запись опознавателя алгоритма не составная
		if(!element.constructed)
			// Выводим отказ состава записи
			return ocsp::error_t::STRUCTURE;
		// Создаём разборщик записи опознавателя алгоритма
		asn1::reader_t reader(element.content);
		// Объект разобранного опознавателя алгоритма
		asn1::element_t item;
		// Если опознаватель алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::OBJECT, item))
			// Выводим отказ кодировки записи
			return translate(reader.err());
		// Отказ извлечения опознавателя алгоритма
		const asn1::error_t failure = asn1::oid(item, oid);
		// Если опознаватель алгоритма извлечь не удалось
		if(failure != asn1::error_t::NONE)
			// Выводим отказ извлечения опознавателя
			return translate(failure);
		// Сбрасываем запись настроек алгоритма
		params = view_t(nullptr, 0);
		// Если настройки алгоритма записаны
		if(!reader.empty()){
			// Объект разобранной записи настроек алгоритма
			asn1::element_t settings;
			// Если запись настроек алгоритма разобрать не удалось
			if(!reader.next(settings))
				// Выводим отказ кодировки записи
				return translate(reader.err());
			// Запоминаем запись настроек алгоритма целиком
			params = settings.element;
		}
		// Если за настройками алгоритма идут лишние поля
		if(!reader.empty())
			// Выводим отказ состава записи
			return ocsp::error_t::STRUCTURE;
		// Выводим успешность разбора опознавателя алгоритма
		return ocsp::error_t::NONE;
	}
	/**
	 * @brief Функция разбора метки времени
	 *
	 * @param reader разборщик, из которого берётся метка времени
	 * @param result место, в которое помещается миг в секундах от начала эпохи
	 * @return       причина отказа либо ocsp::error_t::NONE
	 *
	 * @note Раздел 4.2.2.1 RFC 6960 велит всем меткам времени ответа быть в записи
	 *       GeneralizedTime по Гринвичу: двузначный год здесь не дозволен
	 *
	 */
	static ocsp::error_t stamp(asn1::reader_t & reader, int64_t & result) noexcept {
		// Объект разобранной метки времени
		asn1::element_t item;
		// Если метку времени разобрать не удалось
		if(!reader.next(asn1::tag_t::GENERALIZED_TIME, item))
			// Выводим отказ метки времени
			return ((reader.err() == asn1::error_t::TAG) ? ocsp::error_t::TIME : translate(reader.err()));
		// Если миг из метки времени извлечь не удалось
		if(asn1::time(item, asn1::tag_t::GENERALIZED_TIME, result) != asn1::error_t::NONE)
			// Выводим отказ метки времени
			return ocsp::error_t::TIME;
		// Выводим успешность разбора метки времени
		return ocsp::error_t::NONE;
	}
	/**
	 * @brief Функция разбора набора расширений
	 *
	 * @param data   просмотр содержимого обёртки набора расширений
	 * @param result набор, в который помещаются разобранные расширения
	 * @return       причина отказа либо ocsp::error_t::NONE
	 *
	 * @details Раздел 4.1 RFC 5280: набор расширений есть непустой SEQUENCE записей из
	 *          опознавателя, необязательного признака обязательности и строки байтов
	 *
	 */
	static ocsp::error_t extensions(const view_t & data, vector <x509::extension_t> & result) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Создаём разборщик содержимого обёртки
			asn1::reader_t reader(data);
			// Объект разобранного набора расширений
			asn1::element_t list;
			// Если набор расширений разобрать не удалось
			if(!reader.next(asn1::tag_t::SEQUENCE, list))
				// Выводим отказ кодировки записи
				return translate(reader.err());
			// Если за набором расширений идут лишние поля либо набор не составной
			if(!reader.empty() || !list.constructed)
				// Выводим отказ состава записи
				return ocsp::error_t::STRUCTURE;
			// Создаём разборщик содержимого набора расширений
			asn1::reader_t items(list.content);
			// Если набор расширений пуст
			if(items.empty())
				// Выводим отказ записи расширения
				return ocsp::error_t::EXTENSION;
			/**
			 * Выполняем обход записей расширений
			 */
			while(!items.empty()){
				// Объект разобранной записи расширения
				asn1::element_t entry;
				// Если запись расширения разобрать не удалось
				if(!items.next(asn1::tag_t::SEQUENCE, entry))
					// Выводим отказ кодировки записи
					return translate(items.err());
				// Если запись расширения не составная
				if(!entry.constructed)
					// Выводим отказ состава записи
					return ocsp::error_t::STRUCTURE;
				// Создаём разборщик содержимого записи расширения
				asn1::reader_t fields(entry.content);
				// Объект разобранного поля записи расширения
				asn1::element_t field;
				// Разбираемое расширение
				x509::extension_t extension;
				// Если опознаватель расширения разобрать не удалось
				if(!fields.next(asn1::tag_t::OBJECT, field))
					// Выводим отказ кодировки записи
					return translate(fields.err());
				// Отказ извлечения опознавателя расширения
				const asn1::error_t failure = asn1::oid(field, extension.oid);
				// Если опознаватель расширения извлечь не удалось
				if(failure != asn1::error_t::NONE)
					// Выводим отказ извлечения опознавателя
					return translate(failure);
				// Если поле за опознавателем разобрать не удалось
				if(!fields.next(field))
					// Выводим отказ кодировки записи
					return translate(fields.err());
				// Если записан признак обязательности расширения
				if(alike(field, asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
					// Если признак обязательности извлечь не удалось
					if(asn1::boolean(field, extension.critical) != asn1::error_t::NONE)
						// Выводим отказ записи расширения
						return ocsp::error_t::EXTENSION;
					/**
					 * Правила DER велят опускать признак, равный умолчанию: записанная ложь
					 * есть запись не кратчайшим образом
					 */
					if(!extension.critical)
						// Выводим отказ кодировки записи
						return ocsp::error_t::ENCODING;
					// Если содержимое расширения разобрать не удалось
					if(!fields.next(field))
						// Выводим отказ кодировки записи
						return translate(fields.err());
				}
				// Если содержимое расширения записано не строкой байтов
				if(!alike(field, asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
					// Выводим отказ записи расширения
					return ocsp::error_t::EXTENSION;
				// Запоминаем содержимое расширения
				extension.value = field.content;
				// Если за содержимым расширения идут лишние поля
				if(!fields.empty())
					// Выводим отказ состава записи
					return ocsp::error_t::STRUCTURE;
				/**
				 * Выполняем перебор уже разобранных расширений
				 */
				for(size_t i = 0; i < result.size(); i++){
					// Если расширение с тем же опознавателем уже встречалось
					if(result[i].oid.compare(extension.oid) == 0)
						// Выводим отказ записи расширения
						return ocsp::error_t::EXTENSION;
				}
				// Добавляем разобранное расширение в набор
				result.push_back(extension);
			}
			// Выводим успешность разбора набора расширений
			return ocsp::error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return ocsp::error_t::MEMORY;
		}
	}
	/**
	 * @brief Функция вычисления хешей имени и ключа издателя
	 *
	 * @param issuer    разобранный сертификат издателя
	 * @param algorithm алгоритм хеша
	 * @param name      место, в которое помещается хеш имени издателя
	 * @param key       место, в которое помещается хеш ключа издателя
	 * @param size      место, в которое помещается длина хеша
	 * @return          признак успешности вычисления хешей
	 *
	 * @details Раздел 4.1.1 RFC 6960: хеш имени берётся по записи имени издателя
	 *          целиком, а хеш ключа - по значению строки битов открытого ключа без
	 *          метки, длины и байта неиспользуемых разрядов
	 *
	 */
	static bool hashes(const x509::certificate_t & issuer, const digest::hash_t algorithm, uint8_t * name, uint8_t * key, size_t & size) noexcept {
		// Определяем длину хеша
		size = digest::length(algorithm);
		// Если длина хеша не определена
		if(size == 0)
			// Выводим отказ вычисления хешей
			return false;
		// Если хеш имени издателя вычислить не удалось
		if(!digest::hash(algorithm, issuer.subjects().element, name, size))
			// Выводим отказ вычисления хешей
			return false;
		// Выводим итог вычисления хеша ключа издателя
		return digest::hash(algorithm, issuer.key().key, key, size);
	}
	/**
	 * @brief Функция сличения двух областей байтов
	 *
	 * @param first  первая область байтов
	 * @param second вторая область байтов
	 * @return       признак совпадения областей байтов
	 *
	 */
	static bool same(const view_t & first, const view_t & second) noexcept {
		// Выводим признак совпадения областей байтов
		return ((first.size == second.size) && ((first.size == 0) || (::memcmp(first.data, second.data, first.size) == 0)));
	}
	/**
	 * @brief Функция проверки, назван ли ответчиком данный сертификат
	 *
	 * @param response    разобранный ответ ответчика
	 * @param certificate разобранный сертификат стороны
	 * @return            признак того, что ответчик назван этим сертификатом
	 *
	 * @details Раздел 4.2.1 RFC 6960: ответчик назван либо именем владельца, либо
	 *          хешем SHA-1 значения строки битов его открытого ключа
	 *
	 */
	static bool named(const response_t & response, const x509::certificate_t & certificate) noexcept {
		// Признак того, что ответчик назван хешем ключа
		bool hashed = false;
		// Получаем опознаватель ответчика
		const view_t & responder = response.responder(hashed);
		// Если ответчик назван именем
		if(!hashed)
			// Выводим итог сличения имени ответчика с именем владельца
			return same(responder, certificate.subjects().element);
		// Место, в которое помещается хеш ключа
		uint8_t hash[KEY_HASH];
		// Если хеш ключа вычислить не удалось
		if(!digest::hash(digest::hash_t::SHA1, certificate.key().key, hash, sizeof(hash)))
			// Выводим отсутствие совпадения
			return false;
		// Выводим итог сличения хеша ключа с опознавателем ответчика
		return same(responder, view_t(hash, sizeof(hash)));
	}
	/**
	 * @brief Функция проверки подписи ответа ключом сертификата
	 *
	 * @param response    разобранный ответ ответчика
	 * @param certificate разобранный сертификат подписавшей стороны
	 * @return            причина отказа либо ocsp::error_t::NONE
	 *
	 */
	static ocsp::error_t signed_(const response_t & response, const x509::certificate_t & certificate) noexcept {
		// Число неиспользуемых разрядов последнего байта подписи
		uint8_t unused = 0;
		// Получаем подпись ответчика
		const view_t & signature = response.sign(unused);
		// Если последний байт подписи несёт неиспользуемые разряды
		if(unused != 0)
			// Выводим отказ подписи
			return ocsp::error_t::SIGNATURE;
		// Ответ об отзыве - такое же звено доверия, как сертификат: политика стойкости общая с цепочкой (x509::weak)
		if(x509::weak(response.algorithms(), response.parameters()) || x509::weak(certificate.key()))
			// Выводим отказ стойкости
			return ocsp::error_t::WEAK;
		// Отказ проверки подписи
		const x509::error_t failure = x509::verify(response.body(), signature, response.algorithms(), response.parameters(), certificate.key());
		// Если памяти под проверку подписи не хватило
		if(failure == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return ocsp::error_t::MEMORY;
		// Выводим итог проверки подписи
		return ((failure == x509::error_t::NONE) ? ocsp::error_t::NONE : ocsp::error_t::SIGNATURE);
	}
	/**
	 * @brief Функция проверки права приложенного сертификата отвечать за издателя
	 *
	 * @param candidate разобранный приложенный сертификат
	 * @param issuer    разобранный сертификат издателя
	 * @param moment    миг проверки, ноль сроки не судит
	 * @return          причина отказа либо ocsp::error_t::NONE
	 *
	 * @details Раздел 4.2.2.2 RFC 6960: делегированный ответчик обязан нести расширенное
	 *          назначение ключа id-kp-OCSPSigning, быть изданным тем же издателем, что и
	 *          проверяемый сертификат, и действовать на миг проверки
	 *
	 */
	static ocsp::error_t delegated(const x509::certificate_t & candidate, const x509::certificate_t & issuer, const int64_t moment) noexcept {
		// Разыскиваем расширение расширенного назначения ключа
		const x509::extension_t * extension = candidate.extension(PURPOSE);
		// Если расширения расширенного назначения ключа нет
		if(extension == nullptr)
			// Выводим отказ права ответчика
			return ocsp::error_t::RESPONDER;
		// Набор опознавателей назначения ключа
		vector <string> purposes;
		// Отказ извлечения назначения ключа
		const x509::error_t failure = x509::purpose(*extension, purposes);
		// Если памяти под назначение ключа не хватило
		if(failure == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return ocsp::error_t::MEMORY;
		// Если назначение ключа извлечь не удалось
		if(failure != x509::error_t::NONE)
			// Выводим отказ права ответчика
			return ocsp::error_t::RESPONDER;
		// Признак наличия назначения подписи ответов
		bool suitable = false;
		/**
		 * Выполняем перебор опознавателей назначения ключа
		 */
		for(size_t i = 0; (i < purposes.size()) && !suitable; i++)
			// Запоминаем, найдено ли назначение подписи ответов
			suitable = (purposes[i].compare(SIGNING) == 0);
		// Если назначения подписи ответов нет
		if(!suitable)
			// Выводим отказ права ответчика
			return ocsp::error_t::RESPONDER;
		// Если издатель приложенного сертификата с издателем проверяемого разошёлся
		if(!same(candidate.issuers().element, issuer.subjects().element))
			// Выводим отказ права ответчика
			return ocsp::error_t::RESPONDER;
		// Раздел 4.2 RFC 5280: критичное расширение, библиотеке неведомое, делает сертификат ответчика негодным - как у звеньев цепочки доверия
		if(!x509::recognized(candidate))
			// Выводим отказ права ответчика
			return ocsp::error_t::RESPONDER;
		// Делегированный ответчик судится как звено цепочки: подпись SHA-1 либо ключ RSA короче 2048 разрядов негодны
		if(x509::weak(candidate, false))
			// Выводим отказ стойкости
			return ocsp::error_t::WEAK;
		// Расширение назначения ключа
		const x509::extension_t * keyed = candidate.extension("2.5.29.15");
		// Если назначение ключа объявлено
		if(keyed != nullptr){
			// Разряды назначения
			uint16_t usage = 0;
			// Отказ разбора назначения
			const x509::error_t outcome = x509::usage(*keyed, usage);
			// Если памяти не хватило
			if(outcome == x509::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return ocsp::error_t::MEMORY;
			// Раздел 4.2.2.2 RFC 6960: ответ подписывается ключом, назначенным подписи
			if((outcome != x509::error_t::NONE) || ((usage & static_cast <uint16_t> (x509::usage_t::SIGNATURE)) == 0))
				// Выводим отказ права ответчика
				return ocsp::error_t::RESPONDER;
		}
		// Если сроки судить дозволено
		if(moment != 0){
			// Границы срока действия приложенного сертификата
			int64_t before = 0, after = 0;
			// Получаем срок действия приложенного сертификата
			candidate.validity(before, after);
			// Если приложенный сертификат на миг проверки не действует
			if((moment < before) || (moment > after))
				// Выводим отказ права ответчика
				return ocsp::error_t::RESPONDER;
		}
		// Отказ проверки подписи приложенного сертификата издателем
		const x509::error_t verified = x509::verify(candidate, issuer.key());
		// Если памяти под проверку подписи не хватило
		if(verified == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return ocsp::error_t::MEMORY;
		// Выводим итог проверки подписи приложенного сертификата
		return ((verified == x509::error_t::NONE) ? ocsp::error_t::NONE : ocsp::error_t::RESPONDER);
	}
	/**
	 * @brief Функция перевода отказа составителя записи в отказ модуля
	 *
	 * @param writer составитель записи, ответивший отказом
	 * @return       отказ модуля
	 *
	 */
	static ocsp::error_t failed(const asn1::writer_t & writer) noexcept {
		// Выводим отказ модуля, отвечающий отказу составителя
		return ((writer.err() == asn1::error_t::MEMORY) ? ocsp::error_t::MEMORY : ocsp::error_t::STRUCTURE);
	}
};

/**
 * @brief Метод разбора ответа по одному сертификату
 *
 * @param element элемент записи ответа по сертификату
 * @param result  ответ, в который производится разбор
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::Response::single(const asn1::element_t & element, single_t & result) noexcept {
	// Если запись ответа по сертификату не составная
	if(!element.constructed)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Создаём разборщик записи ответа по сертификату
	asn1::reader_t reader(element.content);
	// Объект разобранного опознавателя сертификата
	asn1::element_t item;
	// Если опознаватель сертификата разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, item))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если запись опознавателя сертификата не составная
	if(!item.constructed)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	{
		// Создаём разборщик записи опознавателя сертификата
		asn1::reader_t fields(item.content);
		// Объект разобранного поля опознавателя
		asn1::element_t field;
		// Если опознаватель алгоритма хеша разобрать не удалось
		if(!fields.next(asn1::tag_t::SEQUENCE, field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Запись настроек алгоритма хеша
		view_t params;
		// Отказ разбора опознавателя алгоритма хеша
		const error_t failure = ::algorithm(field, result.identifier.algorithm, params);
		// Если опознаватель алгоритма хеша разобрать не удалось
		if(failure != error_t::NONE)
			// Выводим отказ разбора опознавателя алгоритма
			return failure;
		// Если хеш имени издателя разобрать не удалось
		if(!fields.next(asn1::tag_t::OCTET_STRING, field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Запоминаем хеш имени издателя
		result.identifier.name = field.content;
		// Если хеш ключа издателя разобрать не удалось
		if(!fields.next(asn1::tag_t::OCTET_STRING, field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Запоминаем хеш ключа издателя
		result.identifier.key = field.content;
		// Если порядковый номер сертификата разобрать не удалось
		if(!fields.next(asn1::tag_t::INTEGER, field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Если порядковый номер сертификата извлечь не удалось
		if(asn1::integer(field, result.identifier.serial) != asn1::error_t::NONE)
			// Выводим отказ кодировки записи
			return error_t::ENCODING;
		// Если за порядковым номером идут лишние поля
		if(!fields.empty())
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
	}
	// Если состояние сертификата разобрать не удалось
	if(!reader.next(item))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если состояние записано меткой не того класса
	if(item.cls != asn1::cls_t::CONTEXT)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	/**
	 * Выполняем определение состояния сертификата по метке выбора
	 */
	switch(item.tag){
		// Если сертификат не отозван
		case static_cast <uint32_t> (status_t::GOOD): {
			// Если состояние записано не пустым значением
			if(item.constructed || (item.content.size != 0))
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
			// Запоминаем состояние сертификата
			result.status = status_t::GOOD;
		} break;
		// Если сертификат отозван
		case static_cast <uint32_t> (status_t::REVOKED): {
			// Если сведения об отзыве записаны не составной записью
			if(!item.constructed)
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
			// Создаём разборщик сведений об отзыве
			asn1::reader_t revoked(item.content);
			// Отказ разбора мига отзыва
			const error_t failure = stamp(revoked, result.revocation);
			// Если миг отзыва разобрать не удалось
			if(failure != error_t::NONE)
				// Выводим отказ разбора мига отзыва
				return failure;
			// Если записана причина отзыва
			if(!revoked.empty()){
				// Объект разобранной причины отзыва
				asn1::element_t reason;
				// Если причину отзыва разобрать не удалось
				if(!revoked.next(reason))
					// Выводим отказ кодировки записи
					return translate(revoked.err());
				// Если причина отзыва записана не своей меткой
				if(!alike(reason, asn1::cls_t::CONTEXT, true, 0))
					// Выводим отказ состава записи
					return error_t::STRUCTURE;
				// Если за причиной отзыва идут лишние поля
				if(!revoked.empty())
					// Выводим отказ состава записи
					return error_t::STRUCTURE;
			}
			// Запоминаем состояние сертификата
			result.status = status_t::REVOKED;
		} break;
		// Если сертификат ответчику неведом
		case static_cast <uint32_t> (status_t::UNKNOWN): {
			// Если состояние записано не пустым значением
			if(item.constructed || (item.content.size != 0))
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
			// Запоминаем состояние сертификата
			result.status = status_t::UNKNOWN;
		} break;
		// Если метка выбора состояния неизвестна
		default:
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
	}
	// Отказ разбора мига верности состояния
	const error_t failure = stamp(reader, result.updated);
	// Если миг верности состояния разобрать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ разбора мига верности
		return failure;
	/**
	 * Выполняем разбор необязательных полей ответа по сертификату
	 */
	while(!reader.empty()){
		// Объект разобранного необязательного поля
		asn1::element_t field;
		// Если необязательное поле разобрать не удалось
		if(!reader.next(field))
			// Выводим отказ кодировки записи
			return translate(reader.err());
		// Если записан миг окончания обещания
		if(alike(field, asn1::cls_t::CONTEXT, true, 0)){
			// Если миг окончания обещания уже был
			if(result.next != 0)
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
			// Создаём разборщик обёртки мига окончания обещания
			asn1::reader_t wrapper(field.content);
			// Отказ разбора мига окончания обещания
			const error_t status = stamp(wrapper, result.next);
			// Если миг окончания обещания разобрать не удалось
			if(status != error_t::NONE)
				// Выводим отказ разбора мига окончания обещания
				return status;
			// Если за мигом окончания обещания идут лишние поля либо миг нулевой
			if(!wrapper.empty() || (result.next == 0))
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
		// Если записан набор расширений ответа по сертификату
		} else if(alike(field, asn1::cls_t::CONTEXT, true, 1)) {
			// Если набор расширений уже был либо за ним идут поля
			if(!result.extensions.empty() || !reader.empty())
				// Выводим отказ состава записи
				return error_t::STRUCTURE;
			// Отказ разбора набора расширений
			const error_t status = ::extensions(field.content, result.extensions);
			// Если набор расширений разобрать не удалось
			if(status != error_t::NONE)
				// Выводим отказ разбора набора расширений
				return status;
		// Если записано неизвестное поле
		} else
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
	}
	// Выводим успешность разбора ответа по сертификату
	return error_t::NONE;
}
/**
 * @brief Метод разбора подписываемой части ответа
 *
 * @param element элемент записи подписываемой части
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::Response::content(const asn1::element_t & element) noexcept {
	// Если подписываемая часть записана не составной записью
	if(!element.constructed)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Запоминаем подписываемую часть ответа целиком
	this->_body = element.element;
	// Создаём разборщик подписываемой части
	asn1::reader_t reader(element.content);
	// Объект разобранного поля подписываемой части
	asn1::element_t item;
	// Если первое поле подписываемой части разобрать не удалось
	if(!reader.next(item))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если записано издание ответа
	if(alike(item, asn1::cls_t::CONTEXT, true, 0)){
		// Создаём разборщик обёртки издания ответа
		asn1::reader_t wrapper(item.content);
		// Объект разобранного издания ответа
		asn1::element_t release;
		// Если издание ответа разобрать не удалось
		if(!wrapper.next(asn1::tag_t::INTEGER, release))
			// Выводим отказ издания ответа
			return error_t::VERSION;
		// Значение издания ответа
		int64_t version = 0;
		// Если издание ответа извлечь не удалось либо за ним идут лишние поля
		if((asn1::integer(release, version) != asn1::error_t::NONE) || !wrapper.empty())
			// Выводим отказ издания ответа
			return error_t::VERSION;
		/**
		 * Раздел 4.2.1 RFC 6960 велит изданию ответа быть первым; записанное явно оно
		 * умолчанию равно и правилам DER не отвечает, но подпись стоит под записью как
		 * есть, и подделке такая запись не служит: она принимается
		 */
		if(version != 0)
			// Выводим отказ издания ответа
			return error_t::VERSION;
		// Если опознаватель ответчика разобрать не удалось
		if(!reader.next(item))
			// Выводим отказ кодировки записи
			return translate(reader.err());
	}
	// Если ответчик назван именем
	if(alike(item, asn1::cls_t::CONTEXT, true, 1)){
		// Создаём разборщик обёртки имени ответчика
		asn1::reader_t wrapper(item.content);
		// Объект разобранного имени ответчика
		asn1::element_t name;
		// Если имя ответчика разобрать не удалось
		if(!wrapper.next(asn1::tag_t::SEQUENCE, name))
			// Выводим отказ кодировки записи
			return translate(wrapper.err());
		// Если за именем ответчика идут лишние поля либо имя не составное
		if(!wrapper.empty() || !name.constructed)
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
		// Запоминаем имя ответчика целиком
		this->_responder = name.element;
		// Запоминаем, что ответчик назван именем
		this->_hashed = false;
	// Если ответчик назван хешем ключа
	} else if(alike(item, asn1::cls_t::CONTEXT, true, 2)) {
		// Создаём разборщик обёртки хеша ключа ответчика
		asn1::reader_t wrapper(item.content);
		// Объект разобранного хеша ключа ответчика
		asn1::element_t hash;
		// Если хеш ключа ответчика разобрать не удалось
		if(!wrapper.next(asn1::tag_t::OCTET_STRING, hash))
			// Выводим отказ кодировки записи
			return translate(wrapper.err());
		// Если за хешем идут лишние поля либо длина хеша не отвечает SHA-1
		if(!wrapper.empty() || (hash.content.size != KEY_HASH))
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
		// Запоминаем хеш ключа ответчика
		this->_responder = hash.content;
		// Запоминаем, что ответчик назван хешем ключа
		this->_hashed = true;
	// Если ответчик назван неизвестным способом
	} else
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Отказ разбора мига составления ответа
	error_t failure = stamp(reader, this->_produced);
	// Если миг составления ответа разобрать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ разбора мига составления
		return failure;
	// Если перечень ответов по сертификатам разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, item))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если перечень ответов по сертификатам не составной
	if(!item.constructed)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Создаём разборщик перечня ответов по сертификатам
	asn1::reader_t list(item.content);
	/**
	 * Выполняем обход ответов по сертификатам
	 */
	while(!list.empty()){
		// Объект разобранной записи ответа по сертификату
		asn1::element_t entry;
		// Если запись ответа по сертификату разобрать не удалось
		if(!list.next(asn1::tag_t::SEQUENCE, entry))
			// Выводим отказ кодировки записи
			return translate(list.err());
		// Разбираемый ответ по сертификату
		single_t response;
		// Отказ разбора ответа по сертификату
		failure = this->single(entry, response);
		// Если ответ по сертификату разобрать не удалось
		if(failure != error_t::NONE)
			// Выводим отказ разбора ответа по сертификату
			return failure;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Добавляем разобранный ответ в перечень
			this->_responses.push_back(response);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	// Если записан набор расширений ответа
	if(!reader.empty()){
		// Объект разобранной обёртки набора расширений
		asn1::element_t wrapper;
		// Если обёртку набора расширений разобрать не удалось
		if(!reader.next(wrapper))
			// Выводим отказ кодировки записи
			return translate(reader.err());
		// Если обёртка записана не своей меткой либо за ней идут лишние поля
		if(!alike(wrapper, asn1::cls_t::CONTEXT, true, 1) || !reader.empty())
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
		// Отказ разбора набора расширений
		failure = ::extensions(wrapper.content, this->_extensions);
		// Если набор расширений разобрать не удалось
		if(failure != error_t::NONE)
			// Выводим отказ разбора набора расширений
			return failure;
	}
	// Выводим успешность разбора подписываемой части
	return error_t::NONE;
}
/**
 * @brief Метод разбора основного ответа
 *
 * @param data просмотр записи основного ответа
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::Response::basic(const view_t & data) noexcept {
	// Создаём разборщик записи основного ответа
	asn1::reader_t reader(data);
	// Объект разобранной записи основного ответа
	asn1::element_t root;
	// Если запись основного ответа разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, root))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если за записью основного ответа идут лишние байты либо запись не составная
	if(!reader.empty() || !root.constructed)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Создаём разборщик содержимого основного ответа
	asn1::reader_t fields(root.content);
	// Объект разобранного поля основного ответа
	asn1::element_t item;
	// Если подписываемую часть разобрать не удалось
	if(!fields.next(asn1::tag_t::SEQUENCE, item))
		// Выводим отказ кодировки записи
		return translate(fields.err());
	// Отказ разбора подписываемой части
	error_t failure = this->content(item);
	// Если подписываемую часть разобрать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ разбора подписываемой части
		return failure;
	// Если опознаватель алгоритма подписи разобрать не удалось
	if(!fields.next(asn1::tag_t::SEQUENCE, item))
		// Выводим отказ кодировки записи
		return translate(fields.err());
	// Отказ разбора опознавателя алгоритма подписи
	failure = ::algorithm(item, this->_algorithm, this->_parameters);
	// Если опознаватель алгоритма подписи разобрать не удалось
	if(failure != error_t::NONE)
		// Выводим отказ разбора опознавателя алгоритма
		return failure;
	// Если подпись ответчика разобрать не удалось
	if(!fields.next(asn1::tag_t::BIT_STRING, item))
		// Выводим отказ кодировки записи
		return translate(fields.err());
	// Если значение подписи извлечь не удалось
	if(asn1::bits(item, this->_signature, this->_unused) != asn1::error_t::NONE)
		// Выводим отказ кодировки записи
		return error_t::ENCODING;
	// Если приложены сертификаты
	if(!fields.empty()){
		// Объект разобранной обёртки сертификатов
		asn1::element_t wrapper;
		// Если обёртку сертификатов разобрать не удалось
		if(!fields.next(wrapper))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Если обёртка записана не своей меткой либо за ней идут лишние поля
		if(!alike(wrapper, asn1::cls_t::CONTEXT, true, 0) || !fields.empty())
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
		// Создаём разборщик обёртки сертификатов
		asn1::reader_t inner(wrapper.content);
		// Объект разобранного перечня сертификатов
		asn1::element_t list;
		// Если перечень сертификатов разобрать не удалось
		if(!inner.next(asn1::tag_t::SEQUENCE, list))
			// Выводим отказ кодировки записи
			return translate(inner.err());
		// Если за перечнем идут лишние поля либо перечень не составной
		if(!inner.empty() || !list.constructed)
			// Выводим отказ состава записи
			return error_t::STRUCTURE;
		// Создаём разборщик перечня сертификатов
		asn1::reader_t entries(list.content);
		/**
		 * Выполняем обход приложенных сертификатов
		 */
		while(!entries.empty()){
			// Объект разобранной записи сертификата
			asn1::element_t entry;
			// Если запись сертификата разобрать не удалось
			if(!entries.next(asn1::tag_t::SEQUENCE, entry))
				// Выводим отказ кодировки записи
				return translate(entries.err());
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Добавляем запись сертификата целиком в перечень
				this->_certificates.push_back(entry.element);
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
		}
	}
	// Выводим успешность разбора основного ответа
	return error_t::NONE;
}
/**
 * @brief Метод разбора записи ответа
 *
 * @param data просмотр разбираемой записи ответа
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::Response::parse(const view_t & data) noexcept {
	// Сброс прежних сведений
	this->clear();
	// Создаём разборщик записи ответа
	asn1::reader_t reader(data);
	// Объект разобранной записи ответа
	asn1::element_t root;
	// Если запись ответа разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, root))
		// Выводим отказ кодировки записи
		return (this->_error = translate(reader.err()));
	// Если за записью ответа идут лишние байты либо запись не составная
	if(!reader.empty() || !root.constructed)
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	// Запоминаем запись ответа целиком
	this->_element = root.element;
	// Создаём разборщик содержимого записи ответа
	asn1::reader_t fields(root.content);
	// Объект разобранного исхода обращения
	asn1::element_t item;
	// Если исход обращения разобрать не удалось
	if(!fields.next(item))
		// Выводим отказ кодировки записи
		return (this->_error = translate(fields.err()));
	// Если исход записан не перечислением в один байт
	if(!alike(item, asn1::cls_t::UNIVERSAL, false, ENUMERATED) || (item.content.size != 1))
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	/**
	 * Выполняем определение исхода обращения по значению перечисления
	 */
	switch(item.content.data[0]){
		// Если исход обращения известен
		case static_cast <uint8_t> (outcome_t::SUCCESSFUL):
		case static_cast <uint8_t> (outcome_t::MALFORMED):
		case static_cast <uint8_t> (outcome_t::INTERNAL):
		case static_cast <uint8_t> (outcome_t::LATER):
		case static_cast <uint8_t> (outcome_t::UNSIGNED):
		case static_cast <uint8_t> (outcome_t::UNAUTHORIZED):
			// Запоминаем исход обращения
			this->_outcome = static_cast <outcome_t> (item.content.data[0]);
		break;
		// Если исход обращения неизвестен
		default:
			// Выводим отказ состава записи
			return (this->_error = error_t::STRUCTURE);
	}
	// Если тела ответа нет
	if(fields.empty())
		/**
		 * Раздел 4.2.1 RFC 6960: тело ответа обязательно лишь при исходе SUCCESSFUL, а
		 * отказ ответчика тела не несёт и разбирается успешно
		 */
		return (this->_error = ((this->_outcome == outcome_t::SUCCESSFUL) ? error_t::STRUCTURE : error_t::NONE));
	// Объект разобранной обёртки тела ответа
	asn1::element_t wrapper;
	// Если обёртку тела ответа разобрать не удалось
	if(!fields.next(wrapper))
		// Выводим отказ кодировки записи
		return (this->_error = translate(fields.err()));
	// Если обёртка записана не своей меткой либо за ней идут лишние поля
	if(!alike(wrapper, asn1::cls_t::CONTEXT, true, 0) || !fields.empty())
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	// Создаём разборщик обёртки тела ответа
	asn1::reader_t inner(wrapper.content);
	// Объект разобранного тела ответа
	asn1::element_t body;
	// Если тело ответа разобрать не удалось
	if(!inner.next(asn1::tag_t::SEQUENCE, body))
		// Выводим отказ кодировки записи
		return (this->_error = translate(inner.err()));
	// Если за телом ответа идут лишние поля либо тело не составное
	if(!inner.empty() || !body.constructed)
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	// Создаём разборщик тела ответа
	asn1::reader_t parts(body.content);
	// Если опознаватель вида ответа разобрать не удалось
	if(!parts.next(asn1::tag_t::OBJECT, item))
		// Выводим отказ кодировки записи
		return (this->_error = translate(parts.err()));
	// Опознаватель вида ответа
	string type;
	// Отказ извлечения опознавателя вида ответа
	const asn1::error_t failure = asn1::oid(item, type);
	// Если опознаватель вида ответа извлечь не удалось
	if(failure != asn1::error_t::NONE)
		// Выводим отказ извлечения опознавателя
		return (this->_error = translate(failure));
	// Если вид ответа не основной
	if(type.compare(BASIC) != 0)
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	// Если запись основного ответа разобрать не удалось
	if(!parts.next(asn1::tag_t::OCTET_STRING, item))
		// Выводим отказ кодировки записи
		return (this->_error = translate(parts.err()));
	// Если за записью основного ответа идут лишние поля
	if(!parts.empty())
		// Выводим отказ состава записи
		return (this->_error = error_t::STRUCTURE);
	// Разбор основного ответа
	this->_error = this->basic(item.content);
	// Если основной ответ разобрать не удалось
	if(this->_error != error_t::NONE){
		// Запоминаем причину отказа
		const error_t error = this->_error;
		// Сброс разобранных сведений
		this->clear();
		// Восстанавливаем причину отказа
		this->_error = error;
	}
	// Выводим итог разбора записи ответа
	return this->_error;
}
/**
 * @brief Метод очистки разобранных сведений
 *
 */
void nts::ocsp::Response::clear() noexcept {
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем исход обращения
	this->_outcome = outcome_t::SUCCESSFUL;
	// Сбрасываем запись ответа целиком
	this->_element = view_t(nullptr, 0);
	// Сбрасываем подписываемую часть
	this->_body = view_t(nullptr, 0);
	// Сбрасываем опознаватель алгоритма подписи
	this->_algorithm.clear();
	// Сбрасываем запись настроек алгоритма подписи
	this->_parameters = view_t(nullptr, 0);
	// Сбрасываем запись подписи
	this->_signature = view_t(nullptr, 0);
	// Сбрасываем число неиспользуемых разрядов подписи
	this->_unused = 0;
	// Сбрасываем способ именования ответчика
	this->_hashed = false;
	// Сбрасываем опознаватель ответчика
	this->_responder = view_t(nullptr, 0);
	// Сбрасываем миг составления ответа
	this->_produced = 0;
	// Сбрасываем ответы по сертификатам
	this->_responses.clear();
	// Сбрасываем набор расширений
	this->_extensions.clear();
	// Сбрасываем приложенные сертификаты
	this->_certificates.clear();
}
/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
nts::ocsp::error_t nts::ocsp::Response::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}
/**
 * @brief Метод извлечения исхода обращения к ответчику
 *
 * @return исход обращения к ответчику
 *
 */
nts::ocsp::outcome_t nts::ocsp::Response::outcome() const noexcept {
	// Выводим исход обращения
	return this->_outcome;
}
/**
 * @brief Метод извлечения подписываемой части ответа
 *
 * @return просмотр подписываемой части ответа
 *
 */
const view_t & nts::ocsp::Response::body() const noexcept {
	// Выводим подписываемую часть ответа
	return this->_body;
}
/**
 * @brief Метод извлечения подписи ответчика
 *
 * @param unused число неиспользуемых разрядов последнего байта подписи
 * @return       просмотр записи подписи
 *
 */
const view_t & nts::ocsp::Response::sign(uint8_t & unused) const noexcept {
	// Выводим число неиспользуемых разрядов подписи
	unused = this->_unused;
	// Выводим запись подписи
	return this->_signature;
}
/**
 * @brief Метод извлечения опознавателя алгоритма подписи
 *
 * @return опознаватель алгоритма подписи
 *
 */
const string & nts::ocsp::Response::algorithms() const noexcept {
	// Выводим опознаватель алгоритма подписи
	return this->_algorithm;
}
/**
 * @brief Метод извлечения записи настроек алгоритма подписи
 *
 * @return просмотр записи настроек алгоритма подписи либо пустой просмотр
 *
 */
const view_t & nts::ocsp::Response::parameters() const noexcept {
	// Выводим запись настроек алгоритма подписи
	return this->_parameters;
}
/**
 * @brief Метод извлечения опознавателя ответчика
 *
 * @param hashed признак того, что ответчик назван хешем ключа, а не именем
 * @return       просмотр записи имени ответчика либо хеша его ключа
 *
 */
const view_t & nts::ocsp::Response::responder(bool & hashed) const noexcept {
	// Выводим способ именования ответчика
	hashed = this->_hashed;
	// Выводим опознаватель ответчика
	return this->_responder;
}
/**
 * @brief Метод извлечения мига составления ответа
 *
 * @return миг составления ответа в секундах от начала эпохи
 *
 */
int64_t nts::ocsp::Response::produced() const noexcept {
	// Выводим миг составления ответа
	return this->_produced;
}
/**
 * @brief Метод извлечения ответов по сертификатам
 *
 * @return ответы по сертификатам
 *
 */
const vector <nts::ocsp::single_t> & nts::ocsp::Response::responses() const noexcept {
	// Выводим ответы по сертификатам
	return this->_responses;
}
/**
 * @brief Метод извлечения набора расширений ответа
 *
 * @return набор расширений ответа
 *
 */
const vector <nts::x509::extension_t> & nts::ocsp::Response::extension() const noexcept {
	// Выводим набор расширений ответа
	return this->_extensions;
}
/**
 * @brief Метод извлечения сертификатов, приложенных ответчиком
 *
 * @return просмотры записей приложенных сертификатов
 *
 */
const vector <view_t> & nts::ocsp::Response::certificates() const noexcept {
	// Выводим приложенные сертификаты
	return this->_certificates;
}
/**
 * @brief Конструктор ответа
 *
 */
nts::ocsp::Response::Response() noexcept :
 _error(error_t::NONE), _outcome(outcome_t::SUCCESSFUL), _unused(0), _hashed(false), _produced(0) {}
/**
 * @brief Функция извлечения неповторимого значения из набора расширений
 *
 * @param extensions набор расширений ответа либо ответа по сертификату
 * @param result     просмотр, в который помещается неповторимое значение
 * @return           причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::nonce(const vector <x509::extension_t> & extensions, view_t & result) noexcept {
	// Сбрасываем неповторимое значение
	result = view_t(nullptr, 0);
	/**
	 * Выполняем перебор расширений набора
	 */
	for(size_t i = 0; i < extensions.size(); i++){
		// Если это не расширение неповторимого значения
		if(extensions[i].oid.compare(NONCE) != 0)
			// Переходим к следующему расширению
			continue;
		// Создаём разборщик содержимого расширения
		asn1::reader_t reader(extensions[i].value);
		// Объект разобранной строки неповторимого значения
		asn1::element_t item;
		// Если строку неповторимого значения разобрать не удалось
		if(!reader.next(asn1::tag_t::OCTET_STRING, item))
			// Выводим отказ записи расширения
			return error_t::EXTENSION;
		/**
		 * RFC 8954 велит значению быть от одного до тридцати двух байтов и лежать
		 * строкой байтов внутри содержимого расширения; лишние поля не дозволены
		 */
		if(!reader.empty() || (item.content.size == 0) || (item.content.size > 32))
			// Выводим отказ записи расширения
			return error_t::EXTENSION;
		// Запоминаем неповторимое значение
		result = item.content;
		// Выводим успешность извлечения
		return error_t::NONE;
	}
	// Выводим успешность: расширения нет, значение пусто
	return error_t::NONE;
}
/**
 * @brief Функция проверки ответа против сертификата и его издателя
 *
 * @param response    разобранный ответ ответчика
 * @param certificate запись проверяемого сертификата
 * @param issuer      запись сертификата издателя проверяемого сертификата
 * @param moment      миг проверки в секундах от начала эпохи, ноль сроки не судит
 * @param leeway      дозволенный люфт сроков в секундах в обе стороны
 * @param nonce       ожидаемое неповторимое значение либо пустой просмотр
 * @param result      место, в которое помещается состояние сертификата
 * @return            причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::verify(const response_t & response, const view_t & certificate, const view_t & issuer, const int64_t moment, const int64_t leeway, const view_t & nonce, status_t & result) noexcept {
	// Сбрасываем состояние сертификата
	result = status_t::NONE;
	// Если разбор ответа завершился отказом
	if(response.err() != error_t::NONE)
		// Выводим отказ разбора ответа
		return response.err();
	// Если ответчик ответил отказом
	if(response.outcome() != outcome_t::SUCCESSFUL)
		// Выводим отказ исхода обращения
		return error_t::STATUS;
	// Объект разбора проверяемого сертификата
	x509::certificate_t subject;
	// Объект разбора сертификата издателя
	x509::certificate_t authority;
	// Отказ разбора проверяемого сертификата
	x509::error_t parsed = subject.parse(certificate);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если проверяемый сертификат разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::KEY;
	// Отказ разбора сертификата издателя
	parsed = authority.parse(issuer);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если сертификат издателя разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::KEY;
	// Ответ по проверяемому сертификату
	const single_t * single = nullptr;
	// Получаем ответы по сертификатам
	const vector <single_t> & responses = response.responses();
	/**
	 * Выполняем перебор ответов по сертификатам в поисках проверяемого
	 */
	for(size_t i = 0; (i < responses.size()) && (single == nullptr); i++){
		// Описание алгоритма хеша опознавателя
		const hash_t * hash = lookup(responses[i].identifier.algorithm);
		// Если алгоритм хеша опознавателя не поддерживается
		if(hash == nullptr)
			// Переходим к следующему ответу
			continue;
		// Места, в которые помещаются хеши имени и ключа издателя
		uint8_t name[64], key[64];
		// Длина хешей
		size_t size = 0;
		// Если хеши издателя вычислить не удалось
		if(!hashes(authority, hash->algorithm, name, key, size))
			// Выводим отказ алгоритма хеша
			return error_t::HASH;
		// Если хеши издателя и порядковый номер сошлись
		if(same(responses[i].identifier.name, view_t(name, size)) && same(responses[i].identifier.key, view_t(key, size)) && same(responses[i].identifier.serial, subject.number()))
			// Запоминаем ответ по проверяемому сертификату
			single = &responses[i];
	}
	// Если ответа по проверяемому сертификату нет
	if(single == nullptr)
		// Выводим отказ опознавателя сертификата
		return error_t::IDENTITY;
	// Отказ проверки
	error_t failure = error_t::RESPONDER;
	// Получаем приложенные сертификаты
	const vector <view_t> & certificates = response.certificates();
	/**
	 * Подписавший ищется сперва среди приложенных сертификатов, и лишь потом у издателя -
	 * так поступают openssl, BoringSSL и NSS. Делегированный ответчик (раздел 4.2.2.2
	 * RFC 6960) вправе нести то же имя владельца, что и издатель, и назван быть им же:
	 * суд одним ключом издателя по совпадению имени отвергал бы годный ответ
	 */
	/**
	 * Выполняем перебор приложенных сертификатов в поисках ответчика
	 */
	for(size_t i = 0; (i < certificates.size()) && (failure == error_t::RESPONDER); i++){
		// Объект разбора приложенного сертификата
		x509::certificate_t candidate;
		// Отказ разбора приложенного сертификата
		parsed = candidate.parse(certificates[i]);
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если приложенный сертификат разобрать не удалось либо ответчик назван не им
		if((parsed != x509::error_t::NONE) || !named(response, candidate))
			// Переходим к следующему сертификату
			continue;
		// Проверка права приложенного сертификата отвечать за издателя
		failure = delegated(candidate, authority, moment);
		// Если приложенный сертификат отвечать вправе
		if(failure == error_t::NONE)
			// Проверка подписи ответа ключом ответчика
			failure = signed_(response, candidate);
	}
	// Если приложенные сертификаты ответ не подтвердили, а ответчиком назван сам издатель
	if((failure != error_t::NONE) && named(response, authority)){
		// Итог проверки подписи ответа ключом издателя
		const error_t direct = signed_(response, authority);
		// Если подпись издателя сошлась либо приложенные сертификаты ничего точнее отсутствия ответчика не сказали
		if((direct == error_t::NONE) || (failure == error_t::RESPONDER))
			// Запоминаем итог проверки подписи издателем
			failure = direct;
	}
	// Если подпись ответа либо право ответчика не подтвердились
	if(failure != error_t::NONE)
		// Выводим отказ проверки
		return failure;
	// Если сроки судить дозволено
	if(moment != 0){
		/**
		 * Раздел 4.2.2.1 RFC 6960: миг верности состояния не вправе лежать в будущем, а
		 * обещанный срок - в прошлом; люфт покрывает расхождение часов сторон
		 */
		if(single->updated > (moment + leeway))
			// Выводим отказ срока ответа
			return error_t::EXPIRED;
		// Если обещанный срок ответа вышел
		if((single->next != 0) && (single->next < (moment - leeway)))
			// Выводим отказ срока ответа
			return error_t::EXPIRED;
		// Если обещанного срока нет: давность мига верности ограничена своим пределом (раздел 4.2.2.1 RFC 6960 велит клиенту судить свежесть самому)
		if((single->next == 0) && ((single->updated + OCSP_STALE) < (moment - leeway)))
			// Выводим отказ срока ответа
			return error_t::EXPIRED;
	}
	// Если неповторимое значение ожидается
	if(nonce.size > 0){
		// Неповторимое значение ответа
		view_t value;
		// Отказ извлечения неповторимого значения из расширений ответа
		failure = ocsp::nonce(response.extension(), value);
		// Если неповторимое значение извлечь не удалось
		if(failure != error_t::NONE)
			// Выводим отказ извлечения неповторимого значения
			return failure;
		// Если в расширениях ответа значения нет
		if(value.size == 0){
			// Отказ извлечения неповторимого значения из расширений ответа по сертификату
			failure = ocsp::nonce(single->extensions, value);
			// Если неповторимое значение извлечь не удалось
			if(failure != error_t::NONE)
				// Выводим отказ извлечения неповторимого значения
				return failure;
		}
		/**
		 * RFC 8954: ответ без запрошенного значения либо с чужим значением
		 * отвергается — иначе подменой сошёл бы ответ, записанный заранее
		 */
		if(!same(value, nonce))
			// Выводим отказ неповторимого значения
			return error_t::NONCE;
	}
	// Выводим состояние сертификата
	result = single->status;
	// Выводим успешность проверки
	return error_t::NONE;
}
/**
 * @brief Функция проверки ответов о состоянии сертификатов цепочки по местам
 *
 * @param chain    цепочка сертификатов собеседника от листа к издателю
 * @param status   запись принятого ответа OCSP листа цепочки либо пустой накопитель
 * @param statuses записи принятых ответов OCSP иных записей цепочки по их местам, пустой элемент - нет ответа; место листа не занято
 * @param anchors  записи доверенных сертификатов запаса для розыска издателя
 * @param moment   миг проверки в секундах от начала эпохи, ноль сроки не судит
 * @param leeway   дозволенный люфт сроков в секундах в обе стороны
 * @param results  место, в которое помещаются состояния сертификатов по местам
 * @return         причина первого отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::verify(const vector <vector <uint8_t>> & chain, const vector <uint8_t> & status, const vector <vector <uint8_t>> & statuses, const vector <vector <uint8_t>> & anchors, const int64_t moment, const int64_t leeway, vector <status_t> & results) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Занимаем место под состояния по числу записей цепочки
		results.assign(chain.size(), status_t::NONE);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	/**
	 * Выполняем перебор записей цепочки с присланными ответами о состоянии
	 */
	for(size_t i = 0; i < chain.size(); i++){
		// Пустой ответ о состоянии записи без присланного
		static const vector <uint8_t> ABSENT;
		// Запись ответа о состоянии записи: лист хранится раздельно вызовом status,
		// иные - по своим местам в statuses (место листа в statuses не занято)
		const vector <uint8_t> & answer = ((i == 0) ? status : (((i < statuses.size()) ? statuses[i] : ABSENT)));
		// Если ответа о состоянии записи нет
		if(answer.empty())
			// Переходим к следующей записи
			continue;
		// Объект разбора ответа о состоянии
		response_t response;
		// Отказ разбора ответа о состоянии
		const error_t failure = response.parse(view_t(answer.data(), answer.size()));
		// Если ответ о состоянии разобрать не удалось
		if(failure != error_t::NONE)
			// Выводим отказ разбора ответа
			return failure;
		// Объект разбора сертификата записи
		x509::certificate_t subject;
		// Отказ разбора сертификата записи
		x509::error_t parsed = subject.parse(view_t(chain[i].data(), chain[i].size()));
		// Если памяти под разбор не хватило
		if(parsed == x509::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если сертификат записи разобрать не удалось
		if(parsed != x509::error_t::NONE)
			// Выводим отказ разбора сертификата
			return error_t::KEY;
		// Имя издателя сертификата записи
		const view_t & name = subject.issuers().element;
		// Запись сертификата издателя записи
		view_t issuer(nullptr, 0);
		/**
		 * Выполняем перебор иных звеньев цепочки в поисках издателя: раздел 4.4.2
		 * RFC 8446 велит слать издателя следом за сертификатом, но иные стороны шлют
		 * лист и дважды - издатель разыскивается по имени, а не по месту
		 */
		for(size_t j = 0; (j < chain.size()) && (issuer.data == nullptr); j++){
			// Сам сертификат издателем здесь не разыскивается
			if(j == i)
				// Переходим к следующему звену
				continue;
			// Объект разбора звена цепочки
			x509::certificate_t link;
			// Отказ разбора звена цепочки
			parsed = link.parse(view_t(chain[j].data(), chain[j].size()));
			// Если памяти под разбор не хватило
			if(parsed == x509::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Если звено цепочки разобрать не удалось
			if(parsed != x509::error_t::NONE)
				// Переходим к следующему звену
				continue;
			// Имя владельца звена цепочки
			const view_t & owner = link.subjects().element;
			// Если имя владельца звена сошлось с именем издателя
			if((owner.size == name.size) && (::memcmp(owner.data, name.data, name.size) == 0))
				// Берём издателем звено цепочки
				issuer = view_t(chain[j].data(), chain[j].size());
		}
		// Если издателя в цепочке нет, а сертификат записи издан им самим
		if(issuer.data == nullptr){
			// Имя владельца сертификата записи
			const view_t & owner = subject.subjects().element;
			// Если имя владельца сошлось с именем издателя
			if((owner.size == name.size) && (::memcmp(owner.data, name.data, name.size) == 0))
				// Берём издателем сам сертификат записи
				issuer = view_t(chain[i].data(), chain[i].size());
		}
		/**
		 * Выполняем перебор запаса доверенных сертификатов в поисках издателя
		 */
		for(size_t j = 0; (j < anchors.size()) && (issuer.data == nullptr); j++){
			// Объект разбора доверенного сертификата
			x509::certificate_t anchor;
			// Отказ разбора доверенного сертификата
			parsed = anchor.parse(view_t(anchors[j].data(), anchors[j].size()));
			// Если памяти под разбор не хватило
			if(parsed == x509::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Если доверенный сертификат разобрать не удалось
			if(parsed != x509::error_t::NONE)
				// Переходим к следующему сертификату
				continue;
			// Имя владельца доверенного сертификата
			const view_t & owner = anchor.subjects().element;
			// Если имя владельца доверенного сертификата сошлось с именем издателя
			if((owner.size == name.size) && (::memcmp(owner.data, name.data, name.size) == 0))
				// Берём издателем доверенный сертификат
				issuer = view_t(anchors[j].data(), anchors[j].size());
		}
		/**
		 * Без издателя ответ проверить нечем: ни хеши опознавателя, ни подпись
		 * ответчика не сличить, и ответ считается негодным
		 */
		if(issuer.data == nullptr)
			// Выводим отказ проверки ответа о состоянии
			return error_t::KEY;
		// Состояние сертификата записи
		status_t status = status_t::NONE;
		// Проверка ответа против сертификата записи и его издателя
		const error_t refused = ocsp::verify(response, view_t(chain[i].data(), chain[i].size()), issuer, moment, leeway, view_t(nullptr, 0), status);
		// Если ответ о состоянии проверку не прошёл
		if(refused != error_t::NONE)
			// Выводим отказ проверки ответа о состоянии
			return refused;
		// Запоминаем состояние сертификата записи по её месту
		results[i] = status;
	}
	// Выводим успешность проверки ответов цепочки
	return error_t::NONE;
}
/**
 * @brief Функция составления запроса состояния сертификата
 *
 * @param certificate запись сертификата, состояние которого запрашивается
 * @param issuer      запись сертификата издателя
 * @param algorithm   алгоритм хеша опознавателя сертификата
 * @param nonce       неповторимое значение запроса либо пустой просмотр
 * @param result      накопитель, в который помещается запись запроса
 * @return            причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::request(const view_t & certificate, const view_t & issuer, const digest::hash_t algorithm, const view_t & nonce, vector <uint8_t> & result) noexcept {
	// Описание алгоритма хеша опознавателя
	const hash_t * hash = lookup(algorithm);
	// Если алгоритм хеша не поддерживается
	if(hash == nullptr)
		// Выводим отказ алгоритма хеша
		return error_t::HASH;
	// Если неповторимое значение длиннее дозволенного RFC 8954
	if(nonce.size > 32)
		// Выводим отказ состава записи
		return error_t::STRUCTURE;
	// Объект разбора сертификата
	x509::certificate_t subject;
	// Объект разбора сертификата издателя
	x509::certificate_t authority;
	// Отказ разбора сертификата
	x509::error_t parsed = subject.parse(certificate);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если сертификат разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::KEY;
	// Отказ разбора сертификата издателя
	parsed = authority.parse(issuer);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если сертификат издателя разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::KEY;
	// Места, в которые помещаются хеши имени и ключа издателя
	uint8_t name[64], key[64];
	// Длина хешей
	size_t size = 0;
	// Если хеши издателя вычислить не удалось
	if(!hashes(authority, algorithm, name, key, size))
		// Выводим отказ алгоритма хеша
		return error_t::HASH;
	// Опознаватель алгоритма хеша строкой
	string digested;
	// Опознаватель расширения неповторимого значения строкой
	string repeatless;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Переносим опознаватель алгоритма хеша
		digested = hash->oid;
		// Переносим опознаватель расширения неповторимого значения
		repeatless = NONCE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Составитель записи запроса
	asn1::writer_t writer;
	// Открываем запись запроса
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Открываем подписываемую часть запроса
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Открываем перечень запросов
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Открываем запрос по сертификату
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Открываем опознаватель сертификата
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Открываем опознаватель алгоритма хеша
	if(!writer.open(asn1::tag_t::SEQUENCE))
		// Выводим отказ составления записи
		return failed(writer);
	// Записываем опознаватель алгоритма хеша
	if(!writer.oid(digested))
		// Выводим отказ составления записи
		return failed(writer);
	/**
	 * Раздел 2.1 RFC 5754 велит записывать настройки хешей SHA-2 пустым значением NULL
	 * ради совместимости, RFC 3279 - у SHA-1, а раздел 3 RFC 9215 велит у «Стрибога»
	 * настройки опускать
	 */
	if(hash->nothing && !writer.nothing())
		// Выводим отказ составления записи
		return failed(writer);
	// Закрываем опознаватель алгоритма хеша
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	// Записываем хеш имени издателя
	if(!writer.octets(view_t(name, size)))
		// Выводим отказ составления записи
		return failed(writer);
	// Записываем хеш ключа издателя
	if(!writer.octets(view_t(key, size)))
		// Выводим отказ составления записи
		return failed(writer);
	// Записываем порядковый номер сертификата записью из самого сертификата
	if(!writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), subject.number()))
		// Выводим отказ составления записи
		return failed(writer);
	// Закрываем опознаватель сертификата
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	// Закрываем запрос по сертификату
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	// Закрываем перечень запросов
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	// Если неповторимое значение задано
	if(nonce.size > 0){
		// Составитель записи неповторимого значения
		asn1::writer_t inner;
		// Записываем неповторимое значение строкой байтов
		if(!inner.octets(nonce))
			// Выводим отказ составления записи
			return failed(inner);
		// Открываем обёртку расширений запроса
		if(!writer.open(asn1::cls_t::CONTEXT, 2))
			// Выводим отказ составления записи
			return failed(writer);
		// Открываем набор расширений запроса
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи
			return failed(writer);
		// Открываем запись расширения неповторимого значения
		if(!writer.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ составления записи
			return failed(writer);
		// Записываем опознаватель расширения неповторимого значения
		if(!writer.oid(repeatless))
			// Выводим отказ составления записи
			return failed(writer);
		// Записываем содержимое расширения: строку байтов со строкой байтов значения
		if(!writer.octets(inner.data()))
			// Выводим отказ составления записи
			return failed(writer);
		// Закрываем запись расширения неповторимого значения
		if(!writer.close())
			// Выводим отказ составления записи
			return failed(writer);
		// Закрываем набор расширений запроса
		if(!writer.close())
			// Выводим отказ составления записи
			return failed(writer);
		// Закрываем обёртку расширений запроса
		if(!writer.close())
			// Выводим отказ составления записи
			return failed(writer);
	}
	// Закрываем подписываемую часть запроса
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	// Закрываем запись запроса
	if(!writer.close())
		// Выводим отказ составления записи
		return failed(writer);
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Получаем составленную запись запроса
		const view_t data = writer.data();
		// Переносим запись запроса в накопитель
		result.assign(data.data, data.data + data.size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выводим успешность составления запроса
	return error_t::NONE;
}
/**
 * @brief Функция извлечения адреса ответчика из сертификата
 *
 * @param certificate запись сертификата
 * @param result      строка, в которую помещается адрес ответчика
 * @return            причина отказа либо error_t::NONE
 *
 */
nts::ocsp::error_t nts::ocsp::responder(const view_t & certificate, string & result) noexcept {
	// Сбрасываем адрес ответчика
	result.clear();
	// Объект разбора сертификата
	x509::certificate_t subject;
	// Отказ разбора сертификата
	const x509::error_t parsed = subject.parse(certificate);
	// Если памяти под разбор не хватило
	if(parsed == x509::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если сертификат разобрать не удалось
	if(parsed != x509::error_t::NONE)
		// Выводим отказ разбора сертификата
		return error_t::KEY;
	// Разыскиваем расширение сведений о доступе к издателю
	const x509::extension_t * extension = subject.extension(AUTHORITY);
	// Если расширения сведений о доступе нет
	if(extension == nullptr)
		// Выводим успешность: адреса нет
		return error_t::NONE;
	// Создаём разборщик содержимого расширения
	asn1::reader_t reader(extension->value);
	// Объект разобранного перечня способов доступа
	asn1::element_t list;
	// Если перечень способов доступа разобрать не удалось
	if(!reader.next(asn1::tag_t::SEQUENCE, list))
		// Выводим отказ кодировки записи
		return translate(reader.err());
	// Если за перечнем идут лишние поля либо перечень не составной
	if(!reader.empty() || !list.constructed)
		// Выводим отказ записи расширения
		return error_t::EXTENSION;
	// Создаём разборщик перечня способов доступа
	asn1::reader_t entries(list.content);
	/**
	 * Выполняем обход способов доступа
	 */
	while(!entries.empty()){
		// Объект разобранной записи способа доступа
		asn1::element_t entry;
		// Если запись способа доступа разобрать не удалось
		if(!entries.next(asn1::tag_t::SEQUENCE, entry))
			// Выводим отказ кодировки записи
			return translate(entries.err());
		// Если запись способа доступа не составная
		if(!entry.constructed)
			// Выводим отказ записи расширения
			return error_t::EXTENSION;
		// Создаём разборщик записи способа доступа
		asn1::reader_t fields(entry.content);
		// Объект разобранного поля способа доступа
		asn1::element_t field;
		// Если опознаватель способа доступа разобрать не удалось
		if(!fields.next(asn1::tag_t::OBJECT, field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Опознаватель способа доступа
		string method;
		// Отказ извлечения опознавателя способа доступа
		const asn1::error_t failure = asn1::oid(field, method);
		// Если опознаватель способа доступа извлечь не удалось
		if(failure != asn1::error_t::NONE)
			// Выводим отказ извлечения опознавателя
			return translate(failure);
		// Если адрес доступа разобрать не удалось
		if(!fields.next(field))
			// Выводим отказ кодировки записи
			return translate(fields.err());
		// Если за адресом доступа идут лишние поля
		if(!fields.empty())
			// Выводим отказ записи расширения
			return error_t::EXTENSION;
		/**
		 * Раздел 4.2.1.6 RFC 5280: единый указатель ресурса записан меткой [6] строки
		 * IA5String; адреса иного вида ответчику не годятся и пропускаются
		 */
		if((method.compare(ACCESS) != 0) || !alike(field, asn1::cls_t::CONTEXT, false, 6))
			// Переходим к следующему способу доступа
			continue;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Переносим адрес ответчика в строку
			result.assign(reinterpret_cast <const char *> (field.content.data), field.content.size);
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выводим успешность извлечения адреса
		return error_t::NONE;
	}
	// Выводим успешность: адреса нет
	return error_t::NONE;
}

/**
 * @brief Конструктор
 *
 */
nts::ocsp::Single::Single() noexcept : status(status_t::NONE), revocation(0), updated(0), next(0) {}

/**
 * @brief Деструктор
 *
 */
nts::ocsp::Response::~Response() noexcept {}
