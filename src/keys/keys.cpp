/**
 * @file keys.cpp
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
 * @brief Исходный файл модуля кодеков ключей
 *
 * @section Намеренные решения
 *
 * 1. Открытая часть секретного ключа выводится из секретной всегда, а записанная в файле
 *    лишь сличается с выведенной. Довериться записанной значило бы принять ключ, у которого
 *    подпись вырабатывается одним числом, а проверяется другим: такой ключ разбирается, но
 *    не работает, и отказ его всплыл бы далеко от места разбора.
 *
 * 2. Настройки алгоритма RSA обязаны быть записаны пустым значением NULL. Раздел 2.3.1
 *    RFC 3279 так и велит, openssl так и пишет, а запись без настроек вовсе стандарту
 *    не отвечает. Закреплено проверкой KeysTest.Refusal.
 *
 * 3. Кривая у EC принимается только именованной. Раздел 2.1.1 RFC 5480 велит писать
 *    именно так, а явные параметры кривой требуют доверия к чужому набору чисел, тогда
 *    как известные кривые заведены самим составом библиотеки.
 *
 * 4. Негодный пароль зашифрованного ключа опознаётся по дополнению PKCS #7 и по устройству
 *    расшифрованной записи. Схема PBES2 признака подлинности не несёт, и различить негодный
 *    пароль от испорченного шифртекста ей нечем: оба отдаются одним отказом PASSWORD.
 *
 * 5. Записи ключей без пароля выходят байт в байт теми же, что у openssl издания 3:
 *    нулевое издание PrivateKeyInfo, открытый ключ внутри ECPrivateKey без повторения
 *    кривой, зерно Ed25519 строкой байтов в строке байтов. Иных способов записи стандарты
 *    дозволяют несколько, а сличение с эталоном возможно только при одном.
 *
 * 6. Соль зашифрованной записи берётся длиной в шестнадцать байтов, а не в восемь, как у
 *    openssl: раздел 4 RFC 8018 велит не меньше восьми, и большая соль стандарту не
 *    противоречит, а обороты PBKDF2 при чтении берутся из записи, а не подразумеваются.
 *
 * 7. Буферы записчика ASN.1 с секретным содержимым затираются через снятие постоянства
 *    у просмотра его накопителя (buffer(), а не data(): последнее пусто при отказе записи
 *    и при незакрытом элементе, и затирание на пути отказа через него не работало вовсе).
 *    Записчик хранит запись в обычной памяти и затирать её сам не умеет, а оставлять
 *    секретный ключ в освобождённой памяти нельзя; рост же его буфера затирает прежнюю
 *    память сам (asn1::Writer::grow), потому промежуточных копий записи не остаётся.
 *
 * 8. Подготовленный ключ (Signer) заводится один раз и не копируется. Разбор записи,
 *    проверки составляющих RSA делением, выработка открытой точки и предвычисления
 *    Монтгомери стоят у RSA-2048 вдвое дороже подписи, у ECDSA - вдвое дороже всего
 *    рукопожатия, и до круга 29 (22.09.2026) связь вела их на каждой подписи. Модули
 *    подписи на кривых держат указатель на кривую внутри ключа, потому копирование
 *    запрещено, а связи разделяют ключ общим указателем из подлинности. Закреплено
 *    проверкой KeysTest.Signer.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <keys/keys.hpp>
#include <pem/pem.hpp>
#include <asn1/asn1.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <digest/hash.hpp>
#include <digest/pbkdf2.hpp>
#include <entropy/entropy.hpp>
#include <agreement/x25519.hpp>
#include <curve/parameters.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён вспомогательных значений модуля
 */
namespace {
	/**
	 * Наибольшее число итераций PBKDF2, принимаемое из недоверенной записи
	 */
	static constexpr int64_t PBKDF2_MOST = 10000000;
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::keys;

	/**
	 * @brief Отказы работы модуля
	 *
	 * @note Имя заведено своё намеренно: у glibc есть собственный error_t в глобальном
	 *       пространстве имён, и обращение к error_t из безымянного пространства выходило
	 *       бы двусмысленным
	 *
	 */
	typedef keys::error_t error_t;

	/**
	 * @brief Разобранный ключ модуля
	 *
	 * @note Имя заведено своё по той же причине: key_t есть и в <sys/types.h>
	 *
	 */
	typedef keys::key_t key_t;

	/**
	 * Опознаватель алгоритма rsaEncryption по RFC 8017
	 */
	static const char * OID_RSA = "1.2.840.113549.1.1.1";

	/**
	 * Опознаватель алгоритма id-ecPublicKey по RFC 5480
	 */
	static const char * OID_EC = "1.2.840.10045.2.1";

	/**
	 * Опознаватель алгоритма Ed25519 по RFC 8410
	 */
	static const char * OID_ED25519 = "1.3.101.112";

	/**
	 * Опознаватель алгоритма X25519 по RFC 8410
	 */
	static const char * OID_X25519 = "1.3.101.110";

	/**
	 * Опознаватель ключа ГОСТ Р 34.10-2012 длиной 256 разрядов
	 */
	static const char * OID_GOST256 = "1.2.643.7.1.1.1.1";

	/**
	 * Опознаватель ключа ГОСТ Р 34.10-2012 длиной 512 разрядов
	 */
	static const char * OID_GOST512 = "1.2.643.7.1.1.1.2";

	/**
	 * Опознаватель ключа ГОСТ Р 34.10-2001
	 */
	static const char * OID_GOST2001 = "1.2.643.2.2.19";

	/**
	 * Опознаватель ключа ML-DSA-44 по RFC 9881
	 */
	static const char * OID_MLDSA44 = "2.16.840.1.101.3.4.3.17";

	/**
	 * Опознаватель ключа ML-DSA-65 по RFC 9881
	 */
	static const char * OID_MLDSA65 = "2.16.840.1.101.3.4.3.18";

	/**
	 * Опознаватель ключа ML-DSA-87 по RFC 9881
	 */
	static const char * OID_MLDSA87 = "2.16.840.1.101.3.4.3.19";

	/**
	 * Опознаватель ключа SM2 по GB/T 32918 и RFC 8998
	 */
	static const char * OID_SM2 = "1.2.156.10197.1.301";

	/**
	 * Опознаватель схемы PBES2 по RFC 8018
	 */
	static const char * OID_PBES2 = "1.2.840.113549.1.5.13";

	/**
	 * Опознаватель выработки ключа PBKDF2 по RFC 8018
	 */
	static const char * OID_PBKDF2 = "1.2.840.113549.1.5.12";

	/**
	 * Метка записи открытого ключа
	 */
	static const char * LABEL_PUBLIC = "PUBLIC KEY";

	/**
	 * Метка записи ECPrivateKey
	 */
	static const char * LABEL_EC = "EC PRIVATE KEY";

	/**
	 * Метка записи RSAPrivateKey
	 */
	static const char * LABEL_RSA_SECRET = "RSA PRIVATE KEY";

	/**
	 * Метка записи RSAPublicKey
	 */
	static const char * LABEL_RSA_PUBLIC = "RSA PUBLIC KEY";

	/**
	 * Длина блока и синхропосылки AES-CBC
	 */
	static constexpr size_t BLOCK = cipher::AES_BLOCK;

	/**
	 * Длина соли зашифрованной записи
	 */
	static constexpr size_t SALT = 16;

	/**
	 * Длина ключа Ed25519 и X25519
	 */
	static constexpr size_t CURVE25519 = 32;

	/**
	 * @brief Имитовставка выработки ключа из пароля
	 *
	 */
	typedef struct Prf {
		// Опознаватель имитовставки по RFC 8018
		const char * oid;
		// Алгоритм хеширования имитовставки
		digest::hash_t algorithm;
	} prf_t;

	/**
	 * Известные имитовставки выработки ключа из пароля
	 */
	static const prf_t PRFS[] = {
		{"1.2.840.113549.2.7", digest::hash_t::SHA1},
		{"1.2.840.113549.2.8", digest::hash_t::SHA224},
		{"1.2.840.113549.2.9", digest::hash_t::SHA256},
		{"1.2.840.113549.2.10", digest::hash_t::SHA384},
		{"1.2.840.113549.2.11", digest::hash_t::SHA512}
	};

	/**
	 * @brief Шифр зашифрованной записи
	 *
	 */
	typedef struct Cipher {
		// Опознаватель шифра по RFC 8018
		const char * oid;
		// Длина ключа шифра в разрядах
		size_t bits;
	} cipher_t;

	/**
	 * Известные шифры зашифрованной записи: AES-CBC трёх длин ключа
	 */
	static const cipher_t CIPHERS[] = {
		{"2.16.840.1.101.3.4.1.2", 128},
		{"2.16.840.1.101.3.4.1.22", 192},
		{"2.16.840.1.101.3.4.1.42", 256}
	};

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод затирания и освобождения набора байтов
	 *
	 * @param data затираемый набор байтов
	 *
	 */
	static void erase(vector <uint8_t> & data) noexcept {
		// Если набор байтов не пуст
		if(!data.empty())
			// Выполняем затирание содержимого набора байтов
			wipe(data.data(), data.size());
		// Пустой набор, которым подменяется затёртый
		vector <uint8_t> empty;
		// Освобождаем память затёртого набора: обмен памяти не выделяет
		data.swap(empty);
	}
	/**
	 * @brief Метод затирания буфера записчика
	 *
	 * @param writer записчик, буфер которого затирается
	 *
	 */
	static void scrub(asn1::writer_t & writer) noexcept {
		// Получаем просмотр накопителя записчика целиком: на пути отказа data() пуст
		const view_t data = writer.buffer();
		// Если буфер записчика не пуст
		if((data.data != nullptr) && (data.size > 0))
			// Выполняем затирание буфера: память буфера принадлежит записчику и постоянной не является
			wipe(const_cast <uint8_t *> (data.data), data.size);
		// Выполняем сброс записчика
		writer.clear();
	}
	/**
	 * @brief Метод копирования области байтов в набор байтов
	 *
	 * @param data   копируемая область байтов
	 * @param size   размер копируемой области байтов
	 * @param result набор байтов, в который помещается итог копирования
	 *
	 * @return       признак успешности копирования: памяти достало
	 *
	 */
	static bool copy(const uint8_t * data, const size_t size, vector <uint8_t> & result) noexcept {
		/**
		 * Копирование выделяет память: нехватка её отдаётся отказом, а не
		 * завершением процесса
		 */
		try {
			// Выполняем копирование области байтов
			result.assign(data, data + size);
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ копирования
			return false;
		}
		// Выводим успешность копирования
		return true;
	}
	/**
	 * @brief Метод переноса ключа с обменом содержимого
	 *
	 * @param source ключ, содержимое которого переносится
	 * @param result ключ, в который помещается перенесённое содержимое
	 *
	 * @note Обмен памяти не выделяет, а прежнее содержимое места назначения
	 *       затирается вместе с источником при его уничтожении
	 *
	 */
	static void transfer(key_t & source, key_t & result) noexcept {
		// Переносим вид ключа
		result.kind = source.kind;
		// Сбрасываем вид ключа у источника
		source.kind = kind_t::NONE;
		// Обмениваем опознаватели
		result.oid.swap(source.oid);
		// Обмениваем опознаватели алгоритма
		result.algorithm.swap(source.algorithm);
		// Обмениваем опознаватели хеша
		result.digest.swap(source.digest);
		// Обмениваем модули
		result.n.swap(source.n);
		// Обмениваем открытые показатели
		result.e.swap(source.e);
		// Обмениваем секретные составляющие
		result.d.swap(source.d);
		// Обмениваем первые сомножители
		result.p.swap(source.p);
		// Обмениваем вторые сомножители
		result.q.swap(source.q);
		// Обмениваем показатели dP
		result.dP.swap(source.dP);
		// Обмениваем показатели dQ
		result.dQ.swap(source.dQ);
		// Обмениваем коэффициенты
		result.qInv.swap(source.qInv);
		// Обмениваем первые координаты
		result.x.swap(source.x);
		// Обмениваем вторые координаты
		result.y.swap(source.y);
		// Обмениваем открытые ключи
		result.key.swap(source.key);
	}
	/**
	 * @brief Метод перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 *
	 * @return      отказ модуля
	 *
	 */
	static error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? error_t::MEMORY : error_t::STRUCTURE);
	}
	/**
	 * @brief Метод завершения записи с переносом её в набор байтов
	 *
	 * @param writer записчик, запись которого переносится
	 * @param result набор байтов, в который помещается запись
	 *
	 * @return       отказ завершения записи
	 *
	 */
	static error_t finish(asn1::writer_t & writer, vector <uint8_t> & result) noexcept {
		// Если запись завершилась отказом
		if(writer.err() != asn1::error_t::NONE)
			// Выводим переведённый отказ записи
			return translate(writer.err());
		// Получаем просмотр собранной записи
		const view_t data = writer.data();
		// Если запись скопировать не удалось
		if(!copy(data.data, data.size, result))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим успешность завершения записи
		return error_t::NONE;
	}
	/**
	 * @brief Метод проверки принадлежности элемента заданной метке своего класса
	 *
	 * @param element     проверяемый элемент
	 * @param cls         ожидаемый класс метки
	 * @param tag         ожидаемый номер метки
	 * @param constructed ожидаемый признак составного вида
	 *
	 * @return            признак того, что элемент отвечает ожиданиям
	 *
	 */
	static bool tagged(const asn1::element_t & element, const asn1::cls_t cls, const uint32_t tag, const bool constructed) noexcept {
		// Выводим итог сличения класса, номера метки и вида элемента
		return ((element.cls == cls) && (element.tag == tag) && (element.constructed == constructed));
	}
	/**
	 * @brief Метод разбора неотрицательного целого числа
	 *
	 * @param element разбираемый элемент
	 * @param result  набор байтов, в который помещается число без ведущих нулей
	 *
	 * @return        отказ разбора числа
	 *
	 */
	static error_t unsignedInteger(const asn1::element_t & element, vector <uint8_t> & result) noexcept {
		// Просмотр содержимого числа
		view_t value;
		// Итог разбора целого числа
		const asn1::error_t outcome = asn1::integer(element, value);
		// Если целое число разобрать не удалось
		if(outcome != asn1::error_t::NONE)
			// Выводим переведённый отказ разбора
			return translate(outcome);
		// Если число отрицательно
		if((value.size == 0) || ((value.data[0] & 0x80) != 0))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Смещение значащей части числа: кратчайшая запись несёт не больше одного ведущего нуля
		const size_t offset = (((value.size > 1) && (value.data[0] == 0)) ? 1 : 0);
		// Если число скопировать не удалось
		if(!copy(value.data + offset, value.size - offset, result))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим успешность разбора числа
		return error_t::NONE;
	}
	/**
	 * @brief Метод записи неотрицательного целого числа
	 *
	 * @param writer записчик, в который помещается число
	 * @param value  записываемое число порядком от старшего байта к младшему
	 *
	 * @return       отказ записи числа
	 *
	 */
	static error_t unsignedInteger(asn1::writer_t & writer, const vector <uint8_t> & value) noexcept {
		// Смещение значащей части числа
		size_t offset = 0;
		/**
		 * Выполняем пропуск ведущих нулей: кодировка DER требует кратчайшей записи
		 */
		while((offset < value.size()) && (value[offset] == 0))
			// Пропускаем очередной ведущий ноль
			offset++;
		// Байты числа с местом под ведущий ноль знака
		vector <uint8_t> buffer;
		/**
		 * Сборка числа выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Если число нулевое
			if(offset == value.size())
				// Записываем один нулевой байт
				buffer.assign(1, 0);
			// Если старший разряд числа выставлен
			else if((value[offset] & 0x80) != 0){
				// Заводим ведущий ноль знака
				buffer.assign(1, 0);
				// Дописываем значащую часть числа
				buffer.insert(buffer.end(), value.begin() + offset, value.end());
			// Если число записывается как есть
			} else buffer.assign(value.begin() + offset, value.end());
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Выполняем запись целого числа
		writer.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), view_t(buffer.data(), buffer.size()));
		// Выполняем затирание байтов числа: оно вправе быть секретным
		erase(buffer);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод разбора малого целого числа
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается число
	 *
	 * @return        отказ разбора числа
	 *
	 */
	static error_t smallInteger(const asn1::element_t & element, int64_t & result) noexcept {
		// Итог разбора целого числа
		const asn1::error_t outcome = asn1::integer(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Метод разбора опознавателя объекта
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается опознаватель
	 *
	 * @return        отказ разбора опознавателя
	 *
	 */
	static error_t identifier(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Метод копирования опознавателя в строку
	 *
	 * @param value  копируемый опознаватель
	 * @param result строка, в которую помещается опознаватель
	 *
	 * @return       признак успешности копирования: памяти достало
	 *
	 */
	static bool store(const char * value, string & result) noexcept {
		/**
		 * Копирование выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Выполняем копирование опознавателя
			result.assign(value);
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ копирования
			return false;
		}
		// Выводим успешность копирования
		return true;
	}
	/**
	 * @brief Метод записи опознавателя объекта из строки знаков
	 *
	 * @param writer записчик, в который помещается опознаватель
	 * @param value  записываемый опознаватель строкой знаков
	 *
	 * @return       отказ записи опознавателя
	 *
	 * @note Записчик принимает опознаватель строкой, а сборка строки из знаков
	 *       выделяет память: нехватка её отдаётся отказом
	 *
	 */
	static error_t object(asn1::writer_t & writer, const char * value) noexcept {
		// Опознаватель строкой
		string oid;
		// Если опознаватель скопировать не удалось
		if(!store(value, oid))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Записываем опознаватель объекта
		writer.oid(oid);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод разбора верхней записи с проверкой отсутствия хвоста
	 *
	 * @param der    разбираемая запись
	 * @param result место, в которое помещается набор верхней записи
	 *
	 * @return       отказ разбора верхней записи
	 *
	 */
	static error_t outer(const view_t & der, asn1::element_t & result) noexcept {
		// Если запись не передана
		if((der.data == nullptr) || (der.size == 0))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Разборщик записи
		asn1::reader_t reader(der);
		// Если набор верхней записи разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, result) || !result.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Если после набора остался хвост
		if(!reader.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Выводим успешность разбора верхней записи
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора опознавателя алгоритма с настройками
	 *
	 * @param reader    разборщик, из которого берётся набор алгоритма
	 * @param algorithm место, в которое помещается опознаватель алгоритма
	 * @param params    место, в которое помещаются настройки алгоритма
	 * @param present   место, в которое помещается признак наличия настроек
	 *
	 * @return          отказ разбора опознавателя алгоритма
	 *
	 */
	static error_t algorithmIdentifier(asn1::reader_t & reader, string & algorithm, asn1::element_t & params, bool & present) noexcept {
		// Сбрасываем признак наличия настроек
		present = false;
		// Набор алгоритма
		asn1::element_t element;
		// Если набор алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = reader.enter(element);
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя алгоритма
		const error_t outcome = identifier(element, algorithm);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(params))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Устанавливаем признак наличия настроек
			present = true;
			// Если после настроек остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
		}
		// Выводим успешность разбора опознавателя алгоритма
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора настроек ключа ГОСТ
	 *
	 * @details Раздел 2.1 RFC 9215: набор из опознавателя кривой и, необязательно,
	 *          опознавателя хеша
	 *
	 * @param params разбираемые настройки ключа
	 * @param key    ключ, в который помещаются опознаватели
	 *
	 * @return       отказ разбора настроек
	 *
	 */
	static error_t gostParameters(const asn1::element_t & params, key_t & key) noexcept {
		// Если настройки записаны не набором
		if(!tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), true))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Разборщик содержимого набора настроек
		asn1::reader_t items(params.content);
		// Разбираемый элемент настроек
		asn1::element_t element;
		// Если опознаватель кривой разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Итог разбора опознавателя кривой
		error_t outcome = identifier(element, key.oid);
		// Если опознаватель кривой разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если опознаватель хеша записан
		if(!items.empty()){
			// Если опознаватель хеша разобрать не удалось
			if(!items.next(asn1::tag_t::OBJECT, element))
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
			// Итог разбора опознавателя хеша
			outcome = identifier(element, key.digest);
			// Если опознаватель хеша разобрать не удалось
			if(outcome != error_t::NONE)
				// Выводим отказ разбора
				return outcome;
			// Если после опознавателя хеша остался хвост
			if(!items.empty())
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
		}
		// Выводим успешность разбора настроек
		return error_t::NONE;
	}
	/**
	 * @brief Метод записи настроек алгоритма ключа
	 *
	 * @param writer записчик, в который помещается набор алгоритма
	 * @param key    записываемый ключ
	 *
	 * @return       отказ записи набора алгоритма
	 *
	 */
	static error_t algorithmIdentifier(asn1::writer_t & writer, const key_t & key) noexcept {
		// Открываем набор алгоритма
		writer.open(asn1::tag_t::SEQUENCE);
		/**
		 * Выполняем определение вида ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Если записывается ключ RSA
			case static_cast <uint8_t> (kind_t::RSA): {
				// Записываем опознаватель алгоритма
				object(writer, OID_RSA);
				// Записываем пустые настройки: раздел 2.3.1 RFC 3279
				writer.nothing();
			} break;
			// Если записывается ключ EC
			case static_cast <uint8_t> (kind_t::EC): {
				// Записываем опознаватель алгоритма
				object(writer, OID_EC);
				// Записываем именованную кривую
				writer.oid(key.oid);
			} break;
			// Если записывается ключ Ed25519
			case static_cast <uint8_t> (kind_t::ED25519):
				// Записываем опознаватель алгоритма: настроек у него нет
				object(writer, OID_ED25519);
			break;
			// Если записывается ключ X25519
			case static_cast <uint8_t> (kind_t::X25519):
				// Записываем опознаватель алгоритма: настроек у него нет
				object(writer, OID_X25519);
			break;
			// Если записывается ключ ML-DSA: настроек у него нет (раздел 5 RFC 9881)
			case static_cast <uint8_t> (kind_t::MLDSA):
				// Записываем опознаватель алгоритма ключа
				writer.oid(key.algorithm);
			break;
			// Если записывается ключ ГОСТ
			case static_cast <uint8_t> (kind_t::GOST): {
				// Записываем опознаватель алгоритма
				writer.oid(key.algorithm);
				// Открываем набор настроек
				writer.open(asn1::tag_t::SEQUENCE);
				// Записываем опознаватель кривой
				writer.oid(key.oid);
				// Если опознаватель хеша задан
				if(!key.digest.empty())
					// Записываем опознаватель хеша
					writer.oid(key.digest);
				// Закрываем набор настроек
				writer.close();
			} break;
			// Если вид ключа не установлен
			default:
				// Выводим отказ пустого ключа
				return error_t::EMPTY;
		}
		// Закрываем набор алгоритма
		writer.close();
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод установки кривой по опознавателю ключа
	 *
	 * @param key   ключ, кривая которого устанавливается
	 * @param curve место, в которое помещается кривая
	 *
	 * @return      отказ установки кривой
	 *
	 */
	static error_t curveOf(const key_t & key, curve::curve_t & curve) noexcept {
		// Если кривую по опознавателю установить не удалось
		if(key.oid.empty() || !curve::parameters(key.oid, curve))
			// Выводим отказ кривой
			return error_t::CURVE;
		// Выводим успешность установки кривой
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора несжатой точки по разделу 2.2 RFC 5480
	 *
	 * @param data  разбираемая запись точки
	 * @param curve кривая, которой обязана принадлежать точка
	 * @param x     место, в которое помещается первая координата
	 * @param y     место, в которое помещается вторая координата
	 *
	 * @return      отказ разбора точки
	 *
	 */
	static error_t pointOf(const view_t & data, const curve::curve_t & curve, vector <uint8_t> & x, vector <uint8_t> & y) noexcept {
		// Размер координаты точки кривой
		const size_t size = curve.size();
		// Если запись точки не несёт признака несжатой записи и двух координат
		if((data.data == nullptr) || (data.size != (1 + (size * 2))) || (data.data[0] != 0x04))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Точка, которой проверяется принадлежность кривой
		curve::point_t point;
		// Если точка кривой не принадлежит
		if(!curve.point(view_t(data.data + 1, size), view_t(data.data + 1 + size, size), point))
			// Выводим отказ кривой
			return error_t::CURVE;
		// Если координаты скопировать не удалось
		if(!copy(data.data + 1, size, x) || !copy(data.data + 1 + size, size, y))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим успешность разбора точки
		return error_t::NONE;
	}
	/**
	 * @brief Метод разворота порядка байтов
	 *
	 * @param data   разворачиваемая область байтов
	 * @param size   размер разворачиваемой области байтов
	 * @param result набор байтов, в который помещается итог разворота
	 *
	 * @return       признак успешности разворота: памяти достало
	 *
	 */
	static bool reverse(const uint8_t * data, const size_t size, vector <uint8_t> & result) noexcept {
		/**
		 * Разворот выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Выделяем место под итог разворота
			result.assign(size, 0);
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ разворота
			return false;
		}
		/**
		 * Выполняем перенос байтов в обратном порядке
		 */
		for(size_t i = 0; i < size; i++)
			// Переносим очередной байт
			result[i] = data[size - i - 1];
		// Выводим успешность разворота
		return true;
	}
	/**
	 * @brief Метод сличения двух наборов байтов за постоянное время
	 *
	 * @param first  первый набор байтов
	 * @param second второй набор байтов
	 *
	 * @return       признак совпадения наборов байтов
	 *
	 */
	static bool same(const vector <uint8_t> & first, const vector <uint8_t> & second) noexcept {
		// Если размеры наборов различны
		if(first.size() != second.size())
			// Выводим несовпадение
			return false;
		// Накопленное различие наборов
		uint8_t difference = 0;
		/**
		 * Выполняем сличение байтов за постоянное время
		 */
		for(size_t i = 0; i < first.size(); i++)
			// Накапливаем различие очередных байтов
			difference |= (first[i] ^ second[i]);
		// Выводим совпадение наборов
		return (difference == 0);
	}
	/**
	 * @brief Метод проверки согласованности составляющих ключа RSA
	 *
	 * @param key проверяемый ключ
	 *
	 * @return    отказ проверки ключа
	 *
	 */
	static error_t checkRSA(const key_t & key) noexcept {
		// Примитив RSA, которым проверяется ключ
		sign::rsa_t rsa;
		// Если ключ примитивом не принят
		if(!key.load(rsa))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Выводим успешность проверки
		return error_t::NONE;
	}
	/**
	 * @brief Метод выведения открытой части ключа из секретной со сличением
	 *
	 * @details Открытая часть выводится из секретной всегда; записанная в файле
	 *          лишь сличается с выведенной, а при отсутствии - заполняется ею
	 *
	 * @param key ключ, открытая часть которого выводится
	 *
	 * @return    отказ выведения открытой части
	 *
	 */
	static error_t derive(key_t & key) noexcept {
		/**
		 * Выполняем определение вида ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Если выводится ключ RSA
			case static_cast <uint8_t> (kind_t::RSA):
				// Выводим итог проверки согласованности составляющих
				return checkRSA(key);
			// Если выводится ключ EC либо ГОСТ
			case static_cast <uint8_t> (kind_t::EC):
			case static_cast <uint8_t> (kind_t::GOST): {
				// Кривая ключа
				curve::curve_t curve;
				// Примитивы, которыми выводится открытая часть
				sign::ecdsa_t ecdsa;
				// Примитив ГОСТ, которым выводится открытая часть
				sign::gost_t gost;
				// Признак ключа EC
				const bool ec = (key.kind == kind_t::EC);
				// Если ключ примитивом не принят
				if(ec ? !key.load(ecdsa, curve) : !key.load(gost, curve))
					// Выводим отказ: кривая неизвестна либо скаляр негоден
					return (curve.ready() ? error_t::VALUE : error_t::CURVE);
				// Если секретной части нет, открытая проверена самим примитивом
				if(!key.secret())
					// Выводим успешность выведения
					return error_t::NONE;
				// Места, в которые помещаются координаты выведенной точки
				uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
				// Размер координаты точки кривой
				const size_t size = curve.size();
				// Если координаты выведенной точки получить не удалось
				if(ec ? !ecdsa.key(x, y, size) : !gost.key(x, y, size))
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Если открытая часть в ключе записана
				if(!key.x.empty() || !key.y.empty()){
					// Выведенные координаты
					vector <uint8_t> dx, dy;
					// Если координаты скопировать не удалось
					if(!copy(x, size, dx) || !copy(y, size, dy))
						// Выводим отказ нехватки памяти
						return error_t::MEMORY;
					// Выводим итог сличения записанной открытой части с выведенной
					return ((same(dx, key.x) && same(dy, key.y)) ? error_t::NONE : error_t::VALUE);
				}
				// Если координаты скопировать не удалось
				if(!copy(x, size, key.x) || !copy(y, size, key.y))
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим успешность выведения
				return error_t::NONE;
			}
			// Если выводится ключ Ed25519 либо X25519
			case static_cast <uint8_t> (kind_t::ED25519):
			case static_cast <uint8_t> (kind_t::X25519): {
				// Если секретной части нет
				if(!key.secret()){
					// Если открытый ключ записан не своей длиной
					if(key.key.size() != CURVE25519)
						// Выводим отказ негодного значения
						return error_t::VALUE;
					// Если ключ подписи Ed25519
					if(key.kind == kind_t::ED25519){
						// Примитив Ed25519, которым проверяется точка
						sign::ed25519_t ed25519;
						// Если открытый ключ примитивом не принят
						if(!key.load(ed25519))
							// Выводим отказ негодного значения
							return error_t::VALUE;
					}
					// Выводим успешность выведения
					return error_t::NONE;
				}
				// Если зерно записано не своей длиной
				if(key.d.size() != CURVE25519)
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Место, в которое помещается выведенный открытый ключ
				uint8_t point[CURVE25519];
				// Если ключ подписи Ed25519
				if(key.kind == kind_t::ED25519){
					// Примитив Ed25519, которым выводится открытый ключ
					sign::ed25519_t ed25519;
					// Если зерно примитивом не принято либо открытый ключ получить не удалось
					if(!key.load(ed25519) || !ed25519.key(point, sizeof(point)))
						// Выводим отказ негодного значения
						return error_t::VALUE;
				// Если открытый ключ X25519 вывести не удалось
				} else if(!agreement::x25519(view_t(key.d.data(), key.d.size()), point))
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Если открытая часть в ключе записана
				if(!key.key.empty()){
					// Выведенный открытый ключ
					vector <uint8_t> derived;
					// Если открытый ключ скопировать не удалось
					if(!copy(point, sizeof(point), derived))
						// Выводим отказ нехватки памяти
						return error_t::MEMORY;
					// Выводим итог сличения записанной открытой части с выведенной
					return (same(derived, key.key) ? error_t::NONE : error_t::VALUE);
				}
				// Если открытый ключ скопировать не удалось
				if(!copy(point, sizeof(point), key.key))
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим успешность выведения
				return error_t::NONE;
			}
			// Если выводится ключ ML-DSA
			case static_cast <uint8_t> (kind_t::MLDSA): {
				// Если секретной части нет
				if(!key.secret()){
					// Если размер записи не отвечает ни одному набору
					if((key.key.size() != 1312) && (key.key.size() != 1952) && (key.key.size() != 2592))
						// Выводим отказ негодного значения
						return error_t::VALUE;
					// Примитив ML-DSA, которым проверяется запись
					sign::mldsa_t mldsa;
					// Выводим итог проверки записи открытого ключа
					return (key.load(mldsa) ? error_t::NONE : error_t::VALUE);
				}
				// Примитив ML-DSA, которым выводится открытая часть
				sign::mldsa_t mldsa;
				// Если ключ примитивом не принят
				if(!key.load(mldsa))
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Запись выведенной открытой части
				uint8_t exposed[2592];
				// Если открытую часть вывести не удалось
				if(!mldsa.key(exposed, sizeof(exposed)))
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Размер открытой части набора ключа
				const size_t size = sign::mldsa_t::publicSize(mldsa.set());
				// Если открытая часть в ключе записана
				if(!key.key.empty()){
					// Выведенная открытая часть
					vector <uint8_t> derived;
					// Если открытую часть скопировать не удалось
					if(!copy(exposed, size, derived))
						// Выводим отказ нехватки памяти
						return error_t::MEMORY;
					// Выводим итог сличения записанной открытой части с выведенной
					return (same(derived, key.key) ? error_t::NONE : error_t::VALUE);
				}
				// Если открытую часть скопировать не удалось
				if(!copy(exposed, size, key.key))
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим успешность выведения
				return error_t::NONE;
			}
		}
		// Выводим отказ пустого ключа
		return error_t::EMPTY;
	}
	/**
	 * @brief Метод разбора набора целых чисел RSA
	 *
	 * @param der   разбираемая запись
	 * @param count ожидаемое число целых чисел
	 * @param items места, в которые помещаются числа
	 *
	 * @return      отказ разбора набора
	 *
	 */
	static error_t rsaIntegers(const view_t & der, const size_t count, vector <uint8_t> ** items) noexcept {
		// Набор верхней записи
		asn1::element_t sequence;
		// Итог разбора верхней записи
		error_t outcome = outer(der, sequence);
		// Если верхнюю запись разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Разборщик содержимого набора
		asn1::reader_t fields(sequence.content);
		/**
		 * Выполняем разбор целых чисел набора
		 */
		for(size_t i = 0; i < count; i++){
			// Очередное поле набора
			asn1::element_t field;
			// Если очередное целое число разобрать не удалось
			if(!fields.next(asn1::tag_t::INTEGER, field))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Если поле есть издание записи
			if(items[i] == nullptr){
				// Издание записи
				int64_t version = -1;
				// Итог разбора издания записи
				outcome = smallInteger(field, version);
				// Если издание записи разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Если издание записи не нулевое: дополнительных сомножителей библиотека не ведёт
				if(version != 0)
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
			// Если поле есть составляющая ключа
			} else {
				// Итог разбора составляющей ключа
				outcome = unsignedInteger(field, * items[i]);
				// Если составляющую ключа разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
			}
		}
		// Если после чисел остался хвост
		if(!fields.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Выводим успешность разбора набора
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора записи RSAPublicKey
	 *
	 * @param der разбираемая запись
	 * @param key ключ, в который помещается итог разбора
	 *
	 * @return    отказ разбора записи
	 *
	 */
	static error_t rsaPublic(const view_t & der, key_t & key) noexcept {
		// Места составляющих открытого ключа
		vector <uint8_t> * items[] = {&key.n, &key.e};
		// Итог разбора набора целых чисел
		const error_t outcome = rsaIntegers(der, 2, items);
		// Если набор разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Устанавливаем вид ключа
		key.kind = kind_t::RSA;
		// Выводим итог проверки согласованности составляющих
		return checkRSA(key);
	}
	/**
	 * @brief Метод разбора записи RSAPrivateKey
	 *
	 * @param der разбираемая запись
	 * @param key ключ, в который помещается итог разбора
	 *
	 * @return    отказ разбора записи
	 *
	 */
	static error_t rsaSecret(const view_t & der, key_t & key) noexcept {
		// Места составляющих секретного ключа: издание записи места не имеет
		vector <uint8_t> * items[] = {nullptr, &key.n, &key.e, &key.d, &key.p, &key.q, &key.dP, &key.dQ, &key.qInv};
		// Итог разбора набора целых чисел
		const error_t outcome = rsaIntegers(der, 9, items);
		// Если набор разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Устанавливаем вид ключа
		key.kind = kind_t::RSA;
		// Выводим итог проверки согласованности составляющих
		return checkRSA(key);
	}
	/**
	 * @brief Метод записи набора целых чисел RSA
	 *
	 * @param key    записываемый ключ
	 * @param secret признак записи секретного ключа
	 * @param writer записчик, в который помещается набор
	 *
	 * @return       отказ записи набора
	 *
	 */
	static error_t rsaIntegers(const key_t & key, const bool secret, asn1::writer_t & writer) noexcept {
		// Если ключ не RSA либо не несёт нужной части
		if((key.kind != kind_t::RSA) || key.n.empty() || key.e.empty() || (secret && !key.secret()))
			// Выводим отказ пустого ключа
			return error_t::EMPTY;
		// Открываем набор составляющих ключа
		writer.open(asn1::tag_t::SEQUENCE);
		// Если записывается секретный ключ
		if(secret)
			// Записываем издание записи: без дополнительных сомножителей
			writer.integer(0);
		// Составляющие ключа в порядке записи
		const vector <uint8_t> * items[] = {&key.n, &key.e, &key.d, &key.p, &key.q, &key.dP, &key.dQ, &key.qInv};
		// Число записываемых составляющих
		const size_t count = (secret ? 8 : 2);
		/**
		 * Выполняем запись составляющих ключа
		 */
		for(size_t i = 0; i < count; i++){
			// Итог записи очередной составляющей
			const error_t outcome = unsignedInteger(writer, * items[i]);
			// Если составляющую записать не удалось
			if(outcome != error_t::NONE)
				// Выводим отказ записи
				return outcome;
		}
		// Закрываем набор составляющих ключа
		writer.close();
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод разбора записи ECPrivateKey по RFC 5915
	 *
	 * @param der     разбираемая запись
	 * @param wrapped признак записи внутри обёртки PrivateKeyInfo с уже известной кривой
	 * @param key     ключ, в который помещается итог разбора
	 *
	 * @return        отказ разбора записи
	 *
	 */
	static error_t ecSecret(const view_t & der, const bool wrapped, key_t & key) noexcept {
		// Набор верхней записи
		asn1::element_t sequence;
		// Итог разбора верхней записи
		error_t outcome = outer(der, sequence);
		// Если верхнюю запись разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Разборщик содержимого набора
		asn1::reader_t fields(sequence.content);
		// Разбираемый элемент набора
		asn1::element_t element;
		// Если издание записи разобрать не удалось
		if(!fields.next(asn1::tag_t::INTEGER, element))
			// Выводим переведённый отказ разбора
			return translate(fields.err());
		// Издание записи
		int64_t version = -1;
		// Итог разбора издания записи
		outcome = smallInteger(element, version);
		// Если издание записи разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если издание записи не единица: раздел 3 RFC 5915 иного не дозволяет
		if(version != 1)
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Если секретный скаляр разобрать не удалось
		if(!fields.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
			// Выводим переведённый отказ разбора
			return translate(fields.err());
		// Если секретный скаляр пуст
		if(element.content.size == 0)
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Если секретный скаляр скопировать не удалось
		if(!copy(element.content.data, element.content.size, key.d))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Признак наличия именованной кривой в записи
		bool named = false;
		// Если необязательные поля записаны
		if(!fields.empty()){
			// Если очередное поле разобрать не удалось
			if(!fields.next(element))
				// Выводим переведённый отказ разбора
				return translate(fields.err());
			// Признак неразобранного поля
			bool pending = true;
			// Если поле есть настройки кривой
			if(tagged(element, asn1::cls_t::CONTEXT, 0, true)){
				// Разборщик содержимого настроек кривой
				asn1::reader_t inner = fields.enter(element);
				// Если опознаватель кривой разобрать не удалось: явные параметры кривой не принимаются
				if(!inner.next(asn1::tag_t::OBJECT, element))
					// Выводим отказ кривой
					return error_t::CURVE;
				// Опознаватель кривой из записи
				string oid;
				// Итог разбора опознавателя кривой
				outcome = identifier(element, oid);
				// Если опознаватель кривой разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Если после опознавателя кривой остался хвост
				if(!inner.empty())
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если кривая обёртки не сошлась с кривой записи
				if(wrapped && (key.oid.compare(oid) != 0))
					// Выводим отказ кривой
					return error_t::CURVE;
				// Устанавливаем опознаватель кривой: обмен памяти не выделяет
				key.oid.swap(oid);
				// Устанавливаем признак наличия именованной кривой
				named = true;
				// Снимаем признак неразобранного поля
				pending = false;
				// Если запись продолжается
				if(!fields.empty()){
					// Если очередное поле разобрать не удалось
					if(!fields.next(element))
						// Выводим переведённый отказ разбора
						return translate(fields.err());
					// Устанавливаем признак неразобранного поля
					pending = true;
				}
			}
			// Если поле есть открытый ключ
			if(pending && tagged(element, asn1::cls_t::CONTEXT, 1, true)){
				// Кривая ключа
				curve::curve_t curve;
				// Итог установки кривой
				outcome = curveOf(key, curve);
				// Если кривую установить не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ установки
					return outcome;
				// Разборщик содержимого открытого ключа
				asn1::reader_t inner = fields.enter(element);
				// Если строку битов открытого ключа разобрать не удалось
				if(!inner.next(asn1::tag_t::BIT_STRING, element))
					// Выводим переведённый отказ разбора
					return translate(inner.err());
				// Если после строки битов остался хвост
				if(!inner.empty())
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Просмотр байтов открытого ключа
				view_t bytes;
				// Число неиспользуемых разрядов последнего байта
				uint8_t unused = 0;
				// Итог разбора строки битов
				const asn1::error_t parsed = asn1::bits(element, bytes, unused);
				// Если строку битов разобрать не удалось либо разряды не заняты целиком
				if((parsed != asn1::error_t::NONE) || (unused != 0))
					// Выводим отказ разбора
					return ((parsed == asn1::error_t::NONE) ? error_t::STRUCTURE : translate(parsed));
				// Итог разбора точки открытого ключа
				outcome = pointOf(bytes, curve, key.x, key.y);
				// Если точку открытого ключа разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
			// Если поле не опознано
			} else if(pending)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Если после полей остался хвост
			if(!fields.empty())
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
		}
		// Если кривой запись не несёт, а объявить её больше нечему
		if(!wrapped && !named)
			// Выводим отказ кривой
			return error_t::CURVE;
		// Устанавливаем вид ключа
		key.kind = kind_t::EC;
		// Выводим итог выведения открытой части ключа
		return derive(key);
	}
	/**
	 * @brief Метод записи ECPrivateKey по RFC 5915
	 *
	 * @param key    записываемый ключ
	 * @param named  признак записи именованной кривой внутри
	 * @param writer записчик, в который помещается запись
	 *
	 * @return       отказ записи
	 *
	 */
	static error_t ecSecret(const key_t & key, const bool named, asn1::writer_t & writer) noexcept {
		// Если ключ не EC либо не несёт нужной части
		if((key.kind != kind_t::EC) || !key.secret() || key.x.empty() || key.y.empty())
			// Выводим отказ пустого ключа
			return error_t::EMPTY;
		// Кривая ключа
		curve::curve_t curve;
		// Итог установки кривой
		const error_t outcome = curveOf(key, curve);
		// Если кривую установить не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ установки
			return outcome;
		// Размер координаты точки кривой
		const size_t size = curve.size();
		// Если скаляр либо координаты записаны не размером кривой
		if((key.d.size() > size) || (key.x.size() != size) || (key.y.size() != size))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Скаляр, дополненный ведущими нулями до размера кривой, и несжатая точка
		vector <uint8_t> scalar, point;
		/**
		 * Сборка выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Заводим ведущие нули скаляра
			scalar.assign(size - key.d.size(), 0);
			// Дописываем скаляр
			scalar.insert(scalar.end(), key.d.begin(), key.d.end());
			// Заводим признак несжатой записи точки
			point.assign(1, 0x04);
			// Дописываем первую координату
			point.insert(point.end(), key.x.begin(), key.x.end());
			// Дописываем вторую координату
			point.insert(point.end(), key.y.begin(), key.y.end());
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выполняем затирание скаляра
			erase(scalar);
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Открываем набор записи
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем издание записи
		writer.integer(1);
		// Записываем секретный скаляр
		writer.octets(view_t(scalar.data(), scalar.size()));
		// Если кривая записывается внутри
		if(named){
			// Открываем настройки кривой
			writer.open(asn1::cls_t::CONTEXT, 0);
			// Записываем опознаватель кривой
			writer.oid(key.oid);
			// Закрываем настройки кривой
			writer.close();
		}
		// Открываем открытый ключ
		writer.open(asn1::cls_t::CONTEXT, 1);
		// Записываем несжатую точку
		writer.bits(view_t(point.data(), point.size()));
		// Закрываем открытый ключ
		writer.close();
		// Закрываем набор записи
		writer.close();
		// Выполняем затирание скаляра
		erase(scalar);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод разбора зерна Ed25519 либо X25519 по разделу 7 RFC 8410
	 *
	 * @param der  разбираемая запись CurvePrivateKey
	 * @param kind вид ключа
	 * @param key  ключ, в который помещается итог разбора
	 *
	 * @return     отказ разбора записи
	 *
	 */
	static error_t seedSecret(const view_t & der, const kind_t kind, key_t & key) noexcept {
		// Если запись не передана
		if((der.data == nullptr) || (der.size == 0))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Разборщик записи
		asn1::reader_t reader(der);
		// Строка байтов зерна
		asn1::element_t element;
		// Если строку байтов зерна разобрать не удалось
		if(!reader.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Если после зерна остался хвост
		if(!reader.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Если зерно записано не своей длиной
		if(element.content.size != CURVE25519)
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Если зерно скопировать не удалось
		if(!copy(element.content.data, element.content.size, key.d))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Устанавливаем вид ключа
		key.kind = kind;
		// Выводим итог выведения открытой части ключа
		return derive(key);
	}
	/**
	 * @brief Метод разбора секретного ключа ML-DSA по разделу 6 RFC 9881
	 *
	 * @details Внутри дозволены три вида записи: зерно с меткой [0] (32 байта,
	 *          рекомендовано), развёрнутый ключ строкой байтов без метки и оба вида
	 *          набором с меткой [2]; у обоих видов зерно разворачивается, а запись
	 *          сличается с поданной - несогласованность отвергается
	 *
	 * @param der       разбираемая запись ключа
	 * @param algorithm опознаватель алгоритма ключа
	 * @param key       ключ, в который помещается итог разбора
	 *
	 * @return          отказ разбора записи
	 *
	 */
	static error_t mldsaSecret(const view_t & der, const string & algorithm, key_t & key) noexcept {
		// Если запись не передана
		if((der.data == nullptr) || (der.size == 0))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Набор параметров по опознавателю алгоритма
		sign::mldsa_t::set_t set = sign::mldsa_t::set_t::NONE;
		// Если опознаватель ML-DSA-44
		if(algorithm.compare(OID_MLDSA44) == 0)
			// Устанавливаем набор ML-DSA-44
			set = sign::mldsa_t::set_t::DSA44;
		// Если опознаватель ML-DSA-65
		else if(algorithm.compare(OID_MLDSA65) == 0)
			// Устанавливаем набор ML-DSA-65
			set = sign::mldsa_t::set_t::DSA65;
		// Если опознаватель ML-DSA-87
		else if(algorithm.compare(OID_MLDSA87) == 0)
			// Устанавливаем набор ML-DSA-87
			set = sign::mldsa_t::set_t::DSA87;
		// Если опознаватель не опознан
		if(set == sign::mldsa_t::set_t::NONE)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Просмотры зерна и развёрнутого ключа
		view_t seed, expanded;
		// Открытая часть, записанная следом за развёрнутым ключом старой записи OpenSSL
		view_t appended;
		// Если записано голое зерно без обёртки (старая запись OpenSSL издания v1)
		if(der.size == 32)
			// Запоминаем зерно целиком
			seed = der;
		// Если записан голый развёрнутый ключ без обёртки (старая запись OpenSSL издания v1)
		else if(der.size == sign::mldsa_t::secretSize(set))
			// Запоминаем развёрнутый ключ целиком
			expanded = der;
		// Иначе запись с разновидностью ключа по разделу 6 RFC 9881
		else {
			// Разборщик записи
			asn1::reader_t reader(der);
			// Элемент разновидности ключа
			asn1::element_t element;
			// Если элемент разновидности разобрать не удалось
			if(!reader.next(element))
				// Выводим переведённый отказ разбора
				return translate(reader.err());
			// Если после разновидности остался хвост
			if(!reader.empty())
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Если записано зерно: неявная метка [0] строки байтов
			if(tagged(element, asn1::cls_t::CONTEXT, 0, false))
				// Запоминаем зерно
				seed = element.content;
			// Если записан развёрнутый ключ: строка байтов без метки
			else if(tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING), false)){
				// Запоминаем развёрнутый ключ
				expanded = element.content;
				// Если следом записана открытая часть (старая запись oqsprovider OpenSSL)
				if(expanded.size == (sign::mldsa_t::secretSize(set) + sign::mldsa_t::publicSize(set))){
					// Отделяем открытую часть от развёрнутого ключа
					appended = view_t((expanded.data + sign::mldsa_t::secretSize(set)), sign::mldsa_t::publicSize(set));
					// Усекаем развёрнутый ключ до его длины
					expanded.size = sign::mldsa_t::secretSize(set);
				}
			// Если записаны оба вида: набор, с меткой [2] либо без неё (как пишет OpenSSL)
			} else if(tagged(element, asn1::cls_t::CONTEXT, 2, true) || tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), true)){
				// Разборщик набора видов
				asn1::reader_t inside(element.content);
				// Если строку байтов зерна разобрать не удалось
				if(!inside.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
					// Выводим переведённый отказ разбора
					return translate(inside.err());
				// Запоминаем зерно
				seed = element.content;
				// Если строку байтов развёрнутого ключа разобрать не удалось
				if(!inside.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
					// Выводим переведённый отказ разбора
					return translate(inside.err());
				// Запоминаем развёрнутый ключ
				expanded = element.content;
				// Если после видов остался хвост
				if(!inside.empty())
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
			// Иначе разновидность ключа не опознана
			} else return error_t::STRUCTURE;
		}
		// Модуль ML-DSA, которым разворачивается и проверяется ключ
		sign::mldsa_t mldsa;
		// Места развёрнутого ключа и выведенной открытой части
		uint8_t record[4896], exposed[2592];
		// Если записано зерно
		if(seed.data != nullptr){
			// Если ключ из зерна развернуть не удалось
			if(!mldsa.generate(set, seed, exposed, record))
				// Выводим отказ негодного значения
				return error_t::VALUE;
			// Если подан и развёрнутый ключ, а с развёрнутым из зерна не сошёлся
			if((expanded.data != nullptr) && ((expanded.size != sign::mldsa_t::secretSize(set)) || (::memcmp(record, expanded.data, expanded.size) != 0))){
				// Выводим отказ негодного значения
				return error_t::VALUE;
			}
		// Иначе записан лишь развёрнутый ключ: устанавливаем его с проверкой трассировки
		} else if(!mldsa.secret(set, expanded))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Если записан лишь развёрнутый ключ
		if(seed.data == nullptr){
			// Выводим открытую часть из установленного ключа
			if(!mldsa.key(exposed, sizeof(exposed)))
				// Выводим отказ негодного значения
				return error_t::VALUE;
			// Если развёрнутый ключ скопировать не удалось
			if(!copy(expanded.data, expanded.size, key.d))
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
		// Иначе ключ развёрнут из зерна
		} else {
			// Если развёрнутый ключ скопировать не удалось
			if(!copy(record, sign::mldsa_t::secretSize(set), key.d))
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
		}
		// Если открытую часть скопировать не удалось
		if(!copy(exposed, sign::mldsa_t::publicSize(set), key.key))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Если записанная следом открытая часть с выведенной не сошлась
		if((appended.data != nullptr) && (::memcmp(exposed, appended.data, appended.size) != 0))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Устанавливаем вид ключа
		key.kind = kind_t::MLDSA;
		// Выводим успешность разбора
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора секретного ключа ГОСТ по разделу 6 RFC 9215
	 *
	 * @details Внутри дозволены три вида записи: строка байтов даёт число порядком от
	 *          младшего байта к старшему, целое число - порядком от старшего, а набор
	 *          из издания и строки байтов - порядком от старшего
	 *
	 * @param der разбираемая запись ключа
	 * @param key ключ, в который помещается итог разбора
	 *
	 * @return    отказ разбора записи
	 *
	 */
	static error_t gostSecret(const view_t & der, key_t & key) noexcept {
		// Если запись не передана
		if((der.data == nullptr) || (der.size == 0))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Разборщик записи
		asn1::reader_t reader(der);
		// Разбираемый элемент записи
		asn1::element_t element;
		// Если элемент записи разобрать не удалось
		if(!reader.next(element))
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Если после элемента остался хвост либо класс метки не универсальный
		if(!reader.empty() || (element.cls != asn1::cls_t::UNIVERSAL))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		/**
		 * Выполняем определение вида записи самого ключа
		 */
		switch(element.tag){
			// Если ключ записан строкой байтов порядком от младшего байта к старшему
			case static_cast <uint32_t> (asn1::tag_t::OCTET_STRING): {
				// Если строка байтов составная либо пуста
				if(element.constructed || (element.content.size == 0))
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если развёрнутый ключ скопировать не удалось
				if(!reverse(element.content.data, element.content.size, key.d))
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
			} break;
			// Если ключ записан целым числом порядком от старшего байта к младшему
			case static_cast <uint32_t> (asn1::tag_t::INTEGER): {
				// Итог разбора целого числа
				const error_t outcome = unsignedInteger(element, key.d);
				// Если целое число разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
			} break;
			// Если ключ записан набором из издания и строки байтов
			case static_cast <uint32_t> (asn1::tag_t::SEQUENCE): {
				// Разборщик содержимого набора
				asn1::reader_t inner = reader.enter(element);
				// Если издание записи разобрать не удалось
				if(!inner.next(asn1::tag_t::INTEGER, element))
					// Выводим переведённый отказ разбора
					return translate(inner.err());
				// Если строку байтов ключа разобрать не удалось
				if(!inner.next(asn1::tag_t::OCTET_STRING, element) || element.constructed || (element.content.size == 0))
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если после строки байтов остался хвост
				if(!inner.empty())
					// Выводим отказ устройства записи
					return error_t::STRUCTURE;
				// Если ключ скопировать не удалось
				if(!copy(element.content.data, element.content.size, key.d))
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
			} break;
			// Если вид записи ключа неизвестен
			default:
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
		}
		// Устанавливаем вид ключа
		key.kind = kind_t::GOST;
		// Выводим итог выведения открытой части ключа
		return derive(key);
	}
	/**
	 * @brief Метод проверки согласованности опознавателя алгоритма ГОСТ с кривой
	 *
	 * @details У ключа 2001 года и ключа 2012 года длиной 256 разрядов координата
	 *          занимает 32 байта, у ключа 2012 года длиной 512 разрядов - 64
	 *
	 * @param key ключ, опознаватель которого проверяется
	 *
	 * @return    признак согласованности опознавателя с кривой
	 *
	 */
	static bool gostAlgorithm(const key_t & key) noexcept {
		// Размер координаты точки кривой
		const size_t size = key.size();
		// Если опознаватель алгоритма ключа 2012 года длиной 256 разрядов либо 2001 года
		if((key.algorithm.compare(OID_GOST256) == 0) || (key.algorithm.compare(OID_GOST2001) == 0))
			// Выводим согласованность с координатой в 32 байта
			return (size == 32);
		// Если опознаватель алгоритма ключа 2012 года длиной 512 разрядов
		if(key.algorithm.compare(OID_GOST512) == 0)
			// Выводим согласованность с координатой в 64 байта
			return (size == 64);
		// Выводим несогласованность: опознаватель неизвестен
		return false;
	}
	/**
	 * @brief Метод разбора открытого ключа ГОСТ по разделу 4 RFC 9215
	 *
	 * @param data разбираемая запись открытого ключа из строки битов
	 * @param key  ключ, в который помещается итог разбора
	 *
	 * @return     отказ разбора записи
	 *
	 */
	static error_t gostPublic(const view_t & data, key_t & key) noexcept {
		// Кривая ключа
		curve::curve_t curve;
		// Итог установки кривой
		const error_t outcome = curveOf(key, curve);
		// Если кривую установить не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ установки
			return outcome;
		// Если запись не передана
		if((data.data == nullptr) || (data.size == 0))
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Размер координаты точки кривой
		const size_t size = curve.size();
		// Разборщик записи открытого ключа
		asn1::reader_t reader(data);
		// Строка байтов координат
		asn1::element_t element;
		// Если строку байтов координат разобрать не удалось
		if(!reader.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Если после строки байтов остался хвост
		if(!reader.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Если строка байтов не занимает двух координат
		if(element.content.size != (size * 2))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Если развёрнутые координаты скопировать не удалось
		if(!reverse(element.content.data, size, key.x) || !reverse(element.content.data + size, size, key.y))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Точка, которой проверяется принадлежность кривой
		curve::point_t point;
		// Если точка кривой не принадлежит
		if(!curve.point(view_t(key.x.data(), key.x.size()), view_t(key.y.data(), key.y.size()), point))
			// Выводим отказ кривой
			return error_t::CURVE;
		// Устанавливаем вид ключа
		key.kind = kind_t::GOST;
		// Если опознаватель алгоритма с кривой не согласован
		if(!gostAlgorithm(key))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Выводим успешность разбора
		return error_t::NONE;
	}
	/**
	 * @brief Метод записи строки байтов из развёрнутых чисел
	 *
	 * @param writer записчик, в который помещается строка байтов
	 * @param first  первое число порядком от старшего байта к младшему
	 * @param second второе число порядком от старшего байта к младшему, вправе быть пустым
	 *
	 * @return       отказ записи
	 *
	 */
	static error_t reversedOctets(asn1::writer_t & writer, const vector <uint8_t> & first, const vector <uint8_t> & second) noexcept {
		// Развёрнутые числа подряд
		vector <uint8_t> buffer;
		/**
		 * Сборка выделяет память: нехватка её отдаётся отказом
		 */
		try {
			// Выделяем место под оба числа
			buffer.assign(first.size() + second.size(), 0);
		// Если памяти не хватило
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		/**
		 * Выполняем разворот первого числа
		 */
		for(size_t i = 0; i < first.size(); i++)
			// Переносим очередной байт первого числа
			buffer[i] = first[first.size() - i - 1];
		/**
		 * Выполняем разворот второго числа
		 */
		for(size_t i = 0; i < second.size(); i++)
			// Переносим очередной байт второго числа
			buffer[first.size() + i] = second[second.size() - i - 1];
		// Записываем строку байтов
		writer.octets(view_t(buffer.data(), buffer.size()));
		// Выполняем затирание буфера: он вправе нести секрет
		erase(buffer);
		// Выводим итог записи
		return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
	}
	/**
	 * @brief Метод записи тела секретного ключа внутри PrivateKeyInfo
	 *
	 * @param key    записываемый ключ
	 * @param writer записчик, в который помещается тело ключа
	 *
	 * @return       отказ записи
	 *
	 */
	static error_t secretBody(const key_t & key, asn1::writer_t & writer) noexcept {
		// Если секретной части нет
		if(!key.secret())
			// Выводим отказ пустого ключа
			return error_t::EMPTY;
		/**
		 * Выполняем определение вида ключа
		 */
		switch(static_cast <uint8_t> (key.kind)){
			// Если записывается ключ RSA
			case static_cast <uint8_t> (kind_t::RSA):
				// Выводим итог записи RSAPrivateKey
				return rsaIntegers(key, true, writer);
			// Если записывается ключ EC
			case static_cast <uint8_t> (kind_t::EC):
				// Выводим итог записи ECPrivateKey без повторения кривой
				return ecSecret(key, false, writer);
			// Если записывается ключ Ed25519 либо X25519
			case static_cast <uint8_t> (kind_t::ED25519):
			case static_cast <uint8_t> (kind_t::X25519): {
				// Если зерно записано не своей длиной
				if(key.d.size() != CURVE25519)
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Записываем зерно строкой байтов
				writer.octets(view_t(key.d.data(), key.d.size()));
				// Выводим итог записи
				return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
			}
			// Если записывается ключ ML-DSA
			case static_cast <uint8_t> (kind_t::MLDSA): {
				// Если записано зерно: оно пишется с неявной меткой [0] (раздел 6 RFC 9881)
				if(key.d.size() == 32)
					// Выводим итог записи зерна
					return (writer.element(asn1::cls_t::CONTEXT, false, 0, view_t(key.d.data(), key.d.size())) ? error_t::NONE : translate(writer.err()));
				// Размер открытой части по размеру развёрнутого ключа
				size_t size = 0;
				// Если развёрнутый ключ набора ML-DSA-44
				if(key.d.size() == 2560)
					// Устанавливаем размер ML-DSA-44
					size = 1312;
				// Если развёрнутый ключ набора ML-DSA-65
				else if(key.d.size() == 4032)
					// Устанавливаем размер ML-DSA-65
					size = 1952;
				// Если развёрнутый ключ набора ML-DSA-87
				else if(key.d.size() == 4896)
					// Устанавливаем размер ML-DSA-87
					size = 2592;
				// Если размер не набора либо записанная открытая часть не согласована
				if((size == 0) || (!key.key.empty() && (key.key.size() != size)))
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Записываем развёрнутый ключ строкой байтов
				writer.octets(view_t(key.d.data(), key.d.size()));
				// Выводим итог записи
				return ((writer.err() == asn1::error_t::NONE) ? error_t::NONE : translate(writer.err()));
			}
			// Если записывается ключ ГОСТ
			case static_cast <uint8_t> (kind_t::GOST): {
				// Кривая ключа
				curve::curve_t curve;
				// Итог установки кривой
				const error_t outcome = curveOf(key, curve);
				// Если кривую установить не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ установки
					return outcome;
				// Если скаляр длиннее размера кривой
				if(key.d.size() > curve.size())
					// Выводим отказ негодного значения
					return error_t::VALUE;
				// Скаляр, дополненный ведущими нулями до размера кривой
				vector <uint8_t> scalar;
				/**
				 * Сборка выделяет память: нехватка её отдаётся отказом
				 */
				try {
					// Заводим ведущие нули скаляра
					scalar.assign(curve.size() - key.d.size(), 0);
					// Дописываем скаляр
					scalar.insert(scalar.end(), key.d.begin(), key.d.end());
				// Если памяти не хватило
				} catch(const bad_alloc &) {
					// Выполняем затирание скаляра
					erase(scalar);
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				}
				// Итог записи скаляра порядком от младшего байта к старшему
				const error_t written = reversedOctets(writer, scalar, vector <uint8_t> ());
				// Выполняем затирание скаляра
				erase(scalar);
				// Выводим итог записи
				return written;
			}
		}
		// Выводим отказ пустого ключа
		return error_t::EMPTY;
	}
	/**
	 * @brief Метод разбора настроек защиты ключа паролем по схеме PBES2
	 *
	 * @param params     разбираемые настройки схемы
	 * @param salt       место, в которое помещается просмотр соли
	 * @param iterations место, в которое помещается число оборотов
	 * @param prf        место, в которое помещается алгоритм имитовставки
	 * @param bits       место, в которое помещается длина ключа шифра в разрядах
	 * @param iv         место, в которое помещается просмотр синхропосылки
	 *
	 * @return           отказ разбора настроек
	 *
	 */
	static error_t pbes2(const asn1::element_t & params, view_t & salt, uint32_t & iterations, digest::hash_t & prf, size_t & bits, view_t & iv) noexcept {
		// Если настройки схемы записаны не набором
		if(!tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), true))
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Разборщик содержимого настроек схемы
		asn1::reader_t items(params.content);
		// Опознаватель алгоритма
		string algorithm;
		// Настройки алгоритма
		asn1::element_t element;
		// Признак наличия настроек алгоритма
		bool present = false;
		// Итог разбора алгоритма выработки ключа
		error_t outcome = algorithmIdentifier(items, algorithm, element, present);
		// Если алгоритм выработки ключа разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если выработка ключа не PBKDF2 либо настроек нет
		if((algorithm.compare(OID_PBKDF2) != 0) || !present || !tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), true))
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Разборщик содержимого настроек PBKDF2
		asn1::reader_t kdf(element.content);
		// Если соль разобрать не удалось: соль из другого источника не принимается
		if(!kdf.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Если соль пуста
		if(element.content.size == 0)
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Устанавливаем просмотр соли
		salt = element.content;
		// Если число оборотов разобрать не удалось
		if(!kdf.next(asn1::tag_t::INTEGER, element))
			// Выводим переведённый отказ разбора
			return translate(kdf.err());
		// Число оборотов из записи
		int64_t count = 0;
		// Итог разбора числа оборотов
		outcome = smallInteger(element, count);
		// Если число оборотов разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если число оборотов не укладывается в дозволенное: потолок 10^7 (openssl по умолчанию 2048), запись с 2^32 - 1 стоила бы часы на один разбор
		if((count < 1) || (count > PBKDF2_MOST))
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Устанавливаем число оборотов
		iterations = static_cast <uint32_t> (count);
		// Имитовставка по умолчанию: раздел A.2 RFC 8018
		prf = digest::hash_t::SHA1;
		// Объявленная длина ключа
		int64_t length = -1;
		// Если необязательные настройки записаны
		if(!kdf.empty()){
			// Если очередную настройку разобрать не удалось
			if(!kdf.next(element))
				// Выводим переведённый отказ разбора
				return translate(kdf.err());
			// Признак неразобранной настройки
			bool pending = true;
			// Если настройка есть длина ключа
			if(tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::INTEGER), false)){
				// Итог разбора длины ключа
				outcome = smallInteger(element, length);
				// Если длину ключа разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Снимаем признак неразобранной настройки
				pending = false;
				// Если запись продолжается
				if(!kdf.empty()){
					// Если очередную настройку разобрать не удалось
					if(!kdf.next(element))
						// Выводим переведённый отказ разбора
						return translate(kdf.err());
					// Устанавливаем признак неразобранной настройки
					pending = true;
				}
			}
			// Если настройка есть имитовставка
			if(pending && tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::SEQUENCE), true)){
				// Разборщик содержимого настроек имитовставки
				asn1::reader_t inner = kdf.enter(element);
				// Если опознаватель имитовставки разобрать не удалось
				if(!inner.next(asn1::tag_t::OBJECT, element))
					// Выводим отказ схемы
					return error_t::CIPHER;
				// Опознаватель имитовставки
				string oid;
				// Итог разбора опознавателя имитовставки
				outcome = identifier(element, oid);
				// Если опознаватель имитовставки разобрать не удалось
				if(outcome != error_t::NONE)
					// Выводим отказ разбора
					return outcome;
				// Если настройки имитовставки записаны
				if(!inner.empty()){
					// Если настройки имитовставки разобрать не удалось либо они не пустое значение
					if(!inner.next(element) || !tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::NOTHING), false) || !inner.empty())
						// Выводим отказ схемы
						return error_t::CIPHER;
				}
				// Сбрасываем имитовставку: искомая обязана найтись среди известных
				prf = digest::hash_t::NONE;
				/**
				 * Выполняем перебор известных имитовставок
				 */
				for(size_t i = 0; i < (sizeof(PRFS) / sizeof(prf_t)); i++){
					// Если опознаватель имитовставки совпал с искомым
					if(oid.compare(PRFS[i].oid) == 0)
						// Устанавливаем алгоритм имитовставки
						prf = PRFS[i].algorithm;
				}
				// Если имитовставка неизвестна
				if(prf == digest::hash_t::NONE)
					// Выводим отказ схемы
					return error_t::CIPHER;
			// Если настройка не опознана
			} else if(pending)
				// Выводим отказ схемы
				return error_t::CIPHER;
			// Если после настроек остался хвост
			if(!kdf.empty())
				// Выводим отказ схемы
				return error_t::CIPHER;
		}
		// Итог разбора шифра
		outcome = algorithmIdentifier(items, algorithm, element, present);
		// Если шифр разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если после шифра остался хвост
		if(!items.empty())
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Сбрасываем длину ключа шифра: искомый обязан найтись среди известных
		bits = 0;
		/**
		 * Выполняем перебор известных шифров
		 */
		for(size_t i = 0; i < (sizeof(CIPHERS) / sizeof(cipher_t)); i++){
			// Если опознаватель шифра совпал с искомым
			if(algorithm.compare(CIPHERS[i].oid) == 0)
				// Устанавливаем длину ключа шифра
				bits = CIPHERS[i].bits;
		}
		// Если шифр неизвестен либо синхропосылка не записана строкой байтов в блок
		if((bits == 0) || !present || !tagged(element, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING), false) || (element.content.size != BLOCK))
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Если объявленная длина ключа не сошлась с длиной ключа шифра
		if((length >= 0) && (static_cast <size_t> (length) != (bits / 8)))
			// Выводим отказ схемы
			return error_t::CIPHER;
		// Устанавливаем просмотр синхропосылки
		iv = element.content;
		// Выводим успешность разбора настроек
		return error_t::NONE;
	}
	/**
	 * @brief Метод разбора записи ключа заданной метки
	 *
	 * @param label    метка записи
	 * @param der      разбираемая запись
	 * @param password пароль последовательностью октетов
	 * @param result   ключ, в который помещается итог разбора
	 * @param known    место, в которое помещается признак известной метки
	 *
	 * @return         отказ разбора записи
	 *
	 */
	static error_t labeled(const string & label, const view_t & der, const view_t & password, key_t & result, bool & known) noexcept {
		// Устанавливаем признак известной метки
		known = true;
		// Если запись есть PrivateKeyInfo
		if(label.compare(pem::PEM_SECRET) == 0)
			// Выводим итог разбора PrivateKeyInfo
			return decodePrivateKeyInfo(der, result);
		// Если запись есть EncryptedPrivateKeyInfo
		if(label.compare(pem::PEM_ENCRYPTED) == 0)
			// Выводим итог разбора EncryptedPrivateKeyInfo
			return decodeEncryptedPrivateKeyInfo(der, password, result);
		// Если запись есть SubjectPublicKeyInfo
		if(label.compare(LABEL_PUBLIC) == 0)
			// Выводим итог разбора SubjectPublicKeyInfo
			return decodeSubjectPublicKeyInfo(der, result);
		// Если запись есть ECPrivateKey
		if(label.compare(LABEL_EC) == 0)
			// Выводим итог разбора ECPrivateKey
			return decodeECPrivateKey(der, result);
		// Если запись есть RSAPrivateKey
		if(label.compare(LABEL_RSA_SECRET) == 0)
			// Выводим итог разбора RSAPrivateKey
			return decodeRSAPrivateKey(der, result);
		// Если запись есть RSAPublicKey
		if(label.compare(LABEL_RSA_PUBLIC) == 0)
			// Выводим итог разбора RSAPublicKey
			return decodeRSAPublicKey(der, result);
		// Снимаем признак известной метки
		known = false;
		// Выводим отказ метки
		return error_t::LABEL;
	}
};

/**
 * @brief Метод проверки наличия секретной части ключа
 *
 * @return признак наличия секретной части ключа
 *
 */
bool nts::keys::Key::secret() const noexcept {
	// Выводим наличие секретной составляющей
	return ((this->kind != kind_t::NONE) && !this->d.empty());
}
/**
 * @brief Метод получения размера ключа в байтах
 *
 * @return размер модуля у RSA, координаты у EC и ГОСТ, ключа у Ed25519 и X25519
 *
 */
size_t nts::keys::Key::size() const noexcept {
	/**
	 * Выполняем определение вида ключа
	 */
	switch(static_cast <uint8_t> (this->kind)){
		// Если ключ RSA
		case static_cast <uint8_t> (kind_t::RSA):
			// Выводим размер модуля
			return this->n.size();
		// Если ключ EC либо ГОСТ
		case static_cast <uint8_t> (kind_t::EC):
		case static_cast <uint8_t> (kind_t::GOST):
			// Выводим размер координаты
			return this->x.size();
		// Если ключ Ed25519 либо X25519
		case static_cast <uint8_t> (kind_t::ED25519):
		case static_cast <uint8_t> (kind_t::X25519):
			// Выводим размер ключа
			return CURVE25519;
	}
	// Выводим нулевой размер: ключ не установлен
	return 0;
}
/**
 * @brief Метод сброса ключа с затиранием секретных составляющих
 *
 */
void nts::keys::Key::clear() noexcept {
	// Сбрасываем вид ключа
	this->kind = kind_t::NONE;
	// Сбрасываем опознаватель кривой
	this->oid.clear();
	// Сбрасываем опознаватель алгоритма
	this->algorithm.clear();
	// Сбрасываем опознаватель хеша
	this->digest.clear();
	// Затираем модуль
	erase(this->n);
	// Затираем открытый показатель
	erase(this->e);
	// Затираем секретную составляющую
	erase(this->d);
	// Затираем первый сомножитель
	erase(this->p);
	// Затираем второй сомножитель
	erase(this->q);
	// Затираем показатель dP
	erase(this->dP);
	// Затираем показатель dQ
	erase(this->dQ);
	// Затираем коэффициент
	erase(this->qInv);
	// Затираем первую координату
	erase(this->x);
	// Затираем вторую координату
	erase(this->y);
	// Затираем открытый ключ
	erase(this->key);
}
/**
 * @brief Метод установки ключа RSA из разобранного ключа
 *
 * @param rsa примитив, в который устанавливается ключ
 *
 * @return    признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::rsa_t & rsa) const noexcept {
	// Выполняем сброс примитива
	rsa.clear();
	// Если ключ не RSA
	if(this->kind != kind_t::RSA)
		// Выводим отказ установки
		return false;
	// Если ключ несёт секретную часть
	if(this->secret())
		// Выводим итог установки секретного ключа: примитив проверяет согласованность сам
		return rsa.key(
			view_t(this->n.data(), this->n.size()), view_t(this->e.data(), this->e.size()),
			view_t(this->d.data(), this->d.size()), view_t(this->p.data(), this->p.size()),
			view_t(this->q.data(), this->q.size()), view_t(this->dP.data(), this->dP.size()),
			view_t(this->dQ.data(), this->dQ.size()), view_t(this->qInv.data(), this->qInv.size())
		);
	// Выводим итог установки открытого ключа
	return rsa.key(view_t(this->n.data(), this->n.size()), view_t(this->e.data(), this->e.size()));
}
/**
 * @brief Метод установки ключа ECDSA из разобранного ключа
 *
 * @param ecdsa примитив, в который устанавливается ключ
 * @param curve кривая, которая устанавливается по опознавателю ключа
 *
 * @return      признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::ecdsa_t & ecdsa, curve::curve_t & curve) const noexcept {
	// Выполняем сброс примитива
	ecdsa.clear();
	// Если ключ не EC либо кривую по опознавателю установить не удалось
	if((this->kind != kind_t::EC) || (curveOf(* this, curve) != error_t::NONE))
		// Выводим отказ установки
		return false;
	// Если кривую в примитив установить не удалось
	if(!ecdsa.start(curve))
		// Выводим отказ установки
		return false;
	// Если ключ несёт секретную часть
	if(this->secret())
		// Выводим итог установки ключа подписи
		return ecdsa.secret(view_t(this->d.data(), this->d.size()));
	// Выводим итог установки ключа проверки подписи
	return ecdsa.key(view_t(this->x.data(), this->x.size()), view_t(this->y.data(), this->y.size()));
}
/**
 * @brief Метод установки ключа SM2 из разобранного ключа
 *
 * @param sm2   примитив, в который устанавливается ключ
 * @param curve кривая, которая устанавливается по опознавателю ключа
 * @param id    опознаватель подписывающего для выработки Z_A
 *
 * @return      признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::sm2_t & sm2, curve::curve_t & curve, const view_t & id) const noexcept {
	// Выполняем сброс примитива
	sm2.clear();
	// Если ключ не SM2 либо кривую по опознавателю установить не удалось
	if((this->kind != kind_t::SM2) || (curveOf(* this, curve) != error_t::NONE))
		// Выводим отказ установки
		return false;
	// Если кривую в примитив установить не удалось
	if(!sm2.start(curve))
		// Выводим отказ установки
		return false;
	// Если ключ несёт секретную часть
	if(this->secret())
		// Выводим итог установки ключа подписи
		return sm2.secret(view_t(this->d.data(), this->d.size()), id);
	// Выводим итог установки ключа проверки подписи
	return sm2.key(view_t(this->x.data(), this->x.size()), view_t(this->y.data(), this->y.size()), id);
}
/**
 * @brief Метод установки ключа Ed25519 из разобранного ключа
 *
 * @param ed25519 примитив, в который устанавливается ключ
 *
 * @return        признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::ed25519_t & ed25519) const noexcept {
	// Выполняем сброс примитива
	ed25519.clear();
	// Если ключ не Ed25519
	if(this->kind != kind_t::ED25519)
		// Выводим отказ установки
		return false;
	// Если ключ несёт секретную часть
	if(this->secret())
		// Выводим итог установки ключа подписи
		return ed25519.secret(view_t(this->d.data(), this->d.size()));
	// Выводим итог установки ключа проверки подписи
	return ed25519.key(view_t(this->key.data(), this->key.size()));
}
/**
 * @brief Метод установки ключа ГОСТ Р 34.10-2012 из разобранного ключа
 *
 * @param gost  примитив, в который устанавливается ключ
 * @param curve кривая, которая устанавливается по опознавателю ключа
 *
 * @return      признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::gost_t & gost, curve::curve_t & curve) const noexcept {
	// Выполняем сброс примитива
	gost.clear();
	// Если ключ не ГОСТ либо кривую по опознавателю установить не удалось
	if((this->kind != kind_t::GOST) || (curveOf(* this, curve) != error_t::NONE))
		// Выводим отказ установки
		return false;
	// Если кривую в примитив установить не удалось
	if(!gost.start(curve))
		// Выводим отказ установки
		return false;
	// Если ключ несёт секретную часть
	if(this->secret())
		// Выводим итог установки ключа подписи
		return gost.secret(view_t(this->d.data(), this->d.size()));
	// Выводим итог установки ключа проверки подписи
	return gost.key(view_t(this->x.data(), this->x.size()), view_t(this->y.data(), this->y.size()));
}
/**
 * @brief Метод установки ключа ML-DSA из разобранного ключа
 *
 * @param mldsa примитив, в который устанавливается ключ
 *
 * @return      признак успешности установки ключа
 *
 */
bool nts::keys::Key::load(sign::mldsa_t & mldsa) const noexcept {
	// Выполняем сброс примитива
	mldsa.clear();
	// Если ключ не ML-DSA
	if(this->kind != kind_t::MLDSA)
		// Выводим отказ установки
		return false;
	// Набор параметров ключа
	sign::mldsa_t::set_t set = sign::mldsa_t::set_t::NONE;
	// Если ключ несёт секретную часть
	if(this->secret()){
		// Если запись секрета длиной набора ML-DSA-44
		if(this->d.size() == 2560)
			// Устанавливаем набор ML-DSA-44
			set = sign::mldsa_t::set_t::DSA44;
		// Если запись секрета длиной набора ML-DSA-65
		else if(this->d.size() == 4032)
			// Устанавливаем набор ML-DSA-65
			set = sign::mldsa_t::set_t::DSA65;
		// Если запись секрета длиной набора ML-DSA-87
		else if(this->d.size() == 4896)
			// Устанавливаем набор ML-DSA-87
			set = sign::mldsa_t::set_t::DSA87;
		// Если набор не определён
		if(set == sign::mldsa_t::set_t::NONE)
			// Выводим отказ установки
			return false;
		// Выводим итог установки ключа подписи
		return mldsa.secret(set, view_t(this->d.data(), this->d.size()));
	}
	// Если запись открытого ключа длиной набора ML-DSA-44
	if(this->key.size() == 1312)
		// Устанавливаем набор ML-DSA-44
		set = sign::mldsa_t::set_t::DSA44;
	// Если запись открытого ключа длиной набора ML-DSA-65
	else if(this->key.size() == 1952)
		// Устанавливаем набор ML-DSA-65
		set = sign::mldsa_t::set_t::DSA65;
	// Если запись открытого ключа длиной набора ML-DSA-87
	else if(this->key.size() == 2592)
		// Устанавливаем набор ML-DSA-87
		set = sign::mldsa_t::set_t::DSA87;
	// Если набор не определён
	if(set == sign::mldsa_t::set_t::NONE)
		// Выводим отказ установки
		return false;
	// Выводим итог установки ключа проверки подписи
	return mldsa.key(set, view_t(this->key.data(), this->key.size()));
}
/**
 * @brief Деструктор
 *
 */
nts::keys::Key::~Key() noexcept {
	// Выполняем сброс ключа с затиранием секретных составляющих
	this->clear();
}
/**
 * @brief Метод проверки готовности ключа
 *
 * @return признак подготовленного ключа
 *
 */
bool nts::keys::Signer::ready() const noexcept {
	// Выводим признак подготовленного ключа
	return (this->_kind != kind_t::NONE);
}
/**
 * @brief Метод получения вида подготовленного ключа
 *
 * @return вид ключа, kind_t::NONE у неподготовленного
 *
 */
nts::keys::kind_t nts::keys::Signer::kind() const noexcept {
	// Выводим вид подготовленного ключа
	return this->_kind;
}
/**
 * @brief Метод получения кривой ключа
 *
 * @return кривая ключа EC либо ГОСТ
 *
 */
const nts::curve::curve_t & nts::keys::Signer::curve() const noexcept {
	// Незаведённая кривая для ключей иных видов
	static const curve::curve_t empty;
	// Выводим кривую ключа
	return (this->_curve ? (* this->_curve) : empty);
}
/**
 * @brief Метод получения модуля подписи RSA
 *
 * @return модуль подписи с установленным ключом RSA
 *
 */
const nts::sign::rsa_t & nts::keys::Signer::rsa() const noexcept {
	// Выводим модуль подписи RSA
	// Пустой модуль для ключей иных видов
	static const sign::rsa_t empty;
	// Выводим модуль подписи
	return (this->_rsa ? (* this->_rsa) : empty);
}
/**
 * @brief Метод получения модуля подписи ECDSA
 *
 * @return модуль подписи с установленным ключом на кривой Вейерштрасса
 *
 */
const nts::sign::ecdsa_t & nts::keys::Signer::ecdsa() const noexcept {
	// Выводим модуль подписи ECDSA
	// Пустой модуль для ключей иных видов
	static const sign::ecdsa_t empty;
	// Выводим модуль подписи
	return (this->_ecdsa ? (* this->_ecdsa) : empty);
}
/**
 * @brief Метод получения модуля подписи Ed25519
 *
 * @return модуль подписи с установленным ключом Ed25519
 *
 */
const nts::sign::ed25519_t & nts::keys::Signer::ed25519() const noexcept {
	// Выводим модуль подписи Ed25519
	// Пустой модуль для ключей иных видов
	static const sign::ed25519_t empty;
	// Выводим модуль подписи
	return (this->_ed25519 ? (* this->_ed25519) : empty);
}
/**
 * @brief Метод получения модуля подписи ГОСТ Р 34.10-2012
 *
 * @return модуль подписи с установленным ключом ГОСТ
 *
 */
const nts::sign::gost_t & nts::keys::Signer::gost() const noexcept {
	// Выводим модуль подписи ГОСТ
	// Пустой модуль для ключей иных видов
	static const sign::gost_t empty;
	// Выводим модуль подписи
	return (this->_gost ? (* this->_gost) : empty);
}
/**
 * @brief Метод получения модуля подписи ML-DSA
 *
 * @return модуль подписи с установленным ключом ML-DSA
 *
 */
const nts::sign::mldsa_t & nts::keys::Signer::mldsa() const noexcept {
	// Пустой модуль для ключей иных видов
	static const sign::mldsa_t empty;
	// Выводим модуль подписи
	return (this->_mldsa ? (* this->_mldsa) : empty);
}
/**
 * @brief Метод получения модуля подписи SM2
 *
 * @return модуль подписи с установленным ключом SM2, пустой у ключей иных видов
 *
 */
const nts::sign::sm2_t & nts::keys::Signer::sm2() const noexcept {
	// Пустой модуль для ключей иных видов
	static const sign::sm2_t empty;
	// Выводим модуль подписи
	return (this->_sm2 ? (* this->_sm2) : empty);
}
/**
 * @brief Метод подготовки ключа по записи секретного ключа
 *
 * @param secret запись PrivateKeyInfo (PKCS #8) в DER либо в PEM без пароля
 *
 * @return       отказ подготовки ключа
 *
 */
nts::keys::error_t nts::keys::Signer::prepare(const view_t & secret) noexcept {
	// Сбрасываем прежний ключ
	this->clear();
	// Если запись ключа пуста
	if((secret.data == nullptr) || (secret.size == 0))
		// Выводим отказ пустой записи
		return error_t::EMPTY;
	// Разобранный ключ: секретные составляющие затираются при его уничтожении
	key_t key;
	/**
	 * Секретный ключ принимается записью PKCS #8 в DER либо в PEM: сперва пробуется
	 * DER, ибо запись PEM начинается с текста и разбором DER отвергается сразу
	 */
	error_t outcome = decodePrivateKeyInfo(secret, key);
	// Если памяти под разбор не хватило
	if(outcome == error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return outcome;
	// Если запись DER не разобрана
	if(outcome != error_t::NONE){
		/**
		 * Выполняем перехват ошибок работы с памятью: текст записи PEM занимает память
		 */
		try {
			// Текст записи PEM секретного ключа: затирается до уничтожения
			string text(reinterpret_cast <const char *> (secret.data), secret.size);
			// Разбираем запись PEM секретного ключа
			outcome = decode(text, view_t(), key);
			// Если текст записи непуст
			if(!text.empty())
				// Выполняем затирание текста записи секретного ключа
				nts::sys::wipe(reinterpret_cast <uint8_t *> (&text[0]), text.size());
		/**
		 * Если памяти под текст записи не хватило
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
		// Если запись PEM разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора записи
			return outcome;
	}
	// Если секретной части у ключа нет
	if(!key.secret())
		// Выводим отказ отсутствия секретной части
		return error_t::EMPTY;
	// Признак заведения ключа в модуле подписи
	bool loaded = false;
	/**
	 * Определяем вид ключа: модуль заводится лишь под свой вид, ибо модули иных видов
	 * стоили бы затирания их полной ёмкости при уничтожении ключа
	 */
	switch(key.kind){
		// Ключ RSA
		case kind_t::RSA: {
			// Заводим модуль подписи RSA
			this->_rsa.reset(new (nothrow) sign::rsa_t());
			// Если памяти под модуль не хватило
			if(!this->_rsa)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Заводим ключ в модуле подписи RSA
			loaded = key.load(* this->_rsa);
		} break;
		// Ключ на кривой Вейерштрасса
		case kind_t::EC: {
			// Заводим кривую и модуль подписи ECDSA
			this->_curve.reset(new (nothrow) curve::curve_t());
			this->_ecdsa.reset(new (nothrow) sign::ecdsa_t());
			// Если памяти под кривую либо модуль не хватило
			if(!this->_curve || !this->_ecdsa){
				// Сбрасываем ключ
				this->clear();
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
			// Заводим ключ в модуле подписи ECDSA вместе с кривой
			loaded = key.load(* this->_ecdsa, * this->_curve);
		} break;
		// Ключ Ed25519
		case kind_t::ED25519: {
			// Заводим модуль подписи Ed25519
			this->_ed25519.reset(new (nothrow) sign::ed25519_t());
			// Если памяти под модуль не хватило
			if(!this->_ed25519)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Заводим ключ в модуле подписи Ed25519
			loaded = key.load(* this->_ed25519);
		} break;
		// Ключ ГОСТ Р 34.10-2012
		case kind_t::GOST: {
			// Заводим кривую и модуль подписи ГОСТ
			this->_curve.reset(new (nothrow) curve::curve_t());
			this->_gost.reset(new (nothrow) sign::gost_t());
			// Если памяти под кривую либо модуль не хватило
			if(!this->_curve || !this->_gost){
				// Сбрасываем ключ
				this->clear();
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
			// Заводим ключ в модуле подписи ГОСТ вместе с кривой
			loaded = key.load(* this->_gost, * this->_curve);
		} break;
		// Ключ ML-DSA
		case kind_t::MLDSA: {
			// Заводим модуль подписи ML-DSA
			this->_mldsa.reset(new (nothrow) sign::mldsa_t());
			// Если памяти под модуль не хватило
			if(!this->_mldsa)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Заводим ключ в модуле подписи ML-DSA
			loaded = key.load(* this->_mldsa);
		} break;
		// Ключ SM2
		case kind_t::SM2: {
			// Заводим кривую и модуль подписи SM2
			this->_curve.reset(new (nothrow) curve::curve_t());
			this->_sm2.reset(new (nothrow) sign::sm2_t());
			// Если памяти под кривую либо модуль не хватило
			if(!this->_curve || !this->_sm2){
				// Сбрасываем ключ
				this->clear();
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
			// Опознаватель подписи сертификата по RFC 8998
			static const char * ID = "1234567812345678";
			// Заводим ключ в модуле подписи SM2 вместе с кривой
			loaded = key.load(* this->_sm2, * this->_curve, view_t(reinterpret_cast <const uint8_t *> (ID), 16));
		} break;
		// Ключ, подписи не выполняющий
		default:
			// Выводим отказ вида ключа
			return error_t::ALGORITHM;
	}
	// Если ключ в модуле подписи не заведён
	if(!loaded){
		// Сбрасываем ключ
		this->clear();
		// Выводим отказ несогласованных составляющих
		return error_t::VALUE;
	}
	// Запоминаем вид подготовленного ключа
	this->_kind = key.kind;
	// Выводим успешность подготовки
	return error_t::NONE;
}
/**
 * @brief Метод подготовки ключа ГОСТ по голому скаляру
 *
 * @param scalar секретный скаляр порядком от старшего байта к младшему
 * @param curve  заведённая кривая ключа
 *
 * @return       отказ подготовки ключа
 *
 */
nts::keys::error_t nts::keys::Signer::prepare(const view_t & scalar, const curve::curve_t & curve) noexcept {
	// Сбрасываем прежний ключ
	this->clear();
	// Если скаляр пуст
	if((scalar.data == nullptr) || (scalar.size == 0))
		// Выводим отказ пустого скаляра
		return error_t::EMPTY;
	// Если кривая не заведена
	if(!curve.ready())
		// Выводим отказ кривой
		return error_t::CURVE;
	// Заводим копию кривой ключа и модуль подписи ГОСТ: модуль ссылается на кривую
	this->_curve.reset(new (nothrow) curve::curve_t(curve));
	this->_gost.reset(new (nothrow) sign::gost_t());
	// Если памяти под кривую либо модуль не хватило
	if(!this->_curve || !this->_gost){
		// Сбрасываем ключ
		this->clear();
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Если кривую подписи установить либо скаляр завести не удалось
	if(!this->_gost->start(* this->_curve) || !this->_gost->secret(scalar)){
		// Сбрасываем ключ
		this->clear();
		// Выводим отказ скаляра
		return error_t::VALUE;
	}
	// Запоминаем вид подготовленного ключа
	this->_kind = kind_t::GOST;
	// Выводим успешность подготовки
	return error_t::NONE;
}
/**
 * @brief Метод сброса ключа
 *
 */
void nts::keys::Signer::clear() noexcept {
	// Сбрасываем вид ключа
	this->_kind = kind_t::NONE;
	// Уничтожаем модули подписи с затиранием: они ссылаются на кривую, потому идут первыми
	this->_rsa.reset();
	this->_ecdsa.reset();
	this->_ed25519.reset();
	this->_gost.reset();
	this->_mldsa.reset();
	this->_sm2.reset();
	// Уничтожаем кривую ключа
	this->_curve.reset();
}
/**
 * @brief Конструктор
 *
 */
nts::keys::Signer::Signer() noexcept : _kind(kind_t::NONE) {}
/**
 * @brief Деструктор
 *
 */
nts::keys::Signer::~Signer() noexcept {
	// Сбрасываем ключ
	this->clear();
}
/**
 * @brief Метод разбора записи SubjectPublicKeyInfo
 *
 * @param der    разбираемая запись в кодировке DER
 * @param result ключ, в который помещается итог разбора
 *
 * @return       отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodeSubjectPublicKeyInfo(const view_t & der, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Набор верхней записи
	asn1::element_t sequence;
	// Итог разбора верхней записи
	error_t outcome = outer(der, sequence);
	// Если верхнюю запись разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Разборщик содержимого набора
	asn1::reader_t fields(sequence.content);
	// Разбираемый ключ
	key_t key;
	// Опознаватель алгоритма ключа
	string algorithm;
	// Настройки алгоритма ключа
	asn1::element_t params;
	// Признак наличия настроек алгоритма
	bool present = false;
	// Итог разбора алгоритма ключа
	outcome = algorithmIdentifier(fields, algorithm, params, present);
	// Если алгоритм ключа разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Строка битов открытого ключа
	asn1::element_t element;
	// Если строку битов открытого ключа разобрать не удалось
	if(!fields.next(asn1::tag_t::BIT_STRING, element))
		// Выводим переведённый отказ разбора
		return translate(fields.err());
	// Если после строки битов остался хвост
	if(!fields.empty())
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Просмотр байтов открытого ключа
	view_t bytes;
	// Число неиспользуемых разрядов последнего байта
	uint8_t unused = 0;
	// Итог разбора строки битов
	const asn1::error_t parsed = asn1::bits(element, bytes, unused);
	// Если строку битов разобрать не удалось
	if(parsed != asn1::error_t::NONE)
		// Выводим переведённый отказ разбора
		return translate(parsed);
	// Если разряды заняты не целиком
	if(unused != 0)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Если ключ RSA
	if(algorithm.compare(OID_RSA) == 0){
		// Если настройки не пусты: раздел 2.3.1 RFC 3279
		if(!present || !tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::NOTHING), false) || (params.content.size != 0))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Выполняем разбор RSAPublicKey
		outcome = rsaPublic(bytes, key);
	// Если ключ EC
	} else if(algorithm.compare(OID_EC) == 0){
		// Если кривая не именованная: раздел 2.1.1 RFC 5480
		if(!present || !tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::OBJECT), false))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Итог разбора опознавателя кривой
		outcome = identifier(params, key.oid);
		// Если опознаватель кривой разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Кривая ключа
		curve::curve_t curve;
		// Итог установки кривой
		outcome = curveOf(key, curve);
		// Если кривую установить не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ установки
			return outcome;
		// Устанавливаем вид ключа: ключ на кривой curveSM2 есть ключ SM2, прочие EC - ECDSA
		key.kind = ((key.oid.compare(OID_SM2) == 0) ? kind_t::SM2 : kind_t::EC);
		// Выполняем разбор несжатой точки
		outcome = pointOf(bytes, curve, key.x, key.y);
	// Если ключ SM2
	} else if(algorithm.compare(OID_SM2) == 0){
		// Если настройки записаны: GB/T 32918 их не несёт, кривая curveSM2 подразумевается
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Запоминаем опознаватель кривой curveSM2
		key.oid = OID_SM2;
		// Кривая ключа
		curve::curve_t curve;
		// Итог установки кривой
		outcome = curveOf(key, curve);
		// Если кривую установить не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ установки
			return outcome;
		// Устанавливаем вид ключа
		key.kind = kind_t::SM2;
		// Выполняем разбор несжатой точки
		outcome = pointOf(bytes, curve, key.x, key.y);
	// Если ключ Ed25519 либо X25519
	} else if((algorithm.compare(OID_ED25519) == 0) || (algorithm.compare(OID_X25519) == 0)){
		// Если настройки записаны: раздел 3 RFC 8410 их запрещает
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Если открытый ключ скопировать не удалось
		if(!copy(bytes.data, bytes.size, key.key))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Устанавливаем вид ключа
		key.kind = ((algorithm.compare(OID_ED25519) == 0) ? kind_t::ED25519 : kind_t::X25519);
		// Выполняем проверку открытого ключа
		outcome = derive(key);
	// Если ключ ML-DSA
	} else if((algorithm.compare(OID_MLDSA44) == 0) || (algorithm.compare(OID_MLDSA65) == 0) || (algorithm.compare(OID_MLDSA87) == 0)){
		// Если настройки записаны: раздел 5 RFC 9881 их запрещает
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Если размер открытого ключа не отвечает опознавателю набора
		if(((algorithm.compare(OID_MLDSA44) == 0) && (bytes.size != 1312)) || ((algorithm.compare(OID_MLDSA65) == 0) && (bytes.size != 1952)) || ((algorithm.compare(OID_MLDSA87) == 0) && (bytes.size != 2592)))
			// Выводим отказ негодного значения
			return error_t::VALUE;
		// Устанавливаем опознаватель алгоритма: обмен памяти не выделяет
		key.algorithm.swap(algorithm);
		// Если открытый ключ скопировать не удалось
		if(!copy(bytes.data, bytes.size, key.key))
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Устанавливаем вид ключа
		key.kind = kind_t::MLDSA;
	// Если ключ ГОСТ
	} else if((algorithm.compare(OID_GOST256) == 0) || (algorithm.compare(OID_GOST512) == 0) || (algorithm.compare(OID_GOST2001) == 0)){
		// Если настройки не записаны
		if(!present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Устанавливаем опознаватель алгоритма: обмен памяти не выделяет
		key.algorithm.swap(algorithm);
		// Итог разбора настроек ключа
		outcome = gostParameters(params, key);
		// Если настройки ключа разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем разбор открытого ключа
		outcome = gostPublic(bytes, key);
	// Если алгоритм ключа неизвестен
	} else return error_t::ALGORITHM;
	// Если ключ разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Переносим разобранный ключ в место назначения
	transfer(key, result);
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод записи SubjectPublicKeyInfo
 *
 * @param key    записываемый ключ
 * @param result место, в которое помещается запись в кодировке DER
 *
 * @return       отказ записи
 *
 */
nts::keys::error_t nts::keys::encodeSubjectPublicKeyInfo(const key_t & key, vector <uint8_t> & result) noexcept {
	// Записчик тела открытого ключа
	asn1::writer_t body;
	// Открытый ключ Ed25519, X25519 либо несжатая точка EC
	vector <uint8_t> point;
	// Итог сборки тела открытого ключа
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем определение вида ключа
	 */
	switch(static_cast <uint8_t> (key.kind)){
		// Если записывается ключ RSA
		case static_cast <uint8_t> (kind_t::RSA):
			// Собираем RSAPublicKey
			outcome = rsaIntegers(key, false, body);
		break;
		// Если записывается ключ EC
		case static_cast <uint8_t> (kind_t::EC): {
			// Если координаты не заполнены либо различны длиной
			if(key.x.empty() || (key.x.size() != key.y.size()))
				// Выводим отказ пустого ключа
				return error_t::EMPTY;
			/**
			 * Сборка выделяет память: нехватка её отдаётся отказом
			 */
			try {
				// Заводим признак несжатой записи точки
				point.assign(1, 0x04);
				// Дописываем первую координату
				point.insert(point.end(), key.x.begin(), key.x.end());
				// Дописываем вторую координату
				point.insert(point.end(), key.y.begin(), key.y.end());
			// Если памяти не хватило
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			}
		} break;
		// Если записывается ключ Ed25519 либо X25519
		case static_cast <uint8_t> (kind_t::ED25519):
		case static_cast <uint8_t> (kind_t::X25519): {
			// Если открытый ключ записан не своей длиной
			if(key.key.size() != CURVE25519)
				// Выводим отказ пустого ключа
				return error_t::EMPTY;
			// Если открытый ключ скопировать не удалось
			if(!copy(key.key.data(), key.key.size(), point))
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
		} break;
		// Если записывается ключ ML-DSA
		case static_cast <uint8_t> (kind_t::MLDSA): {
			// Если размер записи не отвечает ни одному набору
			if((key.key.size() != 1312) && (key.key.size() != 1952) && (key.key.size() != 2592))
				// Выводим отказ пустого ключа
				return error_t::EMPTY;
			// Если открытый ключ скопировать не удалось
			if(!copy(key.key.data(), key.key.size(), point))
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
		} break;
		// Если записывается ключ ГОСТ
		case static_cast <uint8_t> (kind_t::GOST): {
			// Если координаты не заполнены, различны длиной либо алгоритм не согласован
			if(key.x.empty() || (key.x.size() != key.y.size()) || !gostAlgorithm(key))
				// Выводим отказ пустого ключа
				return error_t::EMPTY;
			// Собираем строку байтов координат порядком от младшего байта к старшему
			outcome = reversedOctets(body, key.x, key.y);
		} break;
		// Если вид ключа не установлен
		default:
			// Выводим отказ пустого ключа
			return error_t::EMPTY;
	}
	// Если тело открытого ключа собрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ сборки
		return outcome;
	// Записчик записи
	asn1::writer_t writer;
	// Открываем набор записи
	writer.open(asn1::tag_t::SEQUENCE);
	// Итог записи набора алгоритма
	outcome = algorithmIdentifier(writer, key);
	// Если набор алгоритма записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Просмотр тела открытого ключа: у RSA и ГОСТ из записчика, у прочих из набора байтов
	const view_t bytes = (point.empty() ? body.data() : view_t(point.data(), point.size()));
	// Записываем строку битов открытого ключа
	writer.bits(bytes);
	// Закрываем набор записи
	writer.close();
	// Выводим итог завершения записи
	return finish(writer, result);
}
/**
 * @brief Метод разбора записи PrivateKeyInfo по RFC 5958
 *
 * @param der    разбираемая запись в кодировке DER
 * @param result ключ, в который помещается итог разбора
 *
 * @return       отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodePrivateKeyInfo(const view_t & der, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Набор верхней записи
	asn1::element_t sequence;
	// Итог разбора верхней записи
	error_t outcome = outer(der, sequence);
	// Если верхнюю запись разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Разборщик содержимого набора
	asn1::reader_t fields(sequence.content);
	// Разбираемый элемент набора
	asn1::element_t element;
	// Если издание записи разобрать не удалось
	if(!fields.next(asn1::tag_t::INTEGER, element))
		// Выводим переведённый отказ разбора
		return translate(fields.err());
	// Издание записи
	int64_t version = -1;
	// Итог разбора издания записи
	outcome = smallInteger(element, version);
	// Если издание записи разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Если издание записи не первое и не второе: раздел 2 RFC 5958
	if((version != 0) && (version != 1))
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Разбираемый ключ
	key_t key;
	// Опознаватель алгоритма ключа
	string algorithm;
	// Настройки алгоритма ключа
	asn1::element_t params;
	// Признак наличия настроек алгоритма
	bool present = false;
	// Итог разбора алгоритма ключа
	outcome = algorithmIdentifier(fields, algorithm, params, present);
	// Если алгоритм ключа разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Если строку байтов секретного ключа разобрать не удалось
	if(!fields.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
		// Выводим переведённый отказ разбора
		return translate(fields.err());
	// Просмотр записи секретного ключа
	const view_t body = element.content;
	// Просмотр записанного открытого ключа
	view_t opened;
	// Если необязательные поля записаны
	if(!fields.empty()){
		// Если очередное поле разобрать не удалось
		if(!fields.next(element))
			// Выводим переведённый отказ разбора
			return translate(fields.err());
		// Признак неразобранного поля
		bool pending = true;
		// Если поле есть набор свойств: они пропускаются
		if(tagged(element, asn1::cls_t::CONTEXT, 0, true)){
			// Снимаем признак неразобранного поля
			pending = false;
			// Если запись продолжается
			if(!fields.empty()){
				// Если очередное поле разобрать не удалось
				if(!fields.next(element))
					// Выводим переведённый отказ разбора
					return translate(fields.err());
				// Устанавливаем признак неразобранного поля
				pending = true;
			}
		}
		// Если поле есть открытый ключ: дозволен лишь второму изданию записи
		if(pending && tagged(element, asn1::cls_t::CONTEXT, 1, false)){
			// Если издание записи первое
			if(version != 1)
				// Выводим отказ устройства записи
				return error_t::STRUCTURE;
			// Число неиспользуемых разрядов последнего байта
			uint8_t unused = 0;
			// Строка битов открытого ключа: метка неявная, разбирается как строка битов
			asn1::element_t bits = element;
			// Итог разбора строки битов
			const asn1::error_t parsed = asn1::bits(bits, opened, unused);
			// Если строку битов разобрать не удалось либо разряды не заняты целиком
			if((parsed != asn1::error_t::NONE) || (unused != 0))
				// Выводим отказ разбора
				return ((parsed == asn1::error_t::NONE) ? error_t::STRUCTURE : translate(parsed));
		// Если поле не опознано
		} else if(pending)
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
		// Если после полей остался хвост
		if(!fields.empty())
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
	}
	// Если ключ RSA
	if(algorithm.compare(OID_RSA) == 0){
		// Если настройки не пусты: раздел 2.3.1 RFC 3279
		if(!present || !tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::NOTHING), false) || (params.content.size != 0))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Выполняем разбор RSAPrivateKey
		outcome = rsaSecret(body, key);
	// Если ключ EC
	} else if(algorithm.compare(OID_EC) == 0){
		// Если кривая не именованная
		if(!present || !tagged(params, asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::OBJECT), false))
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Итог разбора опознавателя кривой
		outcome = identifier(params, key.oid);
		// Если опознаватель кривой разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем разбор ECPrivateKey внутри обёртки
		outcome = ecSecret(body, true, key);
		// Если ключ разобран, а кривая его - curveSM2: вид ключа есть SM2, а не ECDSA
		if((outcome == error_t::NONE) && (key.oid.compare(OID_SM2) == 0))
			// Устанавливаем вид ключа
			key.kind = kind_t::SM2;
		// Если ключ разобран, а обёртка несёт открытый ключ
		if((outcome == error_t::NONE) && (opened.data != nullptr)){
			// Кривая ключа
			curve::curve_t curve;
			// Итог установки кривой
			outcome = curveOf(key, curve);
			// Записанные координаты открытого ключа
			vector <uint8_t> x, y;
			// Если кривая установлена
			if(outcome == error_t::NONE)
				// Выполняем разбор несжатой точки
				outcome = pointOf(opened, curve, x, y);
			// Если точка разобрана, а с выведенной не сошлась
			if((outcome == error_t::NONE) && (!same(x, key.x) || !same(y, key.y)))
				// Устанавливаем отказ негодного значения
				outcome = error_t::VALUE;
		}
	// Если ключ SM2
	} else if(algorithm.compare(OID_SM2) == 0){
		// Если настройки записаны: GB/T 32918 их не несёт, кривая curveSM2 подразумевается
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Запоминаем опознаватель кривой curveSM2
		key.oid = OID_SM2;
		// Выполняем разбор ECPrivateKey внутри обёртки
		outcome = ecSecret(body, true, key);
		// Если ключ разобран, вид его - SM2
		if(outcome == error_t::NONE)
			// Устанавливаем вид ключа
			key.kind = kind_t::SM2;
		// Если ключ разобран, а обёртка несёт открытый ключ
		if((outcome == error_t::NONE) && (opened.data != nullptr)){
			// Кривая ключа
			curve::curve_t curve;
			// Итог установки кривой
			outcome = curveOf(key, curve);
			// Записанные координаты открытого ключа
			vector <uint8_t> x, y;
			// Если кривая установлена
			if(outcome == error_t::NONE)
				// Выполняем разбор несжатой точки
				outcome = pointOf(opened, curve, x, y);
			// Если точка разобрана, а с выведенной не сошлась
			if((outcome == error_t::NONE) && (!same(x, key.x) || !same(y, key.y)))
				// Устанавливаем отказ негодного значения
				outcome = error_t::VALUE;
		}
	// Если ключ Ed25519 либо X25519
	} else if((algorithm.compare(OID_ED25519) == 0) || (algorithm.compare(OID_X25519) == 0)){
		// Если настройки записаны: раздел 3 RFC 8410 их запрещает
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Если обёртка несёт открытый ключ
		if(opened.data != nullptr){
			// Если открытый ключ скопировать не удалось: выведение сличит его с зерном
			if(!copy(opened.data, opened.size, key.key))
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
		}
		// Выполняем разбор зерна
		outcome = seedSecret(body, ((algorithm.compare(OID_ED25519) == 0) ? kind_t::ED25519 : kind_t::X25519), key);
	// Если ключ ML-DSA
	} else if((algorithm.compare(OID_MLDSA44) == 0) || (algorithm.compare(OID_MLDSA65) == 0) || (algorithm.compare(OID_MLDSA87) == 0)){
		// Если настройки записаны: раздел 5 RFC 9881 их запрещает
		if(present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Устанавливаем опознаватель алгоритма: обмен памяти не выделяет
		key.algorithm.swap(algorithm);
		// Выполняем разбор секретного ключа
		outcome = mldsaSecret(body, key.algorithm, key);
		// Если ключ разобран, а обёртка несёт открытый ключ, а с выведенным не сошёлся
		if((outcome == error_t::NONE) && (opened.data != nullptr) && ((opened.size != key.key.size()) || (::memcmp(opened.data, key.key.data(), key.key.size()) != 0)))
			// Устанавливаем отказ негодного значения
			outcome = error_t::VALUE;
	// Если ключ ГОСТ
	} else if((algorithm.compare(OID_GOST256) == 0) || (algorithm.compare(OID_GOST512) == 0) || (algorithm.compare(OID_GOST2001) == 0)){
		// Если настройки не записаны
		if(!present)
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
		// Устанавливаем опознаватель алгоритма: обмен памяти не выделяет
		key.algorithm.swap(algorithm);
		// Итог разбора настроек ключа
		outcome = gostParameters(params, key);
		// Если настройки ключа разобрать не удалось
		if(outcome != error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Выполняем разбор секретного ключа
		outcome = gostSecret(body, key);
		// Если ключ разобран, а опознаватель алгоритма с кривой не согласован
		if((outcome == error_t::NONE) && !gostAlgorithm(key))
			// Устанавливаем отказ алгоритма
			outcome = error_t::ALGORITHM;
	// Если алгоритм ключа неизвестен
	} else return error_t::ALGORITHM;
	// Если ключ разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Переносим разобранный ключ в место назначения
	transfer(key, result);
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод записи PrivateKeyInfo по RFC 5958
 *
 * @param key    записываемый ключ
 * @param result место, в которое помещается запись в кодировке DER
 *
 * @return       отказ записи
 *
 */
nts::keys::error_t nts::keys::encodePrivateKeyInfo(const key_t & key, vector <uint8_t> & result) noexcept {
	// Если секретной части нет
	if(!key.secret())
		// Выводим отказ пустого ключа
		return error_t::EMPTY;
	// Записчик тела секретного ключа
	asn1::writer_t body;
	// Итог сборки тела секретного ключа
	error_t outcome = secretBody(key, body);
	// Если тело секретного ключа собрать не удалось
	if(outcome != error_t::NONE){
		// Выполняем затирание буфера записчика
		scrub(body);
		// Выводим отказ сборки
		return outcome;
	}
	// Записчик записи
	asn1::writer_t writer;
	// Открываем набор записи
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем издание записи: открытого ключа обёртка не несёт
	writer.integer(0);
	// Итог записи набора алгоритма
	outcome = algorithmIdentifier(writer, key);
	// Если набор алгоритма записать не удалось
	if(outcome != error_t::NONE){
		// Выполняем затирание буфера записчика
		scrub(body);
		// Выводим отказ записи
		return outcome;
	}
	// Записываем тело секретного ключа строкой байтов
	writer.octets(body.data());
	// Закрываем набор записи
	writer.close();
	// Выполняем затирание буфера тела
	scrub(body);
	// Итог завершения записи
	outcome = finish(writer, result);
	// Выполняем затирание буфера записи
	scrub(writer);
	// Выводим итог завершения записи
	return outcome;
}
/**
 * @brief Метод разбора записи ECPrivateKey по RFC 5915 вне обёртки
 *
 * @param der    разбираемая запись в кодировке DER
 * @param result ключ, в который помещается итог разбора
 *
 * @return       отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodeECPrivateKey(const view_t & der, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Разбираемый ключ
	key_t key;
	// Итог разбора ECPrivateKey с кривой внутри
	const error_t outcome = ecSecret(der, false, key);
	// Если ключ разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Переносим разобранный ключ в место назначения
	transfer(key, result);
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод записи ECPrivateKey по RFC 5915 вне обёртки
 *
 * @param key    записываемый ключ
 * @param result место, в которое помещается запись в кодировке DER
 *
 * @return       отказ записи
 *
 */
nts::keys::error_t nts::keys::encodeECPrivateKey(const key_t & key, vector <uint8_t> & result) noexcept {
	// Записчик записи
	asn1::writer_t writer;
	// Итог сборки ECPrivateKey с кривой внутри
	error_t outcome = ecSecret(key, true, writer);
	// Если запись собрана
	if(outcome == error_t::NONE)
		// Выполняем завершение записи
		outcome = finish(writer, result);
	// Выполняем затирание буфера записи
	scrub(writer);
	// Выводим итог записи
	return outcome;
}
/**
 * @brief Метод разбора записи RSAPrivateKey по RFC 8017
 *
 * @param der    разбираемая запись в кодировке DER
 * @param result ключ, в который помещается итог разбора
 *
 * @return       отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodeRSAPrivateKey(const view_t & der, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Разбираемый ключ
	key_t key;
	// Итог разбора RSAPrivateKey
	const error_t outcome = rsaSecret(der, key);
	// Если ключ разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Переносим разобранный ключ в место назначения
	transfer(key, result);
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод записи RSAPrivateKey по RFC 8017
 *
 * @param key    записываемый ключ
 * @param result место, в которое помещается запись в кодировке DER
 *
 * @return       отказ записи
 *
 */
nts::keys::error_t nts::keys::encodeRSAPrivateKey(const key_t & key, vector <uint8_t> & result) noexcept {
	// Записчик записи
	asn1::writer_t writer;
	// Итог сборки RSAPrivateKey
	error_t outcome = rsaIntegers(key, true, writer);
	// Если запись собрана
	if(outcome == error_t::NONE)
		// Выполняем завершение записи
		outcome = finish(writer, result);
	// Выполняем затирание буфера записи
	scrub(writer);
	// Выводим итог записи
	return outcome;
}
/**
 * @brief Метод разбора записи RSAPublicKey по RFC 8017
 *
 * @param der    разбираемая запись в кодировке DER
 * @param result ключ, в который помещается итог разбора
 *
 * @return       отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodeRSAPublicKey(const view_t & der, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Разбираемый ключ
	key_t key;
	// Итог разбора RSAPublicKey
	const error_t outcome = rsaPublic(der, key);
	// Если ключ разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Переносим разобранный ключ в место назначения
	transfer(key, result);
	// Выводим успешность разбора
	return error_t::NONE;
}
/**
 * @brief Метод записи RSAPublicKey по RFC 8017
 *
 * @param key    записываемый ключ
 * @param result место, в которое помещается запись в кодировке DER
 *
 * @return       отказ записи
 *
 */
nts::keys::error_t nts::keys::encodeRSAPublicKey(const key_t & key, vector <uint8_t> & result) noexcept {
	// Записчик записи
	asn1::writer_t writer;
	// Итог сборки RSAPublicKey
	const error_t outcome = rsaIntegers(key, false, writer);
	// Если запись собрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ сборки
		return outcome;
	// Выводим итог завершения записи
	return finish(writer, result);
}
/**
 * @brief Метод разбора записи EncryptedPrivateKeyInfo по схеме PBES2 из RFC 8018
 *
 * @param der      разбираемая запись в кодировке DER
 * @param password пароль последовательностью октетов
 * @param result   ключ, в который помещается итог разбора
 *
 * @return         отказ разбора записи
 *
 */
nts::keys::error_t nts::keys::decodeEncryptedPrivateKeyInfo(const view_t & der, const view_t & password, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Набор верхней записи
	asn1::element_t sequence;
	// Итог разбора верхней записи
	error_t outcome = outer(der, sequence);
	// Если верхнюю запись разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Разборщик содержимого набора
	asn1::reader_t fields(sequence.content);
	// Опознаватель схемы защиты
	string algorithm;
	// Настройки схемы защиты
	asn1::element_t params;
	// Признак наличия настроек схемы
	bool present = false;
	// Итог разбора схемы защиты
	outcome = algorithmIdentifier(fields, algorithm, params, present);
	// Если схему защиты разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Если схема защиты не PBES2 либо настроек нет
	if((algorithm.compare(OID_PBES2) != 0) || !present)
		// Выводим отказ схемы
		return error_t::CIPHER;
	// Просмотр соли
	view_t salt;
	// Число оборотов выработки ключа
	uint32_t iterations = 0;
	// Алгоритм имитовставки
	digest::hash_t prf = digest::hash_t::NONE;
	// Длина ключа шифра в разрядах
	size_t bits = 0;
	// Просмотр синхропосылки
	view_t iv;
	// Итог разбора настроек схемы
	outcome = pbes2(params, salt, iterations, prf, bits, iv);
	// Если настройки схемы разобрать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ разбора
		return outcome;
	// Строка байтов шифртекста
	asn1::element_t element;
	// Если шифртекст разобрать не удалось
	if(!fields.next(asn1::tag_t::OCTET_STRING, element) || element.constructed)
		// Выводим переведённый отказ разбора
		return translate(fields.err());
	// Если после шифртекста остался хвост
	if(!fields.empty())
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Просмотр шифртекста
	const view_t encrypted = element.content;
	// Если шифртекст не занимает целого числа блоков
	if((encrypted.size < BLOCK) || ((encrypted.size % BLOCK) != 0))
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Ключ шифра
	uint8_t secret[cipher::AES_KEY];
	// Если ключ шифра из пароля вывести не удалось
	if(!digest::pbkdf2(prf, password, salt, iterations, secret, bits / 8)){
		// Выполняем затирание ключа шифра
		wipe(secret, sizeof(secret));
		// Выводим отказ схемы
		return error_t::CIPHER;
	}
	// Шифр AES
	cipher::aes_t aes;
	// Признак установки ключа шифра
	const bool keyed = aes.key(view_t(secret, bits / 8));
	// Выполняем затирание ключа шифра
	wipe(secret, sizeof(secret));
	// Режим сцепления блоков
	cipher::chaining_t chaining;
	// Если ключ шифра либо синхропосылку установить не удалось
	if(!keyed || !chaining.start(cipher::block_t(aes), iv))
		// Выводим отказ схемы
		return error_t::CIPHER;
	// Расшифрованная запись
	vector <uint8_t> plain;
	/**
	 * Расшифрование выделяет память: нехватка её отдаётся отказом
	 */
	try {
		// Выделяем место под расшифрованную запись
		plain.assign(encrypted.size, 0);
	// Если памяти не хватило
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Если расшифровать запись не удалось
	if(!chaining.decrypt(encrypted, plain.data())){
		// Выполняем затирание расшифрованной записи
		erase(plain);
		// Выводим отказ схемы
		return error_t::CIPHER;
	}
	// Длина дополнения PKCS #7
	const size_t padding = plain[plain.size() - 1];
	// Признак годности дополнения
	bool padded = ((padding >= 1) && (padding <= BLOCK));
	/**
	 * Выполняем проверку байтов дополнения: все они обязаны нести его длину
	 */
	for(size_t i = 0; padded && (i < padding); i++)
		// Учитываем годность очередного байта дополнения
		padded = (plain[plain.size() - i - 1] == padding);
	// Если дополнение негодно: пароль не подошёл
	if(!padded){
		// Выполняем затирание расшифрованной записи
		erase(plain);
		// Выводим отказ пароля
		return error_t::PASSWORD;
	}
	// Выполняем разбор расшифрованной записи
	outcome = decodePrivateKeyInfo(view_t(plain.data(), plain.size() - padding), result);
	// Выполняем затирание расшифрованной записи
	erase(plain);
	// Если запись разобрать не удалось и это не нехватка памяти: расшифровано не то
	if((outcome != error_t::NONE) && (outcome != error_t::MEMORY))
		// Выводим отказ пароля
		return error_t::PASSWORD;
	// Выводим итог разбора
	return outcome;
}
/**
 * @brief Метод записи EncryptedPrivateKeyInfo по схеме PBES2 из RFC 8018
 *
 * @param key        записываемый ключ
 * @param password   пароль последовательностью октетов
 * @param result     место, в которое помещается запись в кодировке DER
 * @param bits       длина ключа AES в разрядах: 128, 192 либо 256
 * @param iterations число оборотов PBKDF2, не меньше одного
 *
 * @return           отказ записи
 *
 */
nts::keys::error_t nts::keys::encodeEncryptedPrivateKeyInfo(const key_t & key, const view_t & password, vector <uint8_t> & result, const size_t bits, const uint32_t iterations) noexcept {
	// Опознаватель шифра по длине ключа
	const char * oid = nullptr;
	/**
	 * Выполняем перебор известных шифров
	 */
	for(size_t i = 0; i < (sizeof(CIPHERS) / sizeof(cipher_t)); i++){
		// Если длина ключа шифра совпала с искомой
		if(CIPHERS[i].bits == bits)
			// Устанавливаем опознаватель шифра
			oid = CIPHERS[i].oid;
	}
	// Если длина ключа шифра неизвестна либо оборотов нет
	if((oid == nullptr) || (iterations == 0))
		// Выводим отказ схемы
		return error_t::CIPHER;
	// Запись PrivateKeyInfo ровно по длине
	vector <uint8_t> exact;
	// Итог записи PrivateKeyInfo
	error_t outcome = encodePrivateKeyInfo(key, exact);
	// Если PrivateKeyInfo записать не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ записи
		return outcome;
	// Длина дополнения PKCS #7: от одного байта до целого блока
	const size_t padding = (BLOCK - (exact.size() % BLOCK));
	// Открытая запись ключа с дополнением
	vector <uint8_t> plain;
	/**
	 * Дополнение выделяет память: нехватка её отдаётся отказом. Место берётся сразу с
	 * запасом в блок, иначе дописывание дополнения перевыделяло бы буфер, а копия
	 * записи ключа оставалась бы в освобождённой памяти не затёртой
	 */
	try {
		// Выделяем место под запись с дополнением
		plain.reserve(exact.size() + BLOCK);
		// Переносим запись ключа
		plain.assign(exact.begin(), exact.end());
		// Дописываем дополнение
		plain.insert(plain.end(), padding, static_cast <uint8_t> (padding));
	// Если памяти не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание записи ровно по длине
		erase(exact);
		// Выполняем затирание открытой записи
		erase(plain);
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выполняем затирание записи ровно по длине
	erase(exact);
	// Соль и синхропосылка
	uint8_t salt[SALT], iv[BLOCK];
	// Если случайные байты выработать не удалось
	if(!entropy::bytes(salt, sizeof(salt)) || !entropy::bytes(iv, sizeof(iv))){
		// Выполняем затирание открытой записи
		erase(plain);
		// Выводим отказ случайности
		return error_t::RANDOM;
	}
	// Ключ шифра
	uint8_t secret[cipher::AES_KEY];
	// Признак выработки ключа шифра
	bool ready = digest::pbkdf2(digest::hash_t::SHA256, password, view_t(salt, sizeof(salt)), iterations, secret, bits / 8);
	// Шифр AES
	cipher::aes_t aes;
	// Учитываем установку ключа шифра
	ready = (ready && aes.key(view_t(secret, bits / 8)));
	// Выполняем затирание ключа шифра
	wipe(secret, sizeof(secret));
	// Зашифрованная запись
	vector <uint8_t> encrypted;
	/**
	 * Зашифрование выделяет память: нехватка её отдаётся отказом
	 */
	try {
		// Выделяем место под зашифрованную запись
		encrypted.assign(plain.size(), 0);
	// Если памяти не хватило
	} catch(const bad_alloc &) {
		// Выполняем затирание открытой записи
		erase(plain);
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Режим сцепления блоков
	cipher::chaining_t chaining;
	// Учитываем запуск режима и зашифрование записи
	ready = (ready && chaining.start(cipher::block_t(aes), view_t(iv, sizeof(iv))) && chaining.encrypt(view_t(plain.data(), plain.size()), encrypted.data()));
	// Выполняем затирание открытой записи
	erase(plain);
	// Если запись зашифровать не удалось
	if(!ready)
		// Выводим отказ схемы
		return error_t::CIPHER;
	// Записчик записи
	asn1::writer_t writer;
	// Открываем набор записи
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем набор схемы защиты
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель схемы
	object(writer, OID_PBES2);
	// Открываем настройки схемы
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем набор выработки ключа
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель выработки ключа
	object(writer, OID_PBKDF2);
	// Открываем настройки выработки ключа
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем соль
	writer.octets(view_t(salt, sizeof(salt)));
	// Записываем число оборотов
	writer.integer(static_cast <int64_t> (iterations));
	// Открываем набор имитовставки
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель имитовставки hmacWithSHA256
	object(writer, PRFS[2].oid);
	// Записываем пустые настройки имитовставки
	writer.nothing();
	// Закрываем набор имитовставки
	writer.close();
	// Закрываем настройки выработки ключа
	writer.close();
	// Закрываем набор выработки ключа
	writer.close();
	// Открываем набор шифра
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель шифра
	object(writer, oid);
	// Записываем синхропосылку
	writer.octets(view_t(iv, sizeof(iv)));
	// Закрываем набор шифра
	writer.close();
	// Закрываем настройки схемы
	writer.close();
	// Закрываем набор схемы защиты
	writer.close();
	// Записываем шифртекст
	writer.octets(view_t(encrypted.data(), encrypted.size()));
	// Закрываем набор записи
	writer.close();
	// Выводим итог завершения записи
	return finish(writer, result);
}
/**
 * @brief Метод разбора ключа из текста в обёртке PEM
 *
 * @param text     разбираемый текст
 * @param password пароль последовательностью октетов, нужен лишь зашифрованному ключу
 * @param result   ключ, в который помещается итог разбора
 *
 * @return         отказ разбора текста
 *
 */
nts::keys::error_t nts::keys::decode(const string & text, const view_t & password, key_t & result) noexcept {
	// Выполняем сброс ключа
	result.clear();
	// Разобранные записи текста
	vector <pem::block_t> blocks;
	// Итог разбора обёртки
	const pem::error_t parsed = pem::decode(text, blocks);
	// Если обёртку разобрать не удалось
	if(parsed != pem::error_t::NONE){
		// Если памяти не хватило
		if(parsed == pem::error_t::MEMORY)
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		// Выводим отказ: записей нет либо обёртка испорчена
		return ((parsed == pem::error_t::EMPTY) ? error_t::LABEL : error_t::STRUCTURE);
	}
	// Итог разбора записи
	error_t outcome = error_t::LABEL;
	/**
	 * Выполняем перебор разобранных записей
	 */
	for(auto & block : blocks){
		// Признак известной метки записи
		bool known = false;
		// Выполняем разбор записи по её метке
		outcome = labeled(block.label, view_t(block.data.data(), block.data.size()), password, result, known);
		// Выполняем затирание тела записи: оно вправе нести секрет
		erase(block.data);
		// Если метка записи известна
		if(known)
			// Прерываем перебор: разбирается первая запись известного вида
			break;
	}
	/**
	 * Выполняем затирание тел оставшихся записей
	 */
	for(auto & block : blocks)
		// Затираем тело очередной записи
		erase(block.data);
	// Выводим итог разбора
	return outcome;
}
/**
 * @brief Метод записи ключа в текст в обёртке PEM
 *
 * @param key        записываемый ключ
 * @param container  вид записи ключа
 * @param result     текст, в который помещается итог записи
 * @param password   пароль последовательностью октетов, нужен лишь зашифрованной записи
 * @param bits       длина ключа AES в разрядах у зашифрованной записи
 * @param iterations число оборотов PBKDF2 у зашифрованной записи
 *
 * @return           отказ записи
 *
 */
nts::keys::error_t nts::keys::encode(const key_t & key, const container_t container, string & result, const view_t & password, const size_t bits, const uint32_t iterations) noexcept {
	// Выполняем сброс текста: обёртка дописывается к нему, а не заменяет его
	result.clear();
	// Записываемая запись
	pem::block_t block;
	// Метка записи
	const char * label = nullptr;
	// Итог записи в кодировке DER
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем определение вида записи
	 */
	switch(static_cast <uint8_t> (container)){
		// Если записывается PrivateKeyInfo
		case static_cast <uint8_t> (container_t::PRIVATE): {
			// Устанавливаем метку записи
			label = pem::PEM_SECRET;
			// Выполняем запись PrivateKeyInfo
			outcome = encodePrivateKeyInfo(key, block.data);
		} break;
		// Если записывается EncryptedPrivateKeyInfo
		case static_cast <uint8_t> (container_t::ENCRYPTED): {
			// Устанавливаем метку записи
			label = pem::PEM_ENCRYPTED;
			// Выполняем запись EncryptedPrivateKeyInfo
			outcome = encodeEncryptedPrivateKeyInfo(key, password, block.data, bits, iterations);
		} break;
		// Если записывается SubjectPublicKeyInfo
		case static_cast <uint8_t> (container_t::PUBLIC): {
			// Устанавливаем метку записи
			label = LABEL_PUBLIC;
			// Выполняем запись SubjectPublicKeyInfo
			outcome = encodeSubjectPublicKeyInfo(key, block.data);
		} break;
		// Если вид записи неизвестен
		default:
			// Выводим отказ устройства записи
			return error_t::STRUCTURE;
	}
	// Если запись в кодировке DER не удалась
	if(outcome != error_t::NONE){
		// Выполняем затирание тела записи
		erase(block.data);
		// Выводим отказ записи
		return outcome;
	}
	// Если метку записи скопировать не удалось
	if(!store(label, block.label)){
		// Выполняем затирание тела записи
		erase(block.data);
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Итог записи обёртки
	const pem::error_t wrapped = pem::encode(block, result);
	// Выполняем затирание тела записи
	erase(block.data);
	// Если обёртку записать не удалось
	if(wrapped != pem::error_t::NONE)
		// Выводим отказ: нехватка памяти либо устройство записи
		return ((wrapped == pem::error_t::MEMORY) ? error_t::MEMORY : error_t::STRUCTURE);
	// Выводим успешность записи
	return error_t::NONE;
}
/**
 * @brief Метод получения названия отказа
 *
 * @param error отказ, название которого извлекается
 *
 * @return      название отказа
 *
 */
const char * nts::keys::name(const error_t error) noexcept {
	/**
	 * Выполняем определение отказа
	 */
	switch(static_cast <uint8_t> (error)){
		// Если отказа нет
		case static_cast <uint8_t> (error_t::NONE):
			// Выводим название отказа
			return "NONE";
		// Если ключ не установлен
		case static_cast <uint8_t> (error_t::EMPTY):
			// Выводим название отказа
			return "EMPTY";
		// Если запись не отвечает устройству
		case static_cast <uint8_t> (error_t::STRUCTURE):
			// Выводим название отказа
			return "STRUCTURE";
		// Если алгоритм неизвестен
		case static_cast <uint8_t> (error_t::ALGORITHM):
			// Выводим название отказа
			return "ALGORITHM";
		// Если кривая неизвестна
		case static_cast <uint8_t> (error_t::CURVE):
			// Выводим название отказа
			return "CURVE";
		// Если составляющие негодны
		case static_cast <uint8_t> (error_t::VALUE):
			// Выводим название отказа
			return "VALUE";
		// Если схема защиты неизвестна
		case static_cast <uint8_t> (error_t::CIPHER):
			// Выводим название отказа
			return "CIPHER";
		// Если пароль не подошёл
		case static_cast <uint8_t> (error_t::PASSWORD):
			// Выводим название отказа
			return "PASSWORD";
		// Если записи известного вида нет
		case static_cast <uint8_t> (error_t::LABEL):
			// Выводим название отказа
			return "LABEL";
		// Если случайные байты не выработаны
		case static_cast <uint8_t> (error_t::RANDOM):
			// Выводим название отказа
			return "RANDOM";
		// Если памяти не хватило
		case static_cast <uint8_t> (error_t::MEMORY):
			// Выводим название отказа
			return "MEMORY";
	}
	// Выводим название неизвестного отказа
	return "UNKNOWN";
}
