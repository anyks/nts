/**
 * @file hpke.cpp
 * @date 2026-09-06
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
 * @brief Реализация модуля гибридного шифрования с открытым ключом HPKE по RFC 9180
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Намеренные решения
 *
 * 1. Меченые извлечение и растяжение (LabeledExtract и LabeledExpand раздела 4 RFC 9180)
 *    складываются по частям потоковой имитовставкой `digest::mac_t`, а не склейкой
 *    «HPKE-v1» || suite_id || label || данные в один буфер: у растяжения по разделу 2.3
 *    RFC 5869 итог HMAC берётся по частям T(i-1) || info || i тем же способом. Оттого на
 *    ключевом пути модуль не выделяет память вовсе, и нехватка памяти возможна лишь в
 *    накопителях `vector` наружных обёрток, где она перехватывается и отдаётся кодом MEMORY.
 *
 * 2. Порядковый номер хранится числом в шестьдесят четыре разряда. Раздел 5.2 RFC 9180
 *    велит останавливать переписку при номере 2^(8·Nn) − 1, то есть 2^96 − 1 при Nn = 12;
 *    модуль останавливается раньше — при номере 2^64 − 1 — что строже стандарта и ни одно
 *    законное сообщение не отвергает: столько сообщений по одному состоянию не пошлёт никто.
 *
 * 3. Секретный ключ пары хранится в том виде, в каком его выдало DeriveKeyPair либо задал
 *    потребитель, без зажима разрядов: зажим по разделу 5 RFC 7748 выполняет сама функция
 *    X25519 при каждом употреблении, а вектора приложения A RFC 9180 сличают незажатый вид.
 *
 * 4. Открытый ключ получателя на принадлежность кривой не проверяется: раздел 7.1.4 RFC 9180
 *    велит лишь отвергать нулевое общее значение, и это делает `agreement::x25519`, отдавая
 *    отказ, который здесь обращается в код ENCAPSULATION.
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <hpke/hpke.hpp>
#include <agreement/x25519.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <cipher/gcm.hpp>
#include <cipher/mode.hpp>
#include <cipher/chachapoly.hpp>
#include <sys/wipe.hpp>

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
	using namespace nts::hpke;

	/**
	 * Помощник стирания памяти
	 */
	using nts::sys::wipe;

	/**
	 * Метка издания протокола: раздел 4 RFC 9180
	 */
	static const char * VERSION = "HPKE-v1";
	/**
	 * Длина опознавателя способа инкапсуляции: «KEM» и два байта номера
	 */
	static constexpr size_t KEM_STAMP = 5;
	// Наименьшая длина заранее разделённого ключа в байтах (раздел 9.5 RFC 9180)
	static constexpr size_t PSK_LEAST = 32;
	/**
	 * Длина опознавателя набора: «HPKE» и три номера по два байта
	 */
	static constexpr size_t SUITE_STAMP = 10;
	/**
	 * Длина общего значения способа инкапсуляции: Nsecret раздела 7.1 RFC 9180
	 */
	static constexpr size_t SECRET_SIZE = 32;
	/**
	 * Длина привязки расписания ключей: режим и два хеша
	 */
	static constexpr size_t SCHEDULE_SIZE = (1 + (2 * HASH_SIZE));
	/**
	 * Длина привязки способа инкапсуляции: три открытых ключа
	 */
	static constexpr size_t BINDING_SIZE = (3 * X25519_SIZE);

	/**
	 * @brief Метод выбора алгоритма хеширования функции выработки ключа
	 *
	 * @param kdf функция выработки ключа
	 * @return    алгоритм хеширования либо NONE
	 *
	 */
	static digest::hash_t hashing(const kdf_t kdf) noexcept {
		/**
		 * Определяем функцию выработки ключа
		 */
		switch(static_cast <uint16_t> (kdf)){
			// HKDF-SHA256
			case static_cast <uint16_t> (kdf_t::HKDF_SHA256):
				// Выводим SHA-256
				return digest::hash_t::SHA256;
			// HKDF-SHA384
			case static_cast <uint16_t> (kdf_t::HKDF_SHA384):
				// Выводим SHA-384
				return digest::hash_t::SHA384;
			// HKDF-SHA512
			case static_cast <uint16_t> (kdf_t::HKDF_SHA512):
				// Выводим SHA-512
				return digest::hash_t::SHA512;
		}
		// Выводим отсутствие алгоритма
		return digest::hash_t::NONE;
	}
	/**
	 * @brief Метод записи двухбайтового номера старшим байтом вперёд
	 *
	 * @param value  номер
	 * @param result место под два байта
	 *
	 */
	static void inscribe(const uint16_t value, uint8_t * result) noexcept {
		// Записываем старший байт
		result[0] = static_cast <uint8_t> (value >> 8);
		// Записываем младший байт
		result[1] = static_cast <uint8_t> (value);
	}
	/**
	 * @brief Метод составления опознавателя способа инкапсуляции
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param result место под опознаватель длиной KEM_STAMP
	 *
	 * @details Значение suite_id раздела 4.1 RFC 9180 для функций способа инкапсуляции
	 *
	 */
	static void stamp(const kem_t kem, uint8_t * result) noexcept {
		// Записываем метку «KEM»
		::memcpy(result, "KEM", 3);
		// Записываем номер способа
		inscribe(static_cast <uint16_t> (kem), result + 3);
	}
	/**
	 * @brief Метод составления опознавателя набора алгоритмов
	 *
	 * @param suite  набор алгоритмов
	 * @param result место под опознаватель длиной SUITE_STAMP
	 *
	 * @details Значение suite_id раздела 5.1 RFC 9180 для расписания ключей
	 *
	 */
	static void stamp(const suite_t & suite, uint8_t * result) noexcept {
		// Записываем метку «HPKE»
		::memcpy(result, "HPKE", 4);
		// Записываем номер способа инкапсуляции
		inscribe(static_cast <uint16_t> (suite.kem), result + 4);
		// Записываем номер функции выработки ключа
		inscribe(static_cast <uint16_t> (suite.kdf), result + 6);
		// Записываем номер шифра
		inscribe(static_cast <uint16_t> (suite.aead), result + 8);
	}
	/**
	 * @brief Метод меченого извлечения ключа
	 *
	 * @param hash     алгоритм хеширования
	 * @param salt     соль: пустая заменяется нулями в длину хеша
	 * @param suite    просмотр опознавателя набора либо способа инкапсуляции
	 * @param label    метка извлечения
	 * @param material исходный ключевой материал, вправе быть пустым
	 * @param result   место под извлечённый ключ в длину хеша
	 * @return         признак успешности извлечения
	 *
	 * @details Функция LabeledExtract раздела 4 RFC 9180: Extract(salt, «HPKE-v1» || suite_id || label || ikm)
	 *
	 */
	static bool absorb(const digest::hash_t hash, const view_t & salt, const view_t & suite, const char * label, const view_t & material, uint8_t * result) noexcept {
		// Длина хеша
		const size_t length = digest::length(hash);
		// Нулевая соль в длину хеша: раздел 2.2 RFC 5869
		uint8_t zeros[HASH_SIZE];
		// Обнуляем нулевую соль
		::memset(zeros, 0, sizeof(zeros));
		// Объект имитовставки
		digest::mac_t mac;
		// Заводим имитовставку на соли
		if(!mac.start(hash, ((salt.size > 0) ? salt : view_t(zeros, length))))
			// Выводим отказ извлечения
			return false;
		// Подаём метку издания
		mac.update(view_t(reinterpret_cast <const uint8_t *> (VERSION), ::strlen(VERSION)));
		// Подаём опознаватель набора
		mac.update(suite);
		// Подаём метку извлечения
		mac.update(view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)));
		// Если материал не пуст
		if(material.size > 0)
			// Подаём материал
			mac.update(material);
		// Выводим итог имитовставки
		return mac.finish(result, length);
	}
	/**
	 * @brief Метод меченого растяжения ключа
	 *
	 * @param hash   алгоритм хеширования
	 * @param key    псевдослучайный ключ в длину хеша
	 * @param suite  просмотр опознавателя набора либо способа инкапсуляции
	 * @param label  метка растяжения
	 * @param info   привязка растяжения, вправе быть пустой
	 * @param result место под материал
	 * @param size   длина материала, от одного байта до 255 длин хеша
	 * @return       признак успешности растяжения
	 *
	 * @details Функция LabeledExpand раздела 4 RFC 9180: Expand(prk, I2OSP(L, 2) || «HPKE-v1» ||
	 *          suite_id || label || info, L); растяжение идёт по разделу 2.3 RFC 5869 частями
	 *          T(i) = HMAC(prk, T(i-1) || info' || i) без склейки привязки в один буфер
	 *
	 */
	static bool unfold(const digest::hash_t hash, const view_t & key, const view_t & suite, const char * label, const view_t & info, uint8_t * result, const size_t size) noexcept {
		// Длина хеша
		const size_t length = digest::length(hash);
		// Если длина материала недопустима
		if((size == 0) || (size > (255 * length)))
			// Выводим отказ растяжения
			return false;
		// Двухбайтовая запись длины материала
		uint8_t width[2];
		// Записываем длину материала
		inscribe(static_cast <uint16_t> (size), width);
		// Предыдущий блок растяжения
		uint8_t previous[HASH_SIZE];
		// Число выданных байтов
		size_t offset = 0;
		// Номер блока растяжения
		uint8_t counter = 0;
		// Объект имитовставки
		digest::mac_t mac;
		// Заводим имитовставку на ключе
		if(!mac.start(hash, key))
			// Выводим отказ растяжения
			return false;
		/**
		 * Выполняем выработку блоков растяжения
		 */
		while(offset < size){
			// Увеличиваем номер блока
			counter++;
			// Если блок не первый
			if(offset > 0){
				// Перезаводим имитовставку на том же ключе
				if(!mac.restart()){
					// Стираем предыдущий блок
					wipe(previous, sizeof(previous));
					// Выводим отказ растяжения
					return false;
				}
				// Подаём предыдущий блок
				mac.update(view_t(previous, length));
			}
			// Подаём длину материала
			mac.update(view_t(width, sizeof(width)));
			// Подаём метку издания
			mac.update(view_t(reinterpret_cast <const uint8_t *> (VERSION), ::strlen(VERSION)));
			// Подаём опознаватель набора
			mac.update(suite);
			// Подаём метку растяжения
			mac.update(view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)));
			// Если привязка не пуста
			if(info.size > 0)
				// Подаём привязку
				mac.update(info);
			// Подаём номер блока
			mac.update(view_t(&counter, 1));
			// Вырабатываем блок
			if(!mac.finish(previous, length)){
				// Стираем предыдущий блок
				wipe(previous, sizeof(previous));
				// Стираем выданный материал
				wipe(result, offset);
				// Выводим отказ растяжения
				return false;
			}
			// Длина выдаваемой части блока
			const size_t part = (((size - offset) < length) ? (size - offset) : length);
			// Копируем часть блока в материал
			::memcpy(result + offset, previous, part);
			// Сдвигаем число выданных байтов
			offset += part;
		}
		// Стираем предыдущий блок
		wipe(previous, sizeof(previous));
		// Выводим успех растяжения
		return true;
	}
	/**
	 * @brief Метод выработки общего значения из значений Диффи-Хеллмана
	 *
	 * @param dh      просмотр общих значений Диффи-Хеллмана: одно либо два по тридцать два байта
	 * @param binding просмотр привязки способа инкапсуляции: инкапсулированный ключ и открытые ключи
	 * @param result  место под общее значение длиной SECRET_SIZE
	 * @return        признак успешности выработки
	 *
	 * @details Функция ExtractAndExpand раздела 4.1 RFC 9180 для DHKEM(X25519, HKDF-SHA256):
	 *          eae_prk = LabeledExtract("", "eae_prk", dh), shared_secret = LabeledExpand(eae_prk,
	 *          "shared_secret", kem_context, Nsecret)
	 *
	 */
	static bool combine(const view_t & dh, const view_t & binding, uint8_t * result) noexcept {
		// Опознаватель способа инкапсуляции
		uint8_t suite[KEM_STAMP];
		// Составляем опознаватель способа
		stamp(kem_t::X25519_HKDF_SHA256, suite);
		// Псевдослучайный ключ извлечения
		uint8_t prk[HASH_SIZE];
		// Извлекаем ключ из общих значений
		if(!absorb(digest::hash_t::SHA256, view_t(), view_t(suite, sizeof(suite)), "eae_prk", dh, prk)){
			// Стираем ключ извлечения
			wipe(prk, sizeof(prk));
			// Выводим отказ выработки
			return false;
		}
		// Растягиваем ключ в общее значение
		const bool status = unfold(digest::hash_t::SHA256, view_t(prk, digest::length(digest::hash_t::SHA256)), view_t(suite, sizeof(suite)), "shared_secret", binding, result, SECRET_SIZE);
		// Стираем ключ извлечения
		wipe(prk, sizeof(prk));
		// Выводим итог выработки
		return status;
	}
	/**
	 * @brief Метод проверки допустимости режима работы
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим известен
	 *
	 */
	static bool admissible(const regime_t mode) noexcept {
		/**
		 * Определяем режим работы
		 */
		switch(static_cast <uint8_t> (mode)){
			// Известные режимы
			case static_cast <uint8_t> (regime_t::BASE):
			case static_cast <uint8_t> (regime_t::PSK):
			case static_cast <uint8_t> (regime_t::AUTH):
			case static_cast <uint8_t> (regime_t::AUTH_PSK):
				// Выводим допустимость
				return true;
		}
		// Выводим недопустимость
		return false;
	}
	/**
	 * @brief Метод проверки признака подлинности отправителя у режима
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим требует ключ отправителя
	 *
	 */
	static bool authenticated(const regime_t mode) noexcept {
		// Выводим признак режимов AUTH и AUTH_PSK
		return ((mode == regime_t::AUTH) || (mode == regime_t::AUTH_PSK));
	}
	/**
	 * @brief Метод проверки признака заранее разделённого ключа у режима
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим требует заранее разделённый ключ
	 *
	 */
	static bool preshared(const regime_t mode) noexcept {
		// Выводим признак режимов PSK и AUTH_PSK
		return ((mode == regime_t::PSK) || (mode == regime_t::AUTH_PSK));
	}
}

/**
 * @brief Конструктор пустого набора
 *
 */
nts::hpke::Suite::Suite() noexcept : kem(kem_t::NONE), kdf(kdf_t::NONE), aead(aead_t::NONE) {}
/**
 * @brief Конструктор набора
 *
 * @param kem  способ инкапсуляции ключа
 * @param kdf  функция выработки ключа
 * @param aead шифр с проверкой подлинности
 *
 */
nts::hpke::Suite::Suite(const kem_t kem, const kdf_t kdf, const aead_t aead) noexcept : kem(kem), kdf(kdf), aead(aead) {}
/**
 * @brief Конструктор пустого ключа
 *
 */
nts::hpke::Shared::Shared() noexcept : key(), identity() {}
/**
 * @brief Конструктор ключа
 *
 * @param key      просмотр заранее разделённого ключа
 * @param identity просмотр опознавателя ключа
 *
 */
nts::hpke::Shared::Shared(const view_t & key, const view_t & identity) noexcept : key(key), identity(identity) {}
/**
 * @brief Метод извлечения длины хеша функции выработки ключа
 *
 * @param kdf функция выработки ключа
 * @return    длина хеша в байтах либо ноль у неизвестной функции
 *
 */
size_t nts::hpke::length(const kdf_t kdf) noexcept {
	// Выводим длину хеша алгоритма функции
	return digest::length(hashing(kdf));
}
/**
 * @brief Метод извлечения длины ключа шифра
 *
 * @param aead шифр с проверкой подлинности
 * @return     длина ключа в байтах, ноль у набора только для экспорта и у неизвестного шифра
 *
 */
size_t nts::hpke::length(const aead_t aead) noexcept {
	/**
	 * Определяем шифр
	 */
	switch(static_cast <uint16_t> (aead)){
		// AES-128-GCM
		case static_cast <uint16_t> (aead_t::AES_128_GCM):
			// Выводим шестнадцать байтов
			return 16;
		// AES-256-GCM и ChaCha20-Poly1305
		case static_cast <uint16_t> (aead_t::AES_256_GCM):
		case static_cast <uint16_t> (aead_t::CHACHA20_POLY1305):
			// Выводим тридцать два байта
			return 32;
	}
	// Выводим отсутствие ключа
	return 0;
}
/**
 * @brief Метод извлечения длины метки подлинности шифра
 *
 * @param aead шифр с проверкой подлинности
 * @return     длина метки в байтах, ноль у набора только для экспорта и у неизвестного шифра
 *
 */
size_t nts::hpke::overhead(const aead_t aead) noexcept {
	/**
	 * Определяем шифр
	 */
	switch(static_cast <uint16_t> (aead)){
		// Шифры с меткой в шестнадцать байтов
		case static_cast <uint16_t> (aead_t::AES_128_GCM):
		case static_cast <uint16_t> (aead_t::AES_256_GCM):
		case static_cast <uint16_t> (aead_t::CHACHA20_POLY1305):
			// Выводим длину метки
			return TAG_SIZE;
	}
	// Выводим отсутствие метки
	return 0;
}
/**
 * @brief Метод проверки поддержки набора алгоритмов
 *
 * @param suite набор алгоритмов
 * @return      признак того, что все три алгоритма набора поддерживаются
 *
 */
bool nts::hpke::supported(const suite_t & suite) noexcept {
	// Если способ инкапсуляции не поддерживается
	if(suite.kem != kem_t::X25519_HKDF_SHA256)
		// Выводим отсутствие поддержки
		return false;
	// Если функция выработки ключа не поддерживается
	if(hashing(suite.kdf) == digest::hash_t::NONE)
		// Выводим отсутствие поддержки
		return false;
	// Выводим признак поддержки шифра
	return ((suite.aead == aead_t::EXPORT_ONLY) || (overhead(suite.aead) > 0));
}
/**
 * @brief Метод проверки готовности пары ключей
 *
 * @return признак того, что пара ключей установлена
 *
 */
bool nts::hpke::Key::ready() const noexcept {
	// Выводим признак установленного способа
	return (this->_kem != kem_t::NONE);
}
/**
 * @brief Метод извлечения способа инкапсуляции ключа
 *
 * @return способ инкапсуляции ключа
 *
 */
nts::hpke::kem_t nts::hpke::Key::kem() const noexcept {
	// Выводим способ инкапсуляции
	return this->_kem;
}
/**
 * @brief Метод извлечения секретного ключа
 *
 * @return просмотр секретного ключа либо пустой просмотр у неготовой пары
 *
 */
nts::view_t nts::hpke::Key::secret() const noexcept {
	// Выводим просмотр секретного ключа готовой пары
	return (this->ready() ? view_t(this->_secret, X25519_SIZE) : view_t());
}
/**
 * @brief Метод извлечения открытого ключа
 *
 * @return просмотр открытого ключа либо пустой просмотр у неготовой пары
 *
 */
nts::view_t nts::hpke::Key::point() const noexcept {
	// Выводим просмотр открытого ключа готовой пары
	return (this->ready() ? view_t(this->_point, X25519_SIZE) : view_t());
}
/**
 * @brief Метод выработки пары ключей из случайных байтов
 *
 * @param kem способ инкапсуляции ключа
 * @return    причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::generate(const kem_t kem) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(kem != kem_t::X25519_HKDF_SHA256)
		// Выводим отказ набора
		return error_t::SUITE;
	// Вырабатываем пару ключей из случайных байтов
	if(!agreement::generate(this->_secret, this->_point)){
		// Стираем пару
		this->clear();
		// Выводим отказ источника случайных значений
		return error_t::ENTROPY;
	}
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод выработки пары ключей из исходного материала
 *
 * @param kem      способ инкапсуляции ключа
 * @param material исходный ключевой материал длиной не короче ключа
 * @return         причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::derive(const kem_t kem, const view_t & material) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(kem != kem_t::X25519_HKDF_SHA256)
		// Выводим отказ набора
		return error_t::SUITE;
	// Если материал короче ключа: раздел 7.1.3 RFC 9180
	if((material.data == nullptr) || (material.size < X25519_SIZE))
		// Выводим отказ ключа
		return error_t::KEY;
	// Опознаватель способа инкапсуляции
	uint8_t suite[KEM_STAMP];
	// Составляем опознаватель способа
	stamp(kem, suite);
	// Псевдослучайный ключ извлечения
	uint8_t prk[HASH_SIZE];
	// Извлекаем ключ из материала
	if(!absorb(digest::hash_t::SHA256, view_t(), view_t(suite, sizeof(suite)), "dkp_prk", material, prk)){
		// Стираем ключ извлечения
		wipe(prk, sizeof(prk));
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Растягиваем ключ в секретный ключ
	const bool status = unfold(digest::hash_t::SHA256, view_t(prk, digest::length(digest::hash_t::SHA256)), view_t(suite, sizeof(suite)), "sk", view_t(), this->_secret, X25519_SIZE);
	// Стираем ключ извлечения
	wipe(prk, sizeof(prk));
	// Если секретный ключ не выработан либо открытый ключ не вычислен
	if(!status || !agreement::x25519(view_t(this->_secret, X25519_SIZE), this->_point)){
		// Стираем пару
		this->clear();
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод установки пары ключей по секретному ключу
 *
 * @param kem    способ инкапсуляции ключа
 * @param secret секретный ключ длиной в тридцать два байта
 * @return       причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::set(const kem_t kem, const view_t & secret) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(kem != kem_t::X25519_HKDF_SHA256)
		// Выводим отказ набора
		return error_t::SUITE;
	// Если секретный ключ записан неверной длиной
	if((secret.data == nullptr) || (secret.size != X25519_SIZE))
		// Выводим отказ ключа
		return error_t::KEY;
	// Копируем секретный ключ
	::memcpy(this->_secret, secret.data, X25519_SIZE);
	// Вычисляем открытый ключ
	if(!agreement::x25519(view_t(this->_secret, X25519_SIZE), this->_point)){
		// Стираем пару
		this->clear();
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод стирания пары ключей
 *
 */
void nts::hpke::Key::clear() noexcept {
	// Сбрасываем способ инкапсуляции
	this->_kem = kem_t::NONE;
	// Стираем секретный ключ
	wipe(this->_secret, sizeof(this->_secret));
	// Стираем открытый ключ
	wipe(this->_point, sizeof(this->_point));
}
/**
 * @brief Конструктор пустой пары ключей
 *
 */
nts::hpke::Key::Key() noexcept : _kem(kem_t::NONE) {
	// Обнуляем секретный ключ
	::memset(this->_secret, 0, sizeof(this->_secret));
	// Обнуляем открытый ключ
	::memset(this->_point, 0, sizeof(this->_point));
}
/**
 * @brief Деструктор: стирает секретный ключ
 *
 */
nts::hpke::Key::~Key() noexcept {
	// Стираем пару
	this->clear();
}
/**
 * @brief Метод установки состояния по общему значению
 *
 * @param suite  набор алгоритмов
 * @param mode   режим работы
 * @param shared общее значение способа инкапсуляции
 * @param info   привязка к применению
 * @param psk    заранее разделённый ключ с опознавателем
 * @param sender признак стороны отправителя
 * @return       причина отказа либо NONE
 *
 * @details Функция KeySchedule раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::setup(const suite_t & suite, const regime_t mode, const view_t & shared, const view_t & info, const shared_t & psk, const bool sender) noexcept {
	// Стираем прежнее состояние
	this->clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Признак заданного ключа
	const bool keyed = (psk.key.size > 0);
	// Признак заданного опознавателя
	const bool named = (psk.identity.size > 0);
	// Если ключ и опознаватель заданы порознь: раздел 5.1 RFC 9180
	if(keyed != named)
		// Выводим отказ ключа
		return error_t::PSK;
	// Если наличие ключа не отвечает режиму: раздел 5.1 RFC 9180
	if(keyed != preshared(mode))
		// Выводим отказ ключа
		return error_t::PSK;
	// Если просмотры заданы длиной без места
	if((keyed && ((psk.key.data == nullptr) || (psk.identity.data == nullptr))) || ((info.size > 0) && (info.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Раздел 9.5 RFC 9180: заранее разделённый ключ обязан нести не меньше 32 байтов энтропии - короче 32 байтов он отвергается
	if(keyed && (psk.key.size < PSK_LEAST))
		// Выводим отказ ключа
		return error_t::PSK;
	// Алгоритм хеширования функции выработки ключа
	const digest::hash_t hash = hashing(suite.kdf);
	// Длина хеша
	const size_t length = digest::length(hash);
	// Опознаватель набора
	uint8_t identifier[SUITE_STAMP];
	// Составляем опознаватель набора
	stamp(suite, identifier);
	// Просмотр опознавателя набора
	const view_t label(identifier, sizeof(identifier));
	// Привязка расписания ключей: режим, хеш опознавателя ключа, хеш привязки к применению
	uint8_t schedule[SCHEDULE_SIZE];
	// Записываем режим
	schedule[0] = static_cast <uint8_t> (mode);
	// Секрет расписания
	uint8_t secret[HASH_SIZE];
	// Признак успешности выработки
	bool status = absorb(hash, view_t(), label, "psk_id_hash", psk.identity, schedule + 1);
	// Вырабатываем хеш привязки к применению
	status = (status && absorb(hash, view_t(), label, "info_hash", info, schedule + 1 + length));
	// Вырабатываем секрет расписания на общем значении
	status = (status && absorb(hash, shared, label, "secret", psk.key, secret));
	// Просмотр секрета расписания
	const view_t prk(secret, length);
	// Просмотр привязки расписания
	const view_t binding(schedule, 1 + (2 * length));
	// Если набор шифрует
	if(suite.aead != aead_t::EXPORT_ONLY){
		// Вырабатываем ключ шифра
		status = (status && unfold(hash, prk, label, "key", binding, this->_key, hpke::length(suite.aead)));
		// Вырабатываем начальное заполнение
		status = (status && unfold(hash, prk, label, "base_nonce", binding, this->_nonce, NONCE_SIZE));
	}
	// Вырабатываем секрет экспорта
	status = (status && unfold(hash, prk, label, "exp", binding, this->_exporter, length));
	// Если набор шифрует AES
	if(status && ((suite.aead == aead_t::AES_128_GCM) || (suite.aead == aead_t::AES_256_GCM)))
		// Разворачиваем ключ шифра
		status = this->_aes.key(view_t(this->_key, hpke::length(suite.aead)));
	// Стираем секрет расписания
	wipe(secret, sizeof(secret));
	// Стираем привязку расписания
	wipe(schedule, sizeof(schedule));
	// Если выработка не удалась
	if(!status){
		// Стираем состояние
		this->clear();
		// Выводим отказ набора
		return error_t::SUITE;
	}
	// Запоминаем набор
	this->_suite = suite;
	// Запоминаем сторону
	this->_sender = sender;
	// Устанавливаем признак готовности
	this->_ready = true;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод выработки начального заполнения сообщения
 *
 * @param result место под начальное заполнение длиной NONCE_SIZE
 *
 * @details Функция ComputeNonce раздела 5.2 RFC 9180: base_nonce XOR I2OSP(seq, Nn)
 *
 */
void nts::hpke::Context::mask(uint8_t * result) const noexcept {
	// Копируем начальное заполнение
	::memcpy(result, this->_nonce, NONCE_SIZE);
	/**
	 * Выполняем наложение порядкового номера на младшие восемь байтов
	 */
	for(size_t i = 0; i < sizeof(uint64_t); i++)
		// Накладываем байт номера старшим байтом вперёд
		result[NONCE_SIZE - 1 - i] ^= static_cast <uint8_t> (this->_sequence >> (8 * i));
}
/**
 * @brief Метод проверки готовности состояния
 *
 * @return признак того, что состояние установлено
 *
 */
bool nts::hpke::Context::ready() const noexcept {
	// Выводим признак готовности
	return this->_ready;
}
/**
 * @brief Метод извлечения набора алгоритмов
 *
 * @return набор алгоритмов состояния
 *
 */
const nts::hpke::suite_t & nts::hpke::Context::suite() const noexcept {
	// Выводим набор
	return this->_suite;
}
/**
 * @brief Метод извлечения порядкового номера следующего сообщения
 *
 * @return порядковый номер следующего сообщения
 *
 */
uint64_t nts::hpke::Context::sequence() const noexcept {
	// Выводим порядковый номер
	return this->_sequence;
}
/**
 * @brief Метод установки порядкового номера следующего сообщения
 *
 * @param sequence порядковый номер следующего сообщения
 * @return         причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::sequence(const uint64_t sequence) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Устанавливаем порядковый номер
	this->_sequence = sequence;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     открытый текст, вправе быть пустым
 * @param result     место под шифртекст с меткой подлинности длиной source.size + TAG_SIZE
 * @return           причина отказа либо NONE
 *
 * @details Функция ContextS.Seal раздела 5.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::seal(const view_t & associated, const view_t & source, uint8_t * result) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Если сторона не отправитель либо набор не шифрует
	if(!this->_sender || (this->_suite.aead == aead_t::EXPORT_ONLY))
		// Выводим отказ шифрования
		return error_t::AEAD;
	// Если места под итог нет либо просмотры заданы длиной без места
	if((result == nullptr) || ((source.size > 0) && (source.data == nullptr)) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Если порядковые номера исчерпаны
	if(this->_sequence == UINT64_MAX)
		// Выводим отказ порядкового номера
		return error_t::SEQUENCE;
	// Начальное заполнение сообщения
	uint8_t nonce[NONCE_SIZE];
	// Вырабатываем начальное заполнение
	this->mask(nonce);
	// Признак успешности зашифрования
	bool status = false;
	// Если набор шифрует ChaCha20-Poly1305
	if(this->_suite.aead == aead_t::CHACHA20_POLY1305){
		// Объект шифра
		cipher::chachapoly_t aead;
		// Заводим шифр на ключе и начальном заполнении
		status = aead.start(view_t(this->_key, hpke::length(this->_suite.aead)), view_t(nonce, sizeof(nonce)));
		// Зашифровываем сообщение
		status = (status && aead.encrypt(associated, source, result, result + source.size));
	// Если набор шифрует AES-GCM
	} else {
		// Объект режима
		cipher::gcm_t aead;
		// Заводим режим на развёрнутом ключе и начальном заполнении
		status = aead.start(cipher::block_t(this->_aes), view_t(nonce, sizeof(nonce)), TAG_SIZE);
		// Зашифровываем сообщение
		status = (status && aead.encrypt(associated, source, result, result + source.size));
	}
	// Стираем начальное заполнение
	wipe(nonce, sizeof(nonce));
	// Если зашифрование не удалось
	if(!status){
		// Стираем место под итог
		wipe(result, source.size + TAG_SIZE);
		// Выводим отказ шифрования
		return error_t::AEAD;
	}
	// Увеличиваем порядковый номер
	this->_sequence++;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод зашифрования сообщения в накопитель
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     открытый текст, вправе быть пустым
 * @param result     накопитель шифртекста с меткой подлинности
 * @return           причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::seal(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	/**
	 * Накопитель растёт под шифртекст с меткой: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под шифртекст с меткой
		result.resize(source.size + TAG_SIZE);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Зашифровываем сообщение в накопитель
	const error_t status = this->seal(associated, source, result.data());
	// Если зашифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог зашифрования
	return status;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
 * @param result     место под открытый текст длиной source.size - TAG_SIZE
 * @return           причина отказа либо NONE
 *
 * @details Функция ContextR.Open раздела 5.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::open(const view_t & associated, const view_t & source, uint8_t * result) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Если сторона не получатель либо набор не шифрует
	if(this->_sender || (this->_suite.aead == aead_t::EXPORT_ONLY))
		// Выводим отказ шифрования
		return error_t::AEAD;
	// Если шифртекст короче метки либо просмотры заданы длиной без места
	if((source.data == nullptr) || (source.size < TAG_SIZE) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Длина открытого текста
	const size_t size = (source.size - TAG_SIZE);
	// Если места под открытый текст нет
	if((size > 0) && (result == nullptr))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Если порядковые номера исчерпаны
	if(this->_sequence == UINT64_MAX)
		// Выводим отказ порядкового номера
		return error_t::SEQUENCE;
	// Начальное заполнение сообщения
	uint8_t nonce[NONCE_SIZE];
	// Вырабатываем начальное заполнение
	this->mask(nonce);
	// Просмотр шифртекста без метки
	const view_t sealed(source.data, size);
	// Просмотр метки подлинности
	const view_t tag(source.data + size, TAG_SIZE);
	// Признак успешности расшифрования
	bool status = false;
	// Если набор шифрует ChaCha20-Poly1305
	if(this->_suite.aead == aead_t::CHACHA20_POLY1305){
		// Объект шифра
		cipher::chachapoly_t aead;
		// Заводим шифр на ключе и начальном заполнении
		status = aead.start(view_t(this->_key, hpke::length(this->_suite.aead)), view_t(nonce, sizeof(nonce)));
		// Расшифровываем сообщение
		status = (status && aead.decrypt(associated, sealed, result, tag));
	// Если набор шифрует AES-GCM
	} else {
		// Объект режима
		cipher::gcm_t aead;
		// Заводим режим на развёрнутом ключе и начальном заполнении
		status = aead.start(cipher::block_t(this->_aes), view_t(nonce, sizeof(nonce)), TAG_SIZE);
		// Расшифровываем сообщение
		status = (status && aead.decrypt(associated, sealed, result, tag));
	}
	// Стираем начальное заполнение
	wipe(nonce, sizeof(nonce));
	// Если подлинность не сошлась
	if(!status){
		// Стираем место под открытый текст
		wipe(result, size);
		// Выводим отказ подлинности
		return error_t::OPEN;
	}
	// Увеличиваем порядковый номер
	this->_sequence++;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод расшифрования сообщения в накопитель
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
 * @param result     накопитель открытого текста
 * @return           причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::open(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	// Если шифртекст короче метки
	if((source.data == nullptr) || (source.size < TAG_SIZE))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	/**
	 * Накопитель растёт под открытый текст: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под открытый текст
		result.resize(source.size - TAG_SIZE);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Расшифровываем сообщение в накопитель
	const error_t status = this->open(associated, source, result.data());
	// Если расшифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог расшифрования
	return status;
}
/**
 * @brief Метод выработки секрета экспорта
 *
 * @param context привязка секрета, вправе быть пустой
 * @param result  место под секрет
 * @param size    длина секрета в байтах, не больше 255 длин хеша функции выработки ключа
 * @return        причина отказа либо NONE
 *
 * @details Функция Context.Export раздела 5.3 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::exporter(const view_t & context, uint8_t * result, const size_t size) const noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Длина хеша функции выработки ключа
	const size_t length = hpke::length(this->_suite.kdf);
	// Если длина секрета недопустима
	if((size == 0) || (size > (255 * length)))
		// Выводим отказ длины
		return error_t::LENGTH;
	// Если места под секрет нет либо привязка задана длиной без места
	if((result == nullptr) || ((context.size > 0) && (context.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Опознаватель набора
	uint8_t identifier[SUITE_STAMP];
	// Составляем опознаватель набора
	stamp(this->_suite, identifier);
	// Растягиваем секрет экспорта
	if(!unfold(hashing(this->_suite.kdf), view_t(this->_exporter, length), view_t(identifier, sizeof(identifier)), "sec", context, result, size)){
		// Стираем место под секрет
		wipe(result, size);
		// Выводим отказ набора
		return error_t::SUITE;
	}
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод стирания состояния
 *
 */
void nts::hpke::Context::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем сторону
	this->_sender = false;
	// Сбрасываем набор
	this->_suite = suite_t();
	// Сбрасываем порядковый номер
	this->_sequence = 0;
	// Стираем ключ шифра
	wipe(this->_key, sizeof(this->_key));
	// Стираем начальное заполнение
	wipe(this->_nonce, sizeof(this->_nonce));
	// Стираем секрет экспорта
	wipe(this->_exporter, sizeof(this->_exporter));
	// Стираем развёрнутый ключ шифра
	this->_aes.clear();
}
/**
 * @brief Конструктор пустого состояния
 *
 */
nts::hpke::Context::Context() noexcept : _ready(false), _sender(false), _suite(), _sequence(0) {
	// Обнуляем ключ шифра
	::memset(this->_key, 0, sizeof(this->_key));
	// Обнуляем начальное заполнение
	::memset(this->_nonce, 0, sizeof(this->_nonce));
	// Обнуляем секрет экспорта
	::memset(this->_exporter, 0, sizeof(this->_exporter));
}
/**
 * @brief Деструктор: стирает ключи
 *
 */
nts::hpke::Context::~Context() noexcept {
	// Стираем состояние
	this->clear();
}
/**
 * @brief Метод инкапсуляции ключа
 *
 * @param ephemeral     мимолётная пара ключей отправителя
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param authenticator пара ключей отправителя для подлинности либо nullptr
 * @param shared        место под общее значение длиной X25519_SIZE
 * @param result        место под инкапсулированный ключ длиной X25519_SIZE
 * @return              причина отказа либо NONE
 *
 * @details Функции Encap и AuthEncap раздела 7.1.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::encapsulate(const key_t & ephemeral, const view_t & point, const key_t * authenticator, uint8_t * shared, uint8_t * result) noexcept {
	// Если мимолётная пара не готова
	if(!ephemeral.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Если пара отправителя задана и не готова
	if((authenticator != nullptr) && (!authenticator->ready() || (authenticator->kem() != ephemeral.kem())))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если открытый ключ получателя записан неверной длиной
	if((point.data == nullptr) || (point.size != X25519_SIZE))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под итог нет
	if((shared == nullptr) || (result == nullptr))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Общие значения Диффи-Хеллмана: мимолётное и отправителя
	uint8_t dh[2 * X25519_SIZE];
	// Вырабатываем мимолётное общее значение
	if(!agreement::x25519(ephemeral.secret(), point, dh)){
		// Стираем общие значения
		wipe(dh, sizeof(dh));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Если подлинность отправителя требуется
	if((authenticator != nullptr) && !agreement::x25519(authenticator->secret(), point, dh + X25519_SIZE)){
		// Стираем общие значения
		wipe(dh, sizeof(dh));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Привязка способа инкапсуляции: инкапсулированный ключ, ключ получателя, ключ отправителя
	uint8_t binding[BINDING_SIZE];
	// Записываем инкапсулированный ключ
	::memcpy(binding, ephemeral.point().data, X25519_SIZE);
	// Записываем ключ получателя
	::memcpy(binding + X25519_SIZE, point.data, X25519_SIZE);
	// Если подлинность отправителя требуется
	if(authenticator != nullptr)
		// Записываем ключ отправителя
		::memcpy(binding + (2 * X25519_SIZE), authenticator->point().data, X25519_SIZE);
	// Длина занятой части общих значений
	const size_t width = ((authenticator != nullptr) ? (2 * X25519_SIZE) : X25519_SIZE);
	// Вырабатываем общее значение
	const bool status = combine(view_t(dh, width), view_t(binding, X25519_SIZE + width), shared);
	// Стираем общие значения
	wipe(dh, sizeof(dh));
	// Если выработка не удалась
	if(!status){
		// Стираем место под общее значение
		wipe(shared, X25519_SIZE);
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Копируем инкапсулированный ключ
	::memcpy(result, ephemeral.point().data, X25519_SIZE);
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод декапсуляции ключа
 *
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param authenticator открытый ключ отправителя для подлинности либо пустой просмотр
 * @param shared        место под общее значение длиной X25519_SIZE
 * @return              причина отказа либо NONE
 *
 * @details Функции Decap и AuthDecap раздела 7.1.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::decapsulate(const key_t & own, const view_t & enc, const view_t & authenticator, uint8_t * shared) noexcept {
	// Если пара получателя не готова
	if(!own.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Если инкапсулированный ключ записан неверной длиной
	if((enc.data == nullptr) || (enc.size != X25519_SIZE))
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	// Признак подлинности отправителя
	const bool authenticated = (authenticator.size > 0);
	// Если открытый ключ отправителя записан неверной длиной
	if(authenticated && ((authenticator.data == nullptr) || (authenticator.size != X25519_SIZE)))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под итог нет
	if(shared == nullptr)
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Общие значения Диффи-Хеллмана: мимолётное и отправителя
	uint8_t dh[2 * X25519_SIZE];
	// Вырабатываем мимолётное общее значение
	if(!agreement::x25519(own.secret(), enc, dh)){
		// Стираем общие значения
		wipe(dh, sizeof(dh));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Если подлинность отправителя требуется
	if(authenticated && !agreement::x25519(own.secret(), authenticator, dh + X25519_SIZE)){
		// Стираем общие значения
		wipe(dh, sizeof(dh));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Привязка способа инкапсуляции: инкапсулированный ключ, ключ получателя, ключ отправителя
	uint8_t binding[BINDING_SIZE];
	// Записываем инкапсулированный ключ
	::memcpy(binding, enc.data, X25519_SIZE);
	// Записываем ключ получателя
	::memcpy(binding + X25519_SIZE, own.point().data, X25519_SIZE);
	// Если подлинность отправителя требуется
	if(authenticated)
		// Записываем ключ отправителя
		::memcpy(binding + (2 * X25519_SIZE), authenticator.data, X25519_SIZE);
	// Длина занятой части общих значений
	const size_t width = (authenticated ? (2 * X25519_SIZE) : X25519_SIZE);
	// Вырабатываем общее значение
	const bool status = combine(view_t(dh, width), view_t(binding, X25519_SIZE + width), shared);
	// Стираем общие значения
	wipe(dh, sizeof(dh));
	// Если выработка не удалась
	if(!status){
		// Стираем место под общее значение
		wipe(shared, X25519_SIZE);
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод установки состояния отправителя по заданной мимолётной паре
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
 * @param ephemeral     мимолётная пара ключей отправителя
 * @param enc           место под инкапсулированный ключ длиной X25519_SIZE
 * @param context       состояние связи отправителя
 * @return              причина отказа либо NONE
 *
 * @details Функции SetupBaseS, SetupPSKS, SetupAuthS и SetupAuthPSKS раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const key_t & ephemeral, uint8_t * enc, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Если наличие пары отправителя не отвечает режиму
	if((authenticator != nullptr) != authenticated(mode))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если мимолётная пара не отвечает набору
	if(!ephemeral.ready() || (ephemeral.kem() != suite.kem))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под инкапсулированный ключ нет
	if(enc == nullptr)
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Общее значение способа инкапсуляции
	uint8_t shared[SECRET_SIZE];
	// Инкапсулируем ключ
	error_t status = encapsulate(ephemeral, point, authenticator, shared, enc);
	// Если инкапсуляция удалась
	if(status == error_t::NONE)
		// Устанавливаем состояние отправителя
		status = context.setup(suite, mode, view_t(shared, sizeof(shared)), info, psk, true);
	// Стираем общее значение
	wipe(shared, sizeof(shared));
	// Если установка не удалась
	if(status != error_t::NONE)
		// Стираем инкапсулированный ключ
		wipe(enc, X25519_SIZE);
	// Выводим итог установки
	return status;
}
/**
 * @brief Метод установки состояния отправителя
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
 * @param enc           место под инкапсулированный ключ длиной X25519_SIZE
 * @param context       состояние связи отправителя
 * @return              причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, uint8_t * enc, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Мимолётная пара ключей
	key_t ephemeral;
	// Вырабатываем мимолётную пару
	const error_t status = ephemeral.generate(suite.kem);
	// Если выработка не удалась
	if(status != error_t::NONE)
		// Выводим отказ выработки
		return status;
	// Выводим итог установки по мимолётной паре
	return sender(suite, mode, point, info, psk, authenticator, ephemeral, enc, context);
}
/**
 * @brief Метод установки состояния получателя
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator открытый ключ отправителя: задан в режимах AUTH и AUTH_PSK, иначе пустой просмотр
 * @param context       состояние связи получателя
 * @return              причина отказа либо NONE
 *
 * @details Функции SetupBaseR, SetupPSKR, SetupAuthR и SetupAuthPSKR раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::recipient(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Если наличие ключа отправителя не отвечает режиму
	if((authenticator.size > 0) != authenticated(mode))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если пара получателя не отвечает набору
	if(!own.ready() || (own.kem() != suite.kem))
		// Выводим отказ ключа
		return error_t::KEY;
	// Общее значение способа инкапсуляции
	uint8_t shared[SECRET_SIZE];
	// Декапсулируем ключ
	error_t status = decapsulate(own, enc, authenticator, shared);
	// Если декапсуляция удалась
	if(status == error_t::NONE)
		// Устанавливаем состояние получателя
		status = context.setup(suite, mode, view_t(shared, sizeof(shared)), info, psk, false);
	// Стираем общее значение
	wipe(shared, sizeof(shared));
	// Выводим итог установки
	return status;
}
/**
 * @brief Метод зашифрования одного сообщения
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator пара ключей отправителя по режиму либо nullptr
 * @param associated    связанные данные, вправе быть пустыми
 * @param source        открытый текст, вправе быть пустым
 * @param enc           накопитель инкапсулированного ключа
 * @param result        накопитель шифртекста с меткой подлинности
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка Seal раздела 6.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::seal(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель шифртекста
	result.clear();
	/**
	 * Накопитель растёт под инкапсулированный ключ: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под инкапсулированный ключ
		enc.resize(X25519_SIZE);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель
		enc.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Состояние отправителя
	context_t context;
	// Устанавливаем состояние отправителя
	error_t status = sender(suite, mode, point, info, psk, authenticator, enc.data(), context);
	// Если состояние установлено
	if(status == error_t::NONE)
		// Зашифровываем сообщение
		status = context.seal(associated, source, result);
	// Если зашифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
	// Выводим итог зашифрования
	return status;
}
/**
 * @brief Метод расшифрования одного сообщения
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
 * @param associated    связанные данные, вправе быть пустыми
 * @param source        шифртекст с меткой подлинности
 * @param result        накопитель открытого текста
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка Open раздела 6.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::open(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель открытого текста
	result.clear();
	// Состояние получателя
	context_t context;
	// Устанавливаем состояние получателя
	const error_t status = recipient(suite, mode, own, enc, info, psk, authenticator, context);
	// Если состояние не установлено
	if(status != error_t::NONE)
		// Выводим отказ установки
		return status;
	// Выводим итог расшифрования
	return context.open(associated, source, result);
}
/**
 * @brief Метод выработки секрета экспорта отправителем за один шаг
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator пара ключей отправителя по режиму либо nullptr
 * @param context       привязка секрета, вправе быть пустой
 * @param size          длина секрета в байтах
 * @param enc           накопитель инкапсулированного ключа
 * @param result        накопитель секрета
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка SendExport раздела 6.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::dispatch(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & context, const size_t size, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель секрета
	result.clear();
	/**
	 * Накопители растут под инкапсулированный ключ и секрет: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под инкапсулированный ключ
		enc.resize(X25519_SIZE);
		// Отводим место под секрет
		result.resize(size);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
		// Очищаем накопитель секрета
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Состояние отправителя
	context_t state;
	// Устанавливаем состояние отправителя
	error_t status = sender(suite, mode, point, info, psk, authenticator, enc.data(), state);
	// Если состояние установлено
	if(status == error_t::NONE)
		// Вырабатываем секрет экспорта
		status = state.exporter(context, result.data(), size);
	// Если выработка не удалась
	if(status != error_t::NONE){
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
		// Очищаем накопитель секрета
		result.clear();
	}
	// Выводим итог выработки
	return status;
}
/**
 * @brief Метод выработки секрета экспорта получателем за один шаг
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
 * @param context       привязка секрета, вправе быть пустой
 * @param size          длина секрета в байтах
 * @param result        накопитель секрета
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка ReceiveExport раздела 6.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::receive(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & context, const size_t size, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель секрета
	result.clear();
	// Состояние получателя
	context_t state;
	// Устанавливаем состояние получателя
	error_t status = recipient(suite, mode, own, enc, info, psk, authenticator, state);
	// Если состояние не установлено
	if(status != error_t::NONE)
		// Выводим отказ установки
		return status;
	/**
	 * Накопитель растёт под секрет: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под секрет
		result.resize(size);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Вырабатываем секрет экспорта
	status = state.exporter(context, result.data(), size);
	// Если выработка не удалась
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог выработки
	return status;
}
