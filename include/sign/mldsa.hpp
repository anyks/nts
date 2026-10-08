/**
 * @file mldsa.hpp
 * @date 2026-10-03
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи
 *        ML-DSA (модуль решёточной подписи) по FIPS 204
 *
 * \~english
 * @brief Header file of the module of the production and the check of the
 *        electronic signature ML-DSA (lattice signature module) according to FIPS 204
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
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей электронной подписи
	 *
	 * \~english
	 * @brief Namespace of the electronic signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Электронная подпись ML-DSA по FIPS 204
		 *
		 * @details Кольцо Z_q[X]/(X^256 + 1) при q = 2^23 − 2^13 + 1 = 8 380 417.
		 *          Ключ подписи - запись стандарта: ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0;
		 *          ключ проверки - запись ρ ‖ t1. Подпись - c~ ‖ z ‖ h:
		 *          зерно вызова, ответ по маске и подсказка старших разрядов.
		 *          Подписывается сообщение с обвязкой 0x00 ‖ длина контекста ‖
		 *          контекст ‖ сообщение; контекст в TLS пустой.
		 *
		 * @note Выработка подписи идёт за постоянное время по ключу в части
		 *       секретных значений; проверка подписи секретов не касается и
		 *       вправе идти переменным временем
		 *
		 * \~english
		 * @brief Electronic signature ML-DSA according to FIPS 204
		 * @details The ring Z_q[X]/(X^256 + 1) at q = 2^23 − 2^13 + 1 = 8 380 417.
		 *          The key of the signature is a record of the standard: ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0;
		 *          the key of the check is a record ρ ‖ t1. The signature is c~ ‖ z ‖ h:
		 *          the challenge seed, the answer under the mask and the hint of the senior bits.
		 *          The message is signed with the wrapper 0x00 ‖ length of the context ‖
		 *          context ‖ message; the context in TLS is empty.
		 * @note The production of the signature goes in a constant time by the key in the part
		 *       of secret values; the check of the signature touches no secrets and may go
		 *       in a variable time
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Mldsa {
			public:
				/**
				 * \~russian
				 * @brief Наборы параметров стандарта
				 *
				 * \~english
				 * @brief Parameter sets of the standard
				 *
				 * \~
				 */
				enum class set_t : uint8_t {
					// Признак того, что набор не установлен
					NONE = 0x00,
					// ML-DSA-44: k = 4, l = 4, η = 2, τ = 39, β = 78, γ1 = 2^17, γ2 = (q − 1)/88, ω = 80
					DSA44 = 0x01,
					// ML-DSA-65: k = 6, l = 5, η = 4, τ = 49, β = 196, γ1 = 2^19, γ2 = (q − 1)/32, ω = 55
					DSA65 = 0x02,
					// ML-DSA-87: k = 8, l = 7, η = 2, τ = 60, β = 120, γ1 = 2^19, γ2 = (q − 1)/32, ω = 75
					DSA87 = 0x03
				};
				/**
				 * \~russian
				 * @brief Размер зерна выработки ключа и случайности подписи в байтах
				 *
				 * \~english
				 * @brief Size of the seed of the key generation and of the randomness of the signature in bytes
				 *
				 * \~
				 */
				static constexpr size_t SEED_SIZE = 32;
			private:
				// Набор параметров ключа
				set_t _set;
				// Признак того, что ключ подписи установлен
				bool _secret;
				// Признак того, что ключ проверки подписи установлен
				bool _public;
				// Запись ключа подписи по набору: наибольшая 4 896 байтов у ML-DSA-87
				uint8_t _key[4896];
				// Запись ключа проверки подписи по набору: наибольшая 2 592 байта у ML-DSA-87
				uint8_t _pkey[2592];
			public:
				/**
				 * \~russian
				 * @brief Метод получения набора параметров ключа
				 *
				 * @return набор параметров ключа, NONE без ключа
				 *
				 * \~english
				 * @brief Method of getting the parameter set of the key
				 * @return the parameter set of the key, NONE without a key
				 *
				 * \~
				 */
				set_t set() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера подписи
				 *
				 * @return размер подписи в байтах, ноль без ключа
				 *
				 * \~english
				 * @brief Method of getting the size of a signature
				 * @return the size of a signature in bytes, zero without a key
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения верхнего предела длины подписи в записанном виде
				 *
				 * @return верхний предел длины подписи в байтах, ноль без ключа
				 *
				 * @details Подпись уходит наружу записью стандарта c~ ‖ z ‖ h, длина которой
				 *          постоянна по набору, оттого предел равен size, но обращается в
				 *          ноль, пока ни ключ подписи, ни ключ проверки не установлены
				 *
				 * \~english
				 * @brief Method of getting the upper limit of the length of a signature in the written form
				 * @return the upper limit of the length of a signature in bytes, zero without a key
				 * @details The signature goes outside as a record of the standard c~ ‖ z ‖ h whose
				 *          length is constant per set, therefore the limit equals size, but turns into
				 *          a zero while neither the key of the signature nor the key of the check is set
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния модуля
				 *
				 * \~english
				 * @brief Method of the reset of the state of the module
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод получения размера ключа подписи набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер ключа подписи в байтах, ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the secret key of a set in bytes
				 * @param set the parameter set
				 * @return    the size of the secret key in bytes, zero for a nonexistent set
				 *
				 * \~
				 */
				static size_t secretSize(const set_t set) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера ключа проверки набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер ключа проверки в байтах, ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of the public key of a set in bytes
				 * @param set the parameter set
				 * @return    the size of the public key in bytes, zero for a nonexistent set
				 *
				 * \~
				 */
				static size_t publicSize(const set_t set) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера подписи набора в байтах
				 *
				 * @param set набор параметров
				 *
				 * @return    размер подписи в байтах, ноль у несуществующего набора
				 *
				 * \~english
				 * @brief Method of getting the size of a signature of a set in bytes
				 * @param set the parameter set
				 * @return    the size of a signature in bytes, zero for a nonexistent set
				 *
				 * \~
				 */
				static size_t signatureSize(const set_t set) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод порождения долговременного ключа подписи из зерна
				 *
				 * @param set    набор параметров
				 * @param seed   зерно выработки ξ длиной в тридцать два байта
				 * @param key    место, в которое помещается ключ проверки ρ ‖ t1
				 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
				 *
				 * @return       признак успешности порождения ключа
				 *
				 * @details Раздел 6.1 FIPS 204: расширение ключа из зерна без всякой
				 *          случайности - на одном зерне выходит один и тот же ключ
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature from a seed
				 * @param set    the parameter set
				 * @param seed   the generation seed ξ of a length of thirty two bytes
				 * @param key    the place the key of the check ρ ‖ t1 is put into
				 * @param secret the place the key of the signature ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 is put into
				 * @return       the flag of the success of the key generation
				 * @details Section 6.1 of FIPS 204: the expansion of the key from a seed without
				 *          any randomness - the same seed gives the same key
				 *
				 * \~
				 */
				bool generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод порождения долговременного ключа подписи из источника случайности
				 *
				 * @param set    набор параметров
				 * @param key    место, в которое помещается ключ проверки ρ ‖ t1
				 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
				 *
				 * @return       признак успешности порождения ключа
				 *
				 * @details Зерно ξ берётся из источника случайности целиком; отказ источника
				 *          отвечает отказом порождения, прежнее состояние модуля при этом сброшено
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature from the source of randomness
				 * @param set    the parameter set
				 * @param key    the place the key of the check ρ ‖ t1 is put into
				 * @param secret the place the key of the signature ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 is put into
				 * @return       the flag of the success of the key generation
				 * @details The seed ξ is taken from the source of randomness entirely; a refusal of the
				 *          source answers by a refusal of the generation, the former state of the module
				 *          is reset at that
				 *
				 * \~
				 */
				bool generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа подписи
				 *
				 * @param set    набор параметров ключа
				 * @param secret запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 по набору
				 *
				 * @return       признак успешности установки ключа подписи
				 *
				 * @details Ключ проверки выводится из записи ключа подписи сразу же: раздел 6.1
				 *          вычисляется заново из ρ и сличается с t1 внутри записи, при
				 *          несовпадении ключ отвергается
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 * @param set    the parameter set of the key
				 * @param secret the record of the key of the signature ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 per set
				 * @return       the flag of the success of the setting of the key of the signature
				 * @details The key of the check is derived from the record of the key of the signature at once:
				 *          section 6.1 is computed anew from ρ and collated with t1 inside the record,
				 *          at a mismatch the key is rejected
				 *
				 * \~
				 */
				bool secret(const set_t set, const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа проверки подписи
				 *
				 * @param set набор параметров ключа
				 * @param key запись ключа проверки ρ ‖ t1 по набору
				 *
				 * @return    признак успешности установки ключа проверки подписи
				 *
				 * @note Если ключ подписи уже установлен, открытый ключ из него выведен:
				 *       поданный обязан сойтись с выведенным, тогда состояние не меняется,
				 *       а чужой отвергается. Закрытый ключ этим вызовом не затирается
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 * @param set the parameter set of the key
				 * @param key the record of the key of the check ρ ‖ t1 per set
				 * @return    the flag of the success of the setting of the key of the check
				 * @note If the signing key is already set, the public key is derived from it: the given one
				 *       must coincide with the derived one, then the state does not change, and a foreign one
				 *       is rejected. The private key is not wiped by this call
				 *
				 * \~
				 */
				bool key(const set_t set, const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ключа проверки подписи
				 *
				 * @param result место, в которое записывается ключ проверки ρ ‖ t1 по набору
				 * @param size   размер места, не меньше размера ключа проверки набора
				 *
				 * @return       признак успешности получения ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of getting the key of the check of the signature
				 * @param result the place the key of the check ρ ‖ t1 per set is written into
				 * @param size   the size of the place, not less than the size of the public key of the set
				 * @return       the flag of the success of the getting of the key of the check
				 *
				 * \~
				 */
				bool key(uint8_t * result, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи со случайностью от источника
				 *
				 * @param message подписываемое сообщение целиком
				 * @param context контекст подписи, до 255 байтов, в TLS пустой
				 * @param result  место, в которое помещается подпись c~ ‖ z ‖ h по набору
				 *
				 * @return        признак успешности выработки подписи
				 *
				 * @details Раздел 6.2 FIPS 204: случайность rnd берётся из источника целиком,
				 *          оттого повтор выработки на одном ключе и сообщении даёт разные
				 *          подписи (хеджированная подпись)
				 *
				 * \~english
				 * @brief Method of the production of a signature with randomness from the source
				 * @param message the message being signed as a whole
				 * @param context the context of the signature, up to 255 bytes, empty in TLS
				 * @param result  the place the signature c~ ‖ z ‖ h per set is put into
				 * @return        the flag of the success of the production of the signature
				 * @details Section 6.2 of FIPS 204: the randomness rnd is taken from the source
				 *          entirely, therefore a repetition of the production on a single key and
				 *          message gives different signatures (hedged signature)
				 *
				 * \~
				 */
				bool make(const view_t & message, const view_t & context, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки подписи с заданной случайностью
				 *
				 * @param rnd     случайность подписи длиной в тридцать два байта
				 * @param message подписываемое сообщение целиком
				 * @param context контекст подписи, до 255 байтов, в TLS пустой
				 * @param result  место, в которое помещается подпись c~ ‖ z ‖ h по набору
				 *
				 * @return        признак успешности выработки подписи
				 *
				 * @details Раздел 6.2 FIPS 204: случайность rnd подаётся извне, оттого на одних
				 *          rnd, ключе и сообщении выходит одна и та же подпись; тридцать два
				 *          нулевых байта дают детерминированный вариант примечания стандарта
				 *
				 * \~english
				 * @brief Method of the production of a signature with a given randomness
				 * @param rnd     the randomness of the signature of a length of thirty two bytes
				 * @param message the message being signed as a whole
				 * @param context the context of the signature, up to 255 bytes, empty in TLS
				 * @param result  the place the signature c~ ‖ z ‖ h per set is put into
				 * @return        the flag of the success of the production of the signature
				 * @details Section 6.2 of FIPS 204: the randomness rnd is given from the outside,
				 *          therefore on the same rnd, key and message the same signature comes out;
				 *          thirty two zero bytes give the deterministic variant of the note of the standard
				 *
				 * \~
				 */
				bool make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param message   подписанное сообщение целиком
				 * @param context   контекст подписи, до 255 байтов, в TLS пустой
				 * @param signature проверяемая подпись c~ ‖ z ‖ h по набору
				 *
				 * @return          признак того, что подпись сошлась
				 *
				 * @details Раздел 6.3 FIPS 204: ответ z за границей γ1 − β, лишний вес
				 *          подсказки и зерно вызова, не сошедшееся с пересчитанным,
				 *          отвергаются
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 * @param message   the signed message as a whole
				 * @param context   the context of the signature, up to 255 bytes, empty in TLS
				 * @param signature the signature being checked c~ ‖ z ‖ h per set
				 * @return          the flag of the signature having converged
				 * @details Section 6.3 of FIPS 204: the answer z beyond the bound γ1 − β, an excess
				 *          weight of the hint and the challenge seed not converging with the
				 *          recomputed one are rejected
				 *
				 * \~
				 */
				bool check(const view_t & message, const view_t & context, const view_t & signature) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Mldsa() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Mldsa() noexcept;
		} mldsa_t;
	};
};

