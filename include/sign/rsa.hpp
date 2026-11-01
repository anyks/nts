/**
 * @file rsa.hpp
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
 * \~russian
 * @brief Заголовочный файл модуля RSA — порождение ключей, подпись, проверка,
 *        шифрование и расшифрование по PKCS #1 v2.2 (RFC 8017)
 *
 * \~english
 * @brief Header file of the RSA module — the generation of the keys, the signature,
 *        the verification, the encryption and the decryption according to PKCS #1 v2.2
 *        (RFC 8017)
 *
 * \~
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
#include <vector>
#include <cstdint>
#include <cstddef>
#include <atomic>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/integer.hpp>
#include <digest/hash.hpp>

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
	 * @brief Namespace of the digital signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Схема дополнения RSA
		 *
		 * @details Подпись ведётся по схемам PKCS1 (RSASSA-PKCS1-v1_5) и PSS
		 *          (RSASSA-PSS), шифрование - по схемам PKCS1 (RSAES-PKCS1-v1_5)
		 *          и OAEP (RSAES-OAEP); разделы 7 и 8 RFC 8017
		 *
		 * \~english
		 * @brief Padding scheme of RSA
		 *
		 * @details The signature is carried by the schemes PKCS1 (RSASSA-PKCS1-v1_5) and PSS
		 *          (RSASSA-PSS), the encryption - by the schemes PKCS1 (RSAES-PKCS1-v1_5)
		 *          and OAEP (RSAES-OAEP); the sections 7 and 8 of RFC 8017
		 *
		 * \~
		 */
		enum class scheme_t : uint8_t {
			// Схема не установлена
			NONE  = 0x00, /*!< \~russian Схема не установлена \~english The scheme is not set \~ */
			// Дополнение PKCS #1 v1.5
			PKCS1 = 0x01, /*!< \~russian Дополнение PKCS #1 v1.5 \~english Padding PKCS #1 v1.5 \~ */
			// Вероятностная схема подписи PSS
			PSS   = 0x02, /*!< \~russian Вероятностная схема подписи PSS \~english Probabilistic signature scheme PSS \~ */
			// Оптимальное асимметричное дополнение OAEP
			OAEP  = 0x03  /*!< \~russian Оптимальное асимметричное дополнение OAEP \~english Optimal asymmetric encryption padding OAEP \~ */
		};

		/**
		 * \~russian
		 * @brief Составляющая ключа RSA
		 *
		 * @details Имена отвечают полям RSAPrivateKey приложения A.1.2 RFC 8017
		 *
		 * \~english
		 * @brief Component of the RSA key
		 *
		 * @details The names correspond to the fields of RSAPrivateKey of the appendix A.1.2 of RFC 8017
		 *
		 * \~
		 */
		enum class part_t : uint8_t {
			// Модуль n
			MODULUS     = 0x00, /*!< \~russian Модуль n \~english Modulus n \~ */
			// Открытый показатель e
			PUBLIC      = 0x01, /*!< \~russian Открытый показатель e \~english Public exponent e \~ */
			// Секретный показатель d
			SECRET      = 0x02, /*!< \~russian Секретный показатель d \~english Private exponent d \~ */
			// Первый простой сомножитель p
			PRIME1      = 0x03, /*!< \~russian Первый простой сомножитель p \~english First prime factor p \~ */
			// Второй простой сомножитель q
			PRIME2      = 0x04, /*!< \~russian Второй простой сомножитель q \~english Second prime factor q \~ */
			// Показатель dP = d mod (p - 1)
			EXPONENT1   = 0x05, /*!< \~russian Показатель dP = d mod (p - 1) \~english Exponent dP = d mod (p - 1) \~ */
			// Показатель dQ = d mod (q - 1)
			EXPONENT2   = 0x06, /*!< \~russian Показатель dQ = d mod (q - 1) \~english Exponent dQ = d mod (q - 1) \~ */
			// Коэффициент qInv = q^-1 mod p
			COEFFICIENT = 0x07  /*!< \~russian Коэффициент qInv = q^-1 mod p \~english Coefficient qInv = q^-1 mod p \~ */
		};

		/**
		 * \~russian
		 * @brief RSA по PKCS #1 v2.2
		 *
		 * @details Ключ либо порождается, либо устанавливается составляющими, либо
		 *          разбирается из записи DER. Секретные действия ведутся по китайской
		 *          теореме об остатках с ослеплением случайным числом; возведение в
		 *          секретную степень идёт за постоянное время относительно показателя.
		 *          Расшифрование PKCS #1 v1.5 разбирает дополнение без ранних выходов
		 *          по содержимому: ни время, ни ход исполнения от содержимого не зависят
		 *
		 * @note Памяти криптография не выделяет и исключений не возбуждает: выделяет
		 *       лишь запись ключа в DER, где нехватка памяти отдаётся отказом.
		 *       Секретные составляющие затираются при сбросе и уничтожении объекта.
		 *       Пара ослепления секретного действия хранится в объекте и обновляется
		 *       квадратами, свежая - каждые тридцать два действия. Пару забирает
		 *       атомарный признак занятости без ожидания: секретное действие, заставшее
		 *       пару занятой другим потоком, берёт свежее ослепление на стеке, оттого
		 *       один объект ключа служит нескольким потокам разом без отказов и без
		 *       замка, а одновременные вызовы платят лишь ценой свежего ослепления
		 *
		 * \~english
		 * @brief RSA according to PKCS #1 v2.2
		 *
		 * @details The key is either generated, or set by the components, or parsed from a DER
		 *          record. The secret operations are carried by the Chinese remainder theorem with
		 *          a blinding by a random number; the raise into the secret power goes in a constant
		 *          time relative to the exponent. The decryption of PKCS #1 v1.5 parses the padding
		 *          without early exits by the content: neither the time nor the flow of the execution
		 *          depend on the content
		 *
		 * @note The cryptography does not allocate memory and raises no exceptions: only the writing
		 *       of the key into DER allocates, where the lack of memory is given as a refusal. The
		 *       secret components are wiped at the reset and at the destruction of the object. The
		 *       blinding pair of the secret operation is kept in the object and updated by squaring,
		 *       a fresh one every thirty-two operations. The pair is taken by an atomic busy flag
		 *       without waiting: a secret operation that finds the pair busy by another thread takes
		 *       a fresh blinding on the stack, hence one key object serves several threads at once
		 *       without refusals and without a lock, and the simultaneous calls pay only the price
		 *       of the fresh blinding
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Rsa {
			private:
				// Признак того, что открытый ключ установлен
				bool _public;
				// Признак того, что секретный ключ установлен
				bool _secret;
			private:
				// Число разрядов модуля
				size_t _bits;
			private:
				// Модуль n
				math::integer_t _modulus;
				// Открытый показатель e
				math::integer_t _exponent;
				// Секретный показатель d
				math::integer_t _decryptor;
				// Первый простой сомножитель p
				math::integer_t _prime1;
				// Второй простой сомножитель q
				math::integer_t _prime2;
				// Показатель dP
				math::integer_t _exponent1;
				// Показатель dQ
				math::integer_t _exponent2;
				// Коэффициент qInv
				math::integer_t _coefficient;
			private:
				// Арифметика Монтгомери по модулю n
				math::montgomery_t _field;
				// Арифметика Монтгомери по сомножителю p
				math::montgomery_t _field1;
				// Арифметика Монтгомери по сомножителю q
				math::montgomery_t _field2;
				// Коэффициент qInv в области Монтгомери по p
				math::integer_t _reverse;
			private:
				// Сохранённая пара ослепления по сомножителям в области Монтгомери: r^e и r^-1 по p и по q, обновляемые квадратами на каждом действии
				mutable math::integer_t _raised1;
				// Обратное значение ослепления по первому сомножителю в области Монтгомери
				mutable math::integer_t _inverse1;
				// Ослепление по второму сомножителю в области Монтгомери
				mutable math::integer_t _raised2;
				// Обратное значение ослепления по второму сомножителю в области Монтгомери
				mutable math::integer_t _inverse2;
				// Число секретных действий с сохранённой парой: нулевое требует свежей пары
				mutable size_t _uses;
				// Признак занятости сохранённой пары: забирается без ожидания, заставший её занятой берёт свежее ослепление на стеке
				mutable std::atomic <bool> _busy;
			private:
				/**
				 * \~russian
				 * @brief Метод предвычислений по установленному ключу
				 *
				 * @details Заводится арифметика Монтгомери по модулю n, а при секретном ключе - и
				 *          по сомножителям p и q, и коэффициент qInv переводится в область по p:
				 *          подпись и сличение затем не платят за предвычисления на каждом вызове
				 *
				 * @return признак успешности предвычислений
				 *
				 * \~english
				 * @brief Method of the precomputations by the set key
				 *
				 * @details The Montgomery arithmetic by the modulus n is set up, and with a secret key -
				 *          also by the factors p and q, and the coefficient qInv is transferred into the
				 *          domain by p: the signature and the verification then do not pay for the
				 *          precomputations at every call
				 *
				 * @return the flag of the success of the precomputations
				 *
				 * \~
				 */
				bool prepare() noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки свежей пары ослепления по сомножителям
				 *
				 * @param raised1  место открытой степени r₁^e в области Монтгомери по p
				 * @param inverse1 место обратного r₁⁻¹ в области Монтгомери по p
				 * @param raised2  место открытой степени r₂^e в области Монтгомери по q
				 * @param inverse2 место обратного r₂⁻¹ в области Монтгомери по q
				 * @return         признак успешности выработки
				 *
				 * \~english
				 * @brief Method of the production of a fresh blinding pair by the factors
				 *
				 * @param raised1  the place of the public power r₁^e in the Montgomery domain by p
				 * @param inverse1 the place of the inverse r₁⁻¹ in the Montgomery domain by p
				 * @param raised2  the place of the public power r₂^e in the Montgomery domain by q
				 * @param inverse2 the place of the inverse r₂⁻¹ in the Montgomery domain by q
				 * @return         the flag of the success of the production
				 *
				 * \~
				 */
				bool renew(math::integer_t & raised1, math::integer_t & inverse1, math::integer_t & raised2, math::integer_t & inverse2) const noexcept;
				/**
				 * \~russian
				 * @brief Метод секретной степени с ослеплением по сомножителям
				 *
				 * @param stored   признак хранимой пары: она обновляется квадратами и сменяется свежей по счётчику, пара на стеке вырабатывается свежей
				 * @param part1    вычет числа по первому сомножителю
				 * @param part2    вычет числа по второму сомножителю
				 * @param raised1  открытая степень r₁^e в области Монтгомери по p
				 * @param inverse1 обратное r₁⁻¹ в области Монтгомери по p
				 * @param raised2  открытая степень r₂^e в области Монтгомери по q
				 * @param inverse2 обратное r₂⁻¹ в области Монтгомери по q
				 * @param result   место итога, собранного по китайской теореме об остатках
				 * @return         признак успешности действия
				 *
				 * \~english
				 * @brief Method of the secret power with the blinding by the factors
				 *
				 * @param stored   the flag of the kept pair: it is updated by squaring and replaced by a fresh one by the counter, a pair on the stack is produced fresh
				 * @param part1    the residue of the number by the first factor
				 * @param part2    the residue of the number by the second factor
				 * @param raised1  the public power r₁^e in the Montgomery domain by p
				 * @param inverse1 the inverse r₁⁻¹ in the Montgomery domain by p
				 * @param raised2  the public power r₂^e in the Montgomery domain by q
				 * @param inverse2 the inverse r₂⁻¹ in the Montgomery domain by q
				 * @param result   the place of the outcome assembled by the Chinese remainder theorem
				 * @return         the flag of the success of the operation
				 *
				 * \~
				 */
				bool blinded(const bool stored, const math::integer_t & part1, const math::integer_t & part2, math::integer_t & raised1, math::integer_t & inverse1, math::integer_t & raised2, math::integer_t & inverse2, math::integer_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сборки числа по китайской теореме об остатках за постоянное время
				 *
				 * @param first  вычет по первому сомножителю
				 * @param second вычет по второму сомножителю
				 * @param result место, в которое помещается собранное число
				 * @return       признак успешности сборки
				 *
				 * \~english
				 * @brief Method of the assembly of the number by the Chinese remainder theorem in a constant time
				 *
				 * @param first  the residue by the first factor
				 * @param second the residue by the second factor
				 * @param result the place the assembled number is put into
				 * @return       the flag of the success of the assembly
				 *
				 * \~
				 */
				bool garner(const math::integer_t & first, const math::integer_t & second, math::integer_t & result) const noexcept;
			private:
				/**
				 * \~russian
				 * @brief Метод выработки простого сомножителя ключа
				 *
				 * @param bits   число разрядов сомножителя
				 * @param result место, в которое помещается сомножитель
				 * @return       признак успешности выработки
				 *
				 * \~english
				 * @brief Method of the production of a prime factor of the key
				 *
				 * @param bits   the number of the bits of the factor
				 * @param result the place the factor is put into
				 * @return       the flag of the success of the production
				 *
				 * \~
				 */
				bool factor(const size_t bits, math::integer_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вычисления производных составляющих секретного ключа
				 *
				 * @return признак успешности: показатель обратим по функции Кармайкла
				 *
				 * \~english
				 * @brief Method of the computation of the derived components of the secret key
				 *
				 * @return the flag of the success: the exponent is invertible by the Carmichael function
				 *
				 * \~
				 */
				bool derive() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности модуля к работе
				 *
				 * @return признак того, что открытый ключ установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness of the module for the work
				 *
				 * @return the flag of the public key being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки наличия секретного ключа
				 *
				 * @return признак того, что секретный ключ установлен
				 *
				 * \~english
				 * @brief Method of checking the presence of the secret key
				 *
				 * @return the flag of the secret key being set
				 *
				 * \~
				 */
				bool secret() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера модуля
				 *
				 * @return размер модуля в байтах: размер подписи и шифротекста
				 *
				 * \~english
				 * @brief Method of getting the size of the modulus
				 *
				 * @return the size of the modulus in bytes: the size of a signature and of a ciphertext
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
				 * @details Метод size выдаёт длину сырой подписи, под которую заводится место
				 *          для make, а limit - наибольшую длину подписи в том виде, в котором она
				 *          уходит наружу: она не превышается ни при каком значении подписи, как
				 *          у EVP_PKEY_size. Подпись RSA уходит наружу как есть - числом длиной в модуль по разделу
				 *          8 RFC 8017, оттого предел равен size
				 *
				 * \~english
				 * @brief Method of getting the upper limit of the length of a signature in the written form
				 *
				 * @return the upper limit of the length of a signature in bytes, zero without a key
				 *
				 * @details The method size gives the length of a raw signature the place for make is
				 *          allocated by, while limit gives the greatest length of a signature in the form
				 *          it goes outside in: it is not exceeded at any value of the signature, like
				 *          EVP_PKEY_size. A signature RSA goes outside as is - by a number of the length of the modulus
				 *          according to the section 8 of RFC 8017, therefore the limit equals size
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа разрядов модуля
				 *
				 * @return число разрядов модуля
				 *
				 * \~english
				 * @brief Method of getting the number of the bits of the modulus
				 *
				 * @return the number of the bits of the modulus
				 *
				 * \~
				 */
				size_t bits() const noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния модуля
				 *
				 * @note Составляющие ключа затираются
				 *
				 * \~english
				 * @brief Method of the reset of the state of the module
				 *
				 * @note The components of the key are wiped
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод порождения ключа
				 *
				 * @param bits     число разрядов модуля: 2048, 3072 либо 4096
				 * @param exponent открытый показатель, нечётный и не меньше трёх
				 * @return         признак успешности порождения
				 *
				 * @note Сомножители вырабатываются по приложению A.1.3 FIPS 186-5: старшие
				 *       два разряда каждого выставлены, сомножители различаются не менее чем
				 *       в старших ста разрядах, секретный показатель обращён по функции
				 *       Кармайкла и больше корня из модуля
				 *
				 * \~english
				 * @brief Method of the generation of the key
				 *
				 * @param bits     the number of the bits of the modulus: 2048, 3072 or 4096
				 * @param exponent the public exponent, odd and not less than three
				 * @return         the flag of the success of the generation
				 *
				 * @note The factors are produced according to the appendix A.1.3 of FIPS 186-5: the two
				 *       senior bits of each are set, the factors differ at least in the senior hundred
				 *       bits, the secret exponent is inverted by the Carmichael function and is greater
				 *       than the root of the modulus
				 *
				 * \~
				 */
				bool generate(const size_t bits, const uint64_t exponent = 65537) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки открытого ключа
				 *
				 * @param modulus  модуль n от старшего байта к младшему
				 * @param exponent открытый показатель e от старшего байта к младшему
				 * @return         признак успешности установки
				 *
				 * \~english
				 * @brief Method of setting the public key
				 *
				 * @param modulus  the modulus n from the senior byte to the junior one
				 * @param exponent the public exponent e from the senior byte to the junior one
				 * @return         the flag of the success of the setting
				 *
				 * \~
				 */
				bool key(const view_t & modulus, const view_t & exponent) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки секретного ключа
				 *
				 * @param modulus     модуль n
				 * @param exponent    открытый показатель e
				 * @param decryptor   секретный показатель d
				 * @param prime1      первый простой сомножитель p
				 * @param prime2      второй простой сомножитель q
				 * @param exponent1   показатель dP
				 * @param exponent2   показатель dQ
				 * @param coefficient коэффициент qInv
				 * @return            признак успешности установки: составляющие согласованы
				 *
				 * @note Все составляющие записаны от старшего байта к младшему; проверяется
				 *       равенство модуля произведению сомножителей и границы показателей
				 *
				 * \~english
				 * @brief Method of setting the secret key
				 *
				 * @param modulus     the modulus n
				 * @param exponent    the public exponent e
				 * @param decryptor   the private exponent d
				 * @param prime1      the first prime factor p
				 * @param prime2      the second prime factor q
				 * @param exponent1   the exponent dP
				 * @param exponent2   the exponent dQ
				 * @param coefficient the coefficient qInv
				 * @return            the flag of the success of the setting: the components are consistent
				 *
				 * @note All the components are written from the senior byte to the junior one; the equality
				 *       of the modulus to the product of the factors and the bounds of the exponents are checked
				 *
				 * \~
				 */
				bool key(const view_t & modulus, const view_t & exponent, const view_t & decryptor, const view_t & prime1, const view_t & prime2, const view_t & exponent1, const view_t & exponent2, const view_t & coefficient) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера составляющей ключа
				 *
				 * @param part составляющая ключа
				 * @return     размер составляющей в байтах, ноль при её отсутствии
				 *
				 * \~english
				 * @brief Method of getting the size of a component of the key
				 *
				 * @param part the component of the key
				 * @return     the size of the component in bytes, zero at its absence
				 *
				 * \~
				 */
				size_t length(const part_t part) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения составляющей ключа
				 *
				 * @param part составляющая ключа
				 * @param data место, в которое записывается составляющая от старшего байта к младшему
				 * @param size размер места в байтах: составляющая дополняется ведущими нулями
				 * @return     признак успешности: составляющая есть и умещается в размер
				 *
				 * \~english
				 * @brief Method of getting a component of the key
				 *
				 * @param part the component of the key
				 * @param data the place the component is written into from the senior byte to the junior one
				 * @param size the size of the place in bytes: the component is padded by leading zeros
				 * @return     the flag of the success: the component exists and fits into the size
				 *
				 * \~
				 */
				bool part(const part_t part, uint8_t * data, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод записи ключа в кодировке DER
				 *
				 * @param secret признак записи секретного ключа
				 * @param result место, в которое помещается запись
				 * @return       признак успешности: ключ есть и памяти достало
				 *
				 * @note Открытый ключ записывается RSAPublicKey, секретный - RSAPrivateKey
				 *       без дополнительных сомножителей; приложение A.1 RFC 8017
				 *
				 * \~english
				 * @brief Method of writing the key in the DER encoding
				 *
				 * @param secret the flag of writing the secret key
				 * @param result the place the record is put into
				 * @return       the flag of the success: the key exists and the memory sufficed
				 *
				 * @note The public key is written as RSAPublicKey, the secret one - as RSAPrivateKey
				 *       without additional factors; the appendix A.1 of RFC 8017
				 *
				 * \~
				 */
				bool encode(const bool secret, vector <uint8_t> & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод разбора ключа из кодировки DER
				 *
				 * @param data запись RSAPublicKey либо RSAPrivateKey
				 * @return     признак успешности разбора
				 *
				 * @note Вид записи узнаётся по числу полей; издание с дополнительными
				 *       сомножителями отвергается
				 *
				 * \~english
				 * @brief Method of the parsing of the key from the DER encoding
				 *
				 * @param data the record RSAPublicKey or RSAPrivateKey
				 * @return     the flag of the success of the parsing
				 *
				 * @note The kind of the record is recognized by the number of the fields; the version
				 *       with additional factors is refused
				 *
				 * \~
				 */
				bool decode(const view_t & data) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод открытого действия RSA
				 *
				 * @param input  входное число, меньшее модуля, от старшего байта к младшему
				 * @param output место, в которое записывается итог размером в модуль
				 * @return       признак успешности: ключ установлен, число меньше модуля
				 *
				 * @note Примитивы RSAEP и RSAVP1 раздела 5 RFC 8017: возведение в открытую
				 *       степень без дополнения
				 *
				 * \~english
				 * @brief Method of the public operation of RSA
				 *
				 * @param input  the input number, less than the modulus, from the senior byte to the junior one
				 * @param output the place the result of the size of the modulus is written into
				 * @return       the flag of the success: the key is set, the number is less than the modulus
				 *
				 * @note The primitives RSAEP and RSAVP1 of the section 5 of RFC 8017: the raise into
				 *       the public power without a padding
				 *
				 * \~
				 */
				bool encipher(const view_t & input, uint8_t * output) const noexcept;
				/**
				 * \~russian
				 * @brief Метод секретного действия RSA
				 *
				 * @param input  входное число, меньшее модуля, от старшего байта к младшему
				 * @param output место, в которое записывается итог размером в модуль
				 * @return       признак успешности: секретный ключ установлен, число меньше модуля
				 *
				 * @note Примитивы RSADP и RSASP1 раздела 5 RFC 8017: возведение в секретную
				 *       степень по китайской теореме об остатках с ослеплением
				 *
				 * \~english
				 * @brief Method of the secret operation of RSA
				 *
				 * @param input  the input number, less than the modulus, from the senior byte to the junior one
				 * @param output the place the result of the size of the modulus is written into
				 * @return       the flag of the success: the secret key is set, the number is less than the modulus
				 *
				 * @note The primitives RSADP and RSASP1 of the section 5 of RFC 8017: the raise into
				 *       the secret power by the Chinese remainder theorem with a blinding
				 *
				 * \~
				 */
				bool decipher(const view_t & input, uint8_t * output) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи
				 *
				 * @param scheme    схема подписи: PKCS1 либо PSS
				 * @param algorithm алгоритм хеша сообщения
				 * @param digest    хеш подписываемого сообщения
				 * @param signature место, в которое записывается подпись размером в модуль
				 * @param salt      длина соли PSS в байтах, по умолчанию длина хеша
				 * @param random    соль PSS для проверок, по умолчанию вырабатывается случайно
				 * @return          признак успешности выработки подписи
				 *
				 * @note Хеши «Стрибог» в PKCS #1 не определены и отвергаются
				 *
				 * \~english
				 * @brief Method of the production of a signature
				 *
				 * @param scheme    the scheme of the signature: PKCS1 or PSS
				 * @param algorithm the algorithm of the hash of the message
				 * @param digest    the hash of the message being signed
				 * @param signature the place the signature of the size of the modulus is written into
				 * @param salt      the length of the PSS salt in bytes, by default the length of the hash
				 * @param random    the PSS salt for the tests, by default it is produced randomly
				 * @return          the flag of the success of the production of the signature
				 *
				 * @note The «Streebog» hashes are not defined in PKCS #1 and are refused
				 *
				 * \~
				 */
				bool make(const scheme_t scheme, const digest::hash_t algorithm, const view_t & digest, uint8_t * signature, const size_t salt = SIZE_MAX, const view_t & random = view_t()) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param scheme    схема подписи: PKCS1 либо PSS
				 * @param algorithm алгоритм хеша сообщения
				 * @param digest    хеш подписанного сообщения
				 * @param signature проверяемая подпись размером в модуль
				 * @param salt      длина соли PSS в байтах, по умолчанию длина хеша
				 * @return          признак подлинности подписи
				 *
				 * \~english
				 * @brief Method of the verification of a signature
				 *
				 * @param scheme    the scheme of the signature: PKCS1 or PSS
				 * @param algorithm the algorithm of the hash of the message
				 * @param digest    the hash of the signed message
				 * @param signature the signature being verified of the size of the modulus
				 * @param salt      the length of the PSS salt in bytes, by default the length of the hash
				 * @return          the flag of the authenticity of the signature
				 *
				 * \~
				 */
				bool check(const scheme_t scheme, const digest::hash_t algorithm, const view_t & digest, const view_t & signature, const size_t salt = SIZE_MAX) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод шифрования сообщения
				 *
				 * @param scheme    схема шифрования: PKCS1 либо OAEP
				 * @param algorithm алгоритм хеша OAEP, для PKCS1 не используется
				 * @param message   шифруемое сообщение
				 * @param output    место, в которое записывается шифротекст размером в модуль
				 * @param label     метка OAEP, по умолчанию пустая
				 * @param random    затравка OAEP либо дополнение PKCS1 для проверок, по умолчанию вырабатываются случайно
				 * @return          признак успешности: сообщение умещается в модуль с дополнением
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 *
				 * @param scheme    the scheme of the encryption: PKCS1 or OAEP
				 * @param algorithm the algorithm of the OAEP hash, not used for PKCS1
				 * @param message   the message being encrypted
				 * @param output    the place the ciphertext of the size of the modulus is written into
				 * @param label     the OAEP label, empty by default
				 * @param random    the OAEP seed or the PKCS1 padding for the tests, by default they are produced randomly
				 * @return          the flag of the success: the message fits into the modulus with the padding
				 *
				 * \~
				 */
				bool encrypt(const scheme_t scheme, const digest::hash_t algorithm, const view_t & message, uint8_t * output, const view_t & label = view_t(), const view_t & random = view_t()) const noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param scheme    схема шифрования: PKCS1 либо OAEP
				 * @param algorithm алгоритм хеша OAEP, для PKCS1 не используется
				 * @param input     шифротекст размером в модуль
				 * @param output    место, в которое записывается сообщение: не меньше размера модуля
				 * @param size      переменная, в которую помещается длина сообщения
				 * @param label     метка OAEP, по умолчанию пустая
				 * @return          признак успешности: дополнение верно
				 *
				 * @note Разбор дополнения ведётся за постоянное время: и проверки, и копирование
				 *       сообщения идут по всему буферу под масками, а отказ выдаётся лишь в конце
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 *
				 * @param scheme    the scheme of the encryption: PKCS1 or OAEP
				 * @param algorithm the algorithm of the OAEP hash, not used for PKCS1
				 * @param input     the ciphertext of the size of the modulus
				 * @param output    the place the message is written into: not less than the size of the modulus
				 * @param size      the variable the length of the message is put into
				 * @param label     the OAEP label, empty by default
				 * @return          the flag of the success: the padding is correct
				 *
				 * @note The parsing of the padding is carried in a constant time: both the checks and the
				 *       copying of the message go over the whole buffer under masks, and the refusal is
				 *       given only at the end
				 *
				 * \~
				 */
				bool decrypt(const scheme_t scheme, const digest::hash_t algorithm, const view_t & input, uint8_t * output, size_t & size, const view_t & label = view_t()) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Rsa() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Rsa() noexcept;
		} rsa_t;
	};
};

