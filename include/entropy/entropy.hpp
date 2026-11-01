/**
 * @file entropy.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл модуля источника случайных значений
 *
 * \~english
 * @brief Header file of the module of the source of the random values
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
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>

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
	 * @brief Пространство имён модуля источника случайных значений
	 *
	 * @details Случайные байты выдаёт свой порождатель по потоку: ChaCha20 с ключом,
	 *          стираемым на ходу (fast key erasure), по образцу arc4random OpenBSD и
	 *          порождателя ядра Linux. Запас гаммы в 1 КиБ вырабатывается разом, первые
	 *          44 его байта становятся новыми ключом и заполнением, остальные выдаются и
	 *          затираются по мере выдачи: прежнего ключа нет нигде, и по состоянию
	 *          порождателя не восстановить ни одного уже выданного байта. Наполняется
	 *          порождатель у системы - arc4random_buf у macOS и BSD, getentropy у Linux,
	 *          BCryptGenRandom у Windows, устройство /dev/urandom там, где вызова нет, - и
	 *          переналивается от неё каждые 64 наполнения (около 61 КиБ выдачи) и после
	 *          разветвления процесса (обработчик pthread_atfork). Отказ системы - отказ
	 *          вызова, без подмены. Модуль был заведён с вызовом ядра на каждую выдачу
	 *          (0,86 мкс на M4, 1,8 на Astra при шести микросекундах всей подписи); по
	 *          требованию не уступать эталонам заведён порождатель - так же устроены
	 *          OpenSSL и BoringSSL (CTR-DRBG на AES по потоку с переналивкой по счётчику),
	 *          а libsodium, Go и Rust зовут систему на каждую выдачу. ChaCha20 вместо AES -
	 *          ради одной и той же скорости на машинах без команд AES и без таблиц,
	 *          зависящих от ключа временем
	 *
	 * @note Пространство названо entropy, а не random: свободная функция random входит
	 *       в POSIX, и одноимённое пространство имён сделало бы её вызов у потребителя,
	 *       написавшего using namespace nts, двусмысленным
	 *
	 * \~english
	 * @brief Namespace of the module of the source of the random values
	 *
	 * @details The random bytes are produced by a generator of its own per thread: ChaCha20
	 *          with a key erased on the go (fast key erasure), after the pattern of the
	 *          arc4random of OpenBSD and of the generator of the Linux kernel. A 1 KiB stock
	 *          of the gamma is produced at once, its first 44 bytes become the new key and
	 *          nonce, the rest is given out and wiped as it is given out: the previous key
	 *          exists nowhere, and not a single byte already given out can be recovered from
	 *          the state of the generator. The generator is filled from the system -
	 *          arc4random_buf at macOS and BSD, getentropy at Linux, BCryptGenRandom at
	 *          Windows, the /dev/urandom device where there is no call - and is refilled from
	 *          it every 64 fillings (about 61 KiB of output) and after a fork of the process
	 *          (a pthread_atfork handler). A refusal of the system is a refusal of the call,
	 *          without a substitution. The module was started with a kernel call per output
	 *          (0.86 µs at M4, 1.8 at Astra with six microseconds for the whole signature); by
	 *          the demand of not yielding to the references the generator was introduced -
	 *          OpenSSL and BoringSSL are built the same way (a CTR-DRBG on AES per thread with
	 *          a reseeding by a counter), while libsodium, Go and Rust call the system per
	 *          output. ChaCha20 instead of AES - for the sake of one and the same speed at the
	 *          machines without the AES instructions and without the tables depending on the
	 *          key by the timing
	 *
	 * @note The namespace is named entropy and not random: the free function random is a part
	 *       of POSIX, and a namespace of the same name would make its call ambiguous for a
	 *       consumer who wrote using namespace nts
	 *
	 * \~
	 */
	namespace entropy {
		/**
		 * \~russian
		 * @brief Функция получения случайных байтов
		 *
		 * @param data место, в которое помещаются случайные байты
		 * @param size число получаемых случайных байтов
		 * @return     признак успешности получения случайных байтов
		 *
		 * @note Отказ источника случайности означает, что случайных байтов нет вовсе:
		 *       подменять их чем бы то ни было нельзя, вызов обязан отказать
		 *
		 * \~english
		 * @brief Function of getting the random bytes
		 *
		 * @param data the place the random bytes are put into
		 * @param size the number of the random bytes being received
		 * @return     the flag of the success of the getting of the random bytes
		 *
		 * @note A refusal of the source of the randomness means that there are no random bytes
		 *       at all: it is forbidden to substitute them by anything whatsoever, the call must refuse
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool bytes(uint8_t * data, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения случайного числа по модулю
		 *
		 * @param modulus модуль, меньше которого получается случайное число
		 * @param result  место, в которое помещается случайное число
		 * @return        признак успешности получения случайного числа
		 *
		 * @note Число получается отбором: выпавшее значение, не меньшее модуля либо
		 *       нулевое, отбрасывается целиком, а не приводится по модулю. Приведение
		 *       сделало бы младшие значения вероятнее прочих, а сдвиг вероятностей и есть
		 *       то, чем ломают подпись
		 *
		 * \~english
		 * @brief Function of getting a random number by a modulus
		 *
		 * @param modulus the modulus a random number less than which is received
		 * @param result  the place the random number is put into
		 * @return        the flag of the success of the getting of the random number
		 *
		 * @note The number is received by a selection: a fallen out value not less than the
		 *       modulus or a zero one is discarded entirely and is not reduced by the modulus.
		 *       A reduction would make the junior values more probable than the rest, and a
		 *       shift of the probabilities is exactly what a signature is broken by
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool number(const math::modulus_t & modulus, math::number_t & result) noexcept;
	};
};

