/**
 * @file entropy.cpp
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
 * @brief Исходный файл модуля источника случайных значений
 *
 * @note Случайные байты выдаёт свой порождатель по потоку (устройство в
 *       internal/entropy/generator.hpp), а система нужна лишь для его наполнения:
 *       порождатель libc arc4random_buf у macOS и четырёх BSD, вызов ядра getentropy у
 *       Linux, BCryptGenRandom у Windows, чтение устройства /dev/urandom там, где вызова
 *       ядра нет (Solaris, illumos) либо он отказал. Модуль был заведён с вызовом ядра на
 *       каждую выдачу: 0,86 мкс на M4 и 1,8 мкс на Astra против шести микросекунд всей
 *       подписи (замер 22.09.2026), и по требованию не уступать эталонам в скорости
 *       заведён порождатель - так же устроены OpenSSL и BoringSSL (CTR-DRBG на AES по
 *       потоку с переналивкой по счётчику и обработчиком разветвления). ChaCha20 взят
 *       вместо AES ради одной и той же скорости на всех машинах: команд AES нет ни у
 *       Эльбруса, ни у QEMU без их проброса, а AES таблицами зависит от ключа временем
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <atomic>
#include <cerrno>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <cipher/chacha.hpp>
#include <entropy/entropy.hpp>
#include <internal/entropy/generator.hpp>

/**
 * Определяем платформу, под которую ведётся сборка
 */
#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	/**
	 * Заголовочные файлы операционной системы Windows
	 */
	#include <windows.h>
	#include <bcrypt.h>
#else
	/**
	 * Заголовочные файлы операционной системы Unix
	 */
	#include <fcntl.h>
	#include <unistd.h>
	#include <pthread.h>
	/**
	 * @note Вызов getentropy есть у macOS, у всех четырёх BSD и у Linux, но у Solaris
	 *       и illumos его нет: там остаётся одно лишь устройство случайных байтов
	 */
	#if defined(__APPLE__) || defined(__MACH__) || defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
		/**
		 * Признак наличия вызова ядра, выдающего случайные байты
		 */
		#define __ANTS_ENTROPY_CALL__ 1
		/**
		 * @note У macOS и четырёх BSD случайные байты выдаёт порождатель самой libc
		 *       (arc4random_buf: ChaCha20, наполняемый ядром, с переналивкой по счётчику
		 *       и при ветвлении процесса) - он и назван системой предпочтительным
		 *       источником, а вызов ядра getentropy там заведён для наполнения таких
		 *       порождателей. У Linux порождателя в libc нет (arc4random там лишь обёртка
		 *       над вызовом ядра), и остаётся getentropy
		 */
		#if defined(__APPLE__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
			/**
			 * Признак наличия порождателя случайных байтов у libc
			 */
			#define __ANTS_ENTROPY_LIBC__ 1
		#endif
		/**
		 * Заголовочные файлы вызова ядра, выдающего случайные байты
		 */
		#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
			#include <stdlib.h>
		#else
			#include <stdlib.h>
			#include <sys/random.h>
		#endif
	#endif
#endif

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
	 * @brief Наибольшее число попыток отбора случайного числа
	 *
	 * @details Модули криптографии старшим разрядом не короче половины своей
	 *          разрядности, оттого всякая попытка отбора удаётся с вероятностью не
	 *          ниже половины: сотня попыток подряд не удастся с вероятностью, меньшей
	 *          двух в минус сотой степени
	 *
	 */
	static constexpr size_t ATTEMPTS = 100;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Нулевой текст, покрытие которого гаммой и есть сама гамма
	 *
	 */
	static const uint8_t ZEROS[internal::generator_t::BUFFER] = {0};
	/**
	 * @brief Поколение процесса
	 *
	 * @details Растёт у потомка при разветвлении процесса: порождатель потока помнит
	 *          поколение своей последней переналивки, и несовпадение велит ему
	 *          переналиться прежде выдачи. У Windows разветвления нет, и поколение
	 *          не меняется никогда
	 *
	 */
	static atomic <uint64_t> generation{0};
	/**
	 * @brief Порождатель случайных байтов текущего потока
	 *
	 * @details Заводится при первом обращении потока и затирается деструктором при
	 *          его завершении
	 *
	 */
	static thread_local internal::generator_t instance;
	/**
	 * Разветвление процесса существует лишь у систем Unix
	 */
	#if !defined(_MSC_VER) && !defined(WIN64) && !defined(_WIN64) && !defined(__WIN64__) && !defined(WIN32) && !defined(_WIN32) && !defined(__WIN32__) && !defined(__NT__)
	/**
	 * @brief Обработчик разветвления процесса у потомка
	 *
	 */
	static void forked() noexcept {
		// Открываем новое поколение процесса
		generation.fetch_add(1, memory_order_relaxed);
	}
	/**
	 * @brief Метод заведения обработчика разветвления процесса
	 *
	 * @details Заводится один раз на процесс; отказ заведения (нехватка памяти) не
	 *          запоминается, и следующее обращение заводит обработчик заново. Двойное
	 *          заведение при наперегонки идущих потоках безвредно: поколение у потомка
	 *          вырастет дважды
	 *
	 * @return  признак того, что обработчик заведён
	 *
	 */
	static bool guard() noexcept {
		// Признак того, что обработчик заведён
		static atomic <bool> guarded{false};
		// Если обработчик уже заведён
		if(guarded.load(memory_order_acquire))
			// Сообщаем, что обработчик заведён
			return true;
		// Если обработчик разветвления завести не удалось
		if(::pthread_atfork(nullptr, nullptr, &forked) != 0)
			// Сообщаем об отказе заведения
			return false;
		// Запоминаем, что обработчик заведён
		guarded.store(true, memory_order_release);
		// Сообщаем, что обработчик заведён
		return true;
	}
	#else
	/**
	 * @brief Метод заведения обработчика разветвления процесса
	 *
	 * @return признак того, что обработчик заведён: разветвления у Windows нет
	 *
	 */
	static bool guard() noexcept {
		// Разветвления у системы нет, стеречь нечего
		return true;
	}
	#endif
	/**
	 * Устройство случайных байтов существует лишь у систем Unix: у Windows этого пути
	 * нет вовсе, а у систем с порождателем libc он не нужен, и помощник там не
	 * заводится - иначе он оставался бы неупотребимым
	 */
	#if !defined(_MSC_VER) && !defined(WIN64) && !defined(_WIN64) && !defined(__WIN64__) && !defined(WIN32) && !defined(_WIN32) && !defined(__WIN32__) && !defined(__NT__) && !defined(__ANTS_ENTROPY_LIBC__)
	/**
	 * @brief Метод чтения случайных байтов из устройства системы
	 *
	 * @details Путь этот запасной: он требует описателя файла, а описатели у
	 *          потребителя могут быть исчерпаны либо каталог устройств недоступен
	 *          из-за смены корня
	 *
	 * @param data место, в которое помещаются случайные байты
	 * @param size число получаемых случайных байтов
	 *
	 * @return     признак успешности чтения случайных байтов
	 *
	 */
	static bool device(uint8_t * data, const size_t size) noexcept {
		// Выполняем открытие устройства случайных байтов
		const int fd = ::open("/dev/urandom", O_RDONLY);
		// Если устройство случайных байтов открыть не удалось
		if(fd < 0)
			// Выводим отказ чтения случайных байтов
			return false;
		// Число уже прочитанных случайных байтов
		size_t offset = 0;
		/**
		 * Выполняем чтение случайных байтов до их набора
		 */
		while(offset < size){
			// Выполняем чтение очередной части случайных байтов
			const ssize_t count = ::read(fd, data + offset, size - offset);
			// Если чтение прервано сигналом
			if((count < 0) && (errno == EINTR))
				// Выполняем повторное чтение случайных байтов
				continue;
			// Если чтение случайных байтов не удалось
			if(count <= 0){
				// Выполняем закрытие устройства случайных байтов
				::close(fd);
				// Выводим отказ чтения случайных байтов
				return false;
			}
			// Увеличиваем число прочитанных случайных байтов
			offset += static_cast <size_t> (count);
		}
		// Выполняем закрытие устройства случайных байтов
		::close(fd);
		// Выводим успешность чтения случайных байтов
		return true;
	}
	#endif // Unix
	/**
	 * @brief Метод получения случайных байтов у системы
	 *
	 * @details Единственное место, где модуль обращается к системе: им наполняется
	 *          порождатель потока
	 *
	 * @param data место, в которое помещаются случайные байты
	 * @param size число получаемых случайных байтов
	 *
	 * @return     признак успешности получения случайных байтов
	 *
	 */
	static bool seed(uint8_t * data, const size_t size) noexcept {
		/**
		 * Определяем платформу, под которую ведётся сборка
		 */
		#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
			/**
			 * Выводим итог обращения к источнику случайности системы: описателя устройства
			 * этот вызов не требует и работает при исчерпанных описателях файлов
			 */
			return BCRYPT_SUCCESS(::BCryptGenRandom(
				nullptr, static_cast <PUCHAR> (data), static_cast <ULONG> (size), BCRYPT_USE_SYSTEM_PREFERRED_RNG
			));
		#else
			/**
			 * Если у libc есть порождатель случайных байтов
			 */
			#if defined(__ANTS_ENTROPY_LIBC__)
				// Выполняем получение случайных байтов у порождателя libc: отказать он не может
				::arc4random_buf(data, size);
				// Выводим успешность получения случайных байтов
				return true;
			/**
			 * Если вызова ядра, выдающего случайные байты, у системы нет
			 */
			#elif !defined(__ANTS_ENTROPY_CALL__)
				// Выводим итог чтения случайных байтов из устройства системы
				return device(data, size);
			#else
			// Число уже полученных случайных байтов
			size_t offset = 0;
			/**
			 * Выполняем получение случайных байтов до их набора
			 */
			while(offset < size){
				/**
				 * Вызов ядра выдаёт за раз не более двухсот пятидесяти шести байтов: столько
				 * задано стандартом, и превышение отвергается ошибкой
				 */
				const size_t count = ((size - offset) < 256 ? (size - offset) : 256);
				// Если очередная часть случайных байтов получена не была
				if(::getentropy(data + offset, count) != 0){
					// Если вызов ядра прерван сигналом
					if(errno == EINTR)
						// Выполняем повторное получение случайных байтов
						continue;
					// Выводим итог чтения случайных байтов из устройства системы
					return device(data, size);
				}
				// Увеличиваем число полученных случайных байтов
				offset += count;
			}
			// Выводим успешность получения случайных байтов
			return true;
			#endif
		#endif
	}
	/**
	 * @brief Метод наполнения запаса гаммы порождателя
	 *
	 * @details Гамма ChaCha20 на текущих ключе и заполнении вырабатывается разом на весь
	 *          запас; первые байты запаса становятся новыми ключом и заполнением и в
	 *          запасе затираются, так что прежний ключ не существует более нигде
	 *
	 * @param generator порождатель потока
	 *
	 * @return          признак успешности наполнения
	 *
	 */
	static bool refill(internal::generator_t & generator) noexcept {
		// Объект шифра ChaCha20
		cipher::chacha_t cipher;
		// Если шифр на текущих ключе и заполнении запустить не удалось
		if(!cipher.start(view_t(generator.key, internal::generator_t::KEY), view_t(generator.nonce, internal::generator_t::NONCE)))
			// Выводим отказ наполнения
			return false;
		// Выполняем выработку гаммы покрытием нулевого текста
		const bool produced = cipher.encrypt(view_t(ZEROS, sizeof(ZEROS)), generator.buffer);
		// Выполняем затирание состояния шифра
		cipher.clear();
		// Если гамма выработана не была
		if(!produced){
			// Выполняем затирание запаса
			wipe(generator.buffer, sizeof(generator.buffer));
			// Запаса нет
			generator.rest = 0;
			// Выводим отказ наполнения
			return false;
		}
		// Переносим новый ключ из начала запаса
		::memcpy(generator.key, generator.buffer, internal::generator_t::KEY);
		// Переносим новое заполнение следом за ключом
		::memcpy(generator.nonce, generator.buffer + internal::generator_t::KEY, internal::generator_t::NONCE);
		// Выполняем затирание перенесённого: ключ живёт в одном месте
		wipe(generator.buffer, internal::generator_t::TAKEN);
		// Остаток запаса выдаётся потребителю
		generator.rest = internal::generator_t::REST;
		// Считаем наполнение
		generator.refills++;
		// Выводим успешность наполнения
		return true;
	}
	/**
	 * @brief Метод переналивки порождателя от системы
	 *
	 * @details Свежие байты системы складываются с ключом по модулю два, а не подменяют
	 *          его: худшие байты системы состояния не ухудшат. Неизрасходованный запас
	 *          отбрасывается: у потомка процесса он тот же, что у родителя
	 *
	 * @param generator порождатель потока
	 *
	 * @return          признак успешности переналивки
	 *
	 */
	static bool stir(internal::generator_t & generator) noexcept {
		// Свежие байты системы
		uint8_t fresh[internal::generator_t::KEY];
		// Если свежих байтов у системы получить не удалось
		if(!seed(fresh, sizeof(fresh)))
			// Выводим отказ переналивки
			return false;
		/**
		 * Выполняем примешивание свежих байтов к ключу
		 */
		for(size_t i = 0; i < sizeof(fresh); i++)
			// Складываем очередной байт ключа со свежим
			generator.key[i] = static_cast <uint8_t> (generator.key[i] ^ fresh[i]);
		// Выполняем затирание свежих байтов
		wipe(fresh, sizeof(fresh));
		// Выполняем затирание неизрасходованного запаса
		wipe(generator.buffer, sizeof(generator.buffer));
		// Запаса нет
		generator.rest = 0;
		// Запоминаем поколение процесса переналивки
		generator.generation = generation.load(memory_order_relaxed);
		// Счёт наполнений идёт заново
		generator.refills = 0;
		// Считаем переналивку
		generator.stirs++;
		// Порождатель наполнен, если наполнен и запас
		generator.seeded = refill(generator);
		// Выводим итог переналивки
		return generator.seeded;
	}
};

/**
 * @brief Конструктор: пустое, ненаполненное состояние
 *
 */
nts::internal::Generator::Generator() noexcept : rest(0), refills(0), stirs(0), generation(0), seeded(false) {
	// Выполняем обнуление ключа
	::memset(this->key, 0, sizeof(this->key));
	// Выполняем обнуление заполнения
	::memset(this->nonce, 0, sizeof(this->nonce));
	// Выполняем обнуление запаса
	::memset(this->buffer, 0, sizeof(this->buffer));
}
/**
 * @brief Деструктор: затирание состояния при завершении потока
 *
 */
nts::internal::Generator::~Generator() noexcept {
	// Выполняем затирание ключа
	wipe(this->key, sizeof(this->key));
	// Выполняем затирание заполнения
	wipe(this->nonce, sizeof(this->nonce));
	// Выполняем затирание запаса
	wipe(this->buffer, sizeof(this->buffer));
	// Запаса нет
	this->rest = 0;
	// Порождатель не наполнен
	this->seeded = false;
}
/**
 * @brief Метод получения порождателя текущего потока
 *
 * @return порождатель случайных байтов текущего потока
 *
 */
nts::internal::generator_t & nts::internal::generator() noexcept {
	// Выводим порождатель текущего потока
	return instance;
}
/**
 * @brief Метод получения случайных байтов
 *
 * @param data место, в которое помещаются случайные байты
 * @param size число получаемых случайных байтов
 *
 * @return     признак успешности получения случайных байтов
 *
 */
bool nts::entropy::bytes(uint8_t * data, const size_t size) noexcept {
	// Если место случайных байтов не передано
	if(data == nullptr)
		// Выводим отказ получения случайных байтов
		return false;
	// Если случайных байтов не запрошено вовсе
	if(size == 0)
		// Выводим успешность получения случайных байтов
		return true;
	// Порождатель текущего потока
	internal::generator_t & generator = internal::generator();
	/**
	 * Ненаполненный порождатель и порождатель чужого поколения процесса (потомок после
	 * разветвления) переналиваются от системы прежде выдачи, и лишь под обработчиком
	 * разветвления: без него потомок выдавал бы байты родителя
	 */
	if(!generator.seeded || (generator.generation != generation.load(memory_order_relaxed))){
		// Если обработчик разветвления завести либо порождатель переналить не удалось
		if(!guard() || !stir(generator))
			// Выводим отказ получения случайных байтов
			return false;
	}
	// Число уже выданных случайных байтов
	size_t offset = 0;
	/**
	 * Выполняем выдачу случайных байтов из запаса до их набора
	 */
	while(offset < size){
		// Если запас израсходован
		if(generator.rest == 0){
			// Каждые RESEED наполнений - переналивка от системы, прочие - наполнение своей гаммой
			const bool filled = ((generator.refills >= internal::generator_t::RESEED) ? stir(generator) : refill(generator));
			// Если наполнить запас не удалось
			if(!filled)
				// Выводим отказ получения случайных байтов
				return false;
		}
		// Число байтов, выдаваемых из запаса за раз
		const size_t count = ((generator.rest < (size - offset)) ? generator.rest : (size - offset));
		// Место выдаваемых байтов в запасе: неизрасходованные лежат в хвосте
		uint8_t * place = (generator.buffer + (sizeof(generator.buffer) - generator.rest));
		// Переносим случайные байты потребителю
		::memcpy(data + offset, place, count);
		// Выполняем затирание выданных байтов в запасе
		wipe(place, count);
		// Уменьшаем запас
		generator.rest -= count;
		// Увеличиваем число выданных случайных байтов
		offset += count;
	}
	// Выводим успешность получения случайных байтов
	return true;
}
/**
 * @brief Метод получения случайного числа по модулю
 *
 * @param modulus модуль, меньше которого получается случайное число
 * @param result  место, в которое помещается случайное число
 *
 * @return        признак успешности получения случайного числа
 *
 */
bool nts::entropy::number(const math::modulus_t & modulus, math::number_t & result) noexcept {
	// Выполняем обнуление получаемого случайного числа
	result = math::number_t();
	// Если модуль не установлен
	if(!modulus.ready())
		// Выводим отказ получения случайного числа
		return false;
	// Место, в которое помещаются случайные байты
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Маска старшего байта: у модуля, не занимающего старший байт целиком (порядок
	 * secp521r1 начинается с 0x01), случайный байт без маски лежал бы ниже модуля лишь в
	 * одном случае из сотен, и сто попыток отбора кончались бы отказом; маска срезает
	 * лишние разряды, оставляя отбор равномерным, а долю годных значений - не ниже половины
	 */
	uint8_t mask = 0xFF;
	{
		// Ноль, единица и модуль без единицы
		math::number_t zero, one, last;
		// Ноль
		modulus.word(0, zero);
		// Единица
		modulus.word(1, one);
		// Модуль без единицы: наибольшее число арифметики
		modulus.subtract(zero, one, last);
		// Если наибольшее число записать не удалось
		if(!modulus.store(last, buffer, modulus.size()))
			// Выводим отказ получения случайного числа
			return false;
		/**
		 * Выполняем подбор маски: наименьшая маска, не меньшая старшего байта модуля
		 */
		while(((mask >> 1) >= buffer[0]) && (mask > 1))
			// Сужаем маску
			mask >>= 1;
	}
	/**
	 * Выполняем отбор случайного числа
	 */
	for(size_t i = 0; i < ATTEMPTS; i++){
		// Если случайные байты получить не удалось
		if(!nts::entropy::bytes(buffer, modulus.size()))
			// Выводим отказ получения случайного числа
			return false;
		// Срезаем лишние разряды старшего байта
		buffer[0] &= mask;
		/**
		 * Выпавшее значение, не меньшее модуля, разбору не подлежит и отбрасывается
		 * целиком: приведение по модулю сделало бы младшие значения вероятнее прочих
		 */
		if(modulus.load(view_t(buffer, modulus.size()), result) && !modulus.zero(result)){
			// Выполняем затирание полученных случайных байтов
			wipe(buffer, sizeof(buffer));
			// Выводим успешность получения случайного числа
			return true;
		}
	}
	// Выполняем затирание полученных случайных байтов
	wipe(buffer, sizeof(buffer));
	// Выполняем обнуление получаемого случайного числа
	result = math::number_t();
	// Выводим отказ получения случайного числа
	return false;
}
