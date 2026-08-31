/**
 * @file entropy.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANTS-1.0}
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
 * @note Порядок обращения к источникам: сперва вызов ядра, не требующий описателя
 *       файла, затем чтение устройства. Чтение устройства оставлено запасным путём
 *       ради систем, где вызов ядра моложе поддерживаемых изданий
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cerrno>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <entropy/entropy.hpp>

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
		 * Заголовочные файлы вызова ядра, выдающего случайные байты
		 */
		#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
			#include <stdlib.h>
		#else
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
	using namespace anyks;

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
		/**
		 * Устройство случайных байтов существует лишь у систем Unix
		 */
		#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
			// Отмечаем неиспользуемое место случайных байтов
			(void) data;
			// Отмечаем неиспользуемое число случайных байтов
			(void) size;
			// Выводим отказ чтения случайных байтов
			return false;
		#else
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
		#endif
	}
};

/**
 * @brief Метод получения случайных байтов
 *
 * @param data место, в которое помещаются случайные байты
 * @param size число получаемых случайных байтов
 *
 * @return     признак успешности получения случайных байтов
 *
 */
bool anyks::entropy::bytes(uint8_t * data, const size_t size) noexcept {
	// Если место случайных байтов не передано
	if(data == nullptr)
		// Выводим отказ получения случайных байтов
		return false;
	// Если случайных байтов не запрошено вовсе
	if(size == 0)
		// Выводим успешность получения случайных байтов
		return true;
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
		 * Если вызова ядра, выдающего случайные байты, у системы нет
		 */
		#if !defined(__ANTS_ENTROPY_CALL__)
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
 * @brief Метод получения случайного числа по модулю
 *
 * @param modulus модуль, меньше которого получается случайное число
 * @param result  место, в которое помещается случайное число
 *
 * @return        признак успешности получения случайного числа
 *
 */
bool anyks::entropy::number(const math::modulus_t & modulus, math::number_t & result) noexcept {
	// Выполняем обнуление получаемого случайного числа
	result = math::number_t();
	// Если модуль не установлен
	if(!modulus.ready())
		// Выводим отказ получения случайного числа
		return false;
	// Место, в которое помещаются случайные байты
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Выполняем отбор случайного числа
	 */
	for(size_t i = 0; i < ATTEMPTS; i++){
		// Если случайные байты получить не удалось
		if(!anyks::entropy::bytes(buffer, modulus.size()))
			// Выводим отказ получения случайного числа
			return false;
		/**
		 * Выпавшее значение, не меньшее модуля, разбору не подлежит и отбрасывается
		 * целиком: приведение по модулю сделало бы младшие значения вероятнее прочих
		 */
		if(modulus.load(view_t(buffer, modulus.size()), result) && !modulus.zero(result)){
			// Выполняем затирание полученных случайных байтов
			::memset(buffer, 0, sizeof(buffer));
			// Выводим успешность получения случайного числа
			return true;
		}
	}
	// Выполняем затирание полученных случайных байтов
	::memset(buffer, 0, sizeof(buffer));
	// Выполняем обнуление получаемого случайного числа
	result = math::number_t();
	// Выводим отказ получения случайного числа
	return false;
}
