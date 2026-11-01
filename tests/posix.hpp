/**
 * @file posix.hpp
 * @date 2026-09-17
 *
 * @license{GPL-3.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Переносимая оснастка проверок: вызовы POSIX под MSVC
 *
 * @details Проверки зовут read, write, close, access, getpid, mkdtemp, usleep и
 *          проверяют вид файла через S_ISDIR по именам POSIX. У MinGW и всех систем
 *          POSIX это unistd.h и sys/stat.h. У MSVC read, write, close, access и getpid
 *          объявлены в io.h и process.h под теми же именами; недостаёт mkdtemp, usleep,
 *          ssize_t, признаков доступа и S_ISDIR - они доопределяются здесь, чтобы тексты
 *          проверок не ветвились по собирателю
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_TESTS_POSIX__
	/**
	 * @brief Метка однократного включения заголовка
	 *
	 */
	#define __ANTS_TESTS_POSIX__
/**
 * @brief Ветка MSVC: недостающие имена POSIX доопределяются ниже, чтобы проверки не ветвились по собирателю
 *
 */
#if defined(_MSC_VER)
	#include <io.h>
	#include <direct.h>
	#include <process.h>
	#include <sys/stat.h>
	#include <cstring>
	#include <cstdint>
	#include <cstddef>
	#include <thread>
	#include <chrono>
	/**
	 * @brief ssize_t под MSVC отсутствует: вводим signed-тип размера указателя через intptr_t
	 *
	 */
	#if !defined(_SSIZE_T_DEFINED)
		// Тип signed размера указателя вводим через intptr_t: у MSVC собственного ssize_t нет
		typedef intptr_t ssize_t;
		/**
		 * @brief Метка ввода ssize_t для защиты от повторного определения
		 *
		 */
		#define _SSIZE_T_DEFINED
	#endif
	/**
	 * @brief Признаки доступа к файлу (F_OK/R_OK/W_OK) доопределяем значениями POSIX
	 *
	 */
	#if !defined(F_OK)
		/**
		 * @brief Признак существования файла: значение как в POSIX (0)
		 *
		 */
		#define F_OK 0
		/**
		 * @brief Признак читаемости файла: значение как в POSIX (4)
		 *
		 */
		#define R_OK 4
		/**
		 * @brief Признак доступности файла на запись: значение как в POSIX (2)
		 *
		 */
		#define W_OK 2
	#endif
	/**
	 * @brief Разряда исполнения у Windows нет: проверка исполняемости сводится к наличию файла
	 *
	 */
	#if !defined(X_OK)
		/**
		 * @brief Признак исполняемости файла сведён к существованию: значение как в POSIX (0)
		 *
		 */
		#define X_OK 0
	#endif
	/**
	 * @brief Макрос проверки каталога через маску типа _S_IFMT/_S_IFDIR из sys/stat.h
	 *
	 */
	#if !defined(S_ISDIR)
		/**
		 * @brief Проверка бита каталога в поле типа файла структуры stat
		 *
		 */
		#define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
	#endif
	/**
	 * @brief Макрос проверки обычного файла через маску типа _S_IFMT/_S_IFREG из sys/stat.h
	 *
	 */
	#if !defined(S_ISREG)
		/**
		 * @brief Проверка бита обычного файла в поле типа файла структуры stat
		 *
		 */
		#define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
	#endif
	/**
	 * @brief Создание временного каталога по образцу с шестью X на конце
	 *
	 */
	inline char * mkdtemp(char * pattern) noexcept {
		// Генерируем уникальное имя по шаблону с шестью X на конце; при ошибке возвращаем nullptr
		if(::_mktemp_s(pattern, ::strlen(pattern) + 1) != 0) return nullptr;
		// Создаём каталог по полученному имени: успех — возвращаем шаблон, иначе nullptr
		return ((::_mkdir(pattern) == 0) ? pattern : nullptr);
	}
	/**
	 * @brief Ожидание в микросекундах без windows.h: его макросы (SHORT, POINTS, IN) ломают проверки
	 *
	 */
	inline int usleep(const unsigned long micro) noexcept { std::this_thread::sleep_for(std::chrono::microseconds(micro)); return 0; }
	/**
	 * @brief Ожидание в секундах без windows.h: его макросы (SHORT, POINTS, IN) ломают проверки
	 *
	 */
	inline unsigned int sleep(const unsigned int seconds) noexcept { std::this_thread::sleep_for(std::chrono::seconds(seconds)); return 0; }
/**
 * @brief Ветка POSIX-систем: нужные имена уже есть в unistd.h и sys/stat.h
 *
 */
#else
	#include <unistd.h>
	#include <sys/stat.h>
#endif

#endif
