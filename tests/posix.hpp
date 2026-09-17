/**
 * @file posix.hpp
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
 */

#ifndef __ANTS_TESTS_POSIX__
#define __ANTS_TESTS_POSIX__

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
	#if !defined(_SSIZE_T_DEFINED)
		typedef intptr_t ssize_t;
		#define _SSIZE_T_DEFINED
	#endif
	#if !defined(F_OK)
		#define F_OK 0
		#define R_OK 4
		#define W_OK 2
	#endif
	// Разряда исполнения у Windows нет: проверка исполняемости сводится к наличию файла
	#if !defined(X_OK)
		#define X_OK 0
	#endif
	#if !defined(S_ISDIR)
		#define S_ISDIR(mode) (((mode) & _S_IFMT) == _S_IFDIR)
	#endif
	#if !defined(S_ISREG)
		#define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
	#endif
	/**
	 * @brief Создание временного каталога по образцу с шестью X на конце
	 */
	inline char * mkdtemp(char * pattern) noexcept {
		if(::_mktemp_s(pattern, ::strlen(pattern) + 1) != 0) return nullptr;
		return ((::_mkdir(pattern) == 0) ? pattern : nullptr);
	}
	/**
	 * @brief Ожидание в микросекундах без windows.h: его макросы (SHORT, POINTS, IN) ломают проверки
	 */
	inline int usleep(const unsigned long micro) noexcept { std::this_thread::sleep_for(std::chrono::microseconds(micro)); return 0; }
#else
	#include <unistd.h>
	#include <sys/stat.h>
#endif

#endif // __ANTS_TESTS_POSIX__
