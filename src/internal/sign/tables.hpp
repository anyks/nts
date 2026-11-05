/**
 * @file tables.hpp
 * @date 2026-11-05
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
 * @brief Заголовочный файл внутреннего модуля заготовленных кратных точки основания Эдвардсовой кривой
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Гребёнки кратных точки основания подписей Ed25519 и Ed448
 *       вычисляются при сборке программой tools/sign-tables.cpp: собирать их при
 *       всяком запуске стоило бы половины самой подписи, а держать точку и формулы
 *       кривой при себе программа вычисления кратных и так умеет
 *
 * @note Гребёнка устроена шестнадцатью строками по шестнадцать мест: строка j
 *       держит кратные d * 2^(16j) точки основания для значений полубайта d,
 *       и умножение идёт четырьмя позициями полубайта с общими удвоениями
 *       между строками - шестнадцать удвоений и шестьдесят четыре сложения
 *       на скаляр против двухсот пятидесяти шести пар у лестницы
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_INTERNAL_SIGN_TABLES__
/**
 * Экранируем повторную инициализацию модуля
 */
#define __ANTS_INTERNAL_SIGN_TABLES__

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <internal/sign/edwards.hpp>
#include <internal/sign/edwards448.hpp>

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
	/**
	 * @brief Пространство имён подписей
	 *
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Число строк гребёнки кратных точки основания
		 *
		 * @details Скаляр подписи в двести пятьдесят шесть разрядов делится на
		 *          шестнадцать строк по шестнадцать разрядов
		 *
		 * \~english
		 * @brief Number of the rows of the comb of the multiples of the base point
		 *
		 * @details The signature scalar of two hundred fifty six bits is divided into
		 *          sixteen rows of sixteen bits
		 *
		 * \~
		 */
		static constexpr size_t COMB_ROWS = 16;
		/**
		 * \~russian
		 * @brief Число мест в строке гребёнки кратных точки основания
		 *
		 * @details Место строки держит кратное своему сдвигу по значению полубайта
		 *          множителя: от нулевого - нейтральной точки - до пятнадцатого
		 *
		 * \~english
		 * @brief Number of the places in a row of the comb of the multiples of the base point
		 *
		 * @details A place of a row keeps a multiple of its shift by the value of a nibble
		 *          of the multiplier: from the zeroth - the neutral point - to the fifteenth
		 *
		 * \~
		 */
		static constexpr size_t COMB_PLACES = 16;
		/**
		 * \~russian
		 * @brief Число позиций полубайта в строке гребёнки
		 *
		 * \~english
		 * @brief Number of the nibble positions in a row of the comb
		 *
		 * \~
		 */
		static constexpr size_t COMB_DIGITS = 4;
		/**
		 * \~russian
		 * @brief Число строк гребёнки кратных точки основания Ed448
		 *
		 * @details Скаляр Ed448 в четыреста сорок восемь разрядов делится на
		 *          двадцать восемь строк по шестнадцать разрядов
		 *
		 * \~english
		 * @brief Number of the rows of the comb of the multiples of the Ed448 base point
		 *
		 * @details The Ed448 scalar of four hundred forty eight bits is divided into
		 *          twenty eight rows of sixteen bits
		 *
		 * \~
		 */
		static constexpr size_t COMB448_ROWS = 28;
		/**
		 * \~russian
		 * @brief Число мест в строке гребёнки кратных точки основания Ed448
		 *
		 * @details Место строки держит кратное своему сдвигу по значению полубайта
		 *          множителя: от нулевого - нейтральной точки - до пятнадцатого
		 *
		 * \~english
		 * @brief Number of the places in a row of the comb of the multiples of the Ed448 base point
		 *
		 * @details A place of a row keeps a multiple of its shift by the value of a nibble
		 *          of the multiplier: from the zeroth - the neutral point - to the fifteenth
		 *
		 * \~
		 */
		static constexpr size_t COMB448_PLACES = 16;
		/**
		 * \~russian
		 * @brief Число позиций полубайта в строке гребёнки Ed448
		 *
		 * \~english
		 * @brief Number of the nibble positions in a row of the Ed448 comb
		 *
		 * \~
		 */
		static constexpr size_t COMB448_DIGITS = 4;
		/**
		 * \~russian
		 * @brief Место гребёнки кратных точки основания
		 *
		 * @details Точка кривой в словах конечностей поля: элемент поля несёт свой
		 *          конструктор и литералом из слов не собирается, а место гребёнки -
		 *          данные, и записывается словами напрямую
		 *
		 * \~english
		 * @brief A place of the comb of the multiples of the base point
		 *
		 * @details A point of the curve in the words of the field limbs: an element of the
		 *          field carries its own constructor and is not assembled by a literal of
		 *          words, while a place of the comb is data and is written by words directly
		 *
		 * \~
		 */
		typedef struct Comb {
			// Слова первой координаты точки места
			uint64_t x[math::field25519::LIMBS];
			// Слова второй координаты точки места
			uint64_t y[math::field25519::LIMBS];
			// Слова знаменателя точки места
			uint64_t z[math::field25519::LIMBS];
			// Слова произведения координат точки места
			uint64_t t[math::field25519::LIMBS];
		} comb_t;
		/**
		 * \~russian
		 * @brief Место гребёнки кратных точки основания Ed448
		 *
		 * @details Точка кривой в словах конечностей поля: элемент поля несёт свой
		 *          конструктор и литералом из слов не собирается, а место гребёнки -
		 *          данные, и записывается словами напрямую
		 *
		 * \~english
		 * @brief A place of the comb of the multiples of the Ed448 base point
		 *
		 * @details A point of the curve in the words of the field limbs: an element of the
		 *          field carries its own constructor and is not assembled by a literal of
		 *          words, while a place of the comb is data and is written by words directly
		 *
		 * \~
		 */
		typedef struct Comb448 {
			// Слова первой координаты точки места
			uint64_t x[math::field448::LIMBS];
			// Слова второй координаты точки места
			uint64_t y[math::field448::LIMBS];
			// Слова знаменателя точки места
			uint64_t z[math::field448::LIMBS];
			// Слова произведения координат точки места
			uint64_t t[math::field448::LIMBS];
		} comb448_t;
		/**
		 * \~russian
		 * @brief Функция розыска заготовленной гребёнки кратных точки основания
		 *
		 * @return указатель на первую строку гребёнки подряд либо nullptr, когда
		 *         кратные не заготовлены сборкой: отказом это не считается, и
		 *         умножение точки основания отступает к общей лестнице
		 *
		 * \~english
		 * @brief Function of the search of the prepared comb of the multiples of the base point
		 *
		 * @return the pointer to the first row of the comb in sequence or nullptr when the
		 *         multiples are not prepared by the build: that is not a refusal, and the
		 *         multiplication of the base point falls back to the common ladder
		 *
		 * \~
		 */
		const comb_t * prepared() noexcept;
		/**
		 * \~russian
		 * @brief Функция розыска заготовленной гребёнки кратных точки основания Ed448
		 *
		 * @return указатель на первую строку гребёнки подряд либо nullptr, когда
		 *         кратные не заготовлены сборкой: отказом это не считается, и
		 *         умножение точки основания отступает к общей лестнице
		 *
		 * \~english
		 * @brief Function of the search of the prepared comb of the multiples of the Ed448 base point
		 *
		 * @return the pointer to the first row of the comb in sequence or nullptr when the
		 *         multiples are not prepared by the build: that is not a refusal, and the
		 *         multiplication of the base point falls back to the common ladder
		 *
		 * \~
		 */
		const comb448_t * prepared448() noexcept;
	};
};

#endif
