/**
 * @file patterns.cpp
 * @date 2026-09-07
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
 * @brief Таблица узоров рукопожатия Noise (§7.2 односторонние и основные, §7.3 отложенные)
 *
 * @details Узоры заданы данными: у каждого имя, предсообщения обеих сторон и до четырёх
 *          сообщений из знаков. Заранее разделённые ключи в таблице отсутствуют: их положение
 *          задаётся видоизменением и вставляется машиной рукопожатия
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <noise/noise.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён каркаса
	 */
	using namespace nts::noise;
	/**
	 * Краткие имена знаков
	 */
	static constexpr token_t E = token_t::E, S = token_t::S, EE = token_t::EE, ES = token_t::ES, SE = token_t::SE, SS = token_t::SS, EK = token_t::EKEM, SK = token_t::SKEM, _ = token_t::NONE;
	/**
	 * @brief Строка таблицы узоров
	 *
	 */
	typedef struct Row {
		// Узор
		pattern_t pattern;
		// Имя узора
		const char * title;
		// Предсообщения инициатора и отвечающего
		token_t initiator[2];
		// Предсообщения отвечающего
		token_t responder[2];
		// Число сообщений
		size_t count;
		// Знаки сообщений
		token_t messages[MESSAGES_MAX][TOKENS_MAX];
	} row_t;
	/**
	 * Таблица узоров
	 */
	static const row_t ROWS[] = {
		// Односторонние
		{pattern_t::N,    "N",    {_, _}, {S, _}, 1, {{E, ES, _, _, _, _, _, _}}},
		{pattern_t::K,    "K",    {S, _}, {S, _}, 1, {{E, ES, SS, _, _, _, _, _}}},
		{pattern_t::X,    "X",    {_, _}, {S, _}, 1, {{E, ES, S, SS, _, _, _, _}}},
		// Основные
		{pattern_t::NN,   "NN",   {_, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}}},
		{pattern_t::NK,   "NK",   {_, _}, {S, _}, 2, {{E, ES, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}}},
		{pattern_t::NX,   "NX",   {_, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, S, ES, _, _, _, _}}},
		{pattern_t::XN,   "XN",   {_, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {S, SE, _, _, _, _, _, _}}},
		{pattern_t::XK,   "XK",   {_, _}, {S, _}, 3, {{E, ES, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {S, SE, _, _, _, _, _, _}}},
		{pattern_t::XX,   "XX",   {_, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, S, ES, _, _, _, _}, {S, SE, _, _, _, _, _, _}}},
		{pattern_t::KN,   "KN",   {S, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, SE, _, _, _, _, _}}},
		{pattern_t::KK,   "KK",   {S, _}, {S, _}, 2, {{E, ES, SS, _, _, _, _, _}, {E, EE, SE, _, _, _, _, _}}},
		{pattern_t::KX,   "KX",   {S, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, SE, S, ES, _, _, _}}},
		{pattern_t::IN,   "IN",   {_, _}, {_, _}, 2, {{E, S, _, _, _, _, _, _}, {E, EE, SE, _, _, _, _, _}}},
		{pattern_t::IK,   "IK",   {_, _}, {S, _}, 2, {{E, ES, S, SS, _, _, _, _}, {E, EE, SE, _, _, _, _, _}}},
		{pattern_t::IX,   "IX",   {_, _}, {_, _}, 2, {{E, S, _, _, _, _, _, _}, {E, EE, SE, S, ES, _, _, _}}},
		// Отложенные
		{pattern_t::NK1,  "NK1",  {_, _}, {S, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, ES, _, _, _, _, _}}},
		{pattern_t::NX1,  "NX1",  {_, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, S, _, _, _, _, _}, {ES, _, _, _, _, _, _, _}}},
		{pattern_t::X1N,  "X1N",  {_, _}, {_, _}, 4, {{E, _, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::X1K,  "X1K",  {_, _}, {S, _}, 4, {{E, ES, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::XK1,  "XK1",  {_, _}, {S, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, ES, _, _, _, _, _}, {S, SE, _, _, _, _, _, _}}},
		{pattern_t::X1K1, "X1K1", {_, _}, {S, _}, 4, {{E, _, _, _, _, _, _, _}, {E, EE, ES, _, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::X1X,  "X1X",  {_, _}, {_, _}, 4, {{E, _, _, _, _, _, _, _}, {E, EE, S, ES, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::XX1,  "XX1",  {_, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, S, _, _, _, _, _}, {ES, S, SE, _, _, _, _, _}}},
		{pattern_t::X1X1, "X1X1", {_, _}, {_, _}, 4, {{E, _, _, _, _, _, _, _}, {E, EE, S, _, _, _, _, _}, {ES, S, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::K1N,  "K1N",  {S, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::K1K,  "K1K",  {S, _}, {S, _}, 3, {{E, ES, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::KK1,  "KK1",  {S, _}, {S, _}, 2, {{E, _, _, _, _, _, _, _}, {E, EE, SE, ES, _, _, _, _}}},
		{pattern_t::K1K1, "K1K1", {S, _}, {S, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, ES, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::K1X,  "K1X",  {S, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, S, ES, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::KX1,  "KX1",  {S, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, SE, S, _, _, _, _}, {ES, _, _, _, _, _, _, _}}},
		{pattern_t::K1X1, "K1X1", {S, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {E, EE, S, _, _, _, _, _}, {SE, ES, _, _, _, _, _, _}}},
		{pattern_t::I1N,  "I1N",  {_, _}, {_, _}, 3, {{E, S, _, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::I1K,  "I1K",  {_, _}, {S, _}, 3, {{E, ES, S, _, _, _, _, _}, {E, EE, _, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::IK1,  "IK1",  {_, _}, {S, _}, 2, {{E, S, _, _, _, _, _, _}, {E, EE, SE, ES, _, _, _, _}}},
		{pattern_t::I1K1, "I1K1", {_, _}, {S, _}, 3, {{E, S, _, _, _, _, _, _}, {E, EE, ES, _, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::I1X,  "I1X",  {_, _}, {_, _}, 3, {{E, S, _, _, _, _, _, _}, {E, EE, S, ES, _, _, _, _}, {SE, _, _, _, _, _, _, _}}},
		{pattern_t::IX1,  "IX1",  {_, _}, {_, _}, 3, {{E, S, _, _, _, _, _, _}, {E, EE, SE, S, _, _, _, _}, {ES, _, _, _, _, _, _, _}}},
		{pattern_t::I1X1, "I1X1", {_, _}, {_, _}, 3, {{E, S, _, _, _, _, _, _}, {E, EE, S, _, _, _, _, _}, {SE, ES, _, _, _, _, _, _}}},
		// PQNoise (Angel и др., CCS 2022, Figure 2): ekem - к временному ключу получателя, skem - к постоянному
		{pattern_t::PQN,  "pqN",  {_, _}, {S, _}, 1, {{SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQNN, "pqNN", {_, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {EK, _, _, _, _, _, _, _}}},
		{pattern_t::PQNK, "pqNK", {_, _}, {S, _}, 2, {{SK, E, _, _, _, _, _, _}, {EK, _, _, _, _, _, _, _}}},
		{pattern_t::PQNX, "pqNX", {_, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {EK, S, _, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQKN, "pqKN", {S, _}, {_, _}, 2, {{E, _, _, _, _, _, _, _}, {EK, SK, _, _, _, _, _, _}}},
		{pattern_t::PQKK, "pqKK", {S, _}, {S, _}, 2, {{SK, E, _, _, _, _, _, _}, {EK, SK, _, _, _, _, _, _}}},
		{pattern_t::PQKX, "pqKX", {S, _}, {_, _}, 3, {{E, _, _, _, _, _, _, _}, {EK, SK, S, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQXN, "pqXN", {_, _}, {_, _}, 4, {{E, _, _, _, _, _, _, _}, {EK, _, _, _, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQXK, "pqXK", {_, _}, {S, _}, 4, {{SK, E, _, _, _, _, _, _}, {EK, _, _, _, _, _, _, _}, {S, _, _, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQXX, "pqXX", {_, _}, {_, _}, 4, {{E, _, _, _, _, _, _, _}, {EK, S, _, _, _, _, _, _}, {SK, S, _, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}},
		{pattern_t::PQIN, "pqIN", {_, _}, {_, _}, 2, {{E, S, _, _, _, _, _, _}, {EK, SK, _, _, _, _, _, _}}},
		{pattern_t::PQIK, "pqIK", {_, _}, {S, _}, 2, {{SK, E, S, _, _, _, _, _}, {EK, SK, _, _, _, _, _, _}}},
		{pattern_t::PQIX, "pqIX", {_, _}, {_, _}, 3, {{E, S, _, _, _, _, _, _}, {EK, SK, S, _, _, _, _, _}, {SK, _, _, _, _, _, _, _}}}
	};
	/**
	 * @brief Функция поиска строки узора
	 *
	 * @param pattern узор
	 * @return        строка либо nullptr
	 *
	 */
	static const row_t * row(const pattern_t pattern) noexcept {
		/**
		 * Выполняем перебор таблицы
		 */
		for(size_t i = 0; i < (sizeof(ROWS) / sizeof(ROWS[0])); i++){
			// Если узор совпал
			if(ROWS[i].pattern == pattern)
				// Выводим строку
				return &ROWS[i];
		}
		// Выводим отсутствие
		return nullptr;
	}
	/**
	 * @brief Функция счёта знаков до первого пустого
	 *
	 * @param list  знаки
	 * @param limit предел числа знаков
	 * @return      число знаков
	 *
	 */
	static size_t measure(const token_t * list, const size_t limit) noexcept {
		// Число знаков
		size_t count = 0;
		/**
		 * Выполняем счёт знаков
		 */
		while((count < limit) && (list[count] != token_t::NONE))
			// Считаем знак
			count++;
		// Выводим число
		return count;
	}
};

/**
 * @brief Функция получения числа сообщений узора
 *
 * @param pattern узор рукопожатия
 * @return        число сообщений либо нуль у незнакомого узора
 *
 */
size_t nts::noise::messages(const pattern_t pattern) noexcept {
	// Строка узора
	const row_t * item = row(pattern);
	// Выводим число сообщений
	return ((item != nullptr) ? item->count : 0);
}
/**
 * @brief Функция получения знаков сообщения узора
 *
 * @param pattern узор рукопожатия
 * @param index   номер сообщения от нуля
 * @param result  указатель на знаки
 * @param count   число знаков
 * @return        признак того, что сообщение есть
 *
 */
bool nts::noise::tokens(const pattern_t pattern, const size_t index, const token_t *& result, size_t & count) noexcept {
	// Строка узора
	const row_t * item = row(pattern);
	// Если узора либо сообщения нет
	if((item == nullptr) || (index >= item->count)){
		// Сбрасываем указатель на знаки сообщения
		result = nullptr;
		// Сбрасываем число знаков
		count = 0;
		// Выводим отрицательный результат - узор негоден
		return false;
	}
	// Выводим знаки сообщения
	result = item->messages[index];
	// Выводим число знаков сообщения
	count = measure(result, TOKENS_MAX);
	// Число знаков сообщения выведено
	return true;
}
/**
 * @brief Функция получения знаков предсообщения узора
 *
 * @param pattern   узор рукопожатия
 * @param initiator признак предсообщения инициатора (иначе - отвечающего)
 * @param result    указатель на знаки
 * @param count     число знаков
 * @return          признак того, что узор знаком
 *
 */
bool nts::noise::premessage(const pattern_t pattern, const bool initiator, const token_t *& result, size_t & count) noexcept {
	// Строка узора
	const row_t * item = row(pattern);
	// Если узора нет
	if(item == nullptr){
		// Сбрасываем указатель на знаки предсообщения
		result = nullptr;
		// Сбрасываем число знаков
		count = 0;
		// Выводим отрицательный результат - узор негоден
		return false;
	}
	// Выводим знаки предсообщения
	result = (initiator ? item->initiator : item->responder);
	// Выводим число знаков предсообщения
	count = measure(result, 2);
	// Число знаков предсообщения выведено
	return true;
}
/**
 * @brief Функция получения имени узора
 *
 * @param pattern узор рукопожатия
 * @return        имя узора либо пустая строка
 *
 */
const char * nts::noise::title(const pattern_t pattern) noexcept {
	// Строка узора
	const row_t * item = row(pattern);
	// Выводим имя
	return ((item != nullptr) ? item->title : "");
}
/**
 * @brief Функция проверки, что узор относится к PQNoise
 *
 * @param pattern узор рукопожатия
 * @return        признак PQNoise
 *
 */
bool nts::noise::postquantum(const pattern_t pattern) noexcept {
	// Выводим признак по диапазону перечисления
	return ((pattern >= pattern_t::PQN) && (pattern <= pattern_t::PQIX));
}
