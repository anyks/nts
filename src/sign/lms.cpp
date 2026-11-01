/**
 * @file lms.cpp
 * @date 2026-10-06
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
 * @brief Модуль подписей Лейтона-Микали —
 *        проверка подписи LMS и HSS по RFC 8554 и SP 800-208
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/lms.hpp>
#include <digest/hash.hpp>
#include <sys/wipe.hpp>

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
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * Доменные константы записей: раздел 4 RFC 8554
	 */
	static constexpr uint16_t D_PBLC = 0x8080;
	// Доменная константа сообщения
	static constexpr uint16_t D_MESG = 0x8181;
	// Доменная константа листа
	static constexpr uint16_t D_LEAF = 0x8282;
	// Доменная константа внутреннего узла
	static constexpr uint16_t D_INTR = 0x8383;

	/**
	 * Наибольшая длина хеша SHA-256 в байтах
	 */
	static constexpr size_t M32 = 32;

	/**
	 * Наибольшее число звеньев цепочек Винтерница (при w = 1)
	 */
	static constexpr size_t P_MAX = 265;

	/**
	 * Наибольшее число уровней HSS по SP 800-208
	 */
	static constexpr size_t LEVELS_MAX = 8;

	/**
	 * @brief Функция чтения четырёхбайтового числа старшим байтом вперёд
	 *
	 * @param data место чтения
	 * @return     прочитанное число
	 *
	 */
	static uint32_t u32(const uint8_t * data) noexcept {
		// Складываем число из байтов
		return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) | (static_cast <uint32_t> (data[2]) << 8) | data[3]);
	}

	/**
	 * @brief Функция записи двухбайтового числа старшим байтом вперёд
	 *
	 * @param value  записываемое число
	 * @param result место записи
	 *
	 */
	static void u16(const uint16_t value, uint8_t * result) noexcept {
		// Записываем байты числа
		result[0] = static_cast <uint8_t> (value >> 8);
		// Записываем младший байт числа
		result[1] = static_cast <uint8_t> (value);
	}

	/**
	 * @brief Функция извлечения коэффициента Винтерница
	 *
	 * @param S строка, из которой извлекается коэффициент
	 * @param i порядковый номер w-разрядного значения
	 * @param w разрядность значения: 1, 2, 4 либо 8
	 * @return  значение коэффициента
	 *
	 * @details Раздел 3.1 RFC 8554: coef(S, i, w)
	 *
	 */
	static uint8_t coef(const uint8_t * S, const size_t i, const uint8_t w) noexcept {
		// Сдвиг значения внутри байта
		const uint8_t shift = static_cast <uint8_t> (8 - (w * (i % (8 / w)) + w));
		// Маска w-разрядного значения
		const uint8_t mask = static_cast <uint8_t> ((1 << w) - 1);
		// Извлекаем значение из байта
		return static_cast <uint8_t> ((S[(i * w) / 8] >> shift) & mask);
	}

	/**
	 * @brief Функция вычисления контрольной суммы строки
	 *
	 * @param S  строка из n байтов
	 * @param n  длина строки в байтах
	 * @param w  разрядность значения
	 * @param ls сдвиг контрольной суммы влево
	 * @return   контрольная сумма
	 *
	 * @details Алгоритм 2 RFC 8554: Cksm
	 *
	 */
	static uint16_t cksm(const uint8_t * S, const size_t n, const uint8_t w, const uint8_t ls) noexcept {
		// Накопитель суммы
		uint16_t sum = 0;
		/**
		 * Проходим по w-разрядным значениям строки
		 */
		for(size_t i = 0; i < (n * 8 / w); i++)
			// Накапливаем сумму дополнений
			sum = static_cast <uint16_t> (sum + ((1 << w) - 1) - coef(S, i, w));
		// Выводим сдвинутую сумму
		return static_cast <uint16_t> (sum << ls);
	}

	/**
	 * @brief Сведения о наборе параметров LM-OTS
	 *
	 */
	typedef struct OtsParams {
		// Длина хеша в байтах
		size_t n;
		// Разрядность значения Винтерница
		uint8_t w;
		// Число звеньев цепочек
		size_t p;
		// Сдвиг контрольной суммы
		uint8_t ls;
	} ots_params_t;

	/**
	 * @brief Функция получения сведений о наборе LM-OTS по коду типа
	 *
	 * @param type   код типа LM-OTS
	 * @param params место, в которое помещаются сведения
	 * @return       признак известного кода типа
	 *
	 * @details Таблица 1 RFC 8554
	 *
	 */
	static bool otsParams(const uint32_t type, ots_params_t & params) noexcept {
		/**
		 * По коду типа
		 */
		switch(type){
			// LMOTS_SHA256_N32_W1
			case 1: params.n = 32; params.w = 1; params.p = 265; params.ls = 7; return true;
			// LMOTS_SHA256_N32_W2
			case 2: params.n = 32; params.w = 2; params.p = 133; params.ls = 6; return true;
			// LMOTS_SHA256_N32_W4
			case 3: params.n = 32; params.w = 4; params.p = 67; params.ls = 4; return true;
			// LMOTS_SHA256_N32_W8
			case 4: params.n = 32; params.w = 8; params.p = 34; params.ls = 0; return true;
			// Код типа неизвестен
			default: return false;
		}
	}

	/**
	 * @brief Функция получения высоты дерева LMS по коду типа
	 *
	 * @param type код типа LMS
	 * @return     высота дерева, ноль у неизвестного кода
	 *
	 * @details Таблица 2 RFC 8554: у всех наборов m = 32, различается лишь высота
	 *
	 */
	static size_t lmsHeight(const uint32_t type) noexcept {
		/**
		 * По коду типа
		 */
		switch(type){
			// LMS_SHA256_M32_H5
			case 5: return 5;
			// LMS_SHA256_M32_H10
			case 6: return 10;
			// LMS_SHA256_M32_H15
			case 7: return 15;
			// LMS_SHA256_M32_H20
			case 8: return 20;
			// LMS_SHA256_M32_H25
			case 9: return 25;
			// Код типа неизвестен
			default: return 0;
		}
	}

	/**
	 * @brief Функция вычисления ключа-кандидата LM-OTS из подписи
	 *
	 * @param signature подпись LM-OTS: тип, C, y[0..p-1]
	 * @param message   сообщение
	 * @param I         опознаватель ключа LMS (16 байтов)
	 * @param q         номер листа
	 * @param pubtype   ожидаемый код типа LM-OTS
	 * @param result    место, в которое помещается ключ-кандидат (n байтов)
	 * @return          признак успешности вычисления
	 *
	 * @details Алгоритм 4б RFC 8554
	 *
	 */
	static bool otsCandidate(const view_t & signature, const view_t & message, const uint8_t * I, const uint32_t q, const uint32_t pubtype, uint8_t * result) noexcept {
		// Если подпись короче кода типа
		if(signature.size < 4)
			// Выводим отрицательный результат - подпись короче кода типа
			return false;
		// Код типа подписи
		const uint32_t sigtype = u32(signature.data);
		// Если код типа подписи не отвечает ключу
		if(sigtype != pubtype)
			// Выводим отрицательный результат - тип подписи не отвечает ключу
			return false;
		// Сведения о наборе параметров
		ots_params_t params;
		// Если код типа неизвестен
		if(!otsParams(pubtype, params))
			// Выводим отрицательный результат - тип подписи неизвестен
			return false;
		// Если длина подписи не отвечает набору
		if(signature.size != 4 + params.n * (params.p + 1))
			// Выводим отрицательный результат - длина подписи не отвечает набору
			return false;
		// Случайное число C подписи
		const uint8_t * C = signature.data + 4;
		// Звенья цепочек подписи
		const uint8_t * y = C + params.n;
		// Объект хеширования
		digest::hasher_t hasher(digest::hash_t::SHA256);
		// Место хеша сообщения Q
		uint8_t Q[M32];
		// Буфер записи номера листа
		uint8_t qBytes[4];
		// Записываем номер листа
		qBytes[0] = static_cast <uint8_t> (q >> 24);
		// Записываем второй байт номера листа
		qBytes[1] = static_cast <uint8_t> (q >> 16);
		// Записываем третий байт номера листа
		qBytes[2] = static_cast <uint8_t> (q >> 8);
		// Записываем младший байт номера листа
		qBytes[3] = static_cast <uint8_t> (q);
		// Буфер записи чисел
		uint8_t number[4];
		// Подаём опознаватель ключа
		hasher.update(view_t(I, 16));
		// Подаём номер листа
		hasher.update(view_t(qBytes, 4));
		// Записываем доменную константу сообщения
		u16(D_MESG, number);
		// Подаём доменную константу
		hasher.update(view_t(number, 2));
		// Подаём случайное число
		hasher.update(view_t(C, params.n));
		// Подаём сообщение
		hasher.update(message);
		// Если хеш сообщения снять не удалось
		if(!hasher.finish(Q, params.n))
			// Выводим отрицательный результат - хеш не снят
			return false;
		// Контрольная сумма хеша сообщения
		const uint16_t sum = cksm(Q, params.n, params.w, params.ls);
		// Записываем контрольную сумму старшим байтом вперёд
		uint8_t sumBytes[2];
		// Переводим контрольную сумму в байты
		u16(sum, sumBytes);
		// Место звеньев итога z
		uint8_t z[P_MAX][M32];
		/**
		 * Проходим по звеньям цепочек
		 */
		for(size_t i = 0; i < params.p; i++){
			// Коэффициент звена из хеша сообщения либо контрольной суммы
			const uint8_t a = ((i < (params.n * 8 / params.w)) ? coef(Q, i, params.w) : coef(sumBytes, i - (params.n * 8 / params.w), params.w));
			// Начальное значение звена из подписи
			::memcpy(z[i], y + i * params.n, params.n);
			/**
			 * Доводим цепочку Винтерница до конца
			 */
			for(size_t j = a; j < ((static_cast <size_t> (1) << params.w) - 1); j++){
				// Сбрасываем состояние хеширования
				hasher.reset(digest::hash_t::SHA256);
				// Подаём опознаватель ключа
				hasher.update(view_t(I, 16));
				// Подаём номер листа
				hasher.update(view_t(qBytes, 4));
				// Записываем номер звена
				u16(static_cast <uint16_t> (i), number);
				// Подаём номер звена
				hasher.update(view_t(number, 2));
				// Записываем номер повтора
				number[0] = static_cast <uint8_t> (j);
				// Подаём номер повтора
				hasher.update(view_t(number, 1));
				// Подаём текущее значение звена
				hasher.update(view_t(z[i], params.n));
				// Если очередной хеш цепочки снять не удалось
				if(!hasher.finish(z[i], params.n)){
					// Выполняем затирание рабочих областей
					wipe(z, sizeof(z));
					wipe(Q, sizeof(Q));
					// Выводим отрицательный результат - подпись не выработана
					return false;
				}
			}
		}
		// Сбрасываем состояние хеширования
		hasher.reset(digest::hash_t::SHA256);
		// Подаём опознаватель ключа
		hasher.update(view_t(I, 16));
		// Подаём номер листа
		hasher.update(view_t(qBytes, 4));
		// Записываем доменную константу открытого ключа
		u16(D_PBLC, number);
		// Подаём доменную константу
		hasher.update(view_t(number, 2));
		/**
		 * Подаём звенья итога
		 */
		for(size_t i = 0; i < params.p; i++)
			// Подача очередного звена
			hasher.update(view_t(z[i], params.n));
		// Если ключ-кандидат снять не удалось
		if(!hasher.finish(result, params.n)){
			// Выполняем затирание рабочих областей
			wipe(z, sizeof(z));
			wipe(Q, sizeof(Q));
			// Выводим отрицательный результат - листовой ключ не собран
			return false;
		}
		// Выполняем затирание рабочих областей
		wipe(z, sizeof(z));
		wipe(Q, sizeof(Q));
		// Выводим признак успеха
		return true;
	}

	/**
	 * @brief Функция проверки подписи LMS
	 *
	 * @param key       открытый ключ LMS: тип, тип LM-OTS, I, K
	 * @param message   сообщение
	 * @param signature подпись LMS: q, подпись LM-OTS, тип, путь
	 * @return          признак подлинности подписи
	 *
	 * @details Алгоритмы 6 и 6а RFC 8554
	 *
	 */
	static bool lmsVerify(const view_t & key, const view_t & message, const view_t & signature) noexcept {
		// Если открытый ключ короче заголовка
		if(key.size < 24)
			// Выводим отрицательный результат - ключ короче заголовка
			return false;
		// Код типа LMS ключа
		const uint32_t pubtype = u32(key.data);
		// Код типа LM-OTS ключа
		const uint32_t otstype = u32(key.data + 4);
		// Высота дерева по коду типа
		const size_t h = lmsHeight(pubtype);
		// Если код типа неизвестен либо длина ключа не отвечает
		if((h == 0) || (key.size != 24 + M32))
			// Выводим отрицательный результат - тип либо длина ключа не отвечают
			return false;
		// Опознаватель ключа
		const uint8_t * I = key.data + 8;
		// Корень дерева открытого ключа
		const uint8_t * T = I + 16;
		// Если подпись короче заголовка
		if(signature.size < 12)
			// Выводим отрицательный результат - подпись короче заголовка
			return false;
		// Номер листа подписи
		const uint32_t q = u32(signature.data);
		// Код типа LM-OTS подписи
		const uint32_t sigots = u32(signature.data + 4);
		// Если код типа LM-OTS подписи не отвечает ключу
		if(sigots != otstype)
			// Выводим отрицательный результат - тип LM-OTS не отвечает ключу
			return false;
		// Сведения о наборе LM-OTS
		ots_params_t params;
		// Если код типа LM-OTS неизвестен
		if(!otsParams(otstype, params))
			// Выводим отрицательный результат - тип LM-OTS неизвестен
			return false;
		// Длина подписи LM-OTS
		const size_t otsLength = 4 + params.n * (params.p + 1);
		// Если подпись короче подписи LM-OTS и кода типа LMS
		if(signature.size < 8 + otsLength)
			// Выводим отрицательный результат - подпись усечена
			return false;
		// Код типа LMS подписи
		const uint32_t sigtype = u32(signature.data + 8 + otsLength - 4);
		// Если код типа LMS подписи не отвечает ключу
		if(sigtype != pubtype)
			// Выводим отрицательный результат - тип LMS не отвечает ключу
			return false;
		// Если номер листа вне дерева либо длина подписи не отвечает пути
		if((q >= (static_cast <uint32_t> (1) << h)) || (signature.size != 8 + otsLength + M32 * h))
			// Выводим отрицательный результат - лист вне дерева либо путь усечён
			return false;
		// Путь Меркла подписи
		const uint8_t * path = signature.data + 8 + otsLength;
		// Место ключа-кандидата LM-OTS
		uint8_t Kc[M32];
		// Подпись LM-OTS внутри подписи LMS (с кодом типа)
		const view_t otsSignature(signature.data + 4, otsLength);
		// Если ключ-кандидат вычислить не удалось
		if(!otsCandidate(otsSignature, message, I, q, otstype, Kc))
			// Выводим отрицательный результат - ключ не вычислен
			return false;
		// Объект хеширования
		digest::hasher_t hasher(digest::hash_t::SHA256);
		// Буфер записи чисел
		uint8_t number[4];
		// Номер узла листа
		uint32_t node = (static_cast <uint32_t> (1) << h) + q;
		// Место текущего значения узла
		uint8_t tmp[M32];
		// Подаём опознаватель ключа
		hasher.update(view_t(I, 16));
		// Записываем номер узла
		number[0] = static_cast <uint8_t> (node >> 24);
		// Записываем второй байт номера узла
		number[1] = static_cast <uint8_t> (node >> 16);
		// Записываем третий байт номера узла
		number[2] = static_cast <uint8_t> (node >> 8);
		// Записываем младший байт номера узла
		number[3] = static_cast <uint8_t> (node);
		// Подаём номер узла
		hasher.update(view_t(number, 4));
		// Записываем доменную константу листа
		u16(D_LEAF, number);
		// Подаём доменную константу
		hasher.update(view_t(number, 2));
		// Подаём ключ-кандидат
		hasher.update(view_t(Kc, M32));
		// Если хеш листа снять не удалось
		if(!hasher.finish(tmp, M32)){
			// Выполняем затирание рабочих областей
			wipe(tmp, sizeof(tmp));
			wipe(Kc, sizeof(Kc));
			// Выводим отрицательный результат - путь аутентификации не сошёлся
			return false;
		}
		// Поднимаемся по дереву к корню
		size_t level = 0;
		/**
		 * Пока не дойдём до корня
		 */
		while(node > 1){
			// Признак нечётного узла
			const bool odd = ((node & 1) != 0);
			// Переходим к родителю
			node >>= 1;
			// Сбрасываем состояние хеширования
			hasher.reset(digest::hash_t::SHA256);
			// Подаём опознаватель ключа
			hasher.update(view_t(I, 16));
			// Записываем номер родителя
			number[0] = static_cast <uint8_t> (node >> 24);
			// Записываем второй байт номера родителя
			number[1] = static_cast <uint8_t> (node >> 16);
			// Записываем третий байт номера родителя
			number[2] = static_cast <uint8_t> (node >> 8);
			// Записываем младший байт номера родителя
			number[3] = static_cast <uint8_t> (node);
			// Подаём номер родителя
			hasher.update(view_t(number, 4));
			// Записываем доменную константу внутреннего узла
			u16(D_INTR, number);
			// Подаём доменную константу
			hasher.update(view_t(number, 2));
			// Если узел нечётный, сперва идёт узел пути
			if(odd){
				// Подаём узел пути
				hasher.update(view_t(path + level * M32, M32));
				// Подаём текущее значение
				hasher.update(view_t(tmp, M32));
			// Иначе сперва идёт текущее значение
			} else {
				// Подаём текущее значение
				hasher.update(view_t(tmp, M32));
				// Подаём узел пути
				hasher.update(view_t(path + level * M32, M32));
			}
			// Если хеш родителя снять не удалось
			if(!hasher.finish(tmp, M32)){
				// Выполняем затирание рабочих областей
				wipe(tmp, sizeof(tmp));
				wipe(Kc, sizeof(Kc));
				// Выводим отрицательный результат - корневой ключ не сошёлся
				return false;
			}
			// Поднимаемся на уровень
			level++;
		}
		// Сличаем корень-кандидат с корнем открытого ключа
		const bool valid = (::memcmp(tmp, T, M32) == 0);
		// Выполняем затирание рабочих областей
		wipe(tmp, sizeof(tmp));
		wipe(Kc, sizeof(Kc));
		// Выводим итог сверки
		return valid;
	}
}

/**
 * @brief Функция проверки подписи LMS либо HSS
 *
 * @param key       открытый ключ: запись LMS либо HSS
 * @param message   проверяемое сообщение
 * @param signature проверяемая подпись: запись LMS либо HSS
 * @return          признак подлинности подписи
 *
 */
bool nts::sign::lms::verify(const view_t & key, const view_t & message, const view_t & signature) noexcept {
	// Если ключ, сообщение либо подпись не переданы
	if((key.data == nullptr) || (message.data == nullptr) || (signature.data == nullptr))
		// Выводим отрицательный результат - данные не переданы
		return false;
	// Если ключ короче кода числа уровней и типа LMS
	if(key.size < 8)
		// Выводим отрицательный результат - ключ короче заголовка
		return false;
	/**
	 * Различие записей LMS и HSS: у одноуровневого ключа LMS первые четыре байта -
	 * код типа LMS (5..9), а длина записи ровно 24 + m; у ключа HSS первые четыре
	 * байта - число уровней (1..8), а за ним идёт запись LMS верхнего уровня
	 */
	// Если длина ключа отвечает записи LMS, а первые байты - коду типа LMS
	if((key.size == 24 + M32) && (lmsHeight(u32(key.data)) != 0))
		// Выводим итог проверки подписи LMS
		return lmsVerify(key, message, signature);
	// Число уровней HSS
	const uint32_t levels = u32(key.data);
	// Если число уровней вне дозволенного
	if((levels < 1) || (levels > LEVELS_MAX))
		// Выводим отрицательный результат - число уровней вне дозволенного
		return false;
	/**
	 * Раздел 6 RFC 8554: у HSS открытый ключ - число уровней и открытый ключ LMS
	 * верхнего уровня; подпись - число подписанных открытых ключей (уровней минус
	 * один), затем по каждому уровню подпись LMS и открытый ключ следующего
	 * уровня, а за ними подпись LMS сообщения нижним уровнем
	 */
	// Если подпись короче числа подписанных ключей
	if(signature.size < 4)
		// Выводим отрицательный результат - подпись короче числа подписанных ключей
		return false;
	// Число подписанных открытых ключей в подписи
	const uint32_t signedKeys = u32(signature.data);
	// Если число подписанных ключей не отвечает числу уровней
	if(signedKeys != levels - 1)
		// Выводим отрицательный результат - число подписанных ключей не отвечает уровням
		return false;
	// Открытый ключ текущего уровня: запись LMS за числом уровней
	view_t current(key.data + 4, key.size - 4);
	// Место в подписи
	size_t offset = 4;
	/**
	 * Проходим по подписанным открытым ключам
	 */
	for(uint32_t level = 0; level < signedKeys; level++){
		// Если подпись короче номера листа и типа LM-OTS
		if(signature.size < offset + 8)
			// Выводим отрицательный результат - подпись короче номера листа и типа
			return false;
		// Код типа LM-OTS подписи уровня
		const uint32_t otstype = u32(signature.data + offset + 4);
		// Сведения о наборе LM-OTS
		ots_params_t params;
		// Если код типа LM-OTS неизвестен
		if(!otsParams(otstype, params))
			// Выводим отрицательный результат - тип LM-OTS неизвестен
			return false;
		// Длина подписи LM-OTS
		const size_t otsLength = 4 + params.n * (params.p + 1);
		// Если подпись короче подписи LMS уровня
		if(signature.size < offset + 8 + otsLength)
			// Выводим отрицательный результат - подпись короче подписи уровня
			return false;
		// Код типа LMS подписи уровня
		const uint32_t lmstype = u32(signature.data + offset + 8 + otsLength - 4);
		// Высота дерева уровня
		const size_t h = lmsHeight(lmstype);
		// Если код типа неизвестен
		if(h == 0)
			// Выводим отрицательный результат - тип LMS неизвестен
			return false;
		// Длина подписи LMS уровня
		const size_t lmsLength = 8 + otsLength + M32 * h;
		// Если подпись короче подписи LMS и открытого ключа следующего уровня
		if(signature.size < offset + lmsLength + 24 + M32)
			// Выводим отрицательный результат - подпись усечена
			return false;
		// Открытый ключ следующего уровня за подписью
		const view_t next(signature.data + offset + lmsLength, 24 + M32);
		// Подпись LMS уровня
		const view_t lmsSignature(signature.data + offset, lmsLength);
		// Если подпись открытого ключа следующего уровня не сошлась
		if(!lmsVerify(current, next, lmsSignature))
			// Выводим отрицательный результат - подпись ключа уровня не сошлась
			return false;
		// Переходим к следующему уровню
		current = next;
		// Сдвигаем место в подписи за подпись и открытый ключ уровня
		offset += lmsLength + 24 + M32;
	}
	// Подпись LMS сообщения нижним уровнем
	const view_t bottom(signature.data + offset, signature.size - offset);
	// Выводим итог проверки подписи сообщения нижним уровнем
	return lmsVerify(current, message, bottom);
}
