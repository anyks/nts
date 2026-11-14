/**
 * @file sm2.cpp
 * @date 2026-10-04
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
 * @brief Модуль выработки и проверки электронной подписи SM2 по GB/T 32918.2-2016
 *
 * @details Подписываемое значение e есть хеш SM3 от Z_A ‖ M: Z_A вяжет подпись с
 *          опознавателем подписывающего, параметрами кривой и ключом проверки, и
 *          вырабатывается один раз при установке ключа. Выработка подписи идёт по
 *          разделу 6.1, проверка - по разделу 7.1 GB/T 32918.2-2016
 *
 * @note Значение Z_A вырабатывается по параметрам кривой SM2 из раздела 5
 *       GB/T 32918.5-2017: модуль рассчитан на эту кривую, и установка иной даёт
 *       Z_A, не совпадающий с выработанным контрагентом
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/sm2.hpp>
#include <digest/sm3.hpp>
#include <sys/wipe.hpp>

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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Первый коэффициент уравнения кривой SM2
	 *
	 * @details Раздел 5 GB/T 32918.5-2017
	 *
	 */
	static constexpr uint8_t FIRST[32] = {
		// Старшие байты коэффициента, затем нули и концевые байты 0xFC
		0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
	};

	/**
	 * @brief Второй коэффициент уравнения кривой SM2
	 *
	 * @details Раздел 5 GB/T 32918.5-2017
	 *
	 */
	static constexpr uint8_t SECOND[32] = {
		// Первые 17 байтов коэффициента кривой
		0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
		0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
	};

	/**
	 * @brief Первая координата образующей точки кривой SM2
	 *
	 * @details Раздел 5 GB/T 32918.5-2017
	 *
	 */
	static constexpr uint8_t BASE_X[32] = {
		// Первые 17 байтов абсциссы образующей точки
		0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
		0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
	};

	/**
	 * @brief Вторая координата образующей точки кривой SM2
	 *
	 * @details Раздел 5 GB/T 32918.5-2017
	 *
	 */
	static constexpr uint8_t BASE_Y[32] = {
		// Первые 17 байтов ординаты образующей точки
		0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
		0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
	};
};

/**
 * @brief Метод выработки значения Z_A
 *
 * @param id опознаватель подписывающего
 * @return   признак успешности выработки значения Z_A
 *
 */
bool nts::sign::Sm2::identify(const view_t & id) const noexcept {
	// Если опознаватель не задан либо длиннее отведённого разделом 5.5 GB/T 32918.2-2016
	if((id.data == nullptr) || (id.size == 0) || (id.size >= 8192))
		// Выводим отказ выработки значения Z_A
		return false;
	// Координаты ключа проверки подписи
	uint8_t x[math::NUMBER_SIZE], y[math::NUMBER_SIZE];
	// Если координаты ключа проверки подписи записать не удалось
	if(!this->_curve->coordinates(this->_point, x, y, this->_curve->size()))
		// Выводим отказ выработки значения Z_A
		return false;
	// Длина опознавателя в разрядах, записанная двумя байтами от старшего
	const uint8_t entl[2] = {
		// Старший байт длины опознавателя в разрядах
		static_cast <uint8_t> ((id.size * 8) >> 8),
		static_cast <uint8_t> (id.size * 8)
	};
	// Объект хеширования
	digest::sm3_t hasher;
	// Подаём длину опознавателя в разрядах
	hasher.update(view_t(entl, sizeof(entl)));
	// Подаём опознаватель подписывающего
	hasher.update(id);
	// Подаём первый коэффициент уравнения кривой
	hasher.update(view_t(FIRST, sizeof(FIRST)));
	// Подаём второй коэффициент уравнения кривой
	hasher.update(view_t(SECOND, sizeof(SECOND)));
	// Подаём первую координату образующей точки
	hasher.update(view_t(BASE_X, sizeof(BASE_X)));
	// Подаём вторую координату образующей точки
	hasher.update(view_t(BASE_Y, sizeof(BASE_Y)));
	// Подаём первую координату ключа проверки подписи
	hasher.update(view_t(x, this->_curve->size()));
	// Подаём вторую координату ключа проверки подписи
	hasher.update(view_t(y, this->_curve->size()));
	// Снимаем выработанное значение Z_A
	const bool result = hasher.finish(this->_za, sizeof(this->_za));
	// Затирание координат ключа проверки подписи
	wipe(x, sizeof(x));
	// Затирание координат ключа проверки подписи
	wipe(y, sizeof(y));
	// Выводим признак успешности выработки значения Z_A
	return result;
}
/**
 * @brief Метод смены опознавателя подписывающего
 *
 * @param id новый опознаватель подписывающего
 * @return   признак успешности смены опознавателя
 *
 */
bool nts::sign::Sm2::reidentify(const view_t & id) const noexcept {
	// Если кривая не установлена либо ключ проверки подписи не установлен
	if((this->_curve == nullptr) || !this->_public)
		// Выводим отказ смены опознавателя
		return false;
	// Выводим итог выработки значения Z_A
	return this->identify(id);
}
/**
 * @brief Метод проверки готовности модуля к работе
 *
 * @return признак того, что кривая установлена
 *
 */
bool nts::sign::Sm2::ready() const noexcept {
	// Выводим признак того, что кривая установлена
	return (this->_curve != nullptr);
}
/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах
 *
 */
size_t nts::sign::Sm2::size() const noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим нулевой размер подписи
		return 0;
	// Выводим размер подписи: два числа длиной в порядок подгруппы
	return (this->_curve->order().size() * 2);
}
/**
 * @brief Метод установки эллиптической кривой
 *
 * @param curve устанавливаемая эллиптическая кривая
 * @return      признак успешности установки эллиптической кривой
 *
 */
bool nts::sign::Sm2::start(const curve::curve_t & curve) noexcept {
	// Сброс состояния модуля
	this->clear();
	// Если кривая не готова к работе
	if(!curve.ready())
		// Выводим отказ установки кривой
		return false;
	// Запоминаем установленную кривую
	this->_curve = &curve;
	// Запоминаем разрядность порядка подгруппы точек кривой
	this->_bits = (curve.order().size() * 8);
	// Выводим успешность установки кривой
	return true;
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void nts::sign::Sm2::clear() noexcept {
	// Сбрасываем признак установленного ключа подписи
	this->_secret = false;
	// Сбрасываем признак установленного ключа проверки подписи
	this->_public = false;
	// Сбрасываем разрядность порядка подгруппы точек кривой
	this->_bits = 0;
	// Сбрасываем установленную кривую
	this->_curve = nullptr;
	// Затирание ключа подписи
	wipe(this->_key.words, sizeof(this->_key.words));
	// Затирание ключа проверки подписи
	wipe(&this->_point, sizeof(this->_point));
	// Затирание выработанного значения Z_A
	wipe(this->_za, sizeof(this->_za));
}
/**
 * @brief Метод установки ключа подписи
 *
 * @param secret устанавливаемый ключ подписи, записанный от старшего байта к младшему
 * @param id     опознаватель подписывающего для выработки Z_A
 * @return       признак успешности установки ключа подписи
 *
 */
bool nts::sign::Sm2::secret(const view_t & secret, const view_t & id) noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим отказ установки ключа подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Если ключ подписи не задан либо его длина не та
	if((secret.data == nullptr) || (secret.size == 0) || (secret.size > order.size()))
		// Выводим отказ установки ключа подписи
		return false;
	// Ключ подписи в виде числа
	math::number_t key;
	// Если ключ подписи разобрать не удалось либо он в ноль обратился
	if(!order.load(secret, key) || order.zero(key)){
		// Затирание разобранного ключа подписи
		wipe(key.words, sizeof(key.words));
		// Выводим отказ установки ключа подписи
		return false;
	}
	// Ключ проверки подписи, выработанный из ключа подписи
	curve::point_t point;
	// Умножение образующей точки на ключ подписи
	this->_curve->product(key, point);
	// Если ключ проверки подписи оказался бесконечно удалённым
	if(this->_curve->infinity(point)){
		// Затирание ключа проверки подписи
		wipe(&point, sizeof(point));
		// Затирание разобранного ключа подписи
		wipe(key.words, sizeof(key.words));
		// Выводим отказ установки ключа подписи
		return false;
	}
	// Переносим ключ подписи в состояние модуля
	this->_key = key;
	// Переносим ключ проверки подписи в состояние модуля
	this->_point = point;
	// Запоминаем, что ключ подписи установлен
	this->_secret = true;
	// Запоминаем, что ключ проверки подписи установлен
	this->_public = true;
	// Выводим итог выработки значения Z_A
	return this->identify(id);
}
/**
 * @brief Метод установки ключа проверки подписи
 *
 * @param x  первая координата ключа проверки подписи
 * @param y  вторая координата ключа проверки подписи
 * @param id опознаватель подписывающего для выработки Z_A
 * @return   признак успешности установки ключа проверки подписи
 *
 */
bool nts::sign::Sm2::key(const view_t & x, const view_t & y, const view_t & id) noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим отказ установки ключа проверки подписи
		return false;
	// Ключ проверки подписи в виде точки кривой
	curve::point_t point;
	// Если точка кривой не принадлежит
	if(!this->_curve->point(x, y, point))
		// Выводим отказ установки ключа проверки подписи
		return false;
	// Переносим ключ проверки подписи в состояние модуля
	this->_point = point;
	// Запоминаем, что ключ проверки подписи установлен
	this->_public = true;
	// Выводим итог выработки значения Z_A
	return this->identify(id);
}
/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param x    место, в которое записывается первая координата ключа проверки подписи
 * @param y    место, в которое записывается вторая координата ключа проверки подписи
 * @param size размер места, в которое записывается всякая координата
 * @return     признак успешности получения ключа проверки подписи
 *
 */
bool nts::sign::Sm2::key(uint8_t * x, uint8_t * y, const size_t size) const noexcept {
	// Если кривая не установлена либо ключ проверки подписи не установлен
	if((this->_curve == nullptr) || !this->_public)
		// Выводим отказ получения ключа проверки подписи
		return false;
	// Выводим итог записи координат ключа проверки подписи
	return this->_curve->coordinates(this->_point, x, y, size);
}
/**
 * @brief Метод выработки подписи переданным случайным числом
 *
 * @param message подписываемое сообщение
 * @param random  случайное число выработки подписи, записанное от старшего байта к младшему
 * @param result  место, в которое помещается подпись
 * @return        признак успешности выработки подписи
 *
 */
bool nts::sign::Sm2::make(const view_t & message, const view_t & random, uint8_t * result) const noexcept {
	// Если кривая не установлена либо ключ подписи не установлен
	if((this->_curve == nullptr) || !this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Подписываемое значение e = SM3(Z_A ‖ M)
	uint8_t hashed[32];
	// Объект хеширования
	digest::sm3_t hasher;
	// Подаём выработанное значение Z_A
	hasher.update(view_t(this->_za, sizeof(this->_za)));
	// Подаём подписываемое сообщение
	hasher.update(message);
	// Если подписываемое значение снять не удалось
	if(!hasher.finish(hashed, sizeof(hashed)))
		// Выводим отказ выработки подписи
		return false;
	// Подписываемое значение в виде числа
	math::number_t item;
	// Если подписываемое значение обратить в число не удалось
	if(!order.reduce(view_t(hashed, sizeof(hashed)), item)){
		// Затирание подписываемого значения
		wipe(hashed, sizeof(hashed));
		// Выводим отказ выработки подписи
		return false;
	}
	// Случайное число выработки подписи
	math::number_t number;
	// Первая и вторая части подписи
	math::number_t first, second;
	// Значения в области Монтгомери, участвующие в выработке подписи
	math::number_t entered, item2;
	// Кратная точка образующей по случайному числу
	curve::point_t point;
	// Место, в которое записывается первая координата кратной точки
	uint8_t buffer[math::NUMBER_SIZE];
	/**
	 * Случайное число и всё, что из него выведено, секретны: всякий отказ ниже
	 * ведёт к общему затиранию, оттого признак успеха копится, а не выводится
	 */
	bool ok = (order.load(random, number) && !order.zero(number));
	// Если случайное число разобрано и в ноль не обратилось
	if(ok){
		// Умножение образующей точки на случайное число
		this->_curve->product(number, point);
		/**
		 * Первая часть подписи есть сумма подписываемого значения и первой координаты
		 * кратной точки по порядку подгруппы: r = (e + x1) mod n по разделу 6.1
		 * GB/T 32918.2-2016; нулевая часть и r + k = n велят заменить случайное число
		 */
		ok = (
			this->_curve->coordinates(point, buffer, nullptr, this->_curve->size()) &&
			order.reduce(view_t(buffer, this->_curve->size()), first)
		);
	}
	// Если первая координата кратной точки приведена
	if(ok){
		// Приведение первой координаты в область Монтгомери
		order.enter(first, entered);
		// Приведение подписываемого значения в область Монтгомери
		order.enter(item, item2);
		// Складываем подписываемое значение с первой координатой
		order.add(entered, item2, first);
		// Вывод первой части подписи из области Монтгомери
		order.leave(first, first);
		// Если первая часть подписи в ноль обратилась, случайное число подлежит замене
		ok = !order.zero(first);
	}
	// Если первая часть подписи выработана
	if(ok){
		// Сумма первой части подписи со случайным числом: r + k
		math::number_t sum;
		// Приведение первой части подписи в область Монтгомери
		order.enter(first, entered);
		// Приведение случайного числа в область Монтгомери
		order.enter(number, item2);
		// Складываем первую часть подписи со случайным числом
		order.add(entered, item2, sum);
		// Вывод суммы из области Монтгомери
		order.leave(sum, sum);
		// Если сумма обратилась в ноль, то r + k = n, и случайное число подлежит замене
		ok = !order.zero(sum);
		// Затирание суммы первой части подписи со случайным числом
		wipe(sum.words, sizeof(sum.words));
	}
	// Если случайное число годно
	if(ok){
		/**
		 * Вторая часть подписи есть s = (k − r·d) / (1 + d) mod n по разделу 6.1
		 * GB/T 32918.2-2016; нулевая часть велит заменить случайное число
		 */
		// Приведение первой части подписи в область Монтгомери
		order.enter(first, entered);
		// Приведение ключа подписи в область Монтгомери
		order.enter(this->_key, item2);
		// Умножение первой части подписи на ключ подписи: r·d
		order.multiply(entered, item2, second);
		// Приведение случайного числа в область Монтгомери
		order.enter(number, entered);
		// Вычитаем произведение из случайного числа: k − r·d
		order.subtract(entered, second, second);
		// Единица порядка подгруппы в виде числа
		math::number_t unit;
		// Записываем единицу от старшего байта
		const uint8_t one[1] = {0x01};
		// Если единицу разобрать не удалось
		if(!order.load(view_t(one, sizeof(one)), unit))
			// Запоминаем отказ разбора единицы
			ok = false;
		// Если единица разобрана
		if(ok){
			// Приведение ключа подписи в область Монтгомери
			order.enter(this->_key, entered);
			// Приведение единицы в область Монтгомери
			order.enter(unit, item2);
			// Складываем ключ подписи с единицей: 1 + d
			order.add(entered, item2, entered);
			/**
			 * Обращение суммы ведётся возведением в степень с наложением маски
			 * на всяком разряде показателя: время его от ключа подписи не зависит
			 */
			order.invert(entered, item2);
			// Умножение разности на обращённую сумму: (k − r·d) / (1 + d)
			order.multiply(second, item2, second);
			// Вывод второй части подписи из области Монтгомери
			order.leave(second, second);
			// Если вторая часть подписи в ноль обратилась, случайное число подлежит замене
			ok = !order.zero(second);
			// Затирание единицы порядка подгруппы
			wipe(unit.words, sizeof(unit.words));
		}
	}
	// Если обе части подписи выработаны
	if(ok){
		// Записываем первую часть подписи
		ok = order.store(first, result, order.size());
		// Если первая часть подписи записана
		if(ok)
			// Записываем вторую часть подписи
			ok = order.store(second, result + order.size(), order.size());
	}
	// Затирание подписываемого значения
	wipe(hashed, sizeof(hashed));
	// Затирание первой координаты кратной точки
	wipe(buffer, sizeof(buffer));
	// Затирание кратной точки образующей
	wipe(&point, sizeof(point));
	// Затирание промежуточных значений выработки подписи
	wipe(entered.words, sizeof(entered.words));
	// Затирание промежуточных значений выработки подписи
	wipe(item2.words, sizeof(item2.words));
	// Затирание второй части подписи
	wipe(second.words, sizeof(second.words));
	// Затирание первой части подписи
	wipe(first.words, sizeof(first.words));
	// Затирание случайного числа выработки подписи
	wipe(number.words, sizeof(number.words));
	// Выводим признак успешности выработки подписи
	return ok;
}
/**
 * @brief Метод проверки подписи
 *
 * @param message   подписанное сообщение
 * @param signature проверяемая подпись
 * @return          признак того, что подпись сошлась
 *
 */
bool nts::sign::Sm2::check(const view_t & message, const view_t & signature) const noexcept {
	// Если кривая не установлена либо ключ проверки подписи не установлен
	if((this->_curve == nullptr) || !this->_public)
		// Выводим отказ проверки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Если подпись не занимает двух чисел длиной в порядок подгруппы
	if((signature.data == nullptr) || (signature.size != (order.size() * 2)))
		// Выводим отказ проверки подписи
		return false;
	// Части проверяемой подписи
	math::number_t first, second;
	/**
	 * Раздел 7.1 GB/T 32918.2-2016: обе части подписи обязаны лежать в отрезке
	 * [1, n-1]; разбор отвергает числа не меньше порядка, а ноль отвергается отдельно
	 */
	if(!order.load(view_t(signature.data, order.size()), first))
		// Выводим отказ проверки подписи
		return false;
	// Если вторую часть подписи разобрать не удалось
	if(!order.load(view_t(signature.data + order.size(), order.size()), second))
		// Выводим отказ проверки подписи
		return false;
	// Если всякая из частей подписи обратилась в ноль
	if(order.zero(first) || order.zero(second))
		// Выводим отказ проверки подписи
		return false;
	// Подписываемое значение e' = SM3(Z_A ‖ M)
	uint8_t hashed[32];
	// Объект хеширования
	digest::sm3_t hasher;
	// Подаём выработанное значение Z_A
	hasher.update(view_t(this->_za, sizeof(this->_za)));
	// Подаём подписанное сообщение
	hasher.update(message);
	// Если подписываемое значение снять не удалось
	if(!hasher.finish(hashed, sizeof(hashed)))
		// Выводим отказ проверки подписи
		return false;
	// Подписываемое значение в виде числа
	math::number_t item;
	// Если подписываемое значение обратить в число не удалось
	if(!order.reduce(view_t(hashed, sizeof(hashed)), item)){
		// Затирание подписываемого значения
		wipe(hashed, sizeof(hashed));
		// Выводим отказ проверки подписи
		return false;
	}
	// Сумма частей подписи: t = (r' + s') mod n
	math::number_t sum;
	// Значения в области Монтгомери, участвующие в проверке подписи
	math::number_t entered, item2;
	// Приведение первой части подписи в область Монтгомери
	order.enter(first, entered);
	// Приведение второй части подписи в область Монтгомери
	order.enter(second, item2);
	// Складываем части подписи
	order.add(entered, item2, sum);
	// Вывод суммы из области Монтгомери
	order.leave(sum, sum);
	// Если сумма частей подписи обратилась в ноль
	if(order.zero(sum)){
		// Затирание суммы частей подписи
		wipe(sum.words, sizeof(sum.words));
		// Выводим отказ проверки подписи
		return false;
	}
	// Образующая точка подгруппы точек кривой
	curve::point_t base;
	// Получаем образующую точку подгруппы точек кривой
	this->_curve->base(base);
	// Сумма кратных точек проверки подписи: s'·G + t·P
	curve::point_t total;
	/**
	 * Сумма кратных считается разом: удвоения у обоих кратных общие, и обходится она
	 * вдвое дешевле двух умножений порознь. Зависимость времени работы от чисел здесь
	 * не в счёт: и числа, и точки сличения подписи открыты обеим сторонам
	 */
	this->_curve->combine(base, second, this->_point, sum, total);
	// Затирание суммы частей подписи
	wipe(sum.words, sizeof(sum.words));
	// Если сумма кратных точек оказалась бесконечно удалённой
	if(this->_curve->infinity(total))
		// Выводим отказ проверки подписи
		return false;
	// Место, в которое записывается первая координата суммы кратных точек
	uint8_t buffer[math::NUMBER_SIZE];
	// Если координаты суммы кратных точек записать не удалось
	if(!this->_curve->coordinates(total, buffer, nullptr, this->_curve->size()))
		// Выводим отказ проверки подписи
		return false;
	// Приведённая первая координата суммы кратных точек
	math::number_t reduced;
	// Если первую координату суммы привести по порядку подгруппы не удалось
	if(!order.reduce(view_t(buffer, this->_curve->size()), reduced))
		// Выводим отказ проверки подписи
		return false;
	// Значение сличения: R = (e' + x1') mod n
	math::number_t compared;
	// Приведение первой координаты в область Монтгомери
	order.enter(reduced, entered);
	// Приведение подписываемого значения в область Монтгомери
	order.enter(item, item2);
	// Складываем подписываемое значение с первой координатой
	order.add(entered, item2, compared);
	// Вывод значения сличения из области Монтгомери
	order.leave(compared, compared);
	// Затирание подписываемого значения
	wipe(hashed, sizeof(hashed));
	// Затирание первой координаты суммы кратных точек
	wipe(buffer, sizeof(buffer));
	// Затирание суммы кратных точек проверки подписи
	wipe(&total, sizeof(total));
	// Выводим признак совпадения значения сличения с первой частью подписи
	return order.equal(compared, first);
}
/**
 * @brief Конструктор
 *
 */
nts::sign::Sm2::Sm2() noexcept : _secret(false), _public(false), _bits(0), _curve(nullptr) {
	// Затирание выработанного значения Z_A
	wipe(this->_za, sizeof(this->_za));
}
/**
 * @brief Деструктор
 *
 */
nts::sign::Sm2::~Sm2() noexcept {
	// Сброс состояния модуля
	this->clear();
}
