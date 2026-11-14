/**
 * @file gost.cpp
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
 * @brief Исходный файл модуля выработки и проверки электронной подписи —
 *        реализация по ГОСТ Р 34.10-2012
 *
 * @note Хеш подписываемого сообщения приводится по порядку подгруппы точек кривой
 *       разбором его байтов от старшего к младшему: разряды сверх порядка при этом
 *       не отбрасываются, а именно приводятся, как того и требует раздел 6.1
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <entropy/entropy.hpp>
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

	/**
	 * @brief Наибольшее число попыток выработки подписи
	 *
	 * @details Обращение в ноль всякой из частей подписи невероятно настолько же,
	 *          насколько невероятно угадывание ключа: десятка попыток довольно с
	 *          огромным запасом, а предел здесь стоит заслоном от вечного круга
	 *
	 */
	static constexpr size_t ATTEMPTS = 10;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Функция приведения хеша сообщения по порядку подгруппы точек кривой
	 *
	 * @details Раздел 6.1 ГОСТ Р 34.10-2012: нулевое приведённое значение заменяется
	 *          единицей, иначе подпись обратилась бы в тождество
	 *
	 * @param order  арифметика порядка подгруппы точек кривой
	 * @param digest приводимый хеш сообщения
	 * @param result место, в которое помещается приведённое значение
	 * @return       признак успешности приведения хеша сообщения
	 *
	 */
	static bool digest(const math::modulus_t & order, const view_t & value, math::number_t & result) noexcept {
		// Если хеш сообщения приведению не подлежит
		if(!order.reduce(value, result))
			// Выводим отказ приведения хеша сообщения
			return false;
		// Если приведённое значение обратилось в ноль
		if(order.zero(result))
			// Записываем единицу приведённым значением
			order.word(1, result);
		// Выводим успешность приведения хеша сообщения
		return true;
	}
};

/**
 * @brief Метод проверки готовности модуля к работе
 *
 * @return признак того, что кривая установлена
 *
 */
bool nts::sign::Gost::ready() const noexcept {
	// Выводим признак того, что кривая установлена
	return (this->_curve != nullptr);
}
/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах
 *
 */
size_t nts::sign::Gost::size() const noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим нулевой размер подписи
		return 0;
	// Выводим размер подписи в байтах
	return (this->_curve->order().size() * 2);
}
/**
 * @brief Метод получения верхнего предела длины подписи в записанном виде
 *
 * @return верхний предел длины подписи в байтах, ноль без ключа
 *
 */
size_t nts::sign::Gost::limit() const noexcept {
	// Подпись уходит наружу как есть: предел равен длине сырой подписи
	return this->size();
}
/**
 * @brief Метод установки эллиптической кривой
 *
 * @param curve устанавливаемая эллиптическая кривая
 * @return      признак успешности установки эллиптической кривой
 *
 */
bool nts::sign::Gost::start(const curve::curve_t & curve) noexcept {
	// Сброс прежнего состояния модуля
	this->clear();
	// Если устанавливаемая кривая к работе не готова
	if(!curve.ready())
		// Выводим отказ установки эллиптической кривой
		return false;
	// Запоминаем эллиптическую кривую выработки подписи
	this->_curve = &curve;
	// Выводим успешность установки эллиптической кривой
	return true;
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void nts::sign::Gost::clear() noexcept {
	// Затирание ключа проверки подписи
	wipe(&this->_point, sizeof(this->_point));
	// Затирание ключа подписи
	wipe(this->_key.words, sizeof(this->_key.words));
	// Сбрасываем эллиптическую кривую выработки подписи
	this->_curve = nullptr;
	// Снимаем признак того, что ключ проверки подписи установлен
	this->_public = false;
	// Снимаем признак того, что ключ подписи установлен
	this->_secret = false;
}
/**
 * @brief Метод установки ключа подписи
 *
 * @param secret устанавливаемый ключ подписи
 * @return       признак успешности установки ключа подписи
 *
 */
bool nts::sign::Gost::secret(const view_t & secret) noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим отказ установки ключа подписи
		return false;
	// Если ключ подписи разобрать не удалось
	if(!this->_curve->order().load(secret, this->_key))
		// Выводим отказ установки ключа подписи
		return false;
	// Если ключ подписи обратился в ноль
	if(this->_curve->order().zero(this->_key)){
		// Затирание ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ установки ключа подписи
		return false;
	}
	// Выработка ключа проверки подписи из ключа подписи
	this->_curve->product(this->_key, this->_point);
	// Устанавливаем признак того, что ключ проверки подписи установлен
	this->_public = true;
	// Устанавливаем признак того, что ключ подписи установлен
	this->_secret = true;
	// Выводим успешность установки ключа подписи
	return true;
}
/**
 * @brief Метод порождения долговременного ключа подписи
 *
 * @param secret место, в которое записывается ключ подписи, записанный от старшего байта к младшему
 * @param size   размер места ключа подписи
 * @return       признак успешности порождения ключа подписи
 *
 */
bool nts::sign::Gost::generate(uint8_t * secret, const size_t size) noexcept {
	// Если кривая не установлена либо место ключа подписи не передано
	if((this->_curve == nullptr) || (secret == nullptr))
		// Выводим отказ порождения ключа подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Если размер места не равен длине порядка подгруппы
	if(size != order.size())
		// Выводим отказ порождения ключа подписи
		return false;
	// Затирание прежнего ключа проверки подписи
	wipe(&this->_point, sizeof(this->_point));
	// Затирание прежнего ключа подписи
	wipe(this->_key.words, sizeof(this->_key.words));
	// Снимаем признак того, что ключ проверки подписи установлен
	this->_public = false;
	// Снимаем признак того, что ключ подписи установлен
	this->_secret = false;
	/**
	 * Ключ подписи берётся отбором из отрезка [1, q-1] отбором: источник выдаёт
	 * случайные байты длиной порядка и отбрасывает целиком всякое значение, не
	 * меньшее порядка либо нулевое, - приведение по модулю сместило бы ключ к
	 * младшим значениям, а смещение вскрывается по множеству подписей
	 */
	if(!entropy::number(order, this->_key)){
		// Затирание недовыработанного ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Если ключ подписи записать в переданное место не удалось
	if(!order.store(this->_key, secret, size)){
		// Затирание переданного места
		wipe(secret, size);
		// Затирание выработанного ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Выработка ключа проверки подписи из ключа подписи
	this->_curve->product(this->_key, this->_point);
	// Устанавливаем признак того, что ключ проверки подписи установлен
	this->_public = true;
	// Устанавливаем признак того, что ключ подписи установлен
	this->_secret = true;
	// Выводим успешность порождения ключа подписи
	return true;
}
/**
 * @brief Метод установки ключа проверки подписи
 *
 * @param x первая координата ключа проверки подписи
 * @param y вторая координата ключа проверки подписи
 * @return  признак успешности установки ключа проверки подписи
 *
 */
bool nts::sign::Gost::key(const view_t & x, const view_t & y) noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим отказ установки ключа
		return false;
	// Если ключ подписи уже установлен
	if(this->_secret){
		/**
		 * Открытый ключ выведен из закрытого при его установке: поданный обязан с ним
		 * сойтись, и тогда состояние не меняется; чужой открытый ключ отвергается.
		 * Затирать закрытый ключ молча нельзя: подпись отказала бы там, где ключ был
		 * в полном порядке
		 */
		curve::point_t given;
		// Если поданная точка кривой не принадлежит
		if(!this->_curve->point(x, y, given))
			// Выводим отказ установки ключа
			return false;
		// Координаты выведенного открытого ключа
		uint8_t ax[math::NUMBER_SIZE], ay[math::NUMBER_SIZE];
		// Координаты поданного открытого ключа
		uint8_t bx[math::NUMBER_SIZE], by[math::NUMBER_SIZE];
		// Размер координаты
		const size_t size = this->_curve->size();
		// Признак схождения ключей
		bool same = (this->_curve->coordinates(this->_point, ax, ay, size) && this->_curve->coordinates(given, bx, by, size));
		// Накопленное различие координат
		uint8_t difference = 0;
		/**
		 * Выполняем сличение координат за постоянное время
		 */
		for(size_t i = 0; i < size; i++)
			// Накапливаем различие
			difference = static_cast <uint8_t> (difference | (ax[i] ^ bx[i]) | (ay[i] ^ by[i]));
		// Выводим схождение поданного ключа с выведенным
		return (same && (difference == 0));
	}
	// Если точка ключа проверки кривой не принадлежит
	if(!this->_curve->point(x, y, this->_point))
		// Выводим отказ установки ключа
		return false;
	// Запоминаем, что ключ проверки установлен
	this->_public = true;
	// Выводим успешность установки ключа
	return true;
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
bool nts::sign::Gost::key(uint8_t * x, uint8_t * y, const size_t size) const noexcept {
	// Если кривая не установлена либо ключ проверки подписи не установлен
	if((this->_curve == nullptr) || !this->_public)
		// Выводим отказ получения ключа проверки подписи
		return false;
	// Выводим итог записи координат ключа проверки подписи
	return this->_curve->coordinates(this->_point, x, y, size);
}
/**
 * @brief Метод выработки подписи
 *
 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
 * @param random случайное число выработки подписи
 * @param result место, в которое помещается подпись
 * @return       признак успешности выработки подписи
 *
 */
bool nts::sign::Gost::make(const view_t & value, const view_t & random, uint8_t * result) const noexcept {
	// Если кривая не установлена либо ключ подписи не установлен
	if((this->_curve == nullptr) || !this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Приведённый хеш подписываемого сообщения
	math::number_t item;
	// Если хеш подписываемого сообщения привести не удалось
	if(!::digest(order, value, item))
		// Выводим отказ выработки подписи
		return false;
	// Случайное число выработки подписи
	math::number_t number;
	// Первая и вторая части подписи
	math::number_t first, second;
	// Значения в области Монтгомери, участвующие в выработке второй части подписи
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
		 * Первая часть подписи есть первая координата кратной точки, приведённая по
		 * порядку подгруппы; нулевая часть подписи велит заменить случайное число
		 */
		ok = (
			this->_curve->coordinates(point, buffer, nullptr, this->_curve->size()) &&
			order.reduce(view_t(buffer, this->_curve->size()), first) && !order.zero(first)
		);
	}
	// Если первая часть подписи выработана
	if(ok){
		// Приведение первой части подписи в область Монтгомери
		order.enter(first, entered);
		// Приведение ключа подписи в область Монтгомери
		order.enter(this->_key, item2);
		// Умножение первой части подписи на ключ подписи
		order.multiply(entered, item2, second);
		// Приведение случайного числа в область Монтгомери
		order.enter(number, entered);
		// Приведение хеша сообщения в область Монтгомери
		order.enter(item, item2);
		// Умножение случайного числа на хеш сообщения
		order.multiply(entered, item2, entered);
		// Складываем полученные произведения
		order.add(second, entered, second);
		// Вывод второй части подписи из области Монтгомери
		order.leave(second, second);
		// Если вторая часть подписи в ноль обратилась, случайное число подлежит замене
		ok = !order.zero(second);
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
 * @brief Метод выработки подписи со своим случайным числом
 *
 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
 * @param result место, в которое помещается подпись
 * @return       признак успешности выработки подписи
 *
 */
bool nts::sign::Gost::make(const view_t & value, uint8_t * result) const noexcept {
	// Если кривая не установлена либо ключ подписи не установлен
	if((this->_curve == nullptr) || !this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Место, в которое записывается случайное число выработки подписи
	uint8_t buffer[math::NUMBER_SIZE];
	// Признак успешности выработки подписи
	bool ok = false;
	/**
	 * Выполняем повтор выработки подписи: неудачный выбор случайного числа обращает в
	 * ноль ту либо иную часть подписи, и раздел 6.1 велит выбрать число заново
	 */
	for(size_t i = 0; !ok && (i < ATTEMPTS); i++){
		// Случайное число выработки подписи
		math::number_t number;
		// Если случайное число получить не удалось
		if(!entropy::number(order, number))
			// Выводим отказ выработки подписи
			return false;
		// Если случайное число записать не удалось
		if(!order.store(number, buffer, order.size())){
			// Затирание случайного числа
			wipe(number.words, sizeof(number.words));
			// Выводим отказ выработки подписи
			return false;
		}
		// Выработка подписи полученным случайным числом
		ok = this->make(value, view_t(buffer, order.size()), result);
		// Затирание случайного числа
		wipe(number.words, sizeof(number.words));
		// Затирание записанного случайного числа
		wipe(buffer, sizeof(buffer));
	}
	// Выводим признак успешности выработки подписи
	return ok;
}
/**
 * @brief Метод проверки подписи
 *
 * @param digest    хеш подписанного сообщения, записанный от старшего байта к младшему
 * @param signature проверяемая подпись
 * @return          признак того, что подпись сошлась
 *
 */
bool nts::sign::Gost::check(const view_t & value, const view_t & signature) const noexcept {
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
	// Если первую часть подписи разобрать не удалось
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
	// Приведённый хеш подписанного сообщения
	math::number_t item;
	// Если хеш подписанного сообщения привести не удалось
	if(!::digest(order, value, item))
		// Выводим отказ проверки подписи
		return false;
	// Значения в области Монтгомери, участвующие в проверке подписи
	math::number_t entered, inverse, z1, z2;
	// Приведение хеша сообщения в область Монтгомери
	order.enter(item, entered);
	// Обращение приведённого хеша сообщения
	order.invert(entered, inverse);
	// Приведение второй части подписи в область Монтгомери
	order.enter(second, entered);
	// Умножение второй части подписи на обращённый хеш
	order.multiply(entered, inverse, z1);
	// Вывод первого множителя из области Монтгомери
	order.leave(z1, z1);
	// Приведение первой части подписи в область Монтгомери
	order.enter(first, entered);
	// Умножение первой части подписи на обращённый хеш
	order.multiply(entered, inverse, z2);
	// Вывод полученного произведения из области Монтгомери
	order.leave(z2, z2);
	// Нулевое значение, из которого вычитается полученное произведение
	math::number_t zero;
	// Записываем нулевое значение
	order.word(0, zero);
	// Смену знака второго множителя
	order.subtract(zero, z2, z2);
	// Образующая точка подгруппы точек кривой
	curve::point_t base;
	// Получаем образующую точку подгруппы точек кривой
	this->_curve->base(base);
	// Сумма кратных точек проверки подписи
	curve::point_t left;
	/**
	 * Сумма кратных считается разом: удвоения у обоих кратных общие, и обходится она
	 * вдвое дешевле двух умножений порознь. Зависимость времени работы от чисел здесь
	 * не в счёт: и числа, и точки сличения подписи открыты обеим сторонам
	 */
	this->_curve->combine(base, z1, this->_point, z2, left);
	// Если сумма кратных точек оказалась бесконечно удалённой
	if(this->_curve->infinity(left))
		// Выводим отказ проверки подписи
		return false;
	// Место, в которое записывается первая координата суммы кратных точек
	uint8_t buffer[math::NUMBER_SIZE];
	// Если координаты суммы кратных точек записать не удалось
	if(!this->_curve->coordinates(left, buffer, nullptr, this->_curve->size()))
		// Выводим отказ проверки подписи
		return false;
	// Приведение первой координаты суммы по порядку подгруппы
	if(!order.reduce(view_t(buffer, this->_curve->size()), item))
		// Выводим отказ проверки подписи
		return false;
	// Выводим признак совпадения приведённой координаты с первой частью подписи
	return order.equal(item, first);
}
/**
 * @brief Конструктор
 *
 */
nts::sign::Gost::Gost() noexcept : _secret(false), _public(false), _curve(nullptr) {}
/**
 * @brief Деструктор
 *
 */
nts::sign::Gost::~Gost() noexcept {
	// Сброс состояния модуля
	this->clear();
}
