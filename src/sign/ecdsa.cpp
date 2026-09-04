/**
 * @file ecdsa.cpp
 * @date 2026-09-04
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
 *        реализация ECDSA по FIPS 186-5 и разделу 4.1 SEC 1
 *
 * @note Хеш подписываемого сообщения обращается в число по разделу 4.1.3 SEC 1:
 *       берутся его старшие разряды в числе, равном разрядности порядка подгруппы,
 *       а приведение полученного числа по порядку на итог не влияет, ибо всякое
 *       действие с ним ведётся по этому же порядку
 *
 * @note Случайное число по RFC 6979 выводится ровно теми же шагами, что и в разделе
 *       3.2 документа: усечение хеша до разрядности порядка там зовётся bits2int, а
 *       запись приведённого числа длиной в порядок - bits2octets и int2octets
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/ecdsa.hpp>
#include <asn1/asn1.hpp>
#include <entropy/entropy.hpp>
#include <digest/hmac.hpp>
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
	 * @brief Наибольшее число попыток вывода случайного числа
	 *
	 * @details Обращение в ноль всякой из частей подписи невероятно настолько же,
	 *          насколько невероятно угадывание ключа: десятка попыток довольно с
	 *          огромным запасом, а предел здесь стоит заслоном от вечного круга
	 *
	 */
	static constexpr size_t ATTEMPTS = 10;

	/**
	 * @brief Наибольшая длина хеша, участвующего в выводе случайного числа
	 *
	 */
	static constexpr size_t DIGEST_SIZE = 64;

	/**
	 * @brief Метод получения длины заголовка элемента ASN.1 DER
	 *
	 * @details Заголовок состоит из метки и длины: длина до 128 байтов пишется одним
	 *          байтом, а большая - байтом числа байтов и самими байтами по разделу
	 *          8.1.3 X.690
	 *
	 * @param content длина содержимого элемента
	 *
	 * @return        длина заголовка элемента в байтах
	 *
	 */
	static size_t header(const size_t content) noexcept {
		// Если длина укладывается в короткую форму
		if(content < 128)
			// Выводим длину метки и одного байта длины
			return 2;
		// Если длина укладывается в один байт длинной формы
		if(content < 256)
			// Выводим длину метки, байта числа байтов и одного байта длины
			return 3;
		// Выводим длину метки, байта числа байтов и двух байтов длины
		return 4;
	}

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод усечения потока байтов до старших разрядов заданного числа
	 *
	 * @details Раздел 4.1.3 SEC 1 и раздел 2.3.2 RFC 6979: из потока берутся старшие
	 *          разряды в числе, равном разрядности порядка подгруппы, а поток короче
	 *          порядка берётся целиком
	 *
	 * @param data   усекаемый поток байтов, записанный от старшего байта к младшему
	 * @param bits   число оставляемых старших разрядов
	 * @param result место, в которое помещается усечённый поток
	 *
	 * @return       число байтов усечённого потока
	 *
	 */
	static size_t truncate(const view_t & data, const size_t bits, uint8_t * result) noexcept {
		// Число байтов, вмещающих оставляемые разряды
		size_t count = ((bits + 7) / 8);
		// Если поток короче оставляемых разрядов
		if(data.size < count)
			// Берём поток целиком
			count = data.size;
		/**
		 * Выполняем перебор оставляемых байтов потока
		 */
		for(size_t i = 0; i < count; i++)
			// Переписываем очередной байт потока
			result[i] = data.data[i];
		// Если взятых разрядов больше оставляемых
		if((count * 8) > bits){
			// Число лишних младших разрядов
			const size_t shift = ((count * 8) - bits);
			/**
			 * Выполняем сдвиг усечённого потока вправо от младшего байта к старшему
			 */
			for(size_t i = count; i > 0; i--){
				// Разряды, переходящие из старшего соседнего байта
				const uint8_t carry = ((i > 1) ? static_cast <uint8_t> (result[i - 2] << (8 - shift)) : 0);
				// Выполняем сдвиг очередного байта с приёмом разрядов соседа
				result[i - 1] = static_cast <uint8_t> ((result[i - 1] >> shift) | carry);
			}
		}
		// Выводим число байтов усечённого потока
		return count;
	}
	/**
	 * @brief Метод обращения хеша сообщения в число по порядку подгруппы точек кривой
	 *
	 * @param order  арифметика порядка подгруппы точек кривой
	 * @param bits   разрядность порядка подгруппы точек кривой
	 * @param value  хеш сообщения, записанный от старшего байта к младшему
	 * @param result место, в которое помещается полученное число
	 *
	 * @return       признак успешности обращения хеша сообщения
	 *
	 */
	static bool digest(const math::modulus_t & order, const size_t bits, const view_t & value, math::number_t & result) noexcept {
		// Если хеш сообщения не передан
		if((value.data == nullptr) || (value.size == 0))
			// Выводим отказ обращения хеша сообщения
			return false;
		// Место, в которое помещается усечённый хеш сообщения
		uint8_t buffer[math::NUMBER_SIZE];
		// Выполняем усечение хеша до разрядности порядка
		const size_t count = truncate(value, bits, buffer);
		// Выводим итог приведения усечённого хеша по порядку подгруппы
		return order.reduce(view_t(buffer, count), result);
	}
	/**
	 * @brief Метод разбора целого числа ASN.1 в беззнаковое число заданной длины
	 *
	 * @param reader разбирающий объект
	 * @param result место, в которое помещается число от старшего байта к младшему
	 * @param size   размер места числа
	 *
	 * @return       признак успешности разбора
	 *
	 */
	static bool integer(asn1::reader_t & reader, uint8_t * result, const size_t size) noexcept {
		// Разбираемый элемент
		asn1::element_t element;
		// Если очередной элемент не целое число
		if(!reader.next(asn1::tag_t::INTEGER, element))
			// Выводим отказ разбора
			return false;
		// Содержимое целого числа
		view_t content;
		// Если содержимое числа записано не кратчайшим образом
		if(asn1::integer(element, content) != asn1::error_t::NONE)
			// Выводим отказ разбора
			return false;
		// Если число отрицательное
		if((content.data[0] & 0x80) != 0)
			// Выводим отказ разбора
			return false;
		// Если число начинается ведущим нулём знака
		if((content.size > 1) && (content.data[0] == 0x00)){
			// Пропускаем ведущий ноль знака
			content.data++;
			// Уменьшаем размер содержимого
			content.size--;
		}
		// Если число длиннее места
		if(content.size > size)
			// Выводим отказ разбора
			return false;
		/**
		 * Выполняем дополнение места нулями спереди
		 */
		for(size_t i = 0; i < (size - content.size); i++)
			// Записываем очередной ноль дополнения
			result[i] = 0x00;
		/**
		 * Выполняем перебор байтов содержимого числа
		 */
		for(size_t i = 0; i < content.size; i++)
			// Переписываем очередной байт числа в конец места
			result[(size - content.size) + i] = content.data[i];
		// Выводим успешность разбора
		return true;
	}
};

/**
 * @brief Метод проверки готовности модуля к работе
 *
 * @return признак того, что кривая установлена
 *
 */
bool nts::sign::Ecdsa::ready() const noexcept {
	// Выводим признак того, что кривая установлена
	return (this->_curve != nullptr);
}
/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах
 *
 */
size_t nts::sign::Ecdsa::size() const noexcept {
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
 * @return верхний предел длины подписи в байтах, ноль без кривой
 *
 */
size_t nts::sign::Ecdsa::limit() const noexcept {
	// Если кривая не установлена
	if(this->_curve == nullptr)
		// Выводим нулевой предел
		return 0;
	// Получаем длину порядка подгруппы точек кривой
	const size_t size = this->_curve->order().size();
	/**
	 * Наихудший случай записи числа INTEGER - взведённый старший разряд: тогда
	 * число получает ведущий нулевой байт, и содержимое длиннее порядка на байт
	 */
	const size_t integer = (header(size + 1) + size + 1);
	// Выводим длину последовательности из двух наихудших чисел с её заголовком
	return (header(integer * 2) + (integer * 2));
}
/**
 * @brief Метод установки эллиптической кривой
 *
 * @param curve устанавливаемая эллиптическая кривая
 *
 * @return      признак успешности установки эллиптической кривой
 *
 */
bool nts::sign::Ecdsa::start(const curve::curve_t & curve) noexcept {
	// Выполняем сброс прежнего состояния модуля
	this->clear();
	// Если устанавливаемая кривая к работе не готова
	if(!curve.ready())
		// Выводим отказ установки эллиптической кривой
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = curve.order();
	// Ноль и единица порядка подгруппы
	math::number_t zero, one;
	// Получаем ноль в виде числа порядка
	order.word(0, zero);
	// Получаем единицу в виде числа порядка
	order.word(1, one);
	// Порядок подгруппы без единицы
	math::number_t last;
	/**
	 * Порядок подгруппы без единицы есть наибольшее число арифметики порядка, и
	 * разрядность его равна разрядности самого порядка: степенью двойки простой
	 * порядок быть не может
	 */
	order.subtract(zero, one, last);
	// Место, в которое записывается наибольшее число порядка
	uint8_t buffer[math::NUMBER_SIZE];
	// Если наибольшее число порядка записать не удалось
	if(!order.store(last, buffer, order.size()))
		// Выводим отказ установки эллиптической кривой
		return false;
	// Разрядность порядка подгруппы точек кривой
	size_t bits = 0;
	/**
	 * Выполняем поиск старшего взведённого разряда наибольшего числа порядка
	 */
	for(size_t i = 0; (bits == 0) && (i < order.size()); i++){
		// Если очередной байт числа нулевой
		if(buffer[i] == 0x00)
			// Переходим к следующему байту числа
			continue;
		// Разрядность байтов ниже найденного
		bits = ((order.size() - i - 1) * 8);
		/**
		 * Выполняем счёт разрядов найденного байта
		 */
		for(uint8_t value = buffer[i]; value != 0; value = static_cast <uint8_t> (value >> 1))
			// Учитываем очередной разряд байта
			bits++;
	}
	// Если разрядность порядка не найдена
	if(bits == 0)
		// Выводим отказ установки эллиптической кривой
		return false;
	// Запоминаем разрядность порядка подгруппы точек кривой
	this->_bits = bits;
	// Запоминаем эллиптическую кривую выработки подписи
	this->_curve = &curve;
	// Выводим успешность установки эллиптической кривой
	return true;
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void nts::sign::Ecdsa::clear() noexcept {
	// Выполняем затирание ключа проверки подписи
	wipe(&this->_point, sizeof(this->_point));
	// Выполняем затирание ключа подписи
	wipe(this->_key.words, sizeof(this->_key.words));
	// Сбрасываем эллиптическую кривую выработки подписи
	this->_curve = nullptr;
	// Сбрасываем разрядность порядка подгруппы точек кривой
	this->_bits = 0;
	// Снимаем признак того, что ключ проверки подписи установлен
	this->_public = false;
	// Снимаем признак того, что ключ подписи установлен
	this->_secret = false;
}
/**
 * @brief Метод установки ключа подписи
 *
 * @param secret устанавливаемый ключ подписи, записанный от старшего байта к младшему
 *
 * @return       признак успешности установки ключа подписи
 *
 */
bool nts::sign::Ecdsa::secret(const view_t & secret) noexcept {
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
		// Выполняем затирание ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ установки ключа подписи
		return false;
	}
	// Выполняем выработку ключа проверки подписи из ключа подписи
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
 *
 * @return       признак успешности порождения ключа подписи
 *
 */
bool nts::sign::Ecdsa::generate(uint8_t * secret, const size_t size) noexcept {
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
	// Выполняем затирание прежнего ключа проверки подписи
	wipe(&this->_point, sizeof(this->_point));
	// Выполняем затирание прежнего ключа подписи
	wipe(this->_key.words, sizeof(this->_key.words));
	// Снимаем признак того, что ключ проверки подписи установлен
	this->_public = false;
	// Снимаем признак того, что ключ подписи установлен
	this->_secret = false;
	/**
	 * Ключ подписи берётся отбором по разделу A.2.2 FIPS 186-5: источник выдаёт
	 * случайные байты длиной порядка и отбрасывает целиком всякое значение, не
	 * меньшее порядка либо нулевое, - приведение по модулю сместило бы ключ к
	 * младшим значениям, а смещение вскрывается по множеству подписей
	 */
	if(!entropy::number(order, this->_key)){
		// Выполняем затирание недовыработанного ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Если ключ подписи записать в переданное место не удалось
	if(!order.store(this->_key, secret, size)){
		// Выполняем затирание переданного места
		wipe(secret, size);
		// Выполняем затирание выработанного ключа подписи
		wipe(this->_key.words, sizeof(this->_key.words));
		// Выводим отказ порождения ключа подписи
		return false;
	}
	// Выполняем выработку ключа проверки подписи из ключа подписи
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
 *
 * @return  признак успешности установки ключа проверки подписи
 *
 */
bool nts::sign::Ecdsa::key(const view_t & x, const view_t & y) noexcept {
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
 *
 * @return     признак успешности получения ключа проверки подписи
 *
 */
bool nts::sign::Ecdsa::key(uint8_t * x, uint8_t * y, const size_t size) const noexcept {
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
 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
 * @param random случайное число выработки подписи, записанное от старшего байта к младшему
 * @param result место, в которое помещается подпись
 *
 * @return       признак успешности выработки подписи
 *
 */
bool nts::sign::Ecdsa::make(const view_t & digest, const view_t & random, uint8_t * result) const noexcept {
	// Если кривая не установлена либо ключ подписи не установлен
	if((this->_curve == nullptr) || !this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Хеш подписываемого сообщения в виде числа
	math::number_t item;
	// Если хеш подписываемого сообщения обратить в число не удалось
	if(!::digest(order, this->_bits, digest, item))
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
		// Выполняем умножение образующей точки на случайное число
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
		// Выполняем приведение первой части подписи в область Монтгомери
		order.enter(first, entered);
		// Выполняем приведение ключа подписи в область Монтгомери
		order.enter(this->_key, item2);
		// Выполняем умножение первой части подписи на ключ подписи
		order.multiply(entered, item2, second);
		// Выполняем приведение хеша сообщения в область Монтгомери
		order.enter(item, item2);
		// Складываем хеш сообщения с полученным произведением
		order.add(second, item2, second);
		// Выполняем приведение случайного числа в область Монтгомери
		order.enter(number, entered);
		/**
		 * Обращение случайного числа ведётся возведением в степень с наложением маски
		 * на всяком разряде показателя: время его от случайного числа не зависит
		 */
		order.invert(entered, item2);
		// Выполняем умножение суммы на обращённое случайное число
		order.multiply(second, item2, second);
		// Выполняем вывод второй части подписи из области Монтгомери
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
	// Выполняем затирание первой координаты кратной точки
	wipe(buffer, sizeof(buffer));
	// Выполняем затирание кратной точки образующей
	wipe(&point, sizeof(point));
	// Выполняем затирание промежуточных значений выработки подписи
	wipe(entered.words, sizeof(entered.words));
	// Выполняем затирание промежуточных значений выработки подписи
	wipe(item2.words, sizeof(item2.words));
	// Выполняем затирание второй части подписи
	wipe(second.words, sizeof(second.words));
	// Выполняем затирание первой части подписи
	wipe(first.words, sizeof(first.words));
	// Выполняем затирание случайного числа выработки подписи
	wipe(number.words, sizeof(number.words));
	// Выводим признак успешности выработки подписи
	return ok;
}
/**
 * @brief Метод выработки подписи с выводом случайного числа по RFC 6979
 *
 * @param algorithm алгоритм хеширования, которым получен хеш сообщения
 * @param digest    хеш подписываемого сообщения, записанный от старшего байта к младшему
 * @param result    место, в которое помещается подпись
 *
 * @return          признак успешности выработки подписи
 *
 */
bool nts::sign::Ecdsa::make(const digest::hash_t algorithm, const view_t & digest, uint8_t * result) const noexcept {
	// Если кривая не установлена либо ключ подписи не установлен
	if((this->_curve == nullptr) || !this->_secret || (result == nullptr))
		// Выводим отказ выработки подписи
		return false;
	// Получаем длину хеша названного алгоритма
	const size_t length = digest::length(algorithm);
	// Если длина хеша не совпадает с длиной хеша названного алгоритма
	if((length == 0) || (length > DIGEST_SIZE) || (digest.data == nullptr) || (digest.size != length))
		// Выводим отказ выработки подписи
		return false;
	// Получаем арифметику порядка подгруппы точек кривой
	const math::modulus_t & order = this->_curve->order();
	// Хеш сообщения в виде числа по порядку подгруппы
	math::number_t item;
	// Если хеш сообщения обратить в число не удалось
	if(!::digest(order, this->_bits, digest, item))
		// Выводим отказ выработки подписи
		return false;
	// Запись ключа подписи и запись хеша сообщения длиной в порядок подгруппы
	uint8_t secret[math::NUMBER_SIZE], reduced[math::NUMBER_SIZE];
	// Если ключ подписи либо приведённый хеш записать не удалось
	if(!order.store(this->_key, secret, order.size()) || !order.store(item, reduced, order.size())){
		// Выполняем затирание записи ключа подписи
		wipe(secret, sizeof(secret));
		// Выводим отказ выработки подписи
		return false;
	}
	// Объект выработки имитовставки
	digest::mac_t mac;
	// Значения V и K раздела 3.2 RFC 6979
	uint8_t v[DIGEST_SIZE], k[DIGEST_SIZE];
	// Байт-разделитель, подаваемый между значениями
	uint8_t separator = 0x00;
	/**
	 * Выполняем начальное заполнение: V из единиц, K из нулей
	 */
	for(size_t i = 0; i < length; i++){
		// Записываем очередной байт заполнения V
		v[i] = 0x01;
		// Записываем очередной байт заполнения K
		k[i] = 0x00;
	}
	// Признак успешности выработки подписи
	bool ok = true;
	/**
	 * Выполняем два шага заведения: K = HMAC_K(V || 0x00 || x || h) и V = HMAC_K(V),
	 * затем то же с разделителем 0x01 - шаги d, e, f и g раздела 3.2 RFC 6979
	 */
	for(uint8_t step = 0; ok && (step < 2); step++){
		// Устанавливаем разделитель очередного шага
		separator = step;
		// Выполняем установку ключа K
		ok = mac.start(algorithm, view_t(k, length));
		// Если ключ установлен
		if(ok){
			// Подаём значение V
			mac.update(view_t(v, length));
			// Подаём разделитель шага
			mac.update(view_t(&separator, 1));
			// Подаём запись ключа подписи
			mac.update(view_t(secret, order.size()));
			// Подаём запись приведённого хеша
			mac.update(view_t(reduced, order.size()));
			// Снимаем новое значение K
			ok = mac.finish(k, length);
		}
		// Если новое значение K снято
		if(ok)
			// Выполняем установку нового ключа K
			ok = mac.start(algorithm, view_t(k, length));
		// Если ключ установлен
		if(ok){
			// Подаём значение V
			mac.update(view_t(v, length));
			// Снимаем новое значение V
			ok = mac.finish(v, length);
		}
	}
	// Признак того, что подпись выработана
	bool made = false;
	// Место, в которое помещается собранное значение T
	uint8_t t[math::NUMBER_SIZE];
	// Место, в которое помещается усечённое значение T
	uint8_t candidate[math::NUMBER_SIZE];
	/**
	 * Выполняем повтор вывода случайного числа: число вне отрезка [1, n-1] либо
	 * обращающее в ноль часть подписи отбрасывается, а K и V перезаводятся - шаг h
	 * раздела 3.2 RFC 6979
	 */
	for(size_t attempt = 0; ok && !made && (attempt < ATTEMPTS); attempt++){
		// Число собранных байтов значения T
		size_t collected = 0;
		/**
		 * Выполняем сбор значения T длиной в порядок подгруппы: V = HMAC_K(V), T = T || V
		 */
		while(ok && (collected < order.size())){
			// Выполняем установку ключа K
			ok = mac.start(algorithm, view_t(k, length));
			// Если ключ установлен
			if(ok){
				// Подаём значение V
				mac.update(view_t(v, length));
				// Снимаем новое значение V
				ok = mac.finish(v, length);
			}
			/**
			 * Выполняем дописывание значения V в собираемое значение T
			 */
			for(size_t i = 0; ok && (i < length) && (collected < order.size()); i++)
				// Дописываем очередной байт значения V
				t[collected++] = v[i];
		}
		// Если значение T собрано
		if(ok){
			// Выполняем усечение значения T до разрядности порядка
			const size_t count = truncate(view_t(t, order.size()), this->_bits, candidate);
			// Случайное число выработки подписи
			math::number_t number;
			/**
			 * Число годно, когда лежит в отрезке [1, n-1]: разбор отвергает числа не
			 * меньше порядка, а ноль отвергается отдельно
			 */
			if(order.load(view_t(candidate, count), number) && !order.zero(number))
				// Выполняем выработку подписи выведенным числом
				made = this->make(digest, view_t(candidate, count), result);
			// Выполняем затирание случайного числа
			wipe(number.words, sizeof(number.words));
		}
		// Если подпись не выработана, K и V перезаводятся
		if(ok && !made){
			// Устанавливаем нулевой разделитель
			separator = 0x00;
			// Выполняем установку ключа K
			ok = mac.start(algorithm, view_t(k, length));
			// Если ключ установлен
			if(ok){
				// Подаём значение V
				mac.update(view_t(v, length));
				// Подаём нулевой разделитель
				mac.update(view_t(&separator, 1));
				// Снимаем новое значение K
				ok = mac.finish(k, length);
			}
			// Если новое значение K снято
			if(ok)
				// Выполняем установку нового ключа K
				ok = mac.start(algorithm, view_t(k, length));
			// Если ключ установлен
			if(ok){
				// Подаём значение V
				mac.update(view_t(v, length));
				// Снимаем новое значение V
				ok = mac.finish(v, length);
			}
		}
	}
	// Выполняем сброс ключа имитовставки
	mac.clear();
	// Выполняем затирание усечённого значения T
	wipe(candidate, sizeof(candidate));
	// Выполняем затирание собранного значения T
	wipe(t, sizeof(t));
	// Выполняем затирание значения K
	wipe(k, sizeof(k));
	// Выполняем затирание значения V
	wipe(v, sizeof(v));
	// Выполняем затирание записи приведённого хеша
	wipe(reduced, sizeof(reduced));
	// Выполняем затирание записи ключа подписи
	wipe(secret, sizeof(secret));
	// Выводим признак успешности выработки подписи
	return (ok && made);
}
/**
 * @brief Метод проверки подписи
 *
 * @param digest    хеш подписанного сообщения, записанный от старшего байта к младшему
 * @param signature проверяемая подпись
 *
 * @return          признак того, что подпись сошлась
 *
 */
bool nts::sign::Ecdsa::check(const view_t & digest, const view_t & signature) const noexcept {
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
	 * Раздел 4.1.4 SEC 1: обе части подписи обязаны лежать в отрезке [1, n-1]; разбор
	 * отвергает числа не меньше порядка, а ноль отвергается отдельно
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
	// Хеш подписанного сообщения в виде числа
	math::number_t item;
	// Если хеш подписанного сообщения обратить в число не удалось
	if(!::digest(order, this->_bits, digest, item))
		// Выводим отказ проверки подписи
		return false;
	// Значения в области Монтгомери, участвующие в проверке подписи
	math::number_t entered, inverse, u1, u2;
	// Выполняем приведение второй части подписи в область Монтгомери
	order.enter(second, entered);
	// Выполняем обращение второй части подписи
	order.invert(entered, inverse);
	// Выполняем приведение хеша сообщения в область Монтгомери
	order.enter(item, entered);
	// Выполняем умножение хеша сообщения на обращённую вторую часть
	order.multiply(entered, inverse, u1);
	// Выполняем вывод первого множителя из области Монтгомери
	order.leave(u1, u1);
	// Выполняем приведение первой части подписи в область Монтгомери
	order.enter(first, entered);
	// Выполняем умножение первой части подписи на обращённую вторую часть
	order.multiply(entered, inverse, u2);
	// Выполняем вывод второго множителя из области Монтгомери
	order.leave(u2, u2);
	// Образующая точка подгруппы точек кривой
	curve::point_t base;
	// Получаем образующую точку подгруппы точек кривой
	this->_curve->base(base);
	// Сумма кратных точек проверки подписи
	curve::point_t sum;
	/**
	 * Сумма кратных считается разом: удвоения у обоих кратных общие, и обходится она
	 * вдвое дешевле двух умножений порознь. Зависимость времени работы от чисел здесь
	 * не в счёт: и числа, и точки сличения подписи открыты обеим сторонам
	 */
	this->_curve->combine(base, u1, this->_point, u2, sum);
	// Если сумма кратных точек оказалась бесконечно удалённой
	if(this->_curve->infinity(sum))
		// Выводим отказ проверки подписи
		return false;
	// Место, в которое записывается первая координата суммы кратных точек
	uint8_t buffer[math::NUMBER_SIZE];
	// Если координаты суммы кратных точек записать не удалось
	if(!this->_curve->coordinates(sum, buffer, nullptr, this->_curve->size()))
		// Выводим отказ проверки подписи
		return false;
	// Выполняем приведение первой координаты суммы по порядку подгруппы
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
nts::sign::Ecdsa::Ecdsa() noexcept : _secret(false), _public(false), _bits(0), _curve(nullptr) {}
/**
 * @brief Деструктор
 *
 */
nts::sign::Ecdsa::~Ecdsa() noexcept {
	// Выполняем сброс состояния модуля
	this->clear();
}
/**
 * @brief Метод записи подписи ECDSA в виде ASN.1 DER
 *
 * @param raw подпись в сыром виде: r и s подряд, каждое в половину длины подписи
 * @param der место, в которое помещается запись SEQUENCE {INTEGER r, INTEGER s}
 *
 * @return    признак успешности записи подписи
 *
 */
bool nts::sign::encode(const view_t & raw, uint8_t * der, size_t & size) noexcept {
	// Если подпись либо место не заданы или подпись негодной длины
	if((raw.data == nullptr) || (raw.size == 0) || ((raw.size % 2) != 0) || (raw.size > (math::NUMBER_SIZE * 2)) || (der == nullptr))
		// Выводим отказ
		return false;
	// Длина одного числа подписи
	const size_t half = (raw.size / 2);
	// Начала чисел и их длины без ведущих нулей
	size_t offsets[2] = {0, half}, lengths[2] = {0, 0};
	// Признаки нужды в ведущем нулевом байте
	bool leading[2] = {false, false};
	// Длина содержимого последовательности
	size_t content = 0;
	/**
	 * Выполняем перебор чисел подписи
	 */
	for(size_t i = 0; i < 2; i++){
		// Смещение первого значащего байта числа
		size_t skip = 0;
		/**
		 * Выполняем пропуск ведущих нулевых байтов, оставляя хотя бы один байт
		 */
		while((skip < (half - 1)) && (raw.data[offsets[i] + skip] == 0))
			// Пропускаем очередной нулевой байт
			skip++;
		// Запоминаем начало и длину значащей части числа
		offsets[i] += skip;
		lengths[i] = (half - skip);
		// Если старший разряд числа установлен, ему нужен ведущий нулевой байт
		leading[i] = ((raw.data[offsets[i]] & 0x80) != 0);
		// Учитываем заголовок числа, ведущий байт и само число
		content += (2 + (leading[i] ? 1 : 0) + lengths[i]);
	}
	// Длина заголовка последовательности: короткая форма длины до 127 байтов, иначе длинная в один байт
	const size_t header = ((content < 128) ? 2 : 3);
	// Если места под запись не хватает
	if(size < (header + content))
		// Выводим отказ
		return false;
	// Текущее смещение записи
	size_t offset = 0;
	// Записываем метку последовательности
	der[offset++] = 0x30;
	// Если длина укладывается в короткую форму
	if(content < 128)
		// Записываем длину одним байтом
		der[offset++] = static_cast <uint8_t> (content);
	// Если длина требует длинной формы
	else {
		// Записываем признак длинной формы с одним байтом длины
		der[offset++] = 0x81;
		// Записываем длину
		der[offset++] = static_cast <uint8_t> (content);
	}
	/**
	 * Выполняем запись чисел подписи
	 */
	for(size_t i = 0; i < 2; i++){
		// Записываем метку целого числа
		der[offset++] = 0x02;
		// Записываем длину числа с учётом ведущего байта
		der[offset++] = static_cast <uint8_t> (lengths[i] + (leading[i] ? 1 : 0));
		// Если нужен ведущий нулевой байт
		if(leading[i])
			// Записываем его
			der[offset++] = 0x00;
		// Переносим значащую часть числа
		::memcpy(der + offset, raw.data + offsets[i], lengths[i]);
		// Сдвигаем смещение записи
		offset += lengths[i];
	}
	// Выводим длину записи
	size = offset;
	// Выводим успех записи
	return true;
}
/**
 * @brief Метод записи подписи ECDSA в структуру ASN.1 DER
 *
 * @param raw подпись в сыром виде: r и s подряд равной длины
 * @param der место, в которое помещается запись
 *
 * @return    признак успешности записи
 *
 */
bool nts::sign::encode(const view_t & raw, vector <uint8_t> & der) noexcept {
	// Место под запись наибольшей длины: два числа по NUMBER_SIZE с ведущими байтами и заголовки
	uint8_t buffer[(math::NUMBER_SIZE * 2) + 8];
	// Ёмкость места, а после записи её длина
	size_t size = sizeof(buffer);
	// Если запись не удалась
	if(!nts::sign::encode(raw, buffer, size))
		// Выводим отказ
		return false;
	/**
	 * Перенос записи в переданное место выделяет память, а нехватка её отвечает
	 * отказом; вызывающему, которому важна причина, служит запись в готовое место
	 */
	try {
		// Переносим запись в переданное место
		der.assign(buffer, buffer + size);
	/**
	 * Если памяти под запись не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ
		return false;
	}
	// Выводим успех записи
	return true;
}
/**
 * @brief Метод разбора подписи ECDSA из записи ASN.1 DER
 *
 * @param der  разбираемая запись SEQUENCE {INTEGER r, INTEGER s}
 * @param raw  место, в которое помещается подпись в сыром виде: r и s подряд
 * @param size размер места подписи в сыром виде, две длины порядка подгруппы
 *
 * @return     признак успешности разбора подписи
 *
 */
bool nts::sign::decode(const view_t & der, uint8_t * raw, const size_t size) noexcept {
	// Если запись либо место не переданы, либо место нечётно по длине
	if((der.data == nullptr) || (der.size == 0) || (raw == nullptr) || (size == 0) || ((size % 2) != 0))
		// Выводим отказ разбора подписи
		return false;
	// Длина всякой из частей подписи
	const size_t half = (size / 2);
	// Разбирающий объект записи целиком
	asn1::reader_t reader(der);
	// Элемент последовательности подписи
	asn1::element_t element;
	// Если очередной элемент не последовательность
	if(!reader.next(asn1::tag_t::SEQUENCE, element))
		// Выводим отказ разбора подписи
		return false;
	// Если за последовательностью остались данные
	if(!reader.empty())
		// Выводим отказ разбора подписи
		return false;
	// Разбирающий объект содержимого последовательности
	asn1::reader_t inner = reader.enter(element);
	// Если первую часть подписи разобрать не удалось
	if(!::integer(inner, raw, half))
		// Выводим отказ разбора подписи
		return false;
	// Если вторую часть подписи разобрать не удалось
	if(!::integer(inner, raw + half, half))
		// Выводим отказ разбора подписи
		return false;
	// Выводим признак того, что внутри последовательности данных не осталось
	return inner.empty();
}
