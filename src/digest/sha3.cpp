/**
 * @file sha3.cpp
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
 * @brief Модуль хеширования SHA-3 и функций переменного выхода SHAKE по FIPS 202
 *
 * @details Губка над перестановкой Keccak-f[1600]: состояние в двадцать пять полос по
 *          64 разряда, полосы читаются и пишутся от младшего байта. Скорость хешей
 *          1600 − 2·длина итога разрядов, у SHAKE128 - 1344, у SHAKE256 - 1088 разрядов.
 *          Дополнение хешей начинается байтом 0x06, функций переменного выхода - 0x1F, и
 *          в обоих случаях оканчивается разрядом 0x80 в последнем байте блока
 *
 * @section Намеренные решения
 *
 * 1. Перестановка расписана по шагам θ, ρ, π, χ, ι с таблицами сдвигов и обхода полос:
 *    так код читается против FIPS 202 построчно, а собиратель разворачивает его сам.
 *
 * 2. Поглощение и выжимание идут через одно состояние без отдельного накопителя блока:
 *    байты сообщения сразу складываются в полосы по смещению, оттого память под блок
 *    не занимается, а число байтов в незавершённом блоке хранится счётчиком.
 *
 * 3. После первого выжимания поглощение отвергается: губка FIPS 202 не двусторонняя,
 *    и продолжение поглощения после выжимания дало бы итог, не описанный стандартом.
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
#include <digest/sha3.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Число кругов перестановки Keccak-f[1600]
	 */
	static constexpr size_t ROUNDS = 24;
	/**
	 * Константы шага ι по кругам
	 */
	static const uint64_t IOTA[ROUNDS] = {
		0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
		0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
		0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
		0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
	};
	/**
	 * Сдвиги шага ρ в порядке обхода полос шагом π
	 */
	static const uint8_t RHO[24] = {
		1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
	};
	/**
	 * Порядок обхода полос шагом π
	 */
	static const uint8_t PI[24] = {
		10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
	};
	/**
	 * @brief Метод кругового сдвига полосы влево
	 *
	 * @param lane  сдвигаемая полоса
	 * @param count число разрядов сдвига
	 *
	 * @return      сдвинутая полоса
	 *
	 */
	static inline uint64_t spin(const uint64_t lane, const size_t count) noexcept {
		// Выводим круговой сдвиг полосы
		return ((lane << count) | (lane >> (64 - count)));
	}
};

/**
 * @brief Метод перестановки состояния Keccak-f[1600]
 *
 */
void nts::digest::Keccak::permute() noexcept {
	// Чётности столбцов шага θ
	uint64_t parity[5];
	/**
	 * Выполняем перебор кругов перестановки
	 */
	for(size_t round = 0; round < ROUNDS; round++){
		/**
		 * Шаг θ: чётность каждого столбца
		 */
		for(size_t x = 0; x < 5; x++)
			// Складываем полосы столбца
			parity[x] = (this->_state[x] ^ this->_state[x + 5] ^ this->_state[x + 10] ^ this->_state[x + 15] ^ this->_state[x + 20]);
		/**
		 * Шаг θ: сложение соседних чётностей с каждой полосой столбца
		 */
		for(size_t x = 0; x < 5; x++){
			// Слагаемое столбца из чётностей соседей
			const uint64_t mixed = (parity[(x + 4) % 5] ^ spin(parity[(x + 1) % 5], 1));
			/**
			 * Выполняем перебор полос столбца
			 */
			for(size_t y = 0; y < 25; y += 5)
				// Складываем слагаемое с полосой
				this->_state[x + y] ^= mixed;
		}
		// Полоса, переносимая по обходу шагов ρ и π
		uint64_t carried = this->_state[1];
		/**
		 * Шаги ρ и π: сдвиг и перенос полос по обходу
		 */
		for(size_t i = 0; i < 24; i++){
			// Место, в которое переносится полоса
			const size_t place = PI[i];
			// Полоса, вытесняемая с места
			const uint64_t displaced = this->_state[place];
			// Переносим сдвинутую полосу на место
			this->_state[place] = spin(carried, RHO[i]);
			// Запоминаем вытесненную полосу для переноса
			carried = displaced;
		}
		/**
		 * Шаг χ: нелинейное смешение полос каждой строки
		 */
		for(size_t y = 0; y < 25; y += 5){
			// Полосы строки до смешения
			const uint64_t row[5] = {this->_state[y], this->_state[y + 1], this->_state[y + 2], this->_state[y + 3], this->_state[y + 4]};
			/**
			 * Выполняем перебор полос строки
			 */
			for(size_t x = 0; x < 5; x++)
				// Смешиваем полосу с двумя соседями по строке
				this->_state[y + x] = (row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]));
		}
		// Шаг ι: сложение константы круга с первой полосой
		this->_state[0] ^= IOTA[round];
	}
}
/**
 * @brief Метод дополнения сообщения и перехода к выжиманию
 *
 */
void nts::digest::Keccak::seal() noexcept {
	// Байт начала дополнения по разновидности: 0x06 у хешей, 0x1F у функций переменного выхода
	const uint8_t opening = (((this->_type == sha3_t::SHAKE128) || (this->_type == sha3_t::SHAKE256)) ? 0x1F : 0x06);
	// Складываем байт начала дополнения с полосой по смещению незавершённого блока
	this->_state[this->_size / 8] ^= (static_cast <uint64_t> (opening) << ((this->_size % 8) * 8));
	// Складываем разряд окончания дополнения с последней полосой блока
	this->_state[(this->_rate - 1) / 8] ^= (static_cast <uint64_t> (0x80) << (((this->_rate - 1) % 8) * 8));
	// Выполняем перестановку состояния
	this->permute();
	// Сбрасываем счётчик выжатых из блока байтов
	this->_size = 0;
	// Запоминаем, что выжимание итога началось
	this->_squeezing = true;
}
/**
 * \~russian
 * @brief Метод получения разновидности преобразования
 *
 * @return разновидность преобразования
 *
 * \~english
 * @brief Method of the obtaining of the kind of the transformation
 *
 * @return kind of the transformation
 *
 * \~
 */
nts::digest::sha3_t nts::digest::Keccak::type() const noexcept {
	// Выводим разновидность преобразования
	return this->_type;
}
/**
 * \~russian
 * @brief Метод получения скорости преобразования
 *
 * @return число байтов, поглощаемых за одну перестановку
 *
 * \~english
 * @brief Method of the obtaining of the rate of the transformation
 *
 * @return number of the bytes absorbed per one permutation
 *
 * \~
 */
size_t nts::digest::Keccak::block() const noexcept {
	// Выводим скорость преобразования
	return this->_rate;
}
/**
 * \~russian
 * @brief Метод сброса преобразования в начальное состояние
 *
 * @param type разновидность преобразования
 *
 * \~english
 * @brief Method of the reset of the transformation to the initial state
 *
 * @param type kind of the transformation
 *
 * \~
 */
void nts::digest::Keccak::reset(const sha3_t type) noexcept {
	// Запоминаем разновидность преобразования
	this->_type = type;
	// Запоминаем скорость разновидности
	this->_rate = rate(type);
	// Сбрасываем счётчик байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем признак выжимания
	this->_squeezing = false;
	// Обнуляем состояние губки
	::memset(this->_state, 0, sizeof(this->_state));
}
/**
 * \~russian
 * @brief Метод поглощения куска сообщения
 *
 * @param data кусок сообщения
 *
 * @return     признак того, что кусок поглощён: после выжимания поглощение отвергается
 *
 * \~english
 * @brief Method of the absorption of a piece of the message
 *
 * @param data piece of the message
 *
 * @return     sign that the piece is absorbed: after a squeezing the absorption is refused
 *
 * \~
 */
bool nts::digest::Keccak::update(const view_t & data) noexcept {
	// Если разновидность не установлена либо выжимание уже началось
	if((this->_rate == 0) || this->_squeezing)
		// Выводим отказ поглощения
		return false;
	// Если кусок сообщения пуст
	if((data.data == nullptr) || (data.size == 0))
		// Выводим успешность поглощения пустого куска
		return (data.size == 0);
	/**
	 * Выполняем перебор байтов куска сообщения
	 */
	for(size_t i = 0; i < data.size; i++){
		// Складываем байт сообщения с полосой по смещению незавершённого блока
		this->_state[this->_size / 8] ^= (static_cast <uint64_t> (data.data[i]) << ((this->_size % 8) * 8));
		// Если блок заполнен
		if(++this->_size == this->_rate){
			// Выполняем перестановку состояния
			this->permute();
			// Сбрасываем счётчик байтов незавершённого блока
			this->_size = 0;
		}
	}
	// Выводим успешность поглощения
	return true;
}
/**
 * \~russian
 * @brief Метод выжимания куска итога функции переменного выхода
 *
 * @param result место, в которое помещается кусок итога
 * @param size   длина куска итога в байтах
 *
 * @return       признак того, что кусок выжат: у хешей выжимание отвергается
 *
 * \~english
 * @brief Method of the squeezing of a piece of the result of an extendable-output function
 *
 * @param result place into which the piece of the result is put
 * @param size   length of the piece of the result in bytes
 *
 * @return       sign that the piece is squeezed: at the hashes the squeezing is refused
 *
 * \~
 */
bool nts::digest::Keccak::squeeze(uint8_t * result, const size_t size) noexcept {
	// Если разновидность не функция переменного выхода
	if((this->_type != sha3_t::SHAKE128) && (this->_type != sha3_t::SHAKE256))
		// Выводим отказ выжимания
		return false;
	// Если место под кусок итога не передано
	if((result == nullptr) && (size > 0))
		// Выводим отказ выжимания
		return false;
	// Если выжимание ещё не началось
	if(!this->_squeezing)
		// Выполняем дополнение сообщения и переход к выжиманию
		this->seal();
	/**
	 * Выполняем перебор байтов куска итога
	 */
	for(size_t i = 0; i < size; i++){
		// Если блок выжат целиком
		if(this->_size == this->_rate){
			// Выполняем перестановку состояния
			this->permute();
			// Сбрасываем счётчик выжатых из блока байтов
			this->_size = 0;
		}
		// Выдаём байт полосы по смещению выжатых байтов
		result[i] = static_cast <uint8_t> (this->_state[this->_size / 8] >> ((this->_size % 8) * 8));
		// Увеличиваем счётчик выжатых из блока байтов
		this->_size++;
	}
	// Выводим успешность выжимания
	return true;
}
/**
 * \~russian
 * @brief Метод снятия итога хеша
 *
 * @param result место, в которое помещается итог
 * @param size   длина места в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
 *
 * @return       признак того, что итог снят; повторное снятие отвергается
 *
 * \~english
 * @brief Method of the taking of the result of the hash
 *
 * @param result place into which the result is put
 * @param size   length of the place in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
 *
 * @return       sign that the result is taken; a repeated taking is refused
 *
 * \~
 */
bool nts::digest::Keccak::finish(uint8_t * result, const size_t size) noexcept {
	// Если разновидность не установлена, итог уже снят либо место не передано
	if((this->_rate == 0) || this->_squeezing || (result == nullptr) || (size == 0))
		// Выводим отказ снятия итога
		return false;
	// Если разновидность - функция переменного выхода
	if((this->_type == sha3_t::SHAKE128) || (this->_type == sha3_t::SHAKE256))
		// Выжимаем итог запрошенной длины
		return this->squeeze(result, size);
	// Если длина места не сходится с длиной разновидности
	if(size != length(this->_type))
		// Выводим отказ снятия итога
		return false;
	// Выполняем дополнение сообщения и переход к выжиманию
	this->seal();
	/**
	 * Выполняем перебор байтов итога: итог хеша целиком лежит в первом блоке
	 */
	for(size_t i = 0; i < size; i++)
		// Выдаём байт полосы по смещению
		result[i] = static_cast <uint8_t> (this->_state[i / 8] >> ((i % 8) * 8));
	// Выводим успешность снятия итога
	return true;
}
/**
 * \~russian
 * @brief Конструктор
 *
 * @param type разновидность преобразования
 *
 * \~english
 * @brief Constructor
 *
 * @param type kind of the transformation
 *
 * \~
 */
nts::digest::Keccak::Keccak(const sha3_t type) noexcept : _type(sha3_t::NONE), _squeezing(false), _size(0), _rate(0) {
	// Выполняем сброс преобразования
	this->reset(type);
}
/**
 * \~russian
 * @brief Деструктор: состояние затирается
 *
 * \~english
 * @brief Destructor: the state is wiped
 *
 * \~
 */
nts::digest::Keccak::~Keccak() noexcept {
	// Выполняем затирание состояния губки
	sys::wipe(this->_state, sizeof(this->_state));
}
/**
 * \~russian
 * @brief Метод получения длины итога разновидности
 *
 * @param type разновидность преобразования
 *
 * @return     длина итога хеша в байтах либо нуль у функций переменного выхода
 *
 * \~english
 * @brief Method of the obtaining of the length of the result of a kind
 *
 * @param type kind of the transformation
 *
 * @return     length of the result of the hash in bytes or zero at the extendable-output functions
 *
 * \~
 */
size_t nts::digest::length(const sha3_t type) noexcept {
	/**
	 * Определяем разновидность преобразования
	 */
	switch(static_cast <uint8_t> (type)){
		// Хеши: длина итога равна значению перечисления
		case static_cast <uint8_t> (sha3_t::SHA3_224):
		case static_cast <uint8_t> (sha3_t::SHA3_256):
		case static_cast <uint8_t> (sha3_t::SHA3_384):
		case static_cast <uint8_t> (sha3_t::SHA3_512):
			// Выводим длину итога
			return static_cast <size_t> (type);
	}
	// Выводим отсутствие заданной длины итога
	return 0;
}
/**
 * \~russian
 * @brief Метод получения скорости разновидности
 *
 * @param type разновидность преобразования
 *
 * @return     число байтов, поглощаемых или выдаваемых за одну перестановку, либо нуль
 *
 * \~english
 * @brief Method of the obtaining of the rate of a kind
 *
 * @param type kind of the transformation
 *
 * @return     number of the bytes absorbed or squeezed per one permutation or zero
 *
 * \~
 */
size_t nts::digest::rate(const sha3_t type) noexcept {
	/**
	 * Определяем разновидность преобразования
	 */
	switch(static_cast <uint8_t> (type)){
		// Хеши: скорость есть размер состояния без удвоенной длины итога
		case static_cast <uint8_t> (sha3_t::SHA3_224):
		case static_cast <uint8_t> (sha3_t::SHA3_256):
		case static_cast <uint8_t> (sha3_t::SHA3_384):
		case static_cast <uint8_t> (sha3_t::SHA3_512):
			// Выводим скорость хеша
			return (SHA3_STATE - (static_cast <size_t> (type) * 2));
		// SHAKE128: скорость 1344 разряда
		case static_cast <uint8_t> (sha3_t::SHAKE128):
			// Выводим скорость функции переменного выхода
			return 168;
		// SHAKE256: скорость 1088 разрядов
		case static_cast <uint8_t> (sha3_t::SHAKE256):
			// Выводим скорость функции переменного выхода
			return 136;
	}
	// Выводим отсутствие скорости
	return 0;
}
/**
 * \~russian
 * @brief Метод хеширования сообщения за один вызов
 *
 * @param type   разновидность преобразования
 * @param data   сообщение
 * @param result место, в которое помещается итог
 * @param size   длина итога в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
 *
 * @return       признак того, что итог вычислен
 *
 * \~english
 * @brief Method of the hashing of a message by one call
 *
 * @param type   kind of the transformation
 * @param data   message
 * @param result place into which the result is put
 * @param size   length of the result in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
 *
 * @return       sign that the result is computed
 *
 * \~
 */
bool nts::digest::sha3(const sha3_t type, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Преобразование заданной разновидности
	keccak_t keccak(type);
	// Если сообщение поглотить не удалось
	if(!keccak.update(data))
		// Выводим отказ хеширования
		return false;
	// Выводим итог снятия хеша
	return keccak.finish(result, size);
}
