/**
 * @file stream.hpp
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
 * \~russian
 * @brief Заголовочный файл поточной обёртки шифрования: вектор в голове потока,
 *        имитовставка GCM в хвосте, кусками любой длины
 *
 * \~english
 * @brief Header file of the streaming encryption wrapper: the vector at the head of the
 *        stream, the GCM authentication tag at the tail, by chunks of any length
 *
 * \~
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <cipher/mode.hpp>
#include <cipher/gcm.hpp>

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён модулей шифрования
	 *
	 * \~english
	 * @brief Namespace of the encryption modules
	 *
	 * \~
	 */
	namespace cipher {
		/**
		 * \~russian
		 * @brief Длина вектора GCM в голове потока в байтах
		 *
		 * \~english
		 * @brief Length of the GCM vector at the head of the stream in bytes
		 *
		 * \~
		 */
		static constexpr size_t STREAM_NONCE = 12;

		/**
		 * \~russian
		 * @brief Направление потока
		 *
		 * \~english
		 * @brief Direction of the stream
		 *
		 * \~
		 */
		enum class direction_t : uint8_t {
			// Направление не установлено
			NONE    = 0x00, /*!< \~russian Направление не установлено \~english The direction is not set \~ */
			// Зашифрование
			ENCRYPT = 0x01, /*!< \~russian Зашифрование \~english Encryption \~ */
			// Расшифрование
			DECRYPT = 0x02  /*!< \~russian Расшифрование \~english Decryption \~ */
		};

		/**
		 * \~russian
		 * @brief Режим шифрования потока
		 *
		 * \~english
		 * @brief Encryption mode of the stream
		 *
		 * \~
		 */
		enum class regime_t : uint8_t {
			// Режим не установлен
			NONE     = 0x00, /*!< \~russian Режим не установлен \~english The mode is not set \~ */
			// Гаммирование с обратной связью по шифртексту, без имитовставки
			FEEDBACK = 0x01, /*!< \~russian Гаммирование с обратной связью по шифртексту, без имитовставки \~english Cipher feedback, without an authentication tag \~ */
			// GCM с имитовставкой в хвосте потока
			GCM      = 0x02  /*!< \~russian GCM с имитовставкой в хвосте потока \~english GCM with the authentication tag at the tail of the stream \~ */
		};

		/**
		 * \~russian
		 * @brief Поточная обёртка шифрования
		 *
		 * @details Поток задаётся направлением, шифром и режимом разом. При зашифровании
		 *          вектор вырабатывается из энтропии и уходит первым в выход, у GCM метка
		 *          в 16 байтов дописывается в хвост на завершении. При расшифровании
		 *          вектор копится из головы потока, у GCM последние байты метки
		 *          удерживаются и данными не выдаются: расшифрование отстаёт на длину
		 *          метки, а сличение её идёт лишь на завершении. Нарезка на куски на
		 *          итог не влияет, пустая выдача - законный успех
		 *
		 * @note Намеренные решения: заведение поверх незавершённого потока сбрасывает
		 *       прежний; один объект по очереди работает в обе стороны; порча метки
		 *       ловится только на завершении - выданный до него открытый текст
		 *       подлинным не считается. Нехватка памяти у накопителя выхода отвечает
		 *       отказом, а не прерыванием
		 *
		 * \~english
		 * @brief Streaming encryption wrapper
		 *
		 * @details The stream is set by the direction, the cipher and the mode at once. At the
		 *          encryption the vector is produced from the entropy and goes first into the output,
		 *          at GCM the 16-byte tag is appended to the tail at the completion. At the decryption
		 *          the vector is gathered from the head of the stream, at GCM the last bytes of the tag
		 *          are held back and are not given out as data: the decryption lags by the length of
		 *          the tag, and its comparison goes only at the completion. The slicing into chunks
		 *          does not affect the result, an empty output is a lawful success
		 *
		 * @note Deliberate decisions: a start over an unfinished stream resets the previous one; a
		 *       single object works in both directions in turn; a damage of the tag is caught only at
		 *       the completion - the plain text given out before it is not considered authentic. A lack
		 *       of memory at the output accumulator answers by a refusal, not by a termination
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Stream {
			private:
				// Признак того, что поток заведён и не завершён
				bool _ready;
				// Признак того, что вектор уже выдан в выход
				bool _headed;
			private:
				// Направление потока
				direction_t _direction;
				// Режим шифрования потока
				regime_t _mode;
			private:
				// Длина метки в байтах: ноль у режима без метки
				size_t _tag;
				// Длина вектора в голове потока в байтах
				size_t _head;
				// Число накопленных байтов вектора при расшифровании
				size_t _gathered;
			private:
				// Вектор в голове потока
				uint8_t _vector[MODE_BLOCK];
			private:
				// Удерживаемый хвост потока: возможная метка при расшифровании
				vector <uint8_t> _tail;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Режим гаммирования с обратной связью
				feedback_t _feedback;
				// Режим GCM
				gcm_t _gcm;
			private:
				/**
				 * \~russian
				 * @brief Метод пропуска куска через режим с дописыванием в выход
				 *
				 * @param source пропускаемый кусок
				 * @param result накопитель выхода, в который дописывается итог
				 * @return       признак успешности пропуска
				 *
				 * \~english
				 * @brief Method of passing a chunk through the mode with appending to the output
				 *
				 * @param source the chunk being passed
				 * @param result the output accumulator the result is appended to
				 * @return       the flag of the success of the passing
				 *
				 * \~
				 */
				bool pass(const view_t & source, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима на собранном векторе
				 *
				 * @return признак успешности запуска
				 *
				 * \~english
				 * @brief Method of the start of the mode on the gathered vector
				 *
				 * @return the flag of the success of the start
				 *
				 * \~
				 */
				bool launch() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности потока к работе
				 *
				 * @return признак готовности потока
				 *
				 * \~english
				 * @brief Method of checking the readiness of the stream for the work
				 *
				 * @return the flag of the readiness of the stream
				 *
				 * \~
				 */
				bool ready() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод заведения потока
				 *
				 * @details Поверх незавершённого потока прежний сбрасывается
				 *
				 * @param direction направление потока
				 * @param block     блочный шифр с блоком в 16 байтов и установленным ключом
				 * @param mode      режим шифрования потока
				 * @param tag       длина метки GCM от 4 до 16 байтов, у режима без метки не учитывается
				 * @return          признак успешности заведения
				 *
				 * \~english
				 * @brief Method of the start of the stream
				 *
				 * @details Over an unfinished stream the previous one is reset
				 *
				 * @param direction the direction of the stream
				 * @param block     the block cipher with a 16-byte block and a set key
				 * @param mode      the encryption mode of the stream
				 * @param tag       the length of the GCM tag from 4 to 16 bytes, not regarded at the mode without a tag
				 * @return          the flag of the success of the start
				 *
				 * \~
				 */
				bool start(const direction_t direction, const block_t & block, const regime_t mode, const size_t tag = GCM_TAG) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса потока
				 *
				 * \~english
				 * @brief Method of the reset of the stream
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи куска потока
				 *
				 * @details Итог дописывается в накопитель; пустая выдача - успех
				 *
				 * @param source кусок любой длины, включая пустой
				 * @param result накопитель выхода, в который дописывается итог
				 * @return       признак успешности подачи
				 *
				 * \~english
				 * @brief Method of the feeding of a chunk of the stream
				 *
				 * @details The result is appended to the accumulator; an empty output is a success
				 *
				 * @param source a chunk of any length, including an empty one
				 * @param result the output accumulator the result is appended to
				 * @return       the flag of the success of the feeding
				 *
				 * \~
				 */
				bool update(const view_t & source, vector <uint8_t> & result) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения потока
				 *
				 * @details При зашифровании GCM дописывает метку, при расшифровании
				 *          сличает удержанную; поток закрывается
				 *
				 * @param result накопитель выхода, в который дописывается хвост
				 * @return       признак успешности завершения
				 *
				 * \~english
				 * @brief Method of the completion of the stream
				 *
				 * @details At the encryption GCM appends the tag, at the decryption it compares the
				 *          held one; the stream is closed
				 *
				 * @param result the output accumulator the tail is appended to
				 * @return       the flag of the success of the completion
				 *
				 * \~
				 */
				bool finish(vector <uint8_t> & result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Stream() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Stream() noexcept;
		} stream_t;
	};
};

