/**
 * @file sntrup761.cpp
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
 * @brief Модуль инкапсуляции ключа Streamlined NTRU Prime sntrup761
 *
 * @details Арифметика в Z/4591[x]/(x^761 − x − 1), малые полиномы в {-1,0,1}.
 *          Портировано с эталона OpenSSH sntrup761.c (общественное достояние, SUPERCOP)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/sntrup761.hpp>
#include <digest/sha2.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён проекта
	 */
	using namespace nts;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Параметры sntrup761
	 *
	 */
	// Степень полинома
	constexpr size_t P = 761;
	// Модуль коэффициентов
	constexpr uint16_t Q = 4591;
	// Половина модуля для симметричного представления
	constexpr int16_t Q12 = (Q - 1) / 2;
	// Вес малого полинома
	constexpr size_t W = 286;
	// Длина закодированного полинома Rq
	constexpr size_t RQ_BYTES = 1158;
	// Длина закодированного округлённого полинома
	constexpr size_t ROUNDED_BYTES = 1007;
	// Длина закодированного малого полинома
	constexpr size_t SMALL_BYTES = (P + 3) / 4;
	// Длина хеша
	constexpr size_t HASH_BYTES = 32;

	/**
	 * @brief Типы коэффициентов
	 *
	 */
	// Малый коэффициент в {-1, 0, 1}
	typedef int8_t small_t;
	// Коэффициент по модулю q в [-q12, q12]
	typedef int16_t fq_t;

	/**
	 * @brief Метод получения маски отрицательного числа
	 *
	 * @param x проверяемое число
	 *
	 * @return -1 если x < 0, иначе 0
	 *
	 */
	inline int int16_negative_mask(const int16_t x) noexcept {
		return -(static_cast <int> (static_cast <uint16_t> (x) >> 15));
	}

	/**
	 * @brief Метод получения маски ненулевого числа
	 *
	 * @param x проверяемое число
	 *
	 * @return -1 если x != 0, иначе 0
	 *
	 */
	inline int int16_nonzero_mask(const int16_t x) noexcept {
		const uint32_t v = static_cast <uint32_t> (static_cast <uint16_t> (x));
		return -static_cast <int> ((-v) >> 31);
	}

	/**
	 * @brief Метод деления uint32 на uint14
	 *
	 * @param q частное
	 * @param r остаток
	 * @param x делимое
	 * @param m делитель
	 *
	 */
	void uint32_divmod_uint14(uint32_t * q, uint16_t * r, uint32_t x, const uint16_t m) noexcept {
		uint32_t v = 0x80000000 / m;
		*q = 0;
		uint32_t qpart = static_cast <uint32_t> ((x * static_cast <uint64_t> (v)) >> 31);
		x -= qpart * m;
		*q += qpart;
		qpart = static_cast <uint32_t> ((x * static_cast <uint64_t> (v)) >> 31);
		x -= qpart * m;
		*q += qpart;
		x -= m;
		*q += 1;
		const uint32_t mask = -(x >> 31);
		x += mask & static_cast <uint32_t> (m);
		*q += mask;
		*r = static_cast <uint16_t> (x);
	}

	/**
	 * @brief Метод получения остатка uint32 по модулю uint14
	 *
	 * @param x делимое
	 * @param m делитель
	 *
	 * @return остаток
	 *
	 */
	uint16_t uint32_mod_uint14(const uint32_t x, const uint16_t m) noexcept {
		uint32_t q;
		uint16_t r;
		uint32_divmod_uint14(&q, &r, x, m);
		return r;
	}

	/**
	 * @brief Метод получения остатка int32 по модулю uint14
	 *
	 * @param x делимое
	 * @param m делитель
	 *
	 * @return остаток
	 *
	 */
	uint16_t int32_mod_uint14(const int32_t x, const uint16_t m) noexcept {
		uint32_t ux = static_cast <uint32_t> (x);
		if(x < 0)
			ux = static_cast <uint32_t> (-x);
		uint16_t r = uint32_mod_uint14(ux, m);
		if(x < 0 && r != 0)
			r = m - r;
		return r;
	}

	/**
	 * @brief Метод приведения по модулю 3
	 *
	 * @param x приводимое число
	 *
	 * @return число в {-1, 0, 1}
	 *
	 */
	inline small_t F3_freeze(const int16_t x) noexcept {
		return static_cast <small_t> (int32_mod_uint14(x + 1, 3) - 1);
	}

	/**
	 * @brief Метод приведения по модулю q
	 *
	 * @param x приводимое число
	 *
	 * @return число в [-q12, q12]
	 *
	 */
	inline fq_t Fq_freeze(const int32_t x) noexcept {
		return static_cast <fq_t> (int32_mod_uint14(x + Q12, Q) - Q12);
	}

	/**
	 * @brief Метод обращения по модулю q
	 *
	 * @param a1 обращаемое число
	 *
	 * @return обратное число
	 *
	 */
	fq_t Fq_recip(const fq_t a1) noexcept {
		fq_t ai = a1;
		for(int i = 1; i < Q - 2; ++i)
			ai = Fq_freeze(a1 * static_cast <int32_t> (ai));
		return ai;
	}

	/**
	 * @brief Метод сортировки uint32
	 *
	 * @param array сортируемый массив
	 * @param n     число элементов
	 *
	 */
	void crypto_sort_uint32(uint32_t * array, const size_t n) noexcept {
		if(n < 2)
			return;
		size_t top = 1;
		while(top < n - top)
			top += top;
		for(size_t p = top; p > 0; p >>= 1){
			for(size_t i = 0; i + p < n; ++i){
				if((i & p) == 0){
					const uint32_t a = array[i];
					const uint32_t b = array[i + p];
					if(a > b){
						array[i] = b;
						array[i + p] = a;
					}
				}
			}
			for(size_t q = top; q > p; q >>= 1){
				for(size_t i = 0; i + q < n; ++i){
					if((i & p) == 0 && (i & q) != 0){
						const uint32_t a = array[i];
						const uint32_t b = array[i + p];
						if(a > b){
							array[i] = b;
							array[i + p] = a;
						}
					}
				}
			}
		}
	}

	/**
	 * @brief Метод получения случайного uint32
	 *
	 * @param result место, в которое помещается случайное число
	 *
	 * @return признак успешности
	 *
	 */
	bool urandom32(uint32_t * result) noexcept {
		uint8_t c[4];
		if(!entropy::bytes(c, sizeof(c)))
			return false;
		*result = static_cast <uint32_t> (c[0]) |
		          (static_cast <uint32_t> (c[1]) << 8) |
		          (static_cast <uint32_t> (c[2]) << 16) |
		          (static_cast <uint32_t> (c[3]) << 24);
		return true;
	}

	/**
	 * @brief Метод выработки малого полинома из списка
	 *
	 * @param out выходной полином
	 * @param in  входной список uint32
	 *
	 */
	void Short_fromlist(small_t * out, const uint32_t * in) noexcept {
		uint32_t L[P];
		for(size_t i = 0; i < W; ++i)
			L[i] = in[i] & static_cast <uint32_t> (-2);
		for(size_t i = W; i < P; ++i)
			L[i] = (in[i] & static_cast <uint32_t> (-3)) | 1;
		crypto_sort_uint32(L, P);
		for(size_t i = 0; i < P; ++i)
			out[i] = static_cast <small_t> ((L[i] & 3) - 1);
	}

	/**
	 * @brief Метод выработки случайного короткого полинома
	 *
	 * @param out выходной полином
	 *
	 * @return признак успешности
	 *
	 */
	bool Short_random(small_t * out) noexcept {
		uint32_t L[P];
		for(size_t i = 0; i < P; ++i){
			if(!urandom32(&L[i]))
				return false;
		}
		Short_fromlist(out, L);
		return true;
	}

	/**
	 * @brief Метод выработки случайного малого полинома
	 *
	 * @param out выходной полином
	 *
	 * @return признак успешности
	 *
	 */
	bool Small_random(small_t * out) noexcept {
		for(size_t i = 0; i < P; ++i){
			uint32_t r;
			if(!urandom32(&r))
				return false;
			out[i] = static_cast <small_t> ((((r & 0x3fffffff) * 3) >> 30) - 1);
		}
		return true;
	}

	/**
	 * @brief Метод умножения в кольце R3
	 *
	 * @param h результат
	 * @param f первый множитель
	 * @param g второй множитель
	 *
	 */
	void R3_mult(small_t * h, const small_t * f, const small_t * g) noexcept {
		small_t fg[P + P - 1];
		for(size_t i = 0; i < P; ++i){
			small_t result = 0;
			for(size_t j = 0; j <= i; ++j)
				result = F3_freeze(result + f[j] * g[i - j]);
			fg[i] = result;
		}
		for(size_t i = P; i < P + P - 1; ++i){
			small_t result = 0;
			for(size_t j = i - P + 1; j < P; ++j)
				result = F3_freeze(result + f[j] * g[i - j]);
			fg[i] = result;
		}
		for(size_t i = P + P - 2; i >= P; --i){
			fg[i - P] = F3_freeze(fg[i - P] + fg[i]);
			fg[i - P + 1] = F3_freeze(fg[i - P + 1] + fg[i]);
		}
		for(size_t i = 0; i < P; ++i)
			h[i] = fg[i];
	}

	/**
	 * @brief Метод обращения в кольце R3
	 *
	 * @param out обратный полином
	 * @param in  входной полином
	 *
	 * @return 0 при успехе, -1 при отказе
	 *
	 */
	int R3_recip(small_t * out, const small_t * in) noexcept {
		small_t f[P + 1], g[P + 1], v[P + 1], r[P + 1];
		for(size_t i = 0; i < P + 1; ++i)
			v[i] = 0;
		for(size_t i = 0; i < P + 1; ++i)
			r[i] = 0;
		r[0] = 1;
		for(size_t i = 0; i < P; ++i)
			f[i] = 0;
		f[0] = 1;
		f[P - 1] = f[P] = -1;
		for(size_t i = 0; i < P; ++i)
			g[P - 1 - i] = in[i];
		g[P] = 0;
		int delta = 1;
		for(size_t loop = 0; loop < 2 * P - 1; ++loop){
			for(size_t i = P; i > 0; --i)
				v[i] = v[i - 1];
			v[0] = 0;
			const int sign = -g[0] * f[0];
			const int swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
			delta ^= swap & (delta ^ -delta);
			delta += 1;
			for(size_t i = 0; i < P + 1; ++i){
				int t = swap & (f[i] ^ g[i]);
				f[i] ^= t;
				g[i] ^= t;
				t = swap & (v[i] ^ r[i]);
				v[i] ^= t;
				r[i] ^= t;
			}
			for(size_t i = 0; i < P + 1; ++i)
				g[i] = F3_freeze(g[i] + sign * f[i]);
			for(size_t i = 0; i < P + 1; ++i)
				r[i] = F3_freeze(r[i] + sign * v[i]);
			for(size_t i = 0; i < P; ++i)
				g[i] = g[i + 1];
			g[P] = 0;
		}
		const int sign = f[0];
		for(size_t i = 0; i < P; ++i)
			out[i] = sign * v[P - 1 - i];
		return int16_nonzero_mask(delta);
	}

	/**
	 * @brief Метод умножения в кольце Rq на малый полином
	 *
	 * @param h результат
	 * @param f первый множитель
	 * @param g второй множитель (малый)
	 *
	 */
	void Rq_mult_small(fq_t * h, const fq_t * f, const small_t * g) noexcept {
		fq_t fg[P + P - 1];
		for(size_t i = 0; i < P; ++i){
			fq_t result = 0;
			for(size_t j = 0; j <= i; ++j)
				result = Fq_freeze(result + f[j] * static_cast <int32_t> (g[i - j]));
			fg[i] = result;
		}
		for(size_t i = P; i < P + P - 1; ++i){
			fq_t result = 0;
			for(size_t j = i - P + 1; j < P; ++j)
				result = Fq_freeze(result + f[j] * static_cast <int32_t> (g[i - j]));
			fg[i] = result;
		}
		for(size_t i = P + P - 2; i >= P; --i){
			fg[i - P] = Fq_freeze(fg[i - P] + fg[i]);
			fg[i - P + 1] = Fq_freeze(fg[i - P + 1] + fg[i]);
		}
		for(size_t i = 0; i < P; ++i)
			h[i] = fg[i];
	}

	/**
	 * @brief Метод умножения на 3 в кольце Rq
	 *
	 * @param h результат
	 * @param f входной полином
	 *
	 */
	void Rq_mult3(fq_t * h, const fq_t * f) noexcept {
		for(size_t i = 0; i < P; ++i)
			h[i] = Fq_freeze(3 * f[i]);
	}

	/**
	 * @brief Метод обращения в кольце Rq с умножением на 3
	 *
	 * @param out обратный полином
	 * @param in  входной полином (малый)
	 *
	 * @return 0 при успехе, -1 при отказе
	 *
	 */
	int Rq_recip3(fq_t * out, const small_t * in) noexcept {
		fq_t f[P + 1], g[P + 1], v[P + 1], r[P + 1];
		for(size_t i = 0; i < P + 1; ++i)
			v[i] = 0;
		for(size_t i = 0; i < P + 1; ++i)
			r[i] = 0;
		r[0] = Fq_recip(3);
		for(size_t i = 0; i < P; ++i)
			f[i] = 0;
		f[0] = 1;
		f[P - 1] = f[P] = -1;
		for(size_t i = 0; i < P; ++i)
			g[P - 1 - i] = in[i];
		g[P] = 0;
		int delta = 1;
		for(size_t loop = 0; loop < 2 * P - 1; ++loop){
			for(size_t i = P; i > 0; --i)
				v[i] = v[i - 1];
			v[0] = 0;
			const int swap = int16_negative_mask(-delta) & int16_nonzero_mask(g[0]);
			delta ^= swap & (delta ^ -delta);
			delta += 1;
			for(size_t i = 0; i < P + 1; ++i){
				int t = swap & (f[i] ^ g[i]);
				f[i] ^= t;
				g[i] ^= t;
				t = swap & (v[i] ^ r[i]);
				v[i] ^= t;
				r[i] ^= t;
			}
			const int32_t f0 = f[0];
			const int32_t g0 = g[0];
			for(size_t i = 0; i < P + 1; ++i)
				g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
			for(size_t i = 0; i < P + 1; ++i)
				r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
			for(size_t i = 0; i < P; ++i)
				g[i] = g[i + 1];
			g[P] = 0;
		}
		const fq_t scale = Fq_recip(f[0]);
		for(size_t i = 0; i < P; ++i)
			out[i] = Fq_freeze(scale * static_cast <int32_t> (v[P - 1 - i]));
		return int16_nonzero_mask(delta);
	}

	/**
	 * @brief Метод округления полинома
	 *
	 * @param out округлённый полином
	 * @param a   входной полином
	 *
	 */
	void Round(fq_t * out, const fq_t * a) noexcept {
		for(size_t i = 0; i < P; ++i)
			out[i] = a[i] - F3_freeze(a[i]);
	}

	/**
	 * @brief Метод проверки веса малого полинома
	 *
	 * @param r проверяемый полином
	 *
	 * @return 0 если вес равен W, иначе -1
	 *
	 */
	int Weightw_mask(const small_t * r) noexcept {
		int weight = 0;
		for(size_t i = 0; i < P; ++i)
			weight += r[i] & 1;
		return int16_nonzero_mask(weight - W);
	}

	/**
	 * @brief Метод преобразования из Rq в R3
	 *
	 * @param out выходной полином R3
	 * @param r   входной полином Rq
	 *
	 */
	void R3_fromRq(small_t * out, const fq_t * r) noexcept {
		for(size_t i = 0; i < P; ++i)
			out[i] = F3_freeze(r[i]);
	}

	/**
	 * @brief Метод кодирования малого полинома
	 *
	 * @param s выходной буфер
	 * @param f входной полином
	 *
	 */
	void Small_encode(uint8_t * s, const small_t * f) noexcept {
		for(size_t i = 0; i < P / 4; ++i){
			uint8_t x = static_cast <uint8_t> (*f++ + 1);
			x |= static_cast <uint8_t> ((*f++ + 1) << 2);
			x |= static_cast <uint8_t> ((*f++ + 1) << 4);
			x |= static_cast <uint8_t> ((*f++ + 1) << 6);
			*s++ = x;
		}
		*s++ = static_cast <uint8_t> (*f++ + 1);
	}

	/**
	 * @brief Метод декодирования малого полинома
	 *
	 * @param f выходной полином
	 * @param s входной буфер
	 *
	 */
	void Small_decode(small_t * f, const uint8_t * s) noexcept {
		for(size_t i = 0; i < P / 4; ++i){
			uint8_t x = *s++;
			*f++ = static_cast <small_t> ((x & 3) - 1);
			x >>= 2;
			*f++ = static_cast <small_t> ((x & 3) - 1);
			x >>= 2;
			*f++ = static_cast <small_t> ((x & 3) - 1);
			x >>= 2;
			*f++ = static_cast <small_t> ((x & 3) - 1);
		}
		*f++ = static_cast <small_t> ((*s++ & 3) - 1);
	}

	/**
	 * @brief Метод кодирования массива по модулям
	 *
	 * @param out выходной буфер
	 * @param R   входной массив
	 * @param M   массив модулей
	 * @param len длина массива
	 *
	 */
	void Encode(uint8_t * out, const uint16_t * R, const uint16_t * M, const size_t len) noexcept {
		if(len == 1){
			uint16_t r = R[0];
			uint16_t m = M[0];
			while(m > 1){
				*out++ = r;
				r >>= 8;
				m = (m + 255) >> 8;
			}
			return;
		}
		uint16_t R2[(P + 1) / 2];
		uint16_t M2[(P + 1) / 2];
		size_t i;
		for(i = 0; i < len - 1; i += 2){
			const uint32_t m0 = M[i];
			uint32_t r = R[i] + R[i + 1] * m0;
			uint32_t m = M[i + 1] * m0;
			while(m >= 16384){
				*out++ = r;
				r >>= 8;
				m = (m + 255) >> 8;
			}
			R2[i / 2] = r;
			M2[i / 2] = m;
		}
		if(i < len){
			R2[i / 2] = R[i];
			M2[i / 2] = M[i];
		}
		Encode(out, R2, M2, (len + 1) / 2);
	}

	/**
	 * @brief Метод декодирования массива по модулям
	 *
	 * @param out выходной массив
	 * @param S   входной буфер
	 * @param M   массив модулей
	 * @param len длина массива
	 *
	 */
	void Decode(uint16_t * out, const uint8_t * S, const uint16_t * M, const size_t len) noexcept {
		if(len == 1){
			if(M[0] == 1)
				*out = 0;
			else if(M[0] <= 256)
				*out = uint32_mod_uint14(S[0], M[0]);
			else
				*out = uint32_mod_uint14(S[0] + (static_cast <uint16_t> (S[1]) << 8), M[0]);
			return;
		}
		uint16_t R2[(P + 1) / 2];
		uint16_t M2[(P + 1) / 2];
		uint16_t bottomr[P / 2];
		uint32_t bottomt[P / 2];
		size_t i;
		for(i = 0; i < len - 1; i += 2){
			const uint32_t m = M[i] * static_cast <uint32_t> (M[i + 1]);
			if(m > 256 * 16383){
				bottomt[i / 2] = 256 * 256;
				bottomr[i / 2] = S[0] + 256 * S[1];
				S += 2;
				M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
			} else if(m >= 16384){
				bottomt[i / 2] = 256;
				bottomr[i / 2] = S[0];
				S += 1;
				M2[i / 2] = (m + 255) >> 8;
			} else {
				bottomt[i / 2] = 1;
				bottomr[i / 2] = 0;
				M2[i / 2] = m;
			}
		}
		if(i < len)
			M2[i / 2] = M[i];
		Decode(R2, S, M2, (len + 1) / 2);
		for(i = 0; i < len - 1; i += 2){
			uint32_t r = bottomr[i / 2];
			r += bottomt[i / 2] * R2[i / 2];
			uint32_t r1;
			uint16_t r0;
			uint32_divmod_uint14(&r1, &r0, r, M[i]);
			r1 = uint32_mod_uint14(r1, M[i + 1]);
			*out++ = r0;
			*out++ = r1;
		}
		if(i < len)
			*out++ = R2[i / 2];
	}

	/**
	 * @brief Метод кодирования полинома Rq
	 *
	 * @param s выходной буфер
	 * @param r входной полином
	 *
	 */
	void Rq_encode(uint8_t * s, const fq_t * r) noexcept {
		uint16_t R[P], M[P];
		for(size_t i = 0; i < P; ++i)
			R[i] = r[i] + Q12;
		for(size_t i = 0; i < P; ++i)
			M[i] = Q;
		Encode(s, R, M, P);
	}

	/**
	 * @brief Метод декодирования полинома Rq
	 *
	 * @param r выходной полином
	 * @param s входной буфер
	 *
	 */
	void Rq_decode(fq_t * r, const uint8_t * s) noexcept {
		uint16_t R[P], M[P];
		for(size_t i = 0; i < P; ++i)
			M[i] = Q;
		Decode(R, s, M, P);
		for(size_t i = 0; i < P; ++i)
			r[i] = static_cast <fq_t> (R[i]) - Q12;
	}

	/**
	 * @brief Метод кодирования округлённого полинома
	 *
	 * @param s выходной буфер
	 * @param r входной полином
	 *
	 */
	void Rounded_encode(uint8_t * s, const fq_t * r) noexcept {
		uint16_t R[P], M[P];
		for(size_t i = 0; i < P; ++i)
			R[i] = ((r[i] + Q12) * 10923) >> 15;
		for(size_t i = 0; i < P; ++i)
			M[i] = (Q + 2) / 3;
		Encode(s, R, M, P);
	}

	/**
	 * @brief Метод декодирования округлённого полинома
	 *
	 * @param r выходной полином
	 * @param s входной буфер
	 *
	 */
	void Rounded_decode(fq_t * r, const uint8_t * s) noexcept {
		uint16_t R[P], M[P];
		for(size_t i = 0; i < P; ++i)
			M[i] = (Q + 2) / 3;
		Decode(R, s, M, P);
		for(size_t i = 0; i < P; ++i)
			r[i] = R[i] * 3 - Q12;
	}

	/**
	 * @brief Метод хеширования с префиксом
	 *
	 * @param out   выходной буфер (32 байта)
	 * @param b     префикс
	 * @param in    входные данные
	 * @param inlen длина входных данных
	 *
	 */
	void Hash_prefix(uint8_t * out, const uint8_t b, const uint8_t * in, const size_t inlen) noexcept {
		uint8_t x[SMALL_BYTES + RQ_BYTES + 1];
		uint8_t h[64];
		x[0] = b;
		for(size_t i = 0; i < inlen; ++i)
			x[i + 1] = in[i];
		digest::Sha2 sha(digest::sha_t::SHA512);
		sha.update(view_t(x, inlen + 1));
		sha.finish(h, sizeof(h));
		for(size_t i = 0; i < 32; ++i)
			out[i] = h[i];
		wipe(x, sizeof(x));
		wipe(h, sizeof(h));
	}

	/**
	 * @brief Метод выработки ключей ядра
	 *
	 * @param h    открытый ключ
	 * @param f    секретный полином f
	 * @param ginv обратный к g в R3
	 *
	 * @return признак успешности
	 *
	 */
	bool KeyGen(fq_t * h, small_t * f, small_t * ginv) noexcept {
		small_t g[P];
		fq_t finv[P];
		for(;;){
			if(!Small_random(g))
				return false;
			if(R3_recip(ginv, g) == 0)
				break;
		}
		if(!Short_random(f))
			return false;
		Rq_recip3(finv, f);
		Rq_mult_small(h, finv, g);
		wipe(g, sizeof(g));
		wipe(finv, sizeof(finv));
		return true;
	}

	/**
	 * @brief Метод шифрования ядра
	 *
	 * @param c шифртекст
	 * @param r входной полином
	 * @param h открытый ключ
	 *
	 */
	void Encrypt(fq_t * c, const small_t * r, const fq_t * h) noexcept {
		fq_t hr[P];
		Rq_mult_small(hr, h, r);
		Round(c, hr);
	}

	/**
	 * @brief Метод расшифрования ядра
	 *
	 * @param r    выходной полином
	 * @param c    шифртекст
	 * @param f    секретный полином f
	 * @param ginv обратный к g в R3
	 *
	 */
	void Decrypt(small_t * r, const fq_t * c, const small_t * f, const small_t * ginv) noexcept {
		fq_t cf[P];
		fq_t cf3[P];
		small_t e[P];
		small_t ev[P];
		Rq_mult_small(cf, c, f);
		Rq_mult3(cf3, cf);
		R3_fromRq(e, cf3);
		R3_mult(ev, e, ginv);
		const int mask = Weightw_mask(ev);
		for(size_t i = 0; i < W; ++i)
			r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
		for(size_t i = W; i < P; ++i)
			r[i] = ev[i] & ~mask;
		wipe(cf, sizeof(cf));
		wipe(cf3, sizeof(cf3));
		wipe(e, sizeof(e));
		wipe(ev, sizeof(ev));
	}

	/**
	 * @brief Метод выработки ключей Z
	 *
	 * @param pk открытый ключ
	 * @param sk секретный ключ
	 *
	 * @return признак успешности
	 *
	 */
	bool ZKeyGen(uint8_t * pk, uint8_t * sk) noexcept {
		fq_t h[P];
		small_t f[P], v[P];
		if(!KeyGen(h, f, v))
			return false;
		Rq_encode(pk, h);
		Small_encode(sk, f);
		sk += SMALL_BYTES;
		Small_encode(sk, v);
		wipe(h, sizeof(h));
		wipe(f, sizeof(f));
		wipe(v, sizeof(v));
		return true;
	}

	/**
	 * @brief Метод шифрования Z
	 *
	 * @param C  шифртекст
	 * @param r  входной полином
	 * @param pk открытый ключ
	 *
	 */
	void ZEncrypt(uint8_t * C, const small_t * r, const uint8_t * pk) noexcept {
		fq_t h[P];
		fq_t c[P];
		Rq_decode(h, pk);
		Encrypt(c, r, h);
		Rounded_encode(C, c);
		wipe(h, sizeof(h));
		wipe(c, sizeof(c));
	}

	/**
	 * @brief Метод расшифрования Z
	 *
	 * @param r  выходной полином
	 * @param C  шифртекст
	 * @param sk секретный ключ
	 *
	 */
	void ZDecrypt(small_t * r, const uint8_t * C, const uint8_t * sk) noexcept {
		small_t f[P], v[P];
		fq_t c[P];
		Small_decode(f, sk);
		sk += SMALL_BYTES;
		Small_decode(v, sk);
		Rounded_decode(c, C);
		Decrypt(r, c, f, v);
		wipe(f, sizeof(f));
		wipe(v, sizeof(v));
		wipe(c, sizeof(c));
	}

	/**
	 * @brief Метод вычисления хеша подтверждения
	 *
	 * @param h     выходной буфер
	 * @param r     входной полином (закодированный)
	 * @param cache кэш Hash4(pk)
	 *
	 */
	void HashConfirm(uint8_t * h, const uint8_t * r, const uint8_t * cache) noexcept {
		uint8_t x[HASH_BYTES * 2];
		Hash_prefix(x, 3, r, SMALL_BYTES);
		for(size_t i = 0; i < HASH_BYTES; ++i)
			x[HASH_BYTES + i] = cache[i];
		Hash_prefix(h, 2, x, sizeof(x));
		wipe(x, sizeof(x));
	}

	/**
	 * @brief Метод вычисления хеша сессии
	 *
	 * @param k выходной буфер
	 * @param b префикс
	 * @param y первый вход
	 * @param z второй вход
	 *
	 */
	void HashSession(uint8_t * k, const uint8_t b, const uint8_t * y, const uint8_t * z) noexcept {
		uint8_t x[HASH_BYTES + ROUNDED_BYTES + HASH_BYTES];
		Hash_prefix(x, 3, y, SMALL_BYTES);
		for(size_t i = 0; i < ROUNDED_BYTES + HASH_BYTES; ++i)
			x[HASH_BYTES + i] = z[i];
		Hash_prefix(k, b, x, sizeof(x));
		wipe(x, sizeof(x));
	}

	/**
	 * @brief Метод сокрытия входа
	 *
	 * @param c      шифртекст
	 * @param r_enc  закодированный вход
	 * @param r      входной полином
	 * @param pk     открытый ключ
	 * @param cache  кэш Hash4(pk)
	 *
	 */
	void Hide(uint8_t * c, uint8_t * r_enc, const small_t * r, const uint8_t * pk, const uint8_t * cache) noexcept {
		Small_encode(r_enc, r);
		ZEncrypt(c, r, pk);
		c += ROUNDED_BYTES;
		HashConfirm(c, r_enc, cache);
	}

	/**
	 * @brief Метод сравнения шифртекстов
	 *
	 * @param c  первый шифртекст
	 * @param c2 второй шифртекст
	 *
	 * @return 0 при совпадении, -1 при различии
	 *
	 */
	int Ciphertexts_diff_mask(const uint8_t * c, const uint8_t * c2) noexcept {
		uint16_t differentbits = 0;
		size_t len = ROUNDED_BYTES + HASH_BYTES;
		while(len-- > 0)
			differentbits |= (*c++) ^ (*c2++);
		return (1 & ((differentbits - 1) >> 8)) - 1;
	}
};

/**
 * \~russian
 * @brief Метод выработки пары ключей sntrup761
 *
 * \~english
 * @brief Method of the generation of an sntrup761 key pair
 *
 * \~
 */
bool nts::agreement::pair(uint8_t * key, uint8_t * secret) noexcept {
	// Проверяем указатели
	if(key == nullptr || secret == nullptr)
		return false;
	// Вырабатываем ключи Z
	if(!ZKeyGen(key, secret))
		return false;
	// Дописываем открытый ключ в секретный
	uint8_t * sk = secret + 2 * SMALL_BYTES;
	for(size_t i = 0; i < RQ_BYTES; ++i)
		*sk++ = key[i];
	// Дописываем случайное зерно rho
	if(!entropy::bytes(sk, SMALL_BYTES)){
		wipe(secret, SNTRUP761_SECRET);
		return false;
	}
	sk += SMALL_BYTES;
	// Дописываем кэш Hash4(pk)
	Hash_prefix(sk, 4, key, RQ_BYTES);
	return true;
}

/**
 * \~russian
 * @brief Метод инкапсуляции общего секрета sntrup761
 *
 * \~english
 * @brief Method of the encapsulation of a shared secret sntrup761
 *
 * \~
 */
bool nts::agreement::encaps(const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept {
	// Проверяем параметры
	if(key.data == nullptr || key.size != SNTRUP761_PUBLIC || cipher == nullptr || shared == nullptr)
		return false;
	// Вырабатываем случайный вход
	small_t r[P];
	if(!Short_random(r))
		return false;
	// Вычисляем кэш Hash4(pk)
	uint8_t cache[HASH_BYTES];
	Hash_prefix(cache, 4, key.data, RQ_BYTES);
	// Скрываем вход
	uint8_t r_enc[SMALL_BYTES];
	Hide(cipher, r_enc, r, key.data, cache);
	// Вычисляем общий секрет
	HashSession(shared, 1, r_enc, cipher);
	// Затираем промежуточные данные
	wipe(r, sizeof(r));
	wipe(r_enc, sizeof(r_enc));
	wipe(cache, sizeof(cache));
	return true;
}

/**
 * \~russian
 * @brief Метод декапсуляции общего секрета sntrup761
 *
 * \~english
 * @brief Method of the decapsulation of a shared secret sntrup761
 *
 * \~
 */
bool nts::agreement::decaps(const view_t & cipher, const view_t & secret, uint8_t * shared) noexcept {
	// Проверяем параметры
	if(cipher.data == nullptr || cipher.size != SNTRUP761_CIPHERTEXT ||
	   secret.data == nullptr || secret.size != SNTRUP761_SECRET || shared == nullptr)
		return false;
	// Извлекаем части секретного ключа
	const uint8_t * pk = secret.data + 2 * SMALL_BYTES;
	const uint8_t * rho = pk + RQ_BYTES;
	const uint8_t * cache = rho + SMALL_BYTES;
	// Расшифровываем вход
	small_t r[P];
	ZDecrypt(r, cipher.data, secret.data);
	// Скрываем вход повторно для проверки
	uint8_t r_enc[SMALL_BYTES];
	uint8_t cnew[ROUNDED_BYTES + HASH_BYTES];
	Hide(cnew, r_enc, r, pk, cache);
	// Сравниваем шифртексты
	const int mask = Ciphertexts_diff_mask(cipher.data, cnew);
	// При несовпадении подставляем rho вместо r
	for(size_t i = 0; i < SMALL_BYTES; ++i)
		r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
	// Вычисляем общий секрет
	HashSession(shared, 1 + mask, r_enc, cipher.data);
	// Затираем промежуточные данные
	wipe(r, sizeof(r));
	wipe(r_enc, sizeof(r_enc));
	wipe(cnew, sizeof(cnew));
	// Возвращаем признак совпадения шифртекстов
	return mask == 0;
}
