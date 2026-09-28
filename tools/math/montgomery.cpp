/**
 * @file montgomery.cpp
 * @date 2026-09-23
 * @license{LicenseRef-A-NTS-1.0}
 * @author Yuriy Lobarev
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 * @email forman@anyks.com
 * @site https://anyks.com
 * @brief Щуп ядер умножения Монтгомери: устройства ядра против прежнего эталона в два прохода
 * @details Ядра без библиотеки: два прохода (ядро до круга 33), слитый проход, два и четыре
 *          ряда со сдвигом на C, те же на ассемблере AArch64, квадрат отдельным ядром.
 *          Сходимость сверяется на случайных и краевых входах (модуль из одних единиц,
 *          короткое старшее слово, сомножители на единицу меньше модуля, ноль, единица) по
 *          ширинам от четырёх до шестидесяти четырёх слов, затем меряется полоса
 * @note Итог круга 33 (M4): ряды со сдвигом на C и на ассемблере равны, предел у M4 - три
 *       флаговые команды за такт, а не умножитель (три умножения за такт); под x86-64
 *       четыре ряда медленнее двух. В библиотеку взяты два ряда и квадрат (решение 6
 *       шапки src/math/integer.cpp). Собирается отдельно: c++ -O3 -std=c++17 montgomery.cpp
 * @note Круг 39 (28.09.2026): ряд полосами по четыре слова накопителя в регистрах - две с
 *       половиной флаговые команды на произведение вместо четырёх у рядов на C (образец
 *       bn_mul4x_mont): M4 16 слов 187 → 127 нс при 134 у BN_mod_mul_montgomery, Xeon
 *       E5-2630 v4 на mulx/adcx/adox 713 → 564 при 468. Ядра библиотеки (stripes, решение 7
 *       шапки) включены сюда как есть и сличаются с эталоном; сборка с OpenSSL:
 *       c++ -O3 -std=c++17 -DWITH_OPENSSL montgomery.cpp -lcrypto. Отвергнуто по замеру
 *       (M4, 16 слов): четыре ряда разом с окном в регистрах - 168, два ряда переплетением -
 *       148, квадрат рядами с удвоенным маскированным множимым - 180 (Xeon 610 при 561 у
 *       умножения; полоса только приведения стоит 73 % полной): ядро упирается в задержку
 *       цепочки полосы, а не в число умножений; bn_sqr8x_mont (M4 94) держит восемь слов
 *       накопителя в регистрах на восемь рядов - остаток. Микрозамеры M4: умножитель ~2,6
 *       команды mul/umulh за такт, флаговые ~3,4, смесь полосы 7,3 такта при 8,1…8,7 у ядра
 * @note Круг 40 (28.09.2026): квадрат блоками по восемь слов (square8x, решение 8 шапки) - три
 *       прохода с окном накопителя в регистрах: M4 16 слов 113 нс (с доводкой на C; в библиотеке
 *       110) при 95 у OpenSSL и 128 у полос, Xeon E5-2630 v4 на mulx/adcx/adox 359 при 313 и 561 у
 *       полос; ядро библиотеки включено сюда как есть и сличается с двумя проходами на кратных восьми ширинах
 * @copyright Copyright © 2026
 */

#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
typedef __uint128_t wide_t;
static double now(){ return std::chrono::duration <double> (std::chrono::steady_clock::now().time_since_epoch()).count(); }
static void finish(uint64_t * buffer, const uint64_t * modulus, size_t count, uint64_t * result){
	uint64_t lessened[128]; uint64_t borrow = 0;
	for(size_t i = 0; i < count; i++){ const wide_t d = (wide_t) buffer[i] - modulus[i] - borrow; lessened[i] = (uint64_t) d; borrow = (uint64_t)(d >> 64) & 1; }
	const uint64_t mask = (0 - ((buffer[count] | (borrow ^ 1)) & 1));
	for(size_t i = 0; i < count; i++) result[i] = (lessened[i] & mask) | (buffer[i] & ~mask);
}
extern "C" __attribute__((noinline)) void mont_ref(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	for(size_t i = 0; i < count; i++){
		const uint64_t word = second[i]; uint64_t carry = 0;
		for(size_t j = 0; j < count; j++){ const wide_t item = (static_cast <wide_t> (first[j]) * word + buffer[j] + carry); buffer[j] = (uint64_t) item; carry = (uint64_t)(item >> 64); }
		const wide_t item = (static_cast <wide_t> (buffer[count]) + carry); buffer[count] = (uint64_t) item; buffer[count + 1] = (uint64_t)(item >> 64);
		const uint64_t reducer = (buffer[0] * inverse);
		const wide_t value = (static_cast <wide_t> (reducer) * modulus[0] + buffer[0]); carry = (uint64_t)(value >> 64);
		for(size_t j = 1; j < count; j++){ const wide_t step = (static_cast <wide_t> (reducer) * modulus[j] + buffer[j] + carry); buffer[j - 1] = (uint64_t) step; carry = (uint64_t)(step >> 64); }
		const wide_t last = (static_cast <wide_t> (buffer[count]) + carry); buffer[count - 1] = (uint64_t) last; buffer[count] = (buffer[count + 1] + (uint64_t)(last >> 64));
	}
	finish(buffer, modulus, count, result);
}
extern "C" __attribute__((noinline)) void mont_fused(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	for(size_t i = 0; i < count; i++){
		const uint64_t word = second[i];
		wide_t p = (static_cast <wide_t> (first[0]) * word + buffer[0]);
		const uint64_t low = (uint64_t) p; const uint64_t reducer = (low * inverse);
		wide_t q = (static_cast <wide_t> (reducer) * modulus[0] + low);
		uint64_t carry1 = (uint64_t)(p >> 64), carry2 = (uint64_t)(q >> 64);
		for(size_t j = 1; j < count; j++){
			p = (static_cast <wide_t> (first[j]) * word + buffer[j] + carry1);
			q = (static_cast <wide_t> (reducer) * modulus[j] + (uint64_t) p + carry2);
			buffer[j - 1] = (uint64_t) q; carry1 = (uint64_t)(p >> 64); carry2 = (uint64_t)(q >> 64);
		}
		const wide_t t = (static_cast <wide_t> (buffer[count]) + carry1 + carry2);
		buffer[count - 1] = (uint64_t) t; buffer[count] = (uint64_t)(t >> 64);
	}
	finish(buffer, modulus, count, result);
}
#if defined(__aarch64__)
// Слитый ряд на ассемблере: t = (t + a*w + m*n) / 2^64, t на count+1 слов
static inline void row_arm(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t w, const uint64_t n0, const size_t count){
	uint64_t m;
	__asm__ __volatile__(
		"ldr   x9, [%[a]]\n\t"
		"ldr   x10, [%[n]]\n\t"
		"ldr   x11, [%[t]]\n\t"
		"mul   x12, x9, %[w]\n\t"
		"umulh x13, x9, %[w]\n\t"
		"adds  x12, x12, x11\n\t"
		"adc   x13, x13, xzr\n\t"
		"mul   %[m], x12, %[n0]\n\t"
		"umulh x15, x10, %[m]\n\t"
		"subs  xzr, x12, #1\n\t"
		"adc   x15, x15, xzr\n\t"
		"mov   x16, #1\n\t"
		"1:\n\t"
		"ldr   x9,  [%[a], x16, lsl #3]\n\t"
		"ldr   x10, [%[n], x16, lsl #3]\n\t"
		"ldr   x11, [%[t], x16, lsl #3]\n\t"
		"mul   x12, x9, %[w]\n\t"
		"umulh x14, x9, %[w]\n\t"
		"adds  x12, x12, x13\n\t"
		"adc   x13, x14, xzr\n\t"
		"adds  x12, x12, x11\n\t"
		"adc   x13, x13, xzr\n\t"
		"mul   x14, x10, %[m]\n\t"
		"umulh x17, x10, %[m]\n\t"
		"adds  x14, x14, x15\n\t"
		"adc   x15, x17, xzr\n\t"
		"adds  x14, x14, x12\n\t"
		"adc   x15, x15, xzr\n\t"
		"sub   x17, x16, #1\n\t"
		"str   x14, [%[t], x17, lsl #3]\n\t"
		"add   x16, x16, #1\n\t"
		"cmp   x16, %[count]\n\t"
		"b.ne  1b\n\t"
		"ldr   x11, [%[t], %[count], lsl #3]\n\t"
		"adds  x11, x11, x13\n\t"
		"adc   x12, xzr, xzr\n\t"
		"adds  x11, x11, x15\n\t"
		"adc   x12, x12, xzr\n\t"
		"sub   x17, %[count], #1\n\t"
		"str   x11, [%[t], x17, lsl #3]\n\t"
		"str   x12, [%[t], %[count], lsl #3]\n\t"
		: [m] "=&r" (m)
		: [t] "r" (t), [a] "r" (a), [n] "r" (n), [w] "r" (w), [n0] "r" (n0), [count] "r" (count)
		: "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "cc", "memory");
}
extern "C" __attribute__((noinline)) void mont_row(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	for(size_t i = 0; i < count; i++) row_arm(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}
#endif
// Два ряда со сдвигом на один шаг: ряд i на столбце j, ряд i+1 на столбце j-1 берёт выход ряда i из регистра
static inline void rows2_c(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t w0, const uint64_t w1, const uint64_t n0, const size_t count){
	wide_t p = (static_cast <wide_t> (a[0]) * w0 + t[0]); uint64_t lo = (uint64_t) p; const uint64_t m0 = lo * n0;
	wide_t q = (static_cast <wide_t> (m0) * n[0] + lo); uint64_t c10 = (uint64_t)(p >> 64), c20 = (uint64_t)(q >> 64);
	p = (static_cast <wide_t> (a[1]) * w0 + t[1] + c10); q = (static_cast <wide_t> (m0) * n[1] + (uint64_t) p + c20);
	uint64_t out0 = (uint64_t) q; c10 = (uint64_t)(p >> 64); c20 = (uint64_t)(q >> 64);
	p = (static_cast <wide_t> (a[0]) * w1 + out0); lo = (uint64_t) p; const uint64_t m1 = lo * n0;
	q = (static_cast <wide_t> (m1) * n[0] + lo); uint64_t c11 = (uint64_t)(p >> 64), c21 = (uint64_t)(q >> 64);
	for(size_t j = 2; j < count; j++){
		p = (static_cast <wide_t> (a[j]) * w0 + t[j] + c10); q = (static_cast <wide_t> (m0) * n[j] + (uint64_t) p + c20);
		out0 = (uint64_t) q; c10 = (uint64_t)(p >> 64); c20 = (uint64_t)(q >> 64);
		p = (static_cast <wide_t> (a[j - 1]) * w1 + out0 + c11); q = (static_cast <wide_t> (m1) * n[j - 1] + (uint64_t) p + c21);
		t[j - 2] = (uint64_t) q; c11 = (uint64_t)(p >> 64); c21 = (uint64_t)(q >> 64);
	}
	wide_t T = (static_cast <wide_t> (t[count]) + c10 + c20); const uint64_t top0 = (uint64_t) T, top1 = (uint64_t)(T >> 64);
	p = (static_cast <wide_t> (a[count - 1]) * w1 + top0 + c11); q = (static_cast <wide_t> (m1) * n[count - 1] + (uint64_t) p + c21);
	t[count - 2] = (uint64_t) q; c11 = (uint64_t)(p >> 64); c21 = (uint64_t)(q >> 64);
	T = (static_cast <wide_t> (top1) + c11 + c21); t[count - 1] = (uint64_t) T; t[count] = (uint64_t)(T >> 64);
}
static inline void row_c(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t w, const uint64_t n0, const size_t count){
	wide_t p = (static_cast <wide_t> (a[0]) * w + t[0]); const uint64_t lo = (uint64_t) p; const uint64_t m = lo * n0;
	wide_t q = (static_cast <wide_t> (m) * n[0] + lo); uint64_t c1 = (uint64_t)(p >> 64), c2 = (uint64_t)(q >> 64);
	for(size_t j = 1; j < count; j++){
		p = (static_cast <wide_t> (a[j]) * w + t[j] + c1); q = (static_cast <wide_t> (m) * n[j] + (uint64_t) p + c2);
		t[j - 1] = (uint64_t) q; c1 = (uint64_t)(p >> 64); c2 = (uint64_t)(q >> 64);
	}
	const wide_t T = (static_cast <wide_t> (t[count]) + c1 + c2); t[count - 1] = (uint64_t) T; t[count] = (uint64_t)(T >> 64);
}
extern "C" __attribute__((noinline)) void mont_rows2c(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	size_t i = 0;
	for(; (i + 2) <= count; i += 2) rows2_c(buffer, first, modulus, second[i], second[i + 1], inverse, count);
	for(; i < count; i++) row_c(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}

#if defined(__aarch64__)
// Два ряда со сдвигом: пролог и эпилог на C, цикл столбцов на ассемблере; переносы и перенесённые слова живут в регистрах
static inline void rows2_arm(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t w0, const uint64_t w1, const uint64_t n0, const size_t count){
	wide_t p = (static_cast <wide_t> (a[0]) * w0 + t[0]); uint64_t lo = (uint64_t) p; const uint64_t m0 = lo * n0;
	wide_t q = (static_cast <wide_t> (m0) * n[0] + lo); uint64_t c10 = (uint64_t)(p >> 64), c20 = (uint64_t)(q >> 64);
	p = (static_cast <wide_t> (a[1]) * w0 + t[1] + c10); q = (static_cast <wide_t> (m0) * n[1] + (uint64_t) p + c20);
	uint64_t out0 = (uint64_t) q; c10 = (uint64_t)(p >> 64); c20 = (uint64_t)(q >> 64);
	p = (static_cast <wide_t> (a[0]) * w1 + out0); lo = (uint64_t) p; const uint64_t m1 = lo * n0;
	q = (static_cast <wide_t> (m1) * n[0] + lo); uint64_t c11 = (uint64_t)(p >> 64), c21 = (uint64_t)(q >> 64);
	uint64_t aj1 = a[1], nj1 = n[1];
	if(count > 2){
		uint64_t j = 2;
		__asm__ __volatile__(
			"1:\n\t"
			"ldr   x9,  [%[a], %[j], lsl #3]\n\t"        // a[j]
			"ldr   x11, [%[n], %[j], lsl #3]\n\t"        // n[j]
			"ldr   x13, [%[t], %[j], lsl #3]\n\t"        // t[j]
			/* ряд 0, столбец j */
			"mul   x14, x9, %[w0]\n\t"
			"umulh x15, x9, %[w0]\n\t"
			"adds  x14, x14, %[c10]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x14, x14, x13\n\t"
			"adc   %[c10], x15, xzr\n\t"
			"mul   x16, %[m0], x11\n\t"
			"umulh x17, %[m0], x11\n\t"
			"adds  x16, x16, %[c20]\n\t"
			"adc   x17, x17, xzr\n\t"
			"adds  x16, x16, x14\n\t"
			"adc   %[c20], x17, xzr\n\t"                  // x16 = выход ряда 0
			/* ряд 1, столбец j-1: вход x16 */
			"mul   x14, %[aj1], %[w1]\n\t"
			"umulh x15, %[aj1], %[w1]\n\t"
			"adds  x14, x14, %[c11]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x14, x14, x16\n\t"
			"adc   %[c11], x15, xzr\n\t"
			"mul   x16, %[m1], %[nj1]\n\t"
			"umulh x17, %[m1], %[nj1]\n\t"
			"adds  x16, x16, %[c21]\n\t"
			"adc   x17, x17, xzr\n\t"
			"adds  x16, x16, x14\n\t"
			"adc   %[c21], x17, xzr\n\t"
			"sub   x15, %[j], #2\n\t"
			"str   x16, [%[t], x15, lsl #3]\n\t"          // t[j-2]
			"mov   %[aj1], x9\n\t"
			"mov   %[nj1], x11\n\t"
			"add   %[j], %[j], #1\n\t"
			"cmp   %[j], %[count]\n\t"
			"b.ne  1b\n\t"
			: [c10] "+r" (c10), [c20] "+r" (c20), [c11] "+r" (c11), [c21] "+r" (c21), [aj1] "+r" (aj1), [nj1] "+r" (nj1), [j] "+r" (j)
			: [t] "r" (t), [a] "r" (a), [n] "r" (n), [w0] "r" (w0), [w1] "r" (w1), [m0] "r" (m0), [m1] "r" (m1), [count] "r" (count)
			: "x9", "x11", "x13", "x14", "x15", "x16", "x17", "cc", "memory");
	}
	wide_t T = (static_cast <wide_t> (t[count]) + c10 + c20); const uint64_t top0 = (uint64_t) T, top1 = (uint64_t)(T >> 64);
	p = (static_cast <wide_t> (aj1) * w1 + top0 + c11); q = (static_cast <wide_t> (m1) * nj1 + (uint64_t) p + c21);
	t[count - 2] = (uint64_t) q; c11 = (uint64_t)(p >> 64); c21 = (uint64_t)(q >> 64);
	T = (static_cast <wide_t> (top1) + c11 + c21); t[count - 1] = (uint64_t) T; t[count] = (uint64_t)(T >> 64);
}
extern "C" __attribute__((noinline)) void mont_rows2(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	size_t i = 0;
	for(; (i + 2) <= count; i += 2) rows2_arm(buffer, first, modulus, second[i], second[i + 1], inverse, count);
	for(; i < count; i++) row_c(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}
#endif

// Четыре ряда со сдвигом на шаг (C): единый цикл J по «итерациям», ряд r на столбце J-r
static inline void rows4_c(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t * w, const uint64_t n0, const size_t count){
	uint64_t m[4] = {0,0,0,0}, c1[4] = {0,0,0,0}, c2[4] = {0,0,0,0}, out[4] = {0,0,0,0}, top[4] = {0,0,0,0};
	for(size_t J = 0; J < (count + 5); J++){
		for(size_t r = 0; r < 4; r++){
			if(J < r) continue;
			const size_t c = (J - r);
			const uint64_t in = ((r == 0) ? ((c <= count) ? t[c] : 0) : out[r - 1]);
			if(c < count){
				wide_t p = (static_cast <wide_t> (a[c]) * w[r] + in + c1[r]);
				if(c == 0) m[r] = (static_cast <uint64_t> (p) * n0);
				wide_t q = (static_cast <wide_t> (m[r]) * n[c] + static_cast <uint64_t> (p) + c2[r]);
				out[r] = static_cast <uint64_t> (q); c1[r] = static_cast <uint64_t> (p >> 64); c2[r] = static_cast <uint64_t> (q >> 64);
			} else if(c == count){
				const wide_t T = (static_cast <wide_t> (in) + c1[r] + c2[r]);
				out[r] = static_cast <uint64_t> (T); top[r] = static_cast <uint64_t> (T >> 64);
			} else if(c == (count + 1)){
				out[r] = top[r];
			} else continue;
			if((r == 3) && (c >= 1) && (c <= (count + 1))) t[c - 1] = out[3];
		}
	}
}
extern "C" __attribute__((noinline)) void mont_rows4c(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	size_t i = 0;
	for(; (i + 4) <= count; i += 4) rows4_c(buffer, first, modulus, second + i, inverse, count);
	for(; (i + 2) <= count; i += 2) rows2_c(buffer, first, modulus, second[i], second[i + 1], inverse, count);
	for(; i < count; i++) row_c(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}
// Квадрат: симметричные произведения (n(n-1)/2), удвоение, диагональ, затем приведение Монтгомери рядами со сдвигом по два
static inline void reduce2_c(uint64_t * P, const uint64_t * n, const uint64_t n0, const size_t count, const size_t i){
	// Два ряда приведения: ряд i берёт P[i..], ряд i+1 - выход ряда i; вклад m*n в P со смещением; итог: P[i], P[i+1] обнуляются
	const uint64_t m0 = (P[i] * n0);
	wide_t q = (static_cast <wide_t> (m0) * n[0] + P[i]); uint64_t c0 = static_cast <uint64_t> (q >> 64);
	q = (static_cast <wide_t> (m0) * n[1] + P[i + 1] + c0); const uint64_t s1 = static_cast <uint64_t> (q); c0 = static_cast <uint64_t> (q >> 64);
	const uint64_t m1 = (s1 * n0);
	q = (static_cast <wide_t> (m1) * n[0] + s1); uint64_t c1 = static_cast <uint64_t> (q >> 64);
	for(size_t j = 2; j < count; j++){
		q = (static_cast <wide_t> (m0) * n[j] + P[i + j] + c0); const uint64_t s = static_cast <uint64_t> (q); c0 = static_cast <uint64_t> (q >> 64);
		q = (static_cast <wide_t> (m1) * n[j - 1] + s + c1); P[i + j] = static_cast <uint64_t> (q); c1 = static_cast <uint64_t> (q >> 64);
	}
	// хвост ряда 0: P[i+count] += c0 ; ряд 1 добирает столбец count-1 и хвост
	wide_t T = (static_cast <wide_t> (P[i + count]) + c0); const uint64_t s = static_cast <uint64_t> (T); uint64_t carry = static_cast <uint64_t> (T >> 64);
	q = (static_cast <wide_t> (m1) * n[count - 1] + s + c1); P[i + count] = static_cast <uint64_t> (q); c1 = static_cast <uint64_t> (q >> 64);
	// P[i+count+1] += carry + c1, распространение переноса вверх
	size_t k = (i + count + 1);
	wide_t U = (static_cast <wide_t> (P[k]) + carry + c1); P[k] = static_cast <uint64_t> (U); uint64_t up = static_cast <uint64_t> (U >> 64);
	for(k++; up && (k < (2 * count + 2)); k++){ U = (static_cast <wide_t> (P[k]) + up); P[k] = static_cast <uint64_t> (U); up = static_cast <uint64_t> (U >> 64); }
}
extern "C" __attribute__((noinline)) void mont_sqrc(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	(void) second;
	uint64_t P[132]; memset(P, 0, (2 * count + 2) * 8);
	// Симметричные произведения a[i]*a[j], i<j
	for(size_t i = 0; i + 1 < count; i++){
		const uint64_t w = first[i]; uint64_t carry = 0;
		for(size_t j = i + 1; j < count; j++){
			const wide_t p = (static_cast <wide_t> (first[j]) * w + P[i + j] + carry);
			P[i + j] = static_cast <uint64_t> (p); carry = static_cast <uint64_t> (p >> 64);
		}
		P[i + count] = carry;
	}
	// Удвоение
	uint64_t top = 0;
	for(size_t k = 0; k < (2 * count); k++){ const uint64_t v = P[k]; P[k] = ((v << 1) | top); top = (v >> 63); }
	// Диагональ
	uint64_t carry = 0;
	for(size_t i = 0; i < count; i++){
		const wide_t s = (static_cast <wide_t> (first[i]) * first[i]);
		wide_t lo = (static_cast <wide_t> (P[2 * i]) + static_cast <uint64_t> (s) + carry); P[2 * i] = static_cast <uint64_t> (lo);
		wide_t hi = (static_cast <wide_t> (P[2 * i + 1]) + static_cast <uint64_t> (s >> 64) + static_cast <uint64_t> (lo >> 64)); P[2 * i + 1] = static_cast <uint64_t> (hi);
		carry = static_cast <uint64_t> (hi >> 64);
	}
	P[2 * count] = carry;
	// Приведение рядами по два (count чётный) либо по одному
	size_t i = 0;
	for(; (i + 2) <= count; i += 2) reduce2_c(P, modulus, inverse, count, i);
	for(; i < count; i++){
		const uint64_t m = (P[i] * inverse); uint64_t c = 0;
		for(size_t j = 0; j < count; j++){ const wide_t q = (static_cast <wide_t> (m) * modulus[j] + P[i + j] + c); P[i + j] = static_cast <uint64_t> (q); c = static_cast <uint64_t> (q >> 64); }
		size_t k = (i + count);
		for(; c && (k < (2 * count + 2)); k++){ const wide_t U = (static_cast <wide_t> (P[k]) + c); P[k] = static_cast <uint64_t> (U); c = static_cast <uint64_t> (U >> 64); }
	}
	// Итог в P[count .. 2count], условное вычитание
	finish(P + count, modulus, count, result);
}
// Пропускная способность умножителя: независимые mul+umulh
extern "C" __attribute__((noinline)) uint64_t multhroughput(uint64_t x, size_t N){
	uint64_t a0 = x, a1 = x + 1, a2 = x + 2, a3 = x + 3, s0 = 0, s1 = 0, s2 = 0, s3 = 0;
	for(size_t i = 0; i < N; i++){
		const wide_t p0 = static_cast <wide_t> (a0) * a1, p1 = static_cast <wide_t> (a2) * a3, p2 = static_cast <wide_t> (a1) * a2, p3 = static_cast <wide_t> (a3) * a0;
		s0 ^= static_cast <uint64_t> (p0) ^ static_cast <uint64_t> (p0 >> 64); s1 ^= static_cast <uint64_t> (p1) ^ static_cast <uint64_t> (p1 >> 64);
		s2 ^= static_cast <uint64_t> (p2) ^ static_cast <uint64_t> (p2 >> 64); s3 ^= static_cast <uint64_t> (p3) ^ static_cast <uint64_t> (p3 >> 64);
		a0 += 3; a1 += 5; a2 += 7; a3 += 11;
	}
	return (s0 ^ s1 ^ s2 ^ s3);
}

// Четыре ряда со сдвигом: пролог, прямой основной цикл без ветвлений, эпилог
static inline void rows4b_c(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t * w, const uint64_t n0, const size_t count){
	uint64_t m0, m1, m2, m3, c10 = 0, c20 = 0, c11 = 0, c21 = 0, c12 = 0, c22 = 0, c13 = 0, c23 = 0, o0, o1, o2, o3;
	wide_t p, q;
	#define STEP(r, c, in, cc1, cc2, mm, out) \
		p = (static_cast <wide_t> (a[c]) * w[r] + (in) + cc1); \
		q = (static_cast <wide_t> (mm) * n[c] + static_cast <uint64_t> (p) + cc2); \
		out = static_cast <uint64_t> (q); cc1 = static_cast <uint64_t> (p >> 64); cc2 = static_cast <uint64_t> (q >> 64);
	#define FIRST(r, in, cc1, cc2, mm, out) \
		p = (static_cast <wide_t> (a[0]) * w[r] + (in)); mm = (static_cast <uint64_t> (p) * n0); \
		q = (static_cast <wide_t> (mm) * n[0] + static_cast <uint64_t> (p)); \
		out = static_cast <uint64_t> (q); cc1 = static_cast <uint64_t> (p >> 64); cc2 = static_cast <uint64_t> (q >> 64);
	// Пролог: J = 0..3
	FIRST(0, t[0], c10, c20, m0, o0)
	STEP(0, 1, t[1], c10, c20, m0, o0) FIRST(1, o0, c11, c21, m1, o1)
	STEP(0, 2, t[2], c10, c20, m0, o0) STEP(1, 1, o0, c11, c21, m1, o1) FIRST(2, o1, c12, c22, m2, o2)
	STEP(0, 3, t[3], c10, c20, m0, o0) STEP(1, 2, o0, c11, c21, m1, o1) STEP(2, 1, o1, c12, c22, m2, o2) FIRST(3, o2, c13, c23, m3, o3)
	// Основной цикл: J = 4..count-1
	for(size_t J = 4; J < count; J++){
		STEP(0, J, t[J], c10, c20, m0, o0)
		STEP(1, J - 1, o0, c11, c21, m1, o1)
		STEP(2, J - 2, o1, c12, c22, m2, o2)
		STEP(3, J - 3, o2, c13, c23, m3, o3)
		t[J - 4] = o3;
	}
	// Эпилог: ряд 0 завершает столбец count, остальные добирают
	wide_t T;
	uint64_t top0, top1, top2, top3;
	T = (static_cast <wide_t> (t[count]) + c10 + c20); o0 = static_cast <uint64_t> (T); top0 = static_cast <uint64_t> (T >> 64);      // J = count
	STEP(1, count - 1, o0, c11, c21, m1, o1) STEP(2, count - 2, o1, c12, c22, m2, o2) STEP(3, count - 3, o2, c13, c23, m3, o3) t[count - 4] = o3;
	T = (static_cast <wide_t> (top0) + c11 + c21); o1 = static_cast <uint64_t> (T); top1 = static_cast <uint64_t> (T >> 64);        // J = count + 1
	STEP(2, count - 1, o1, c12, c22, m2, o2) STEP(3, count - 2, o2, c13, c23, m3, o3) t[count - 3] = o3;
	T = (static_cast <wide_t> (top1) + c12 + c22); o2 = static_cast <uint64_t> (T); top2 = static_cast <uint64_t> (T >> 64);        // J = count + 2
	STEP(3, count - 1, o2, c13, c23, m3, o3) t[count - 2] = o3;
	T = (static_cast <wide_t> (top2) + c13 + c23); t[count - 1] = static_cast <uint64_t> (T); top3 = static_cast <uint64_t> (T >> 64); // J = count + 3
	t[count] = top3;                                                                                                                 // J = count + 4
	#undef STEP
	#undef FIRST
}
extern "C" __attribute__((noinline)) void mont_rows4b(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	size_t i = 0;
	if(count >= 4) for(; (i + 4) <= count; i += 4) rows4b_c(buffer, first, modulus, second + i, inverse, count);
	for(; (i + 2) <= count; i += 2) rows2_c(buffer, first, modulus, second[i], second[i + 1], inverse, count);
	for(; i < count; i++) row_c(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}

// Квадрат Монтгомери: симметричные произведения рядами по два со сдвигом, удвоение с диагональю одним проходом,
// приведение рядами по четыре со сдвигом без сдвига окна (хвостовые переносы фиксированной длины)
static inline void sqrrows2(uint64_t * P, const uint64_t * a, const size_t count, const size_t i){
	// Ряд i: столбцы i+j, j = i+1..count-1; ряд i+1: столбцы i+1+j, j = i+2..count-1; ряд i+1 на столбце c читает выход ряда i
	const uint64_t w0 = a[i], w1 = a[i + 1];
	uint64_t c0 = 0, c1 = 0;
	// Пролог: ряд 0 на столбцах 2i+1 и 2i+2 (у ряда 1 первый столбец 2i+3)
	{ wide_t p = (static_cast <wide_t> (a[i + 1]) * w0 + P[2 * i + 1]); P[2 * i + 1] = static_cast <uint64_t> (p); c0 = static_cast <uint64_t> (p >> 64); }
	uint64_t s0;
	if((2 * i + 2) < (i + count)){ wide_t p = (static_cast <wide_t> (a[i + 2]) * w0 + P[2 * i + 2] + c0); s0 = static_cast <uint64_t> (p); c0 = static_cast <uint64_t> (p >> 64); P[2 * i + 2] = s0; }
	// Основной цикл: столбцы c = 2i+3 .. i+count-1: ряд 0 (j = c - i), ряд 1 (j = c - i - 1)
	for(size_t c = (2 * i + 3); c < (i + count); c++){
		wide_t p = (static_cast <wide_t> (a[c - i]) * w0 + P[c] + c0); s0 = static_cast <uint64_t> (p); c0 = static_cast <uint64_t> (p >> 64);
		wide_t q = (static_cast <wide_t> (a[c - i - 1]) * w1 + s0 + c1); P[c] = static_cast <uint64_t> (q); c1 = static_cast <uint64_t> (q >> 64);
	}
	// Эпилог: ряд 0 кладёт перенос в P[i+count] (столбец свежий), ряд 1 добирает столбец i+count и кладёт перенос в P[i+count+1]
	{ const uint64_t v = c0; wide_t q = (static_cast <wide_t> (a[count - 1]) * w1 + v + c1); P[i + count] = static_cast <uint64_t> (q); P[i + count + 1] = static_cast <uint64_t> (q >> 64); }
}
static inline void sqrrow1(uint64_t * P, const uint64_t * a, const size_t count, const size_t i){
	const uint64_t w = a[i]; uint64_t c = 0;
	for(size_t j = i + 1; j < count; j++){ wide_t p = (static_cast <wide_t> (a[j]) * w + P[i + j] + c); P[i + j] = static_cast <uint64_t> (p); c = static_cast <uint64_t> (p >> 64); }
	P[i + count] = c;
}
// Приведение четырьмя рядами со сдвигом на столбцах P[i ..]; ряды пишут только через ряд 3, хвостовые переносы до конца P
static inline void red4(uint64_t * P, const uint64_t * n, const uint64_t n0, const size_t count, const size_t i, const size_t last){
	uint64_t m[4] = {0,0,0,0}, c[4] = {0,0,0,0};
	// На итерации J все начатые ряды r <= J обрабатывают ОДИН столбец i+J (у ряда r это шаг j = J - r), цепочкой в одной итерации
	for(size_t J = 0; (i + J) < last; J++){
		uint64_t in = P[i + J];
		for(size_t r = 0; r < 4; r++){
			if(J < r) break;
			const size_t j = (J - r);
			if(j == 0){ m[r] = (in * n0); const wide_t q = (static_cast <wide_t> (m[r]) * n[0] + in); in = static_cast <uint64_t> (q); c[r] = static_cast <uint64_t> (q >> 64); }
			else if(j < count){ const wide_t q = (static_cast <wide_t> (m[r]) * n[j] + in + c[r]); in = static_cast <uint64_t> (q); c[r] = static_cast <uint64_t> (q >> 64); }
			else { const wide_t T = (static_cast <wide_t> (in) + c[r]); in = static_cast <uint64_t> (T); c[r] = static_cast <uint64_t> (T >> 64); }
		}
		P[i + J] = in;
	}
}
// Приведение четырьмя рядами по столбцам, прямолинейно: пролог (столбцы i..i+3), основной цикл (i+4..i+count-1),
// добор рядов (i+count..i+count+3) и хвост переносов до конца P
static inline void red4b(uint64_t * P, const uint64_t * n, const uint64_t n0, const size_t count, const size_t i, const size_t last){
	uint64_t m0, m1, m2, m3, c0, c1, c2, c3; wide_t q;
	#define RSTEP(mm, j, cc) q = (static_cast <wide_t> (mm) * n[j] + in + cc); in = static_cast <uint64_t> (q); cc = static_cast <uint64_t> (q >> 64);
	#define RFIRST(mm, cc) mm = (in * n0); q = (static_cast <wide_t> (mm) * n[0] + in); in = static_cast <uint64_t> (q); cc = static_cast <uint64_t> (q >> 64);
	#define RTAIL(cc) q = (static_cast <wide_t> (in) + cc); in = static_cast <uint64_t> (q); cc = static_cast <uint64_t> (q >> 64);
	uint64_t * const Q = (P + i);
	{ uint64_t in = Q[0]; RFIRST(m0, c0) Q[0] = in; }
	{ uint64_t in = Q[1]; RSTEP(m0, 1, c0) RFIRST(m1, c1) Q[1] = in; }
	{ uint64_t in = Q[2]; RSTEP(m0, 2, c0) RSTEP(m1, 1, c1) RFIRST(m2, c2) Q[2] = in; }
	{ uint64_t in = Q[3]; RSTEP(m0, 3, c0) RSTEP(m1, 2, c1) RSTEP(m2, 1, c2) RFIRST(m3, c3) Q[3] = in; }
	for(size_t J = 4; J < count; J++){
		uint64_t in = Q[J];
		RSTEP(m0, J, c0) RSTEP(m1, J - 1, c1) RSTEP(m2, J - 2, c2) RSTEP(m3, J - 3, c3)
		Q[J] = in;
	}
	{ uint64_t in = Q[count]; RTAIL(c0) RSTEP(m1, count - 1, c1) RSTEP(m2, count - 2, c2) RSTEP(m3, count - 3, c3) Q[count] = in; }
	{ uint64_t in = Q[count + 1]; RTAIL(c0) RTAIL(c1) RSTEP(m2, count - 1, c2) RSTEP(m3, count - 2, c3) Q[count + 1] = in; }
	{ uint64_t in = Q[count + 2]; RTAIL(c0) RTAIL(c1) RTAIL(c2) RSTEP(m3, count - 1, c3) Q[count + 2] = in; }
	// Хвост: четыре переноса складываются в один и идут до конца P
	uint64_t carry = 0;
	{ wide_t s = (static_cast <wide_t> (c0) + c1 + c2 + c3); uint64_t low = static_cast <uint64_t> (s); carry = static_cast <uint64_t> (s >> 64);
	  wide_t t = (static_cast <wide_t> (Q[count + 3]) + low); Q[count + 3] = static_cast <uint64_t> (t); carry += static_cast <uint64_t> (t >> 64); }
	for(size_t k = (i + count + 4); k < last; k++){ const wide_t t = (static_cast <wide_t> (P[k]) + carry); P[k] = static_cast <uint64_t> (t); carry = static_cast <uint64_t> (t >> 64); }
	#undef RSTEP
	#undef RFIRST
	#undef RTAIL
}

static inline void red1(uint64_t * P, const uint64_t * n, const uint64_t n0, const size_t count, const size_t i, const size_t last){
	const uint64_t m = (P[i] * n0); uint64_t c = 0;
	for(size_t j = 0; j < count; j++){ const wide_t q = (static_cast <wide_t> (m) * n[j] + P[i + j] + c); P[i + j] = static_cast <uint64_t> (q); c = static_cast <uint64_t> (q >> 64); }
	for(size_t k = (i + count); k < last; k++){ const wide_t T = (static_cast <wide_t> (P[k]) + c); P[k] = static_cast <uint64_t> (T); c = static_cast <uint64_t> (T >> 64); }
}
extern "C" __attribute__((noinline)) void mont_sqr2(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	(void) second;
	uint64_t P[132]; memset(P, 0, (2 * count + 2) * 8);
	// Симметричные произведения
	size_t i = 0;
	for(; (i + 2) < count; i += 2) sqrrows2(P, first, count, i);   // ряды i и i+1, у ряда i+1 есть столбцы, если i+2 < count
	for(; (i + 1) < count; i++) sqrrow1(P, first, count, i);
	// Удвоение с диагональю
	uint64_t top = 0, carry = 0;
	for(size_t k = 0; k < count; k++){
		const wide_t s = (static_cast <wide_t> (first[k]) * first[k]);
		uint64_t v = P[2 * k]; uint64_t d0 = ((v << 1) | top); top = (v >> 63);
		v = P[2 * k + 1]; uint64_t d1 = ((v << 1) | top); top = (v >> 63);
		wide_t lo = (static_cast <wide_t> (d0) + static_cast <uint64_t> (s) + carry); P[2 * k] = static_cast <uint64_t> (lo);
		wide_t hi = (static_cast <wide_t> (d1) + static_cast <uint64_t> (s >> 64) + static_cast <uint64_t> (lo >> 64)); P[2 * k + 1] = static_cast <uint64_t> (hi);
		carry = static_cast <uint64_t> (hi >> 64);
	}
	P[2 * count] = (top + carry);
	// Приведение
	const size_t last = (2 * count + 2);
	i = 0;
	for(; (i + 4) <= count; i += 4) red4b(P, modulus, inverse, count, i, last);
	for(; i < count; i++) red1(P, modulus, inverse, count, i, last);
	finish(P + count, modulus, count, result);
}

#if defined(__aarch64__)
// Четыре ряда со сдвигом: пролог и эпилог на C (как rows4b_c), основной цикл на ассемблере с продвигаемыми указателями
static inline void rows4_arm(uint64_t * t, const uint64_t * a, const uint64_t * n, const uint64_t * w, const uint64_t n0, const size_t count){
	uint64_t m0, m1, m2, m3, c10 = 0, c20 = 0, c11 = 0, c21 = 0, c12 = 0, c22 = 0, c13 = 0, c23 = 0, o0, o1, o2, o3;
	wide_t p, q;
	#define STEP(r, c, in, cc1, cc2, mm, out) \
		p = (static_cast <wide_t> (a[c]) * w[r] + (in) + cc1); \
		q = (static_cast <wide_t> (mm) * n[c] + static_cast <uint64_t> (p) + cc2); \
		out = static_cast <uint64_t> (q); cc1 = static_cast <uint64_t> (p >> 64); cc2 = static_cast <uint64_t> (q >> 64);
	#define FIRST(r, in, cc1, cc2, mm, out) \
		p = (static_cast <wide_t> (a[0]) * w[r] + (in)); mm = (static_cast <uint64_t> (p) * n0); \
		q = (static_cast <wide_t> (mm) * n[0] + static_cast <uint64_t> (p)); \
		out = static_cast <uint64_t> (q); cc1 = static_cast <uint64_t> (p >> 64); cc2 = static_cast <uint64_t> (q >> 64);
	FIRST(0, t[0], c10, c20, m0, o0)
	STEP(0, 1, t[1], c10, c20, m0, o0) FIRST(1, o0, c11, c21, m1, o1)
	STEP(0, 2, t[2], c10, c20, m0, o0) STEP(1, 1, o0, c11, c21, m1, o1) FIRST(2, o1, c12, c22, m2, o2)
	STEP(0, 3, t[3], c10, c20, m0, o0) STEP(1, 2, o0, c11, c21, m1, o1) STEP(2, 1, o1, c12, c22, m2, o2) FIRST(3, o2, c13, c23, m3, o3)
	if(count > 4){
		uint64_t * tp = (t + 4); const uint64_t * ap = (a + 4); const uint64_t * np = (n + 4); uint64_t left = (count - 4);
		const uint64_t w0 = w[0], w1 = w[1], w2 = w[2], w3 = w[3];
		__asm__ __volatile__(
			"1:\n\t"
			"ldr   x11, [%[tp]]\n\t"
			/* ряд 0: столбец J */
			"ldr   x9,  [%[ap]]\n\t"
			"ldr   x10, [%[np]]\n\t"
			"mul   x12, x9, %[w0]\n\t"
			"umulh x13, x9, %[w0]\n\t"
			"adds  x12, x12, %[c10]\n\t"
			"adc   x13, x13, xzr\n\t"
			"adds  x12, x12, x11\n\t"
			"adc   %[c10], x13, xzr\n\t"
			"mul   x14, %[m0], x10\n\t"
			"umulh x15, %[m0], x10\n\t"
			"adds  x14, x14, %[c20]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x14, x14, x12\n\t"
			"adc   %[c20], x15, xzr\n\t"
			/* ряд 1: столбец J-1, вход x14 */
			"ldur  x9,  [%[ap], #-8]\n\t"
			"ldur  x10, [%[np], #-8]\n\t"
			"mul   x12, x9, %[w1]\n\t"
			"umulh x13, x9, %[w1]\n\t"
			"adds  x12, x12, %[c11]\n\t"
			"adc   x13, x13, xzr\n\t"
			"adds  x12, x12, x14\n\t"
			"adc   %[c11], x13, xzr\n\t"
			"mul   x16, %[m1], x10\n\t"
			"umulh x15, %[m1], x10\n\t"
			"adds  x16, x16, %[c21]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x16, x16, x12\n\t"
			"adc   %[c21], x15, xzr\n\t"
			/* ряд 2: столбец J-2, вход x16 */
			"ldur  x9,  [%[ap], #-16]\n\t"
			"ldur  x10, [%[np], #-16]\n\t"
			"mul   x12, x9, %[w2]\n\t"
			"umulh x13, x9, %[w2]\n\t"
			"adds  x12, x12, %[c12]\n\t"
			"adc   x13, x13, xzr\n\t"
			"adds  x12, x12, x16\n\t"
			"adc   %[c12], x13, xzr\n\t"
			"mul   x14, %[m2], x10\n\t"
			"umulh x15, %[m2], x10\n\t"
			"adds  x14, x14, %[c22]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x14, x14, x12\n\t"
			"adc   %[c22], x15, xzr\n\t"
			/* ряд 3: столбец J-3, вход x14 */
			"ldur  x9,  [%[ap], #-24]\n\t"
			"ldur  x10, [%[np], #-24]\n\t"
			"mul   x12, x9, %[w3]\n\t"
			"umulh x13, x9, %[w3]\n\t"
			"adds  x12, x12, %[c13]\n\t"
			"adc   x13, x13, xzr\n\t"
			"adds  x12, x12, x14\n\t"
			"adc   %[c13], x13, xzr\n\t"
			"mul   x16, %[m3], x10\n\t"
			"umulh x15, %[m3], x10\n\t"
			"adds  x16, x16, %[c23]\n\t"
			"adc   x15, x15, xzr\n\t"
			"adds  x16, x16, x12\n\t"
			"adc   %[c23], x15, xzr\n\t"
			"stur  x16, [%[tp], #-32]\n\t"
			"add   %[tp], %[tp], #8\n\t"
			"add   %[ap], %[ap], #8\n\t"
			"add   %[np], %[np], #8\n\t"
			"subs  %[left], %[left], #1\n\t"
			"b.ne  1b\n\t"
			: [c10] "+r" (c10), [c20] "+r" (c20), [c11] "+r" (c11), [c21] "+r" (c21), [c12] "+r" (c12), [c22] "+r" (c22), [c13] "+r" (c13), [c23] "+r" (c23),
			  [tp] "+r" (tp), [ap] "+r" (ap), [np] "+r" (np), [left] "+r" (left)
			: [w0] "r" (w0), [w1] "r" (w1), [w2] "r" (w2), [w3] "r" (w3), [m0] "r" (m0), [m1] "r" (m1), [m2] "r" (m2), [m3] "r" (m3)
			: "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "cc", "memory");
	}
	// Эпилог как у rows4b_c: внутри итерации ряд r берёт выход ряда r-1 на столбце c+1, потому выходов цикла не нужно
	wide_t T; uint64_t top0, top1, top2, top3;
	T = (static_cast <wide_t> (t[count]) + c10 + c20); o0 = static_cast <uint64_t> (T); top0 = static_cast <uint64_t> (T >> 64);
	STEP(1, count - 1, o0, c11, c21, m1, o1) STEP(2, count - 2, o1, c12, c22, m2, o2) STEP(3, count - 3, o2, c13, c23, m3, o3) t[count - 4] = o3;
	T = (static_cast <wide_t> (top0) + c11 + c21); o1 = static_cast <uint64_t> (T); top1 = static_cast <uint64_t> (T >> 64);
	STEP(2, count - 1, o1, c12, c22, m2, o2) STEP(3, count - 2, o2, c13, c23, m3, o3) t[count - 3] = o3;
	T = (static_cast <wide_t> (top1) + c12 + c22); o2 = static_cast <uint64_t> (T); top2 = static_cast <uint64_t> (T >> 64);
	STEP(3, count - 1, o2, c13, c23, m3, o3) t[count - 2] = o3;
	T = (static_cast <wide_t> (top2) + c13 + c23); t[count - 1] = static_cast <uint64_t> (T); top3 = static_cast <uint64_t> (T >> 64);
	t[count] = top3;
	#undef STEP
	#undef FIRST
}
extern "C" __attribute__((noinline)) void mont_rows4(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	size_t i = 0;
	if(count >= 4) for(; (i + 4) <= count; i += 4) rows4_arm(buffer, first, modulus, second + i, inverse, count);
	for(; (i + 2) <= count; i += 2) rows2_c(buffer, first, modulus, second[i], second[i + 1], inverse, count);
	for(; i < count; i++) row_c(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}
#endif

// Квадрат Монтгомери со сдвиговым приведением: REDC(P) = REDC_shift(P_low) + P_high, где REDC_shift - ряды со сдвигом
// (как rows4b без члена a*w): цепочки рядов независимы. Итог < 2n, одно условное вычитание
static inline void red4s(uint64_t * t, const uint64_t * n, const uint64_t n0, const size_t count){
	uint64_t m0, m1, m2, m3, c0 = 0, c1 = 0, c2 = 0, c3 = 0, o0, o1, o2, o3; wide_t q;
	#define QSTEP(c, in, cc, mm, out) q = (static_cast <wide_t> (mm) * n[c] + (in) + cc); out = static_cast <uint64_t> (q); cc = static_cast <uint64_t> (q >> 64);
	#define QFIRST(in, cc, mm, out) mm = ((in) * n0); q = (static_cast <wide_t> (mm) * n[0] + (in)); out = static_cast <uint64_t> (q); cc = static_cast <uint64_t> (q >> 64);
	QFIRST(t[0], c0, m0, o0)
	QSTEP(1, t[1], c0, m0, o0) QFIRST(o0, c1, m1, o1)
	QSTEP(2, t[2], c0, m0, o0) QSTEP(1, o0, c1, m1, o1) QFIRST(o1, c2, m2, o2)
	QSTEP(3, t[3], c0, m0, o0) QSTEP(2, o0, c1, m1, o1) QSTEP(1, o1, c2, m2, o2) QFIRST(o2, c3, m3, o3)
	for(size_t J = 4; J < count; J++){
		QSTEP(J, t[J], c0, m0, o0) QSTEP(J - 1, o0, c1, m1, o1) QSTEP(J - 2, o1, c2, m2, o2) QSTEP(J - 3, o2, c3, m3, o3)
		t[J - 4] = o3;
	}
	wide_t T; uint64_t top;
	T = (static_cast <wide_t> (t[count]) + c0); o0 = static_cast <uint64_t> (T); top = static_cast <uint64_t> (T >> 64);
	QSTEP(count - 1, o0, c1, m1, o1) QSTEP(count - 2, o1, c2, m2, o2) QSTEP(count - 3, o2, c3, m3, o3) t[count - 4] = o3;
	T = (static_cast <wide_t> (top) + c1); o1 = static_cast <uint64_t> (T); top = static_cast <uint64_t> (T >> 64);
	QSTEP(count - 1, o1, c2, m2, o2) QSTEP(count - 2, o2, c3, m3, o3) t[count - 3] = o3;
	T = (static_cast <wide_t> (top) + c2); o2 = static_cast <uint64_t> (T); top = static_cast <uint64_t> (T >> 64);
	QSTEP(count - 1, o2, c3, m3, o3) t[count - 2] = o3;
	T = (static_cast <wide_t> (top) + c3); t[count - 1] = static_cast <uint64_t> (T); t[count] = static_cast <uint64_t> (T >> 64);
	#undef QSTEP
	#undef QFIRST
}
static inline void red1s(uint64_t * t, const uint64_t * n, const uint64_t n0, const size_t count){
	const uint64_t m = (t[0] * n0); wide_t q = (static_cast <wide_t> (m) * n[0] + t[0]); uint64_t c = static_cast <uint64_t> (q >> 64);
	for(size_t j = 1; j < count; j++){ q = (static_cast <wide_t> (m) * n[j] + t[j] + c); t[j - 1] = static_cast <uint64_t> (q); c = static_cast <uint64_t> (q >> 64); }
	const wide_t T = (static_cast <wide_t> (t[count]) + c); t[count - 1] = static_cast <uint64_t> (T); t[count] = static_cast <uint64_t> (T >> 64);
}
extern "C" __attribute__((noinline)) void mont_sqr3(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	(void) second;
	uint64_t P[132]; memset(P, 0, (2 * count + 2) * 8);
	size_t i = 0;
	for(; (i + 2) < count; i += 2) sqrrows2(P, first, count, i);
	for(; (i + 1) < count; i++) sqrrow1(P, first, count, i);
	uint64_t top = 0, carry = 0;
	for(size_t k = 0; k < count; k++){
		const wide_t s = (static_cast <wide_t> (first[k]) * first[k]);
		uint64_t v = P[2 * k]; const uint64_t d0 = ((v << 1) | top); top = (v >> 63);
		v = P[2 * k + 1]; const uint64_t d1 = ((v << 1) | top); top = (v >> 63);
		const wide_t lo = (static_cast <wide_t> (d0) + static_cast <uint64_t> (s) + carry); P[2 * k] = static_cast <uint64_t> (lo);
		const wide_t hi = (static_cast <wide_t> (d1) + static_cast <uint64_t> (s >> 64) + static_cast <uint64_t> (lo >> 64)); P[2 * k + 1] = static_cast <uint64_t> (hi);
		carry = static_cast <uint64_t> (hi >> 64);
	}
	// Сдвиговое приведение младшей половины: t = P_low, t[count] = 0
	uint64_t t[66]; memcpy(t, P, count * 8); t[count] = 0;
	i = 0;
	for(; (i + 4) <= count; i += 4) red4s(t, modulus, inverse, count);
	for(; i < count; i++) red1s(t, modulus, inverse, count);
	// Прибавляем старшую половину
	uint64_t c = 0;
	for(size_t k = 0; k < count; k++){ const wide_t s = (static_cast <wide_t> (t[k]) + P[count + k] + c); t[k] = static_cast <uint64_t> (s); c = static_cast <uint64_t> (s >> 64); }
	t[count] += c;
	finish(t, modulus, count, result);
}


/**
 * Ядра библиотеки: ряд полосами по четыре слова (круг 39, решение 7 шапки) и квадрат блоками по
 * восемь слов (круг 40, решение 8 шапки) из src/math/integer.cpp
 */
namespace library {
/**
 * Ветвь AArch64 (GCC, clang): ряд умножения Монтгомери полосами по четыре слова на ассемблере
 * (решение 7 шапки). Регистр x18 у Apple закреплён за системой и не берётся
 */
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	/**
	 * @brief Метод одного ряда умножения Монтгомери полосами по четыре слова на ассемблере AArch64
	 *
	 * @param buffer  накопитель в count + 1 слов: на входе значение меньше удвоенного модуля, на выходе (buffer + first · word + q · modulus) / 2^64
	 * @param first   слова первого сомножителя, меньшего модуля
	 * @param modulus слова нечётного модуля
	 * @param word    слово второго сомножителя
	 * @param inverse множитель приведения по модулю
	 * @param count   число слов модуля, кратное четырём и не меньшее четырёх
	 *
	 * @note Полоса - четыре слова накопителя в регистрах: младшие половины четырёх произведений
	 *       ложатся одной цепочкой adds/adcs, старшие - второй, со сдвигом на слово; переносы
	 *       полосы в следующую - слово старшей половины последнего произведения с разрядом
	 *       переноса (умещается: сумма полосы меньше 2^320). Так на произведение приходится
	 *       две с половиной флаговые команды вместо четырёх у рядов на C
	 *
	 */
	static inline void stripes(uint64_t * buffer, const uint64_t * first, const uint64_t * modulus, const uint64_t word, const uint64_t inverse, const size_t count){
		__asm__ __volatile__(
			"mov   x24, %[buffer]\n\t"
			"mov   x25, %[first]\n\t"
			"mov   x26, %[modulus]\n\t"
			"ldr   x21, %[word]\n\t"
			"sub   x27, %[count], #4\n\t"
			/* Полоса 0: произведения a[0..3] · b, множитель приведения, n[0..3] · q */
			"ldp   x4, x5, [x25]\n\t"
			"ldp   x6, x7, [x25, #16]\n\t"
			"ldp   x12, x13, [x24]\n\t"
			"ldp   x14, x15, [x24, #16]\n\t"
			"mul   x16, x4, x21\n\t"
			"mul   x17, x5, x21\n\t"
			"mul   x19, x6, x21\n\t"
			"mul   x20, x7, x21\n\t"
			"adds  x12, x12, x16\n\t"
			"adcs  x13, x13, x17\n\t"
			"adcs  x14, x14, x19\n\t"
			"adcs  x15, x15, x20\n\t"
			"adc   x23, xzr, xzr\n\t"
			"ldr   x22, %[inverse]\n\t"
			"mul   x22, x12, x22\n\t"
			"umulh x16, x4, x21\n\t"
			"umulh x17, x5, x21\n\t"
			"umulh x19, x6, x21\n\t"
			"umulh x20, x7, x21\n\t"
			"ldp   x4, x5, [x26]\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"adds  x13, x13, x16\n\t"
			"adcs  x14, x14, x17\n\t"
			"adcs  x15, x15, x19\n\t"
			"adc   x9, x20, x23\n\t"
			"mul   x16, x4, x22\n\t"
			"mul   x17, x5, x22\n\t"
			"mul   x19, x6, x22\n\t"
			"mul   x20, x7, x22\n\t"
			"cmn   x12, x16\n\t"
			"adcs  x13, x13, x17\n\t"
			"adcs  x14, x14, x19\n\t"
			"adcs  x15, x15, x20\n\t"
			"adc   x23, xzr, xzr\n\t"
			"umulh x16, x4, x22\n\t"
			"umulh x17, x5, x22\n\t"
			"umulh x19, x6, x22\n\t"
			"umulh x20, x7, x22\n\t"
			"adds  x13, x13, x16\n\t"
			"adcs  x14, x14, x17\n\t"
			"adcs  x15, x15, x19\n\t"
			"adc   x10, x20, x23\n\t"
			"stp   x13, x14, [x24]\n\t"
			"str   x15, [x24, #16]\n\t"
			"cbz   x27, 2f\n\t"
			/* Полосы k = 4, 8, …: x24 указывает на слово k - 4 накопителя */
			"1:\n\t"
			"ldp   x4, x5, [x25, #32]!\n\t"
			"ldp   x6, x7, [x25, #16]\n\t"
			"ldp   x12, x13, [x24, #32]\n\t"
			"ldp   x14, x15, [x24, #48]\n\t"
			"mul   x16, x4, x21\n\t"
			"mul   x17, x5, x21\n\t"
			"mul   x19, x6, x21\n\t"
			"mul   x20, x7, x21\n\t"
			"adds  x12, x12, x16\n\t"
			"adcs  x13, x13, x17\n\t"
			"adcs  x14, x14, x19\n\t"
			"adcs  x15, x15, x20\n\t"
			"adc   x23, xzr, xzr\n\t"
			"umulh x16, x4, x21\n\t"
			"umulh x17, x5, x21\n\t"
			"umulh x19, x6, x21\n\t"
			"umulh x20, x7, x21\n\t"
			"ldp   x4, x5, [x26, #32]!\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"adds  x12, x12, x9\n\t"
			"adcs  x13, x13, x16\n\t"
			"adcs  x14, x14, x17\n\t"
			"adcs  x15, x15, x19\n\t"
			"adc   x9, x20, x23\n\t"
			"mul   x16, x4, x22\n\t"
			"mul   x17, x5, x22\n\t"
			"mul   x19, x6, x22\n\t"
			"mul   x20, x7, x22\n\t"
			"adds  x12, x12, x16\n\t"
			"adcs  x13, x13, x17\n\t"
			"adcs  x14, x14, x19\n\t"
			"adcs  x15, x15, x20\n\t"
			"adc   x23, xzr, xzr\n\t"
			"umulh x16, x4, x22\n\t"
			"umulh x17, x5, x22\n\t"
			"umulh x19, x6, x22\n\t"
			"umulh x20, x7, x22\n\t"
			"adds  x12, x12, x10\n\t"
			"adcs  x13, x13, x16\n\t"
			"adcs  x14, x14, x17\n\t"
			"adcs  x15, x15, x19\n\t"
			"adc   x10, x20, x23\n\t"
			"str   x12, [x24, #24]\n\t"
			"stp   x13, x14, [x24, #32]\n\t"
			"str   x15, [x24, #48]\n\t"
			"add   x24, x24, #32\n\t"
			"subs  x27, x27, #4\n\t"
			"b.ne  1b\n\t"
			"2:\n\t"
			/* Старшие слова: предпоследнее - старшее слово накопителя с переносами полос, последнее - перенос */
			"ldr   x16, [x24, #32]\n\t"
			"adds  x16, x16, x9\n\t"
			"adc   x17, xzr, xzr\n\t"
			"adds  x16, x16, x10\n\t"
			"adc   x17, x17, xzr\n\t"
			"stp   x16, x17, [x24, #24]\n\t"
			:
			: [buffer] "r" (buffer), [first] "r" (first), [modulus] "r" (modulus), [count] "r" (count), [word] "m" (word), [inverse] "m" (inverse)
			: "x4", "x5", "x6", "x7", "x9", "x10", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "cc", "memory");
	}
/**
 * Ветвь x86-64 (GCC, clang) с расширениями BMI2 и ADX: ряд полосами по четыре слова на MULX и
 * двух независимых цепочках переносов ADCX/ADOX (решение 7 шапки). Под ASan без оптимизации
 * ветвь не берётся: вставка занимает все регистры общего назначения (признак __ANTS_ASAN_UNOPTIMIZED__)
 */
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__)
	/**
	 * @brief Метод одного ряда умножения Монтгомери полосами по четыре слова на ассемблере x86-64 (BMI2, ADX)
	 *
	 * @param buffer  накопитель в count + 1 слов: на входе значение меньше удвоенного модуля, на выходе (buffer + first · word + q · modulus) / 2^64
	 * @param first   слова первого сомножителя, меньшего модуля
	 * @param modulus слова нечётного модуля
	 * @param word    слово второго сомножителя
	 * @param inverse множитель приведения по модулю
	 * @param count   число слов модуля, кратное четырём и не меньшее четырёх
	 *
	 * @note MULX не трогает флаги, потому младшие половины произведений с накопителем идут
	 *       цепочкой ADCX по переносу CF, а старшие - цепочкой ADOX по переносу OF, и обе
	 *       цепочки живут разом. Множитель приведения тоже считается MULX: IMUL портит оба
	 *       переноса посреди цепочек. Сравнение конца полос ведётся в порядке, оставляющем
	 *       CF и OF нулевыми: обнуление флагов на каждой полосе не нужно. Порядок команд -
	 *       умножения вперемежку с цепочками, как у OpenSSL: окно планировщика Broadwell
	 *       мало, и порядок в потоке команд стоит до восьми процентов
	 *
	 */
	static inline void stripes(uint64_t * buffer, const uint64_t * first, const uint64_t * modulus, const uint64_t word, const uint64_t inverse, const size_t count){
		// Конец слов первого сомножителя
		const uint64_t * end = (first + count);
		__asm__ __volatile__(
			"movq  %[buffer], %%rcx\n\t"
			"movq  %[first], %%rsi\n\t"
			"movq  %[modulus], %%rdi\n\t"
			"movq  %[word], %%rdx\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			/* Полоса 0: произведения a[0..3] · b, множитель приведения через MULX, n[0..3] · q */
			"mulx  0(%%rsi), %%r8, %%rax\n\t"
			"mulx  8(%%rsi), %%r9, %%r15\n\t"
			"mulx  16(%%rsi), %%r10, %%r12\n\t"
			"mulx  24(%%rsi), %%r11, %%r14\n\t"
			"movq  %[inverse], %%rdx\n\t"
			"adcx  0(%%rcx), %%r8\n\t"
			"adox  %%rax, %%r9\n\t"
			"mulx  %%r8, %%r13, %%rax\n\t"
			"adcx  8(%%rcx), %%r9\n\t"
			"adox  %%r15, %%r10\n\t"
			"movq  %%r13, %%rdx\n\t"
			"adcx  16(%%rcx), %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"adcx  24(%%rcx), %%r11\n\t"
			"adox  %%rbx, %%r14\n\t"
			"adcx  %%rbx, %%r14\n\t"
			"mulx  0(%%rdi), %%rax, %%r15\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r15, %%r9\n\t"
			"mulx  8(%%rdi), %%rax, %%r15\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r15, %%r10\n\t"
			"mulx  16(%%rdi), %%rax, %%r15\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r15, %%r11\n\t"
			"mulx  24(%%rdi), %%rax, %%r12\n\t"
			"movq  %[word], %%rdx\n\t"
			"movq  %%r9, 0(%%rcx)\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"movq  %%r10, 8(%%rcx)\n\t"
			"adcx  %%rbx, %%r12\n\t"
			"movq  %%r11, 16(%%rcx)\n\t"
			"leaq  32(%%rsi), %%rsi\n\t"
			"leaq  32(%%rdi), %%rdi\n\t"
			"leaq  32(%%rcx), %%rcx\n\t"
			"cmpq  %%rsi, %[end]\n\t"
			"je    2f\n\t"
			/* Полосы k = 4, 8, …: rcx указывает на слово k накопителя, CF и OF нулевые */
			".p2align 5\n\t"
			"1:\n\t"
			"mulx  0(%%rsi), %%r8, %%rax\n\t"
			"adox  %%r14, %%r8\n\t"
			"mulx  8(%%rsi), %%r9, %%r15\n\t"
			"adcx  0(%%rcx), %%r8\n\t"
			"adox  %%rax, %%r9\n\t"
			"mulx  16(%%rsi), %%r10, %%rax\n\t"
			"adcx  8(%%rcx), %%r9\n\t"
			"adox  %%r15, %%r10\n\t"
			"mulx  24(%%rsi), %%r11, %%r14\n\t"
			"movq  %%r13, %%rdx\n\t"
			"adcx  16(%%rcx), %%r10\n\t"
			"adox  %%rax, %%r11\n\t"
			"adcx  24(%%rcx), %%r11\n\t"
			"adox  %%rbx, %%r14\n\t"
			"leaq  32(%%rsi), %%rsi\n\t"
			"adcx  %%rbx, %%r14\n\t"
			"adox  %%r12, %%r8\n\t"
			"mulx  0(%%rdi), %%rax, %%r15\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r15, %%r9\n\t"
			"mulx  8(%%rdi), %%rax, %%r15\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r15, %%r10\n\t"
			"mulx  16(%%rdi), %%rax, %%r15\n\t"
			"movq  %%r8, -8(%%rcx)\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r15, %%r11\n\t"
			"mulx  24(%%rdi), %%rax, %%r12\n\t"
			"movq  %[word], %%rdx\n\t"
			"movq  %%r9, 0(%%rcx)\n\t"
			"movq  %%r10, 8(%%rcx)\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"leaq  32(%%rdi), %%rdi\n\t"
			"adcx  %%rbx, %%r12\n\t"
			"movq  %%r11, 16(%%rcx)\n\t"
			"leaq  32(%%rcx), %%rcx\n\t"
			"cmpq  %%rsi, %[end]\n\t"
			"jne   1b\n\t"
			"2:\n\t"
			/* Старшие слова: предпоследнее - старшее слово накопителя с переносами полос, последнее - перенос */
			"movq  0(%%rcx), %%rax\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			"addq  %%r14, %%rax\n\t"
			"adcq  $0, %%rbx\n\t"
			"addq  %%r12, %%rax\n\t"
			"adcq  $0, %%rbx\n\t"
			"movq  %%rax, -8(%%rcx)\n\t"
			"movq  %%rbx, 0(%%rcx)\n\t"
			:
			: [buffer] "m" (buffer), [first] "m" (first), [modulus] "m" (modulus), [end] "m" (end), [word] "m" (word), [inverse] "m" (inverse)
			: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory");
	}
#endif
/**
 * Ветвь AArch64 (GCC, clang): квадрат Монтгомери блоками по восемь слов на ассемблере
 * (решение 8 шапки). Регистры: x4…x11 - окно слов числа либо модуля, x12…x17, x19, x20 -
 * окно накопителя, x21…x24 - временные, x25 - множитель, x26 - указатель накопителя,
 * x27 - указатель окна, x28 - указатель блока, x0 - счётчик, x1 - конец, x2 - перенос;
 * доводы идут одним указателем на структуру (регистр выбирает собиратель), x18 не берётся
 */
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
	/**
	 * @brief Метод квадрата Монтгомери блоками по восемь слов на ассемблере AArch64
	 *
	 * @param buffer  накопитель в 2 · count + 2 слов: на выходе слова count … 2 · count - значение, меньшее удвоенного модуля, младшие count слов - отложенные множители приведения
	 * @param value   слова числа, меньшего модуля
	 * @param modulus слова нечётного модуля
	 * @param count   число слов модуля, кратное восьми и не меньшее восьми
	 * @param inverse множитель приведения по модулю
	 *
	 * @note Три прохода. Первый - произведения слов ниже диагонали без удвоения: восемь слов
	 *       числа (блок) в регистрах, треугольник блока (двадцать восемь произведений) в окно
	 *       из восьми слов накопителя, затем каждое слово блока умножается на окна остальных
	 *       слов числа по восемь произведений на слово со сдвигом окна на слово; ранее
	 *       накопленное прибавляется к окну при каждом переходе к следующему окну. Второй -
	 *       удвоение сдвигом пар слов с прибавлением квадратов диагонали одной цепочкой.
	 *       Третий - приведение по восемь рядов на блок: множители приведения считаются в
	 *       регистрах друг за другом с прибавлением восьми слов модуля к окну и откладываются
	 *       в освободившиеся слова накопителя, затем окна остальных слов модуля умножаются на
	 *       восемь отложенных множителей тем же циклом, что и в первом проходе; перенос за
	 *       старшее слово блока переходит в следующий блок. Между шагами окна перенос хранится
	 *       разрядом флага, а на выходе из восьми шагов он нулевой: к последнему шагу в окне
	 *       остаются лишь произведения восьми слов блока на текущее окно, и их сумма меньше
	 *       2^576 - 2^512, а прибавленное ранее и произведения прежних окон блока уже вышли
	 *       из окна; окно рядов приведения меньше 2^512 по построению. Так на квадрат
	 *       приходится три четверти умножений умножения, а цепочки окна не упираются в
	 *       задержку: у полос квадрат стоил столько же, сколько умножение (образец -
	 *       bn_sqr8x_mont OpenSSL)
	 *
	 */
	static void square8x(uint64_t * buffer, const uint64_t * value, const uint64_t * modulus, const size_t count, const uint64_t inverse) {
		// Доводы ядра одним указателем: накопитель, число, модуль, число слов, множитель приведения, перенос между блоками
		struct {
			uint64_t * buffer;
			const uint64_t * value;
			const uint64_t * modulus;
			uint64_t count;
			uint64_t inverse;
			uint64_t carry;
		} args = {buffer, value, modulus, count, inverse, 0};
		__asm__ __volatile__(
			/* Указатели накопителя и числа, число слов; обнуление удвоенной ширины накопителя */
			"ldp   x26, x27, [%[p]]\n\t"
			"ldr   x0, [%[p], #24]\n\t"
			"mov   x1, x26\n\t"
			"add   x2, x26, x0, lsl #4\n\t"
			"1:\n\t"
			"stp   xzr, xzr, [x1], #16\n\t"
			"cmp   x1, x2\n\t"
			"b.ne  1b\n\t"
			"add   x1, x27, x0, lsl #3\n\t"
			"add   x28, x27, #64\n\t"
			/* Проход 1, блок I: окно накопителя - слова 16I … 16I + 7, слова блока a[8I … 8I + 7] */
			"2:\n\t"
			"ldp   x12, x13, [x26]\n\t"
			"ldp   x14, x15, [x26, #16]\n\t"
			"ldp   x16, x17, [x26, #32]\n\t"
			"ldp   x19, x20, [x26, #48]\n\t"
			"ldp   x4, x5, [x28, #-64]\n\t"
			"ldp   x6, x7, [x28, #-48]\n\t"
			"ldp   x8, x9, [x28, #-32]\n\t"
			"ldp   x10, x11, [x28, #-16]\n\t"
			/* Треугольник блока: младшие половины ряда одной цепочкой, старшие - второй; слова 16I … 16I + 7 итоговые и пишутся, слова 8 … 14 окна остаются в регистрах */
			"mul   x21, x5, x4\n\t"
			"mul   x22, x6, x4\n\t"
			"mul   x23, x7, x4\n\t"
			"mul   x24, x8, x4\n\t"
			"adds  x13, x13, x21\n\t"
			"mul   x21, x9, x4\n\t"
			"adcs  x14, x14, x22\n\t"
			"mul   x22, x10, x4\n\t"
			"adcs  x15, x15, x23\n\t"
			"mul   x23, x11, x4\n\t"
			"adcs  x16, x16, x24\n\t"
			"adcs  x17, x17, x21\n\t"
			"adcs  x19, x19, x22\n\t"
			"adcs  x20, x20, x23\n\t"
			"stp   x12, x13, [x26], #16\n\t"
			"adc   x12, xzr, xzr\n\t"
			"umulh x21, x5, x4\n\t"
			"umulh x22, x6, x4\n\t"
			"umulh x23, x7, x4\n\t"
			"umulh x24, x8, x4\n\t"
			"adds  x14, x14, x21\n\t"
			"umulh x21, x9, x4\n\t"
			"adcs  x15, x15, x22\n\t"
			"umulh x22, x10, x4\n\t"
			"adcs  x16, x16, x23\n\t"
			"umulh x23, x11, x4\n\t"
			"adcs  x17, x17, x24\n\t"
			"adcs  x19, x19, x21\n\t"
			"adcs  x20, x20, x22\n\t"
			"adc   x12, x12, x23\n\t"
			"mul   x21, x6, x5\n\t"
			"mul   x22, x7, x5\n\t"
			"mul   x23, x8, x5\n\t"
			"mul   x24, x9, x5\n\t"
			"adds  x15, x15, x21\n\t"
			"mul   x21, x10, x5\n\t"
			"adcs  x16, x16, x22\n\t"
			"mul   x22, x11, x5\n\t"
			"adcs  x17, x17, x23\n\t"
			"adcs  x19, x19, x24\n\t"
			"adcs  x20, x20, x21\n\t"
			"adcs  x12, x12, x22\n\t"
			"stp   x14, x15, [x26], #16\n\t"
			"adc   x13, xzr, xzr\n\t"
			"umulh x21, x6, x5\n\t"
			"umulh x22, x7, x5\n\t"
			"umulh x23, x8, x5\n\t"
			"umulh x24, x9, x5\n\t"
			"adds  x16, x16, x21\n\t"
			"umulh x21, x10, x5\n\t"
			"adcs  x17, x17, x22\n\t"
			"umulh x22, x11, x5\n\t"
			"adcs  x19, x19, x23\n\t"
			"adcs  x20, x20, x24\n\t"
			"adcs  x12, x12, x21\n\t"
			"adc   x13, x13, x22\n\t"
			"mul   x21, x7, x6\n\t"
			"mul   x22, x8, x6\n\t"
			"mul   x23, x9, x6\n\t"
			"mul   x24, x10, x6\n\t"
			"adds  x17, x17, x21\n\t"
			"mul   x21, x11, x6\n\t"
			"adcs  x19, x19, x22\n\t"
			"adcs  x20, x20, x23\n\t"
			"adcs  x12, x12, x24\n\t"
			"adcs  x13, x13, x21\n\t"
			"stp   x16, x17, [x26], #16\n\t"
			"adc   x14, xzr, xzr\n\t"
			"umulh x21, x7, x6\n\t"
			"umulh x22, x8, x6\n\t"
			"umulh x23, x9, x6\n\t"
			"umulh x24, x10, x6\n\t"
			"adds  x19, x19, x21\n\t"
			"umulh x21, x11, x6\n\t"
			"adcs  x20, x20, x22\n\t"
			"adcs  x12, x12, x23\n\t"
			"adcs  x13, x13, x24\n\t"
			"adc   x14, x14, x21\n\t"
			"mul   x21, x8, x7\n\t"
			"mul   x22, x9, x7\n\t"
			"mul   x23, x10, x7\n\t"
			"mul   x24, x11, x7\n\t"
			"adds  x20, x20, x21\n\t"
			"adcs  x12, x12, x22\n\t"
			"adcs  x13, x13, x23\n\t"
			"adcs  x14, x14, x24\n\t"
			"stp   x19, x20, [x26], #16\n\t"
			"adc   x15, xzr, xzr\n\t"
			"umulh x21, x8, x7\n\t"
			"umulh x22, x9, x7\n\t"
			"umulh x23, x10, x7\n\t"
			"umulh x24, x11, x7\n\t"
			"adds  x12, x12, x21\n\t"
			"adcs  x13, x13, x22\n\t"
			"adcs  x14, x14, x23\n\t"
			"adc   x15, x15, x24\n\t"
			"mul   x21, x9, x8\n\t"
			"mul   x22, x10, x8\n\t"
			"mul   x23, x11, x8\n\t"
			"adds  x13, x13, x21\n\t"
			"adcs  x14, x14, x22\n\t"
			"adcs  x15, x15, x23\n\t"
			"adc   x16, xzr, xzr\n\t"
			"umulh x21, x9, x8\n\t"
			"umulh x22, x10, x8\n\t"
			"umulh x23, x11, x8\n\t"
			"adds  x14, x14, x21\n\t"
			"adcs  x15, x15, x22\n\t"
			"adc   x16, x16, x23\n\t"
			"mul   x21, x10, x9\n\t"
			"mul   x22, x11, x9\n\t"
			"adds  x15, x15, x21\n\t"
			"adcs  x16, x16, x22\n\t"
			"adc   x17, xzr, xzr\n\t"
			"umulh x21, x10, x9\n\t"
			"umulh x22, x11, x9\n\t"
			"adds  x16, x16, x21\n\t"
			"adc   x17, x17, x22\n\t"
			"mul   x21, x11, x10\n\t"
			"adds  x17, x17, x21\n\t"
			"adc   x19, xzr, xzr\n\t"
			"umulh x21, x11, x10\n\t"
			"adds  x19, x19, x21\n\t"
			"mov   x20, xzr\n\t"
			"cmp   x28, x1\n\t"
			"b.eq  5f\n\t"
			"mov   x27, x28\n\t"
			/* Окно следующих восьми слов числа: ранее накопленное прибавляется к окну, слово блока - множитель */
			"3:\n\t"
			"ldp   x4, x5, [x26]\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"ldp   x8, x9, [x26, #32]\n\t"
			"ldp   x10, x11, [x26, #48]\n\t"
			"adds  x12, x12, x4\n\t"
			"adcs  x13, x13, x5\n\t"
			"adcs  x14, x14, x6\n\t"
			"adcs  x15, x15, x7\n\t"
			"adcs  x16, x16, x8\n\t"
			"adcs  x17, x17, x9\n\t"
			"adcs  x19, x19, x10\n\t"
			"adcs  x20, x20, x11\n\t"
			"ldp   x4, x5, [x27]\n\t"
			"ldp   x6, x7, [x27, #16]\n\t"
			"ldp   x8, x9, [x27, #32]\n\t"
			"ldp   x10, x11, [x27, #48]\n\t"
			"add   x27, x27, #64\n\t"
			"ldur  x25, [x28, #-64]\n\t"
			"mov   x0, #-64\n\t"
			/* Восемь произведений на слово блока: младшие половины в окно, старшие - со сдвигом окна на слово, младшее слово окна пишется */
			"4:\n\t"
			"mul   x21, x4, x25\n\t"
			"adc   x2, xzr, xzr\n\t"
			"mul   x22, x5, x25\n\t"
			"add   x0, x0, #8\n\t"
			"mul   x23, x6, x25\n\t"
			"mul   x24, x7, x25\n\t"
			"adds  x12, x12, x21\n\t"
			"mul   x21, x8, x25\n\t"
			"adcs  x13, x13, x22\n\t"
			"mul   x22, x9, x25\n\t"
			"adcs  x14, x14, x23\n\t"
			"mul   x23, x10, x25\n\t"
			"adcs  x15, x15, x24\n\t"
			"mul   x24, x11, x25\n\t"
			"adcs  x16, x16, x21\n\t"
			"umulh x21, x4, x25\n\t"
			"adcs  x17, x17, x22\n\t"
			"umulh x22, x5, x25\n\t"
			"adcs  x19, x19, x23\n\t"
			"umulh x23, x6, x25\n\t"
			"adcs  x20, x20, x24\n\t"
			"umulh x24, x7, x25\n\t"
			"adc   x2, x2, xzr\n\t"
			"str   x12, [x26], #8\n\t"
			"adds  x12, x13, x21\n\t"
			"umulh x21, x8, x25\n\t"
			"adcs  x13, x14, x22\n\t"
			"umulh x22, x9, x25\n\t"
			"adcs  x14, x15, x23\n\t"
			"umulh x23, x10, x25\n\t"
			"adcs  x15, x16, x24\n\t"
			"umulh x24, x11, x25\n\t"
			"ldr   x25, [x28, x0]\n\t"
			"adcs  x16, x17, x21\n\t"
			"adcs  x17, x19, x22\n\t"
			"adcs  x19, x20, x23\n\t"
			"adcs  x20, x2, x24\n\t"
			"cbnz  x0, 4b\n\t"
			"cmp   x27, x1\n\t"
			"b.ne  3b\n\t"
			/* Окно блока целиком в слова 8I + count … 8I + count + 7; следующий блок */
			"stp   x12, x13, [x26]\n\t"
			"stp   x14, x15, [x26, #16]\n\t"
			"stp   x16, x17, [x26, #32]\n\t"
			"stp   x19, x20, [x26, #48]\n\t"
			"ldr   x2, [%[p], #8]\n\t"
			"sub   x2, x28, x2\n\t"
			"ldr   x26, [%[p]]\n\t"
			"add   x26, x26, x2, lsl #1\n\t"
			"add   x28, x28, #64\n\t"
			"b     2b\n\t"
			/* Последний блок: слова 8 … 14 окна, старшее слово квадрата без удвоения - ноль */
			"5:\n\t"
			"stp   x12, x13, [x26]\n\t"
			"stp   x14, x15, [x26, #16]\n\t"
			"stp   x16, x17, [x26, #32]\n\t"
			"str   x19, [x26, #48]\n\t"
			/* Проход 2: удвоение сдвигом пар слов с прибавлением квадратов диагонали одной цепочкой; перенос за старшее слово невозможен */
			"ldp   x26, x27, [%[p]]\n\t"
			"ldr   x0, [%[p], #24]\n\t"
			"lsr   x0, x0, #1\n\t"
			"mov   x2, xzr\n\t"
			"cmn   xzr, xzr\n\t"
			"6:\n\t"
			"ldp   x4, x5, [x26]\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"ldp   x12, x13, [x27], #16\n\t"
			"mul   x14, x12, x12\n\t"
			"umulh x15, x12, x12\n\t"
			"mul   x16, x13, x13\n\t"
			"umulh x17, x13, x13\n\t"
			"extr  x8, x4, x2, #63\n\t"
			"extr  x9, x5, x4, #63\n\t"
			"extr  x10, x6, x5, #63\n\t"
			"extr  x11, x7, x6, #63\n\t"
			"mov   x2, x7\n\t"
			"adcs  x8, x8, x14\n\t"
			"adcs  x9, x9, x15\n\t"
			"adcs  x10, x10, x16\n\t"
			"adcs  x11, x11, x17\n\t"
			"stp   x8, x9, [x26]\n\t"
			"stp   x10, x11, [x26, #16]\n\t"
			"add   x26, x26, #32\n\t"
			"sub   x0, x0, #1\n\t"
			"cbnz  x0, 6b\n\t"
			/* Проход 3, блок I: окно - слова 8I … 8I + 7 накопителя, в регистрах слова модуля m[0 … 7] и множитель приведения */
			"ldr   x26, [%[p]]\n\t"
			"ldr   x27, [%[p], #16]\n\t"
			"ldr   x0, [%[p], #24]\n\t"
			"add   x1, x27, x0, lsl #3\n\t"
			"str   xzr, [%[p], #40]\n\t"
			"7:\n\t"
			"ldp   x12, x13, [x26]\n\t"
			"ldp   x14, x15, [x26, #16]\n\t"
			"ldp   x16, x17, [x26, #32]\n\t"
			"ldp   x19, x20, [x26, #48]\n\t"
			"ldr   x27, [%[p], #16]\n\t"
			"ldp   x4, x5, [x27]\n\t"
			"ldp   x6, x7, [x27, #16]\n\t"
			"ldp   x8, x9, [x27, #32]\n\t"
			"ldp   x10, x11, [x27, #48]\n\t"
			"add   x27, x27, #64\n\t"
			"ldr   x28, [%[p], #32]\n\t"
			"mul   x25, x12, x28\n\t"
			"mov   x0, #8\n\t"
			/* Восемь рядов: множитель ряда откладывается в слово накопителя, младшее слово окна обнуляется по построению (перенос - признак его ненулевости), окно сдвигается на слово */
			"8:\n\t"
			"str   x25, [x26], #8\n\t"
			"mul   x22, x5, x25\n\t"
			"mul   x23, x6, x25\n\t"
			"mul   x24, x7, x25\n\t"
			"subs  xzr, x12, #1\n\t"
			"mul   x21, x8, x25\n\t"
			"adcs  x12, x13, x22\n\t"
			"mul   x22, x9, x25\n\t"
			"adcs  x13, x14, x23\n\t"
			"mul   x23, x10, x25\n\t"
			"adcs  x14, x15, x24\n\t"
			"mul   x24, x11, x25\n\t"
			"adcs  x15, x16, x21\n\t"
			"umulh x21, x4, x25\n\t"
			"adcs  x16, x17, x22\n\t"
			"umulh x22, x5, x25\n\t"
			"adcs  x17, x19, x23\n\t"
			"umulh x23, x6, x25\n\t"
			"adcs  x19, x20, x24\n\t"
			"umulh x24, x7, x25\n\t"
			"adc   x20, xzr, xzr\n\t"
			"adds  x12, x12, x21\n\t"
			"umulh x21, x8, x25\n\t"
			"adcs  x13, x13, x22\n\t"
			"umulh x22, x9, x25\n\t"
			"adcs  x14, x14, x23\n\t"
			"umulh x23, x10, x25\n\t"
			"adcs  x15, x15, x24\n\t"
			"umulh x24, x11, x25\n\t"
			"mul   x25, x12, x28\n\t"
			"adcs  x16, x16, x21\n\t"
			"adcs  x17, x17, x22\n\t"
			"adcs  x19, x19, x23\n\t"
			"adc   x20, x20, x24\n\t"
			"sub   x0, x0, #1\n\t"
			"cbnz  x0, 8b\n\t"
			"mov   x28, x26\n\t"
			"cmp   x27, x1\n\t"
			"b.eq  10f\n\t"
			/* Окна остальных слов модуля на восемь отложенных множителей: тот же цикл, что и у прохода 1 */
			"9:\n\t"
			"ldp   x4, x5, [x26]\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"ldp   x8, x9, [x26, #32]\n\t"
			"ldp   x10, x11, [x26, #48]\n\t"
			"adds  x12, x12, x4\n\t"
			"adcs  x13, x13, x5\n\t"
			"adcs  x14, x14, x6\n\t"
			"adcs  x15, x15, x7\n\t"
			"adcs  x16, x16, x8\n\t"
			"adcs  x17, x17, x9\n\t"
			"adcs  x19, x19, x10\n\t"
			"adcs  x20, x20, x11\n\t"
			"ldp   x4, x5, [x27]\n\t"
			"ldp   x6, x7, [x27, #16]\n\t"
			"ldp   x8, x9, [x27, #32]\n\t"
			"ldp   x10, x11, [x27, #48]\n\t"
			"add   x27, x27, #64\n\t"
			"ldur  x25, [x28, #-64]\n\t"
			"mov   x0, #-64\n\t"
			"11:\n\t"
			"mul   x21, x4, x25\n\t"
			"adc   x2, xzr, xzr\n\t"
			"mul   x22, x5, x25\n\t"
			"add   x0, x0, #8\n\t"
			"mul   x23, x6, x25\n\t"
			"mul   x24, x7, x25\n\t"
			"adds  x12, x12, x21\n\t"
			"mul   x21, x8, x25\n\t"
			"adcs  x13, x13, x22\n\t"
			"mul   x22, x9, x25\n\t"
			"adcs  x14, x14, x23\n\t"
			"mul   x23, x10, x25\n\t"
			"adcs  x15, x15, x24\n\t"
			"mul   x24, x11, x25\n\t"
			"adcs  x16, x16, x21\n\t"
			"umulh x21, x4, x25\n\t"
			"adcs  x17, x17, x22\n\t"
			"umulh x22, x5, x25\n\t"
			"adcs  x19, x19, x23\n\t"
			"umulh x23, x6, x25\n\t"
			"adcs  x20, x20, x24\n\t"
			"umulh x24, x7, x25\n\t"
			"adc   x2, x2, xzr\n\t"
			"str   x12, [x26], #8\n\t"
			"adds  x12, x13, x21\n\t"
			"umulh x21, x8, x25\n\t"
			"adcs  x13, x14, x22\n\t"
			"umulh x22, x9, x25\n\t"
			"adcs  x14, x15, x23\n\t"
			"umulh x23, x10, x25\n\t"
			"adcs  x15, x16, x24\n\t"
			"umulh x24, x11, x25\n\t"
			"ldr   x25, [x28, x0]\n\t"
			"adcs  x16, x17, x21\n\t"
			"adcs  x17, x19, x22\n\t"
			"adcs  x19, x20, x23\n\t"
			"adcs  x20, x2, x24\n\t"
			"cbnz  x0, 11b\n\t"
			"cmp   x27, x1\n\t"
			"b.ne  9b\n\t"
			/* Окно блока с накопленным и переносом прошлого блока в слова 8I + count … 8I + count + 7; перенос - в следующий блок */
			"10:\n\t"
			"ldp   x4, x5, [x26]\n\t"
			"ldp   x6, x7, [x26, #16]\n\t"
			"ldp   x8, x9, [x26, #32]\n\t"
			"ldp   x10, x11, [x26, #48]\n\t"
			"ldr   x2, [%[p], #40]\n\t"
			"subs  xzr, x2, #1\n\t"
			"adcs  x4, x4, x12\n\t"
			"adcs  x5, x5, x13\n\t"
			"adcs  x6, x6, x14\n\t"
			"adcs  x7, x7, x15\n\t"
			"adcs  x8, x8, x16\n\t"
			"adcs  x9, x9, x17\n\t"
			"adcs  x10, x10, x19\n\t"
			"adcs  x11, x11, x20\n\t"
			"adc   x2, xzr, xzr\n\t"
			"str   x2, [%[p], #40]\n\t"
			"stp   x4, x5, [x26]\n\t"
			"stp   x6, x7, [x26, #16]\n\t"
			"stp   x8, x9, [x26, #32]\n\t"
			"stp   x10, x11, [x26, #48]\n\t"
			"mov   x26, x28\n\t"
			"ldr   x2, [%[p]]\n\t"
			"ldr   x0, [%[p], #24]\n\t"
			"add   x2, x2, x0, lsl #3\n\t"
			"cmp   x26, x2\n\t"
			"b.ne  7b\n\t"
			/* Перенос последнего блока - старшее слово итога */
			"add   x2, x2, x0, lsl #3\n\t"
			"ldr   x0, [%[p], #40]\n\t"
			"str   x0, [x2]\n\t"
			:
			: [p] "r" (&args)
			: "x0", "x1", "x2", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "cc", "memory");
	}
/**
 * Ветвь x86-64 (GCC, clang) с расширениями BMI2 и ADX: то же устройство на MULX и двух
 * цепочках переносов ADCX/ADOX (решение 8 шапки). Регистры: r8…r15 - окно накопителя,
 * rdx - множитель, rax и rbx - половины произведения, исходящее слово и ноль, rsi - окно
 * слов числа либо модуля (операнды в памяти у MULX), rdi - накопитель, rcx - блок; счётчиков
 * нет - восемь шагов окна развёрнуты, а старшая половина произведения ложится прямо в
 * регистр сдвинутого слова. Под ASan без оптимизации ветвь не берётся (все регистры заняты)
 */
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__)
	/**
	 * @brief Метод квадрата Монтгомери блоками по восемь слов на ассемблере x86-64 (BMI2, ADX)
	 *
	 * @param buffer  накопитель в 2 · count + 2 слов: на выходе слова count … 2 · count - значение, меньшее удвоенного модуля, младшие count слов - отложенные множители приведения
	 * @param value   слова числа, меньшего модуля
	 * @param modulus слова нечётного модуля
	 * @param count   число слов модуля, кратное восьми и не меньшее восьми
	 * @param inverse множитель приведения по модулю
	 *
	 * @note Проходы те же, что у ветви AArch64. Перенос прибавления накопленного к окну не
	 *       входит в окно, а откладывается до следующего прибавления восемью словами выше:
	 *       окно ровно восемь слов, и на каждом шаге оба переноса нулевые (сумма окна и
	 *       произведения слова на окно меньше 2^576). Множитель приведения считается MULX:
	 *       IMUL портит оба переноса. Удвоение и диагональ идут двумя цепочками разом,
	 *       счётчик прохода - LEA и JRCXZ, флагов не трогающие
	 *
	 */
	static void square8x(uint64_t * buffer, const uint64_t * value, const uint64_t * modulus, const size_t count, const uint64_t inverse) {
		// Отложенный перенос прибавления и перенос между блоками (ноль либо маска из единиц)
		uint64_t carry = 0, top = 0;
		// Конец слов числа, конец слов модуля, старшая половина накопителя
		const uint64_t * end = (value + count);
		const uint64_t * last = (modulus + count);
		uint64_t * high = (buffer + count);
		__asm__ __volatile__(
			/* Обнуление удвоенной ширины накопителя */
			"movq  %[buffer], %%rdi\n\t"
			"movq  %[count], %%rcx\n\t"
			"xorl  %%eax, %%eax\n\t"
			"1:\n\t"
			"movq  %%rax, 0(%%rdi)\n\t"
			"movq  %%rax, 8(%%rdi)\n\t"
			"leaq  16(%%rdi), %%rdi\n\t"
			"decq  %%rcx\n\t"
			"jnz   1b\n\t"
			/* Проход 1, блок I: окно накопителя - слова 16I … 16I + 7 (rdi), слова блока a[8I … 8I + 7] (rcx) */
			"movq  %[buffer], %%rdi\n\t"
			"movq  %[value], %%rcx\n\t"
			"2:\n\t"
			"movq  0(%%rdi), %%r8\n\t"
			"movq  8(%%rdi), %%r9\n\t"
			"movq  16(%%rdi), %%r10\n\t"
			"movq  24(%%rdi), %%r11\n\t"
			"movq  32(%%rdi), %%r12\n\t"
			"movq  40(%%rdi), %%r13\n\t"
			"movq  48(%%rdi), %%r14\n\t"
			"movq  56(%%rdi), %%r15\n\t"
			"xorl  %%eax, %%eax\n\t"
			/* Треугольник блока: младшие половины цепочкой ADCX, старшие - ADOX; слово j пишется и его регистр берёт слово j + 8 */
			"movq  0(%%rcx), %%rdx\n\t"
			"movq  %%r8, 0(%%rdi)\n\t"
			"movl  $0, %%r8d\n\t"
			"mulx  8(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%rbx, %%r10\n\t"
			"mulx  16(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%rbx, %%r11\n\t"
			"mulx  24(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"mulx  32(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%rbx, %%r13\n\t"
			"mulx  40(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%rbx, %%r14\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r15\n\t"
			"adox  %%rbx, %%r8\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r8\n\t"
			"movq  8(%%rcx), %%rdx\n\t"
			"movq  %%r9, 8(%%rdi)\n\t"
			"movl  $0, %%r9d\n\t"
			"mulx  16(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"mulx  24(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%rbx, %%r13\n\t"
			"mulx  32(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%rbx, %%r14\n\t"
			"mulx  40(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r15\n\t"
			"adox  %%rbx, %%r8\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%rbx, %%r9\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r9\n\t"
			"movq  16(%%rcx), %%rdx\n\t"
			"movq  %%r10, 16(%%rdi)\n\t"
			"movl  $0, %%r10d\n\t"
			"mulx  24(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%rbx, %%r14\n\t"
			"mulx  32(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"mulx  40(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r15\n\t"
			"adox  %%rbx, %%r8\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%rbx, %%r9\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%rbx, %%r10\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r10\n\t"
			"movq  24(%%rcx), %%rdx\n\t"
			"movq  %%r11, 24(%%rdi)\n\t"
			"movl  $0, %%r11d\n\t"
			"mulx  32(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r15\n\t"
			"adox  %%rbx, %%r8\n\t"
			"mulx  40(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%rbx, %%r9\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%rbx, %%r10\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%rbx, %%r11\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r11\n\t"
			"movq  32(%%rcx), %%rdx\n\t"
			"movq  %%r12, 32(%%rdi)\n\t"
			"movl  $0, %%r12d\n\t"
			"mulx  40(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%rbx, %%r10\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%rbx, %%r11\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r12\n\t"
			"movq  40(%%rcx), %%rdx\n\t"
			"movq  %%r13, 40(%%rdi)\n\t"
			"movl  $0, %%r13d\n\t"
			"mulx  48(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%rbx, %%r12\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%rbx, %%r13\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r13\n\t"
			"movq  48(%%rcx), %%rdx\n\t"
			"movq  %%r14, 48(%%rdi)\n\t"
			"movl  $0, %%r14d\n\t"
			"mulx  56(%%rcx), %%rax, %%rbx\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%rbx, %%r14\n\t"
			"movl  $0, %%eax\n\t"
			"adcx  %%rax, %%r14\n\t"
			"movq  %%r15, 56(%%rdi)\n\t"
			"movl  $0, %%r15d\n\t"
			/* Окна следующих восьми слов числа: накопленное прибавляется с отложенным переносом, слово блока - множитель */
			"leaq  64(%%rdi), %%rdi\n\t"
			"movq  $0, %[carry]\n\t"
			"leaq  64(%%rcx), %%rsi\n\t"
			"cmpq  %[end], %%rsi\n\t"
			"je    5f\n\t"
			"3:\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			"subq  %[carry], %%rbx\n\t"
			"adcq  0(%%rdi), %%r8\n\t"
			"adcq  8(%%rdi), %%r9\n\t"
			"adcq  16(%%rdi), %%r10\n\t"
			"adcq  24(%%rdi), %%r11\n\t"
			"adcq  32(%%rdi), %%r12\n\t"
			"adcq  40(%%rdi), %%r13\n\t"
			"adcq  48(%%rdi), %%r14\n\t"
			"adcq  56(%%rdi), %%r15\n\t"
			"sbbq  %%rbx, %%rbx\n\t"
			"movq  %%rbx, %[carry]\n\t"
			"movq  0(%%rcx), %%rdx\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			/* Восемь шагов окна: старшая половина произведения ложится в регистр сдвинутого слова, прежнее слово прибавляется ADOX, младшая половина - ADCX */
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 0(%%rdi)\n\t"
			"movq  8(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 8(%%rdi)\n\t"
			"movq  16(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 16(%%rdi)\n\t"
			"movq  24(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 24(%%rdi)\n\t"
			"movq  32(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 32(%%rdi)\n\t"
			"movq  40(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 40(%%rdi)\n\t"
			"movq  48(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 48(%%rdi)\n\t"
			"movq  56(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 56(%%rdi)\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"leaq  64(%%rdi), %%rdi\n\t"
			"leaq  64(%%rsi), %%rsi\n\t"
			"cmpq  %[end], %%rsi\n\t"
			"jne   3b\n\t"
			/* Окно блока с отложенным переносом в слова 8I + count … 8I + count + 7; следующий блок */
			"xorl  %%ebx, %%ebx\n\t"
			"subq  %[carry], %%rbx\n\t"
			"adcq  $0, %%r8\n\t"
			"adcq  $0, %%r9\n\t"
			"adcq  $0, %%r10\n\t"
			"adcq  $0, %%r11\n\t"
			"adcq  $0, %%r12\n\t"
			"adcq  $0, %%r13\n\t"
			"adcq  $0, %%r14\n\t"
			"adcq  $0, %%r15\n\t"
			"movq  %%r8, 0(%%rdi)\n\t"
			"movq  %%r9, 8(%%rdi)\n\t"
			"movq  %%r10, 16(%%rdi)\n\t"
			"movq  %%r11, 24(%%rdi)\n\t"
			"movq  %%r12, 32(%%rdi)\n\t"
			"movq  %%r13, 40(%%rdi)\n\t"
			"movq  %%r14, 48(%%rdi)\n\t"
			"movq  %%r15, 56(%%rdi)\n\t"
			"leaq  64(%%rcx), %%rcx\n\t"
			"movq  %%rcx, %%rdi\n\t"
			"subq  %[value], %%rdi\n\t"
			"addq  %%rdi, %%rdi\n\t"
			"addq  %[buffer], %%rdi\n\t"
			"jmp   2b\n\t"
			/* Последний блок: слова 8 … 15 окна, старшее слово - ноль */
			"5:\n\t"
			"movq  %%r8, 0(%%rdi)\n\t"
			"movq  %%r9, 8(%%rdi)\n\t"
			"movq  %%r10, 16(%%rdi)\n\t"
			"movq  %%r11, 24(%%rdi)\n\t"
			"movq  %%r12, 32(%%rdi)\n\t"
			"movq  %%r13, 40(%%rdi)\n\t"
			"movq  %%r14, 48(%%rdi)\n\t"
			"movq  %%r15, 56(%%rdi)\n\t"
			/* Проход 2: удвоение цепочкой ADCX с прибавлением квадратов диагонали цепочкой ADOX; счётчик и переходы флагов не трогают */
			"movq  %[buffer], %%rdi\n\t"
			"movq  %[value], %%rsi\n\t"
			"movq  %[count], %%rcx\n\t"
			"shrq  $2, %%rcx\n\t"
			"xorl  %%eax, %%eax\n\t"
			"6:\n\t"
			"movq  0(%%rsi), %%rdx\n\t"
			"mulx  %%rdx, %%rax, %%rbx\n\t"
			"movq  0(%%rdi), %%r8\n\t"
			"movq  8(%%rdi), %%r9\n\t"
			"adcx  %%r8, %%r8\n\t"
			"adox  %%rax, %%r8\n\t"
			"adcx  %%r9, %%r9\n\t"
			"adox  %%rbx, %%r9\n\t"
			"movq  %%r8, 0(%%rdi)\n\t"
			"movq  %%r9, 8(%%rdi)\n\t"
			"movq  8(%%rsi), %%rdx\n\t"
			"mulx  %%rdx, %%rax, %%rbx\n\t"
			"movq  16(%%rdi), %%r8\n\t"
			"movq  24(%%rdi), %%r9\n\t"
			"adcx  %%r8, %%r8\n\t"
			"adox  %%rax, %%r8\n\t"
			"adcx  %%r9, %%r9\n\t"
			"adox  %%rbx, %%r9\n\t"
			"movq  %%r8, 16(%%rdi)\n\t"
			"movq  %%r9, 24(%%rdi)\n\t"
			"movq  16(%%rsi), %%rdx\n\t"
			"mulx  %%rdx, %%rax, %%rbx\n\t"
			"movq  32(%%rdi), %%r8\n\t"
			"movq  40(%%rdi), %%r9\n\t"
			"adcx  %%r8, %%r8\n\t"
			"adox  %%rax, %%r8\n\t"
			"adcx  %%r9, %%r9\n\t"
			"adox  %%rbx, %%r9\n\t"
			"movq  %%r8, 32(%%rdi)\n\t"
			"movq  %%r9, 40(%%rdi)\n\t"
			"movq  24(%%rsi), %%rdx\n\t"
			"mulx  %%rdx, %%rax, %%rbx\n\t"
			"movq  48(%%rdi), %%r8\n\t"
			"movq  56(%%rdi), %%r9\n\t"
			"adcx  %%r8, %%r8\n\t"
			"adox  %%rax, %%r8\n\t"
			"adcx  %%r9, %%r9\n\t"
			"adox  %%rbx, %%r9\n\t"
			"movq  %%r8, 48(%%rdi)\n\t"
			"movq  %%r9, 56(%%rdi)\n\t"
			"leaq  32(%%rsi), %%rsi\n\t"
			"leaq  64(%%rdi), %%rdi\n\t"
			"leaq  -1(%%rcx), %%rcx\n\t"
			"jrcxz 7f\n\t"
			"jmp   6b\n\t"
			"7:\n\t"
			/* Проход 3, блок I: окно - слова 8I … 8I + 7 накопителя (rdi), слова модуля m[0 … 7] (rsi), множители приведения откладываются в слова блока (rcx) */
			"movq  %[buffer], %%rdi\n\t"
			"movq  $0, %[top]\n\t"
			"8:\n\t"
			"movq  0(%%rdi), %%r8\n\t"
			"movq  8(%%rdi), %%r9\n\t"
			"movq  16(%%rdi), %%r10\n\t"
			"movq  24(%%rdi), %%r11\n\t"
			"movq  32(%%rdi), %%r12\n\t"
			"movq  40(%%rdi), %%r13\n\t"
			"movq  48(%%rdi), %%r14\n\t"
			"movq  56(%%rdi), %%r15\n\t"
			"movq  %[modulus], %%rsi\n\t"
			"movq  %%rdi, %%rcx\n\t"
			"xorl  %%eax, %%eax\n\t"
			/* Восемь рядов: множитель ряда через MULX без флагов, младшее слово окна обнуляется по построению (перенос - признак его ненулевости) */
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 0(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 8(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 16(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 24(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 32(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 40(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 48(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rdx\n\t"
			"mulx  %[inverse], %%rdx, %%rax\n\t"
			"movq  %%rdx, 56(%%rcx)\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			/* Окна остальных слов модуля на восемь отложенных множителей: тот же цикл, что и у прохода 1 */
			"leaq  64(%%rdi), %%rdi\n\t"
			"leaq  64(%%rsi), %%rsi\n\t"
			"movq  $0, %[carry]\n\t"
			"cmpq  %[last], %%rsi\n\t"
			"je    10f\n\t"
			"9:\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			"subq  %[carry], %%rbx\n\t"
			"adcq  0(%%rdi), %%r8\n\t"
			"adcq  8(%%rdi), %%r9\n\t"
			"adcq  16(%%rdi), %%r10\n\t"
			"adcq  24(%%rdi), %%r11\n\t"
			"adcq  32(%%rdi), %%r12\n\t"
			"adcq  40(%%rdi), %%r13\n\t"
			"adcq  48(%%rdi), %%r14\n\t"
			"adcq  56(%%rdi), %%r15\n\t"
			"sbbq  %%rbx, %%rbx\n\t"
			"movq  %%rbx, %[carry]\n\t"
			"movq  0(%%rcx), %%rdx\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 0(%%rdi)\n\t"
			"movq  8(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 8(%%rdi)\n\t"
			"movq  16(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 16(%%rdi)\n\t"
			"movq  24(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 24(%%rdi)\n\t"
			"movq  32(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 32(%%rdi)\n\t"
			"movq  40(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 40(%%rdi)\n\t"
			"movq  48(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 48(%%rdi)\n\t"
			"movq  56(%%rcx), %%rdx\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"movq  %%r8, %%rbx\n\t"
			"mulx  0(%%rsi), %%rax, %%r8\n\t"
			"adcx  %%rax, %%rbx\n\t"
			"adox  %%r9, %%r8\n\t"
			"mulx  8(%%rsi), %%rax, %%r9\n\t"
			"adcx  %%rax, %%r8\n\t"
			"adox  %%r10, %%r9\n\t"
			"mulx  16(%%rsi), %%rax, %%r10\n\t"
			"adcx  %%rax, %%r9\n\t"
			"adox  %%r11, %%r10\n\t"
			"mulx  24(%%rsi), %%rax, %%r11\n\t"
			"adcx  %%rax, %%r10\n\t"
			"adox  %%r12, %%r11\n\t"
			"mulx  32(%%rsi), %%rax, %%r12\n\t"
			"adcx  %%rax, %%r11\n\t"
			"adox  %%r13, %%r12\n\t"
			"mulx  40(%%rsi), %%rax, %%r13\n\t"
			"adcx  %%rax, %%r12\n\t"
			"adox  %%r14, %%r13\n\t"
			"mulx  48(%%rsi), %%rax, %%r14\n\t"
			"adcx  %%rax, %%r13\n\t"
			"adox  %%r15, %%r14\n\t"
			"mulx  56(%%rsi), %%rax, %%r15\n\t"
			"movq  %%rbx, 56(%%rdi)\n\t"
			"movl  $0, %%ebx\n\t"
			"adcx  %%rax, %%r14\n\t"
			"adox  %%rbx, %%r15\n\t"
			"adcx  %%rbx, %%r15\n\t"
			"leaq  64(%%rdi), %%rdi\n\t"
			"leaq  64(%%rsi), %%rsi\n\t"
			"cmpq  %[last], %%rsi\n\t"
			"jne   9b\n\t"
			/* Окно блока с накопленным, отложенным переносом и переносом прошлого блока в слова 8I + count … 8I + count + 7 */
			"10:\n\t"
			"xorl  %%ebx, %%ebx\n\t"
			"subq  %[carry], %%rbx\n\t"
			"adcq  0(%%rdi), %%r8\n\t"
			"adcq  8(%%rdi), %%r9\n\t"
			"adcq  16(%%rdi), %%r10\n\t"
			"adcq  24(%%rdi), %%r11\n\t"
			"adcq  32(%%rdi), %%r12\n\t"
			"adcq  40(%%rdi), %%r13\n\t"
			"adcq  48(%%rdi), %%r14\n\t"
			"adcq  56(%%rdi), %%r15\n\t"
			"sbbq  %%rbx, %%rbx\n\t"
			"xorl  %%eax, %%eax\n\t"
			"subq  %[top], %%rax\n\t"
			"adcq  $0, %%r8\n\t"
			"adcq  $0, %%r9\n\t"
			"adcq  $0, %%r10\n\t"
			"adcq  $0, %%r11\n\t"
			"adcq  $0, %%r12\n\t"
			"adcq  $0, %%r13\n\t"
			"adcq  $0, %%r14\n\t"
			"adcq  $0, %%r15\n\t"
			"sbbq  %%rax, %%rax\n\t"
			"orq   %%rax, %%rbx\n\t"
			"movq  %%rbx, %[top]\n\t"
			"movq  %%r8, 0(%%rdi)\n\t"
			"movq  %%r9, 8(%%rdi)\n\t"
			"movq  %%r10, 16(%%rdi)\n\t"
			"movq  %%r11, 24(%%rdi)\n\t"
			"movq  %%r12, 32(%%rdi)\n\t"
			"movq  %%r13, 40(%%rdi)\n\t"
			"movq  %%r14, 48(%%rdi)\n\t"
			"movq  %%r15, 56(%%rdi)\n\t"
			"leaq  64(%%rcx), %%rdi\n\t"
			"cmpq  %[high], %%rdi\n\t"
			"jne   8b\n\t"
			/* Перенос последнего блока - старшее слово итога */
			"movq  %[top], %%rax\n\t"
			"negq  %%rax\n\t"
			"movq  %[high], %%rdi\n\t"
			"movq  %[count], %%rcx\n\t"
			"movq  %%rax, (%%rdi, %%rcx, 8)\n\t"
			:
			: [buffer] "m" (buffer), [value] "m" (value), [modulus] "m" (modulus), [count] "m" (count), [inverse] "m" (inverse), [carry] "m" (carry), [top] "m" (top), [end] "m" (end), [last] "m" (last), [high] "m" (high)
			: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory");
	}
#endif
}
#if (defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))) || (defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER))
#define __ANTS_PROBE_STRIPES__ 1
extern "C" __attribute__((noinline)) void mont_stripes(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130]; memset(buffer, 0, (count + 2) * 8);
	for(size_t i = 0; i < count; i++) library::stripes(buffer, first, modulus, second[i], inverse, count);
	finish(buffer, modulus, count, result);
}
#endif
#if (defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))) || (defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(_MSC_VER))
#define __ANTS_PROBE_SQUARE8X__ 1
extern "C" __attribute__((noinline)) void mont_square8x(const uint64_t * first, const uint64_t *, const uint64_t * modulus, const size_t count, const uint64_t inverse, uint64_t * result){
	uint64_t buffer[130];
	library::square8x(buffer, first, modulus, count, inverse);
	finish(buffer + count, modulus, count, result);
}
#endif
#if defined(WITH_OPENSSL)
#include <openssl/bn.h>
// Полоса эталона: BN_mod_mul_montgomery того же OpenSSL, умножение и квадрат
static void opensslmont(size_t n, const uint64_t * m, const uint64_t * a, const uint64_t * b){
	BN_CTX * ctx = BN_CTX_new(); BIGNUM * M = BN_lebin2bn((const unsigned char *) m, n * 8, nullptr); BIGNUM * A = BN_lebin2bn((const unsigned char *) a, n * 8, nullptr); BIGNUM * B = BN_lebin2bn((const unsigned char *) b, n * 8, nullptr);
	BN_MONT_CTX * mont = BN_MONT_CTX_new(); BN_MONT_CTX_set(mont, M, ctx);
	const int N = (n <= 16 ? 200000 : 60000); double t0 = now();
	for(int i = 0; i < N; i++) BN_mod_mul_montgomery(A, A, B, mont, ctx);
	double t1 = now(); printf("  OpenSSL %6.1f нс", (t1 - t0) / N * 1e9);
	t0 = now(); for(int i = 0; i < N; i++) BN_mod_mul_montgomery(A, A, A, mont, ctx); t1 = now(); printf("  OpenSSL квадрат %6.1f нс", (t1 - t0) / N * 1e9);
	BN_MONT_CTX_free(mont); BN_free(A); BN_free(B); BN_free(M); BN_CTX_free(ctx);
}
#endif
typedef void (* kernel_t)(const uint64_t *, const uint64_t *, const uint64_t *, size_t, uint64_t, uint64_t *);
static uint64_t inverse64(uint64_t n0){ uint64_t x = 1; for(int i = 0; i < 6; i++) x *= (2 - n0 * x); return (0 - x); }
static uint64_t seed = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(){ seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed; }
static void fill(uint64_t * w, size_t n){ for(size_t i = 0; i < n; i++) w[i] = rnd(); }
static bool less(const uint64_t * a, const uint64_t * m, size_t n){ for(size_t i = n; i > 0; i--){ if(a[i-1] != m[i-1]) return a[i-1] < m[i-1]; } return false; }
int main(int argc, char **){
	kernel_t kernels[] = { mont_ref, mont_fused, mont_rows2c, mont_rows4c, mont_rows4b,
#if defined(__aarch64__)
		mont_row, mont_rows2, mont_rows4,
#endif
#if defined(__ANTS_PROBE_STRIPES__)
		mont_stripes,
#endif
	};
	const char * names[] = { "два прохода C", "слитый проход C", "два ряда C", "четыре ряда C", "четыре ряда прямые C",
#if defined(__aarch64__)
		"слитый ряд asm", "два ряда asm", "четыре ряда asm",
#endif
		"полосы 4 asm (библиотека)" };
	const int K = sizeof(kernels) / sizeof(kernels[0]);
	// Сходимость: случайные и краевые входы
	size_t bad = 0, total = 0;
	for(size_t n : {4, 8, 16, 17, 32, 48, 64}){
		for(int c = 0; c < 4000; c++){
			uint64_t a[64], b[64], m[64], r[8][64];
			fill(m, n); m[0] |= 1;
			const int kind = c % 8;
			if(kind == 1) m[n - 1] |= (1ull << 63);
			if(kind == 2){ for(size_t i = 0; i < n; i++) m[i] = ~0ull; }               // m = 2^(64n) - 1
			if(kind == 3){ for(size_t i = 0; i < n; i++) m[i] = 0; m[n - 1] = 1; m[0] |= 1; } // маленький старший
			if(kind == 4){ m[n - 1] = 3; }                                                // короткий старший
			fill(a, n); fill(b, n);
			// a, b < m: берём остаток грубо - обнуляем старшие, пока не меньше
			while(!less(a, m, n)){ a[n - 1] >>= 1; if(a[n - 1] == 0 && !less(a, m, n)){ for(size_t i = 0; i < n; i++) a[i] = m[i]; a[0] -= 1; break; } }
			while(!less(b, m, n)){ b[n - 1] >>= 1; if(b[n - 1] == 0 && !less(b, m, n)){ for(size_t i = 0; i < n; i++) b[i] = m[i]; b[0] -= 1; break; } }
			if(kind == 5){ for(size_t i = 0; i < n; i++){ a[i] = m[i]; b[i] = m[i]; } a[0] -= 1; b[0] -= 1; } // a = b = m-1
			if(kind == 6){ for(size_t i = 0; i < n; i++) a[i] = 0; }                                       // a = 0
			if(kind == 7){ for(size_t i = 0; i < n; i++) b[i] = 0; b[0] = 1; }                            // b = 1
			const uint64_t inv = inverse64(m[0]);
			for(int k = 0; k < K; k++){ if((k == K - 1) && ((n % 4) != 0)) continue; kernels[k](a, b, m, n, inv, r[k]); }
			for(int k = 1; k < K; k++){ if((k == K - 1) && ((n % 4) != 0)) continue; total++; if(memcmp(r[0], r[k], n * 8) != 0){ bad++; if(bad < 5) printf("РАСХОЖДЕНИЕ %s n=%zu kind=%d\n", names[k], n, kind); } }
		}
	}
	printf("сходимость: расхождений %zu из %zu\n", bad, total);
	{ size_t sbad = 0, stotal = 0;
	  for(size_t n : {4, 8, 16, 17, 32, 48, 64}) for(int c = 0; c < 4000; c++){
		uint64_t a[64], m[64], r1[64], r2[64]; fill(m, n); m[0] |= 1; if(c % 4 == 1) m[n-1] |= (1ull << 63); if(c % 4 == 2){ for(size_t i = 0; i < n; i++) m[i] = ~0ull; }
		fill(a, n); while(!less(a, m, n)){ a[n - 1] >>= 1; if(a[n - 1] == 0 && !less(a, m, n)){ for(size_t i = 0; i < n; i++) a[i] = m[i]; a[0] -= 1; break; } }
		if(c % 4 == 3){ for(size_t i = 0; i < n; i++) a[i] = m[i]; a[0] -= 1; }
		const uint64_t inv = inverse64(m[0]); mont_ref(a, a, m, n, inv, r1); mont_sqr3(a, a, m, n, inv, r2); stotal++; if(memcmp(r1, r2, n * 8) != 0){ sbad++; if(sbad < 5) printf("РАСХОЖДЕНИЕ квадрата n=%zu c=%d\n", n, c); }
#if defined(__ANTS_PROBE_SQUARE8X__)
		if((n % 8) == 0){ mont_square8x(a, a, m, n, inv, r2); stotal++; if(memcmp(r1, r2, n * 8) != 0){ sbad++; if(sbad < 5) printf("РАСХОЖДЕНИЕ квадрата блоками n=%zu c=%d\n", n, c); } }
#endif
	  }
	  printf("квадрат: расхождений %zu из %zu\n", sbad, stotal); }
	{ const size_t N = 20000000; double t0 = now(); uint64_t s = multhroughput(12345, N); double t1 = now(); printf("умножитель: %.2f нс на пару mul+umulh (%llu)\n", (t1 - t0) / (N * 4) * 1e9, (unsigned long long)(s & 1)); }
	// Полоса
	for(size_t n : {16, 32, 48, 64}){
		uint64_t a[64], b[64], m[64];
		fill(m, n); m[0] |= 1; m[n - 1] |= (1ull << 63); fill(a, n); fill(b, n); a[n - 1] >>= 1; b[n - 1] >>= 1;
		const uint64_t inv = inverse64(m[0]);
		printf("слов %2zu:", n);
		for(int k = 0; k < K; k++){
			uint64_t x[64]; memcpy(x, a, n * 8);
			const int N = (n <= 16 ? 200000 : 60000); double t0 = now();
			for(int i = 0; i < N; i++) kernels[k](x, b, m, n, inv, x);
			double t1 = now(); printf("  %s %6.1f нс", names[k], (t1 - t0) / N * 1e9);
			if(argc > 99) printf("%llu", (unsigned long long) x[0]);
		}
		{ uint64_t x[64]; memcpy(x, a, n * 8); const int N = (n <= 16 ? 200000 : 60000); double t0 = now(); for(int i = 0; i < N; i++) mont_sqr3(x, x, m, n, inv, x); double t1 = now(); printf("  квадрат3 C %6.1f нс", (t1 - t0) / N * 1e9); }
#if defined(__ANTS_PROBE_SQUARE8X__)
		if((n % 8) == 0){ uint64_t x[64]; memcpy(x, a, n * 8); const int N = (n <= 16 ? 200000 : 60000); double t0 = now(); for(int i = 0; i < N; i++) mont_square8x(x, x, m, n, inv, x); double t1 = now(); printf("  квадрат блоками 8 asm (библиотека) %6.1f нс", (t1 - t0) / N * 1e9); }
#endif
#if defined(WITH_OPENSSL)
		opensslmont(n, m, a, b);
#endif
		printf("\n");
	}
	return 0;
}
