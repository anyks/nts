#!/usr/bin/env python3
"""
Проверка верхних границ накопителей src/internal/math/power.hpp.

Вызов: python3 tools/math/power29.py

Коэффициенты неотрицательны. Каждое произведение и сложение заменяется верхней
границей; младшая часть после маски ограничена B - 1 независимо от старшей.
Множитель приведения ограничен B - 1. Поэтому проверка охватывает все входы
договора, а не только случайную выборку. Численная граница результата
m + 4m²/R < 2m дополнительно возвращает старший коэффициент к пределу 1024.

Модель необходимо сверять с ядрами при изменении места частичного переноса
либо числа рядов. Она проверяет отсутствие переполнений, но не заменяет
сличение машинного результата с независимой арифметикой.

Попарное приведение квадрата вычисляет Q = -T/m mod B², где T = c[0] + B*c[1].
Его младшие и старшие 29 разрядов равны двум последовательным множителям:
сначала c[0] + Q[0]*m[0] делится на B, затем второй множитель снимает
следующий коэффициент. Поэтому ниже сохраняется проверка обычных рядов:
меняется только способ получения множителей, каждый остаётся не больше B - 1.
Удвоение половинной свёртки до добавления диагонали имеет ту же верхнюю
границу, поскольку все произведения неотрицательны. После свёртки квадрата
один перенос коэффициентов 28…39 заменяет переносы внутри каждого блока:
полная сумма сохраняется, а границы ниже учитывают новое место переноса.

@license LicenseRef-A-NTS-1.0
@author Yuriy Lobarev
"""

BASE = 1 << 29
LIMIT = 1 << 64


def bounds(square):
	"""Вывести границы умножения либо квадрата с приведением по четыре ряда."""
	peak = 0

	def add(first, second):
		"""Сложить верхние границы и проверить вместимость 64 разрядов."""
		nonlocal peak
		result = first + second
		peak = max(peak, result)
		assert result < LIMIT, "Переполнение накопителя"
		return result

	def normalize(value):
		"""Ограничить младшую часть маской и перенести старшую на одну позицию."""
		return [add(BASE - 1, 0 if i == 0 else value[i - 1] // BASE)
				for i in range(len(value))]

	# Дополнение нулевое, у 1024-разрядного модуля старший коэффициент девятиразрядный.
	value = [BASE + 64] * 35 + [1024] + [0] * 4
	modulus = [BASE - 1] * 35 + [511] + [0] * 4
	accumulator = [0] * 80

	# Полная свёртка имеет ту же границу, что удвоенный треугольник с диагональю:
	# все слагаемые неотрицательны, промежуточная сумма не превышает окончательную.
	if square:
		for i in range(36):
			for j in range(36):
				accumulator[i + j] = add(accumulator[i + j], value[i] * value[j])

		# Перед приведением квадрата переносим только середину готовой свёртки.
		high = [item // BASE for item in accumulator[28:40]]
		for i in range(12):
			accumulator[28 + i] = add(BASE - 1, 0 if i == 0 else high[i - 1])
		accumulator[40] = add(accumulator[40], high[-1])

	for block in range(0, 36, 4):
		if not square:
			# Перенос внутри c3 и из его последней дорожки в первую дорожку c4.
			high = [item // BASE for item in accumulator[12:16]]
			for i in range(4):
				accumulator[12 + i] = add(BASE - 1, 0 if i == 0 else high[i - 1])
			accumulator[16] = add(accumulator[16], high[3])

		# Умножение дополняет накопитель произведением очередного ряда;
		# у квадрата произведение уже лежит в накопителе целиком.
		for row in range(4):
			if not square:
				for i in range(36):
					accumulator[i + row] = add(accumulator[i + row], value[block + row] * value[i])
			for i in range(36):
				accumulator[i + row] = add(accumulator[i + row], (BASE - 1) * modulus[i])
			accumulator[row + 1] = add(accumulator[row + 1], accumulator[row] // BASE)
		accumulator = accumulator[4:] + [0] * 4

	# Два прохода возвращают коэффициенты в договор следующего умножения.
	result = normalize(normalize(accumulator[:36]))
	assert max(result) <= BASE + 64, "Нарушена граница коэффициентов"
	name = "Квадрат" if square else "Умножение"
	print(f"{name}: накопитель <= {peak}, доля 2^64 = {peak / LIMIT:.12f}; "
		  f"коэффициент <= 2^29 + {max(result) - BASE}")


if __name__ == "__main__":
	bounds(False)
	bounds(True)
