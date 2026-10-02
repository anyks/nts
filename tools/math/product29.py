#!/usr/bin/env python3
"""
Порождатель симметричной свёртки product29Avx2 из src/internal/math/power.hpp.

python3 tools/math/product29.py проверяет команды, границы и совпадение с заголовком.
python3 tools/math/product29.py --emit выводит проверенное определение метода.

Двенадцать регистров сохраняют рассылки коэффициентов. Когда все заняты, вытесняется
коэффициент с наиболее далёким следующим чтением. Выбор выполняет порождатель;
готовое ядро не содержит ветвлений и адресует вход по постоянным смещениям.
Оставшиеся регистры: ymm12 — временный, ymm13 — диагонали соседних блоков,
ymm14 — сумма четырёх коэффициентов, ymm15 — текущее произведение.

Для двух блоков, начинающихся с k и k + 4, h = k / 2, одна команда получает
[a[h+1]², a[h+1]*a[h+2], a[h+3]², a[h+3]*a[h+4]]. После удвоения только нечётных
дорожек младшая и старшая пары попадают в старшие дорожки соответствующих блоков.
Остальная часть треугольника и нижняя диагональ вычисляются независимо.

Проверка разбирает выданные строки ассемблера, ведёт в каждой дорожке точный
полином и сличает все 72 коэффициента с полным квадратом. Верхние границы всех
промежуточных полиномов проверяют вместимость команд, включая 32-разрядные
сомножители vpmuludq. Это проверяет расписание и маски; исполнение машинного
ядра дополнительно проверяется IntegerTest.VectorSquare и стендовыми щупами.

@license LicenseRef-A-NTS-1.0
@author Yuriy Lobarev
"""

from collections import Counter
from pathlib import Path
import re
import sys


def generate():
	"""Породить одно определение метода с постоянным расписанием регистров."""
	requests = []
	for column in range(0, 72, 4):
		requests.extend(list(range(max(0, column - 35), column // 2)) + [column // 2])
	cache = {}
	position = 0
	lines = []

	def emit(command):
		lines.append('\t' * 6 + '"' + command + '\\n\\t"\n')

	def register(index):
		"""Сохранить рассылку до следующего чтения либо освободить её регистр."""
		nonlocal position
		assert requests[position] == index
		if index not in cache:
			free = [number for number in range(12) if number not in cache.values()]
			if free:
				chosen = free[0]
			else:
				future = requests[position + 1:]
				victim = max(cache, key=lambda item: future.index(item) if item in future else len(requests))
				chosen = cache.pop(victim)
			cache[index] = chosen
			emit(f'vpbroadcastq {index * 8}(%[value]), %%ymm{chosen}')
		position += 1
		return cache[index]

	for column in range(0, 72, 4):
		lines.append('\t' * 6 + f'// Коэффициенты {column}…{column + 3}\n')
		for term, index in enumerate(range(max(0, column - 35), column // 2)):
			destination = 15 if term else 14
			emit(f'vpmuludq {(column - index) * 8}(%[value]), %%ymm{register(index)}, %%ymm{destination}')
			if term:
				emit('vpaddq %%ymm15, %%ymm14, %%ymm14')
		if column:
			emit('vpaddq %%ymm14, %%ymm14, %%ymm14')
		index = column // 2
		emit(f'vpmuludq {index * 8}(%[value]), %%ymm{register(index)}, %%ymm15')
		emit('vpaddq %%ymm15, %%ymm15, %%ymm12')
		emit(f'vpblendd $3, %%ymm15, %%ymm12, %%ymm{15 if column else 14}')
		if column:
			emit('vpaddq %%ymm15, %%ymm14, %%ymm14')
		if column % 8 == 0:
			emit(f'vmovdqu {(index + 1) * 8}(%[value]), %%ymm15')
			emit('vpermq $160, %%ymm15, %%ymm12')
			emit('vpmuludq %%ymm15, %%ymm12, %%ymm13')
			emit('vpaddq %%ymm13, %%ymm13, %%ymm15')
			emit('vpblendd $51, %%ymm13, %%ymm15, %%ymm13')
			emit('vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15')
		else:
			emit('vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15')
		emit('vpaddq %%ymm15, %%ymm14, %%ymm14')
		emit(f'vmovdqu %%ymm14, {column * 8}(%[product])')
	assert position == len(requests)
	return ('\t' * 4 + '__attribute__((target("avx2"), noinline)) static void product29Avx2(uint64_t * __restrict__ product, const uint64_t * value) noexcept {\n'
		+ '\t' * 5 + '// Порождатель и проверка полиномов: tools/math/product29.py\n'
		+ '\t' * 5 + '// ymm0…11 сохраняют рассылки, ymm13 — диагонали двух соседних блоков\n'
		+ '\t' * 5 + '__asm__(\n' + ''.join(lines)
		+ '\t' * 6 + ': [output] "=m" (* reinterpret_cast <uint64_t (*)[72]> (product))\n'
		+ '\t' * 6 + ': [product] "r" (product), [value] "r" (value), [input] "m" (* reinterpret_cast <const uint64_t (*)[40]> (value))\n'
		+ '\t' * 6 + ': ' + ', '.join(f'"ymm{index}"' for index in range(16)) + '\n'
		+ '\t' * 5 + ');\n' + '\t' * 4 + '}')


def verify(code):
	"""Сверить фактические команды с полным квадратом и договором коэффициентов."""
	instructions = re.findall(r'^\t{6}"(.+?)\\n\\t"$', code, re.M)
	registers = {}
	output = [None] * 72
	reads = []
	peak = 0

	def memory(operand, count):
		match = re.fullmatch(r'(\d+)\(%\[value\]\)', operand)
		assert match, operand
		offset = int(match[1])
		word = offset // 8
		assert offset % 8 == 0 and 0 <= word <= 40 - count
		reads.extend(range(word, word + count))
		return [Counter({(index,): 1}) if index < 36 else Counter() for index in range(word, word + count)]

	def multiply(first, second):
		result = Counter()
		for left, count in first.items():
			for right, number in second.items():
				result[tuple(sorted(left + right))] += count * number
		return result

	def bound(polynomial):
		result = 0
		for term, count in polynomial.items():
			value = count
			for word in term:
				value *= 1024 if word == 35 else (1 << 29) + 64
			result += value
		return result

	for instruction in instructions:
		operation, tail = instruction.replace('%%', '%').split(' ', 1)
		args = [item.strip() for item in tail.split(',')]
		destination = args[-1]
		if operation == 'vpbroadcastq':
			registers[destination] = memory(args[0], 1) * 4
		elif operation == 'vpmuludq':
			first = registers[args[0]] if args[0].startswith('%ymm') else memory(args[0], 4)
			second = registers[args[1]]
			assert all(bound(item) < (1 << 32) for item in first + second)
			registers[destination] = [multiply(left, right) for left, right in zip(first, second)]
		elif operation == 'vpaddq':
			registers[destination] = [left + right for left, right in zip(registers[args[0]], registers[args[1]])]
		elif operation == 'vpblendd':
			mask = int(args[0][1:])
			first, second = registers[args[2]], registers[args[1]]
			assert all(((mask >> (index * 2)) & 3) in [0, 3] for index in range(4))
			registers[destination] = [second[index] if mask & (3 << (index * 2)) else first[index] for index in range(4)]
		elif operation == 'vpermq':
			mask, value = int(args[0][1:]), registers[args[1]]
			registers[destination] = [value[(mask >> (2 * index)) & 3] for index in range(4)]
		elif operation == 'vperm2i128':
			assert args[0] in ['$8', '$24'] and args[1] == args[2]
			half = registers[args[1]][:2] if args[0] == '$8' else registers[args[1]][2:]
			registers[destination] = [Counter(), Counter()] + half
		elif operation == 'vmovdqu':
			if destination.startswith('%ymm'):
				registers[destination] = memory(args[0], 4)
			else:
				match = re.fullmatch(r'(\d+)\(%\[product\]\)', destination)
				assert match, destination
				offset = int(match[1])
				word = offset // 8
				assert offset % 8 == 0 and 0 <= word <= 68
				assert all(item is None for item in output[word:word + 4])
				output[word:word + 4] = registers[args[0]]
		else:
			raise AssertionError(instruction)
		if destination.startswith('%ymm'):
			for polynomial in registers[destination]:
				upper = bound(polynomial)
				peak = max(peak, upper)
				assert upper < (1 << 64), 'Переполнение дорожки'
	for column, actual in enumerate(output):
		expected = Counter()
		for first in range(36):
			second = column - first
			if 0 <= second < 36:
				expected[tuple(sorted([first, second]))] += 1
		assert actual == expected, f'Неверный коэффициент {column}'
	return (f'Свёртка: все 72 полинома совпали; {len(instructions)} команд, '
		f'{sum(item.startswith("vpmuludq ") for item in instructions)} произведений; '
		f'чтение слов {min(reads)}…{max(reads)}, запись 72 слов; накопитель <= {peak}')


if __name__ == '__main__':
	assert sys.argv[1:] in [[], ['--emit']], 'Допустим только параметр --emit'
	code = generate()
	report = verify(code)
	if sys.argv[1:]:
		print(code)
		print(report, file=sys.stderr)
	else:
		header = Path(__file__).resolve().parents[2] / 'src/internal/math/power.hpp'
		assert code in header.read_text(), 'Заголовок отличается от проверенного порождения'
		print(report)
