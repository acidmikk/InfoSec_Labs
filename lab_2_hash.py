import struct
import math


# Функции MD4
def F(X, Y, Z):
    return (X & Y) | ((~X) & Z)


def G(X, Y, Z):
    return (X & Y) | (X & Z) | (Y & Z)


def H(X, Y, Z):
    return X ^ Y ^ Z


# Шаги MD4
def md4_step(a, b, c, d, k, s, X):
    if k == 0:
        f = F(b, c, d)
    elif k == 1:
        f = G(b, c, d)
    else:
        f = H(b, c, d)

    temp = (a + f + X) & 0xFFFFFFFF
    return d, (b + ((temp << s) | (temp >> (32 - s))) & 0xFFFFFFFF) & 0xFFFFFFFF


# Функция для хеширования строки
def md4(message):
    # Инициализация переменных
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Предварительная обработка сообщения
    message = bytearray(message, 'utf-8')
    message_len = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message.append(0x00)
    message += struct.pack('<Q', message_len)

    # Обработка блоков
    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        X = list(struct.unpack('<16I', block))

        a, b, c, d = A, B, C, D

        # Цикл обработки блока
        for j in range(64):
            if j < 16:
                k, s = j, [3, 7, 11, 19][j % 4]
            elif j < 32:
                k, s = (j + 4) % 16, [3, 5, 9, 13][j % 4]
            else:
                k, s = (j + 8) % 16, [3, 9, 11, 15][j % 4]

            a, b = md4_step(a, b, c, d, k, s, X[k])

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Формирование хеша
    return struct.pack('<4I', A, B, C, D).hex()


# Пример использования
if __name__ == '__main__':
    message = "Hello, MD4!"
    hashed = md4(message)
    print(f"Сообщение: {message}")
    print(f"Хэш: {hashed}")