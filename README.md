﻿# XOR JPG(JFIF) Decryptor

Этот инструмент предназначен для дешифровки JPG-файлов, зашифрованных с помощью повторяющегося XOR-ключа.

## 🧩 Как работает

Считывает весь файл в память.

Подбирает XOR-ключ по заголовку JPEG (JFIF сигнатура).

Перебирает возможные длины ключа до 14 байт.

Проверяет, расшифровался ли файл корректно (по сигнатуре конца FF D9).

Сохраняет результат в res.jpg.

## 🚀 Использование

Скомпилируй программу:

```bash
gcc -o xor_decryptor main.c

./xor_decryptor secret.jpg.enc
