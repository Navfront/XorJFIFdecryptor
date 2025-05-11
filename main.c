#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

// Структура с магическими байтами JPG
struct JPG_TYPE {
    unsigned char begin[12];
    short bSize;
    unsigned char end[2];
    short eSize;
};

// Инициализация магических байтов JPG
struct JPG_TYPE jpgType = {
    .begin = { 0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00 , 0x01 },
    .end = { 0xFF, 0xD9 },
    .bSize = 12,
    .eSize = 2,
};

// XOR-дешифратор
void doXor(unsigned char* buffer, long bufferSize, unsigned char* key, short keySize) {
    for (long i = 0; i < bufferSize; i++) {
        buffer[i] ^= key[i % keySize];
    }
}

// Печать буфера в hex
void printBuffer(unsigned char* buffer, int size) {
    for (int j = 0; j < size; j++) {
        printf("%02x ", buffer[j]);
    }
    printf("\n");
}

// Копирование буфера (опционально с хвоста)
void copyBuffer(unsigned char* buffer, int size, unsigned char* destination, int fromTailSize) {
    if (fromTailSize > 0) {
        for (int i = size - fromTailSize, j = 0; i < size; i++, j++) {
            destination[j] = buffer[i];
        }
    }
    else {
        for (int i = 0; i < size; i++) {
            destination[i] = buffer[i];
        }
    }
}

// Проверка начала JPG
bool checkValidStart(unsigned char* startBuffer, int startSize) {
    if (startSize < jpgType.bSize) {
        printf("Need %d chars min start to check!\n", jpgType.bSize);
        abort();
    }
    int res = memcmp(startBuffer, jpgType.begin, jpgType.bSize);
    return res == 0;
}

// Проверка конца JPG
bool checkValidEnd(unsigned char* endBuffer, int endSize) {
    for (int j = 0; j < jpgType.eSize; j++) {
        if (endBuffer[endSize - jpgType.eSize + j] != jpgType.end[j]) {
            return false;
        }
    }
    return true;
}

// Восстановление XOR-ключа по начальному блоку JFIF
void findStartKeyChars(unsigned char* startBuffer, unsigned char* keyBuffer) {
    for (int i = 0; i < jpgType.bSize; i++) {
        keyBuffer[i] = startBuffer[i] ^ jpgType.begin[i];
    }
}

// Получить размер файла
long getFileSize(FILE* f) {
    fseek(f, 0, SEEK_END);
    long s = ftell(f);
    rewind(f);
    return s;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input.enc>\n", argv[0]);
        return 1;
    }

    printf("Decrypting file: %s\n", argv[1]);

    // Чтение файла
    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    long fileSize = getFileSize(file);
    printf("File size: %ld bytes\n", fileSize);

    unsigned char* buffer = malloc(fileSize);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return 1;
    }

    fread(buffer, 1, fileSize, file);
    fclose(file);

    unsigned char* tempBuffer = malloc(fileSize);
    if (!tempBuffer) {
        perror("Memory allocation failed");
        free(buffer);
        return 1;
    }

    unsigned char startPart[14];
    unsigned char key[14] = { 0 };

    findStartKeyChars(buffer, key);

    printf("Initial key guess:\n");
    printBuffer(key, 12);

    bool isValid = false;
    for (int a = 0; a <= 0xFF && !isValid; a++) {
        key[13] = a;
        for (int b = 0; b <= 0xFF && !isValid; b++) {
            key[12] = b;
            for (int k = 12; k <= 14 && !isValid; k++) {
                copyBuffer(buffer, 14, startPart, 0);
                doXor(startPart, 14, key, k);

                if (checkValidStart(startPart, 14)) {
                    memcpy(tempBuffer, buffer, fileSize);
                    doXor(tempBuffer, fileSize, key, k);

                    isValid = checkValidEnd(tempBuffer, fileSize);
                    if (isValid) {
                        printf("Decryption successful with key length: %d\n", k);
                        printf("Final key:\n");
                        printBuffer(key, k);
                        
                        FILE* res = fopen("res.jpg", "wb");
                        fwrite(tempBuffer, sizeof(char), fileSize, res);
                        fclose(res);
                    }
                }
            }
        }
    }

    if (!isValid) {
        printf("Failed to find valid key.\n");
    }

    free(tempBuffer);
    free(buffer);
    return 0;
}
