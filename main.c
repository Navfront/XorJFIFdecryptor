#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

// ��������� ��� ���������/������ JPG
#define HEADER_SIZE 12
#define FOOTER_SIZE 2
#define MAX_KEY_SIZE 32

// JPG ��������� (������ � ����� JFIF-�����)
const unsigned char JPG_HEADER[HEADER_SIZE] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10,
    0x4A, 0x46, 0x49, 0x46, 0x00, 0x01
};
const unsigned char JPG_FOOTER[FOOTER_SIZE] = { 0xFF, 0xD9 };

// XOR-����������
void doXor(unsigned char* buffer, long size, const unsigned char* key, int keySize) {
    for (long i = 0; i < size; i++) {
        buffer[i] ^= key[i % keySize];
    }
}

// �������� ������ JPG
bool checkJpgStart(const unsigned char* buffer) {
    return memcmp(buffer, JPG_HEADER, HEADER_SIZE) == 0;
}

// �������� ����� JPG
bool checkJpgEnd(const unsigned char* buffer, long size) {
    if (size < FOOTER_SIZE) return false;
    return memcmp(buffer + size - FOOTER_SIZE, JPG_FOOTER, FOOTER_SIZE) == 0;
}

// �������������� ����� �� ���������
void recoverKeyFromHeader(const unsigned char* buffer, unsigned char* outKey, int keySize) {
    for (int i = 0; i < keySize; i++) {
        outKey[i] = buffer[i] ^ JPG_HEADER[i];
    }
}

// ������ ������ � hex
void printHex(const unsigned char* buffer, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

// ��������� ������� �����
long getFileSize(FILE* file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    return size;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input.enc>\n", argv[0]);
        return 1;
    }

    const char* inputFile = argv[1];
    const char* outputFile = "res.jpg";

    FILE* f = fopen(inputFile, "rb");
    if (!f) {
        perror("Error opening file");
        return 1;
    }

    long fileSize = getFileSize(f);
    printf("File size: %ld bytes\n", fileSize);

    unsigned char* encrypted = (unsigned char*)malloc(fileSize);
    unsigned char* decrypted = (unsigned char*)malloc(fileSize);
    if (!encrypted || !decrypted) {
        perror("Memory allocation failed");
        fclose(f);
        free(encrypted);
        free(decrypted);
        return 1;
    }

    fread(encrypted, 1, fileSize, f);
    fclose(f);

    bool success = false;
    unsigned char key[32] = { 0 };

    // ������� ��������� ����� �����
    for (int keyLen = 1; keyLen <= MAX_KEY_SIZE && !success; keyLen++) {
        recoverKeyFromHeader(encrypted, key, keyLen);

        memcpy(decrypted, encrypted, fileSize);
        doXor(decrypted, fileSize, key, keyLen);

        if (checkJpgStart(decrypted) && checkJpgEnd(decrypted, fileSize)) {
            printf("Decryption successful!\n");
            printf("Key length: %d\nKey: ", keyLen);
            printHex(key, keyLen);

            FILE* out = fopen(outputFile, "wb");
            if (!out) {
                perror("Failed to write output file");
            }
            else {
                fwrite(decrypted, 1, fileSize, out);
                fclose(out);
                printf("Decrypted file saved to %s\n", outputFile);
            }

            success = true;
        }
    }

    if (!success) {
        printf("Failed to find valid key or decrypt JPEG.\n");
    }

    free(encrypted);
    free(decrypted);
    return 0;
}
