
//#define _CRT_SECURE_NO_WARNINGS
//#include <openssl/applink.c> // in Window

//��ȣȭ�� ���¼ҽ��� ����Ѵ�.
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>  
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCKSIZE 16
#define KEYSIZE 32
#define IV 16
#define SALT 16

char salt[SALT] = { 0, };
char iv[IV] = { 0, };

/* Dir */
// may delete someday ..
const char* DIR_MATERKEY = "/mnt/kernel/keystore/xenics/MASTER_KEY"; // ������ �ּҽ���� ������ ��й�ȣ�� ������Ű�� �ȴ� ( KEK ) => �������� �� ������Ű�� ������ �����ϴ� ��� �����ִ�.
const char* DIR_DEK = "/mnt/kernel/keystore/xenics/DATA_KEY";        // KEK �� ��ȣȯ DEK�� ������ �����ϴ�
const char* DIR_SALT = "/mnt/kernel/keystore/xenics/SALT";           // SALT�� ��ȣȭ ��������� �ƴϴ�.
const char* DIR_IV = "/mnt/kernel/keystore/xenics/IV";               // IV�� �������� ������� ������ ��ȣȭ ��������� �ƴϴ�.

const char* DIR_ENC_KEY = "/mnt/kernel/keystore/xenics/server.key";
const char* DIR_ENC_CERT = "/mnt/kernel/keystore/xenics/server.crt";
const char* DIR_ENC_CA = "/mnt/kernel/keystore/xenics/ca.crt";

const char* DIR_DEC_KEY = "/usr/sslplus/xenics/cert/server.key";
const char* DIR_DEC_CERT = "/usr/sslplus/xenics/cert/server.crt";
const char* DIR_DEC_CA = "/usr/sslplus/xenics/cert/ca.crt";

/* Generating key function */
void generateKeys(unsigned char* KEK, unsigned char* DEK);
void generateKEK(unsigned char* KEK);
void generateDEK(unsigned char* DEK);

/* Encrypt function */
void encryptCert(char* input, char* output, unsigned char* DEK);
void encryptDEK(unsigned char* KEK, unsigned char* DEK, unsigned char* encryptedDEK);
int encryptData(unsigned char* plain, int plainLength, unsigned char* decryptedDEK, unsigned char* encryptedData, int cipherLength);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);

/* Decrypt function */
void decryptCert(char* input, char* output);
void decryptDEK(unsigned char* encryptedDEK, unsigned char* KEK, unsigned char* decryptedDEK);
int decryptData(unsigned char* encryptedData, int cipherLength, unsigned char* decryptedDEK, unsigned char* decryptedData, int plainLength);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

/* handle Enc/Dec Errors */
void handleErrors(void);

/* Utils */
int getFileSize(char* fileName);
void readFile(char* fileName, unsigned char* data, int fileSize);
void writeFile(char* fileName, unsigned char* data, int size);

void main(int argc, char* argv[])
{

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    struct stat st = { 0 };

    if (stat("/mnt/kernel/keystore", &st) == -1) {
        printf("\nKeyStrore not Exist .. \n");
        //mkdir("/mnt/kernel/keystore", 0777);
        return 0;
    }

    if (stat("/mnt/kernel/keystore/xenics", &st) == -1) {
        printf("\Xenics KeyStore not Exist .. \n");
        //mkdir("/mnt/kernel/keystore/xenics", 0777);
        return 0;
    }

    if (stat(DIR_MATERKEY, &st) == -1) {
        printf("\MasterKey not Exist .. \n");
        //mkdir("/mnt/kernel/keystore/xenics", 0777);
        return 0;
    }

    if (strcmp(argv[1], "decrypt") == 0) {
        // ��ȣȭ ��� 
        printf("Enter Decryption Mode ... \n\n");
        decryptCert(DIR_ENC_KEY, DIR_DEC_KEY);
        decryptCert(DIR_ENC_CERT, DIR_DEC_CERT);
        decryptCert(DIR_ENC_CA, DIR_DEC_CA);
        printf("Complete Decryption \n\n");
    } 

    if (strcmp(argv[1], "encrypt") == 0) {
        // ��ȣȭ ��� 
        printf("Enter Encryption Mode ... \n\n");

        unsigned char KEK[KEYSIZE] = { 0, };
        unsigned char DEK[KEYSIZE] = { 0, };

        // Ű ����
        generateKeys(KEK, DEK);

        // DEK�� ���� ��ȣȭ
        encryptCert(DIR_DEC_KEY, DIR_ENC_KEY, DEK);
        encryptCert(DIR_DEC_CERT, DIR_ENC_CERT, DEK);
        encryptCert(DIR_DEC_CA, DIR_ENC_CA, DEK);

        memset(DEK, 0, KEYSIZE);
        memset(DEK, 1, KEYSIZE);
        memset(DEK, 0, KEYSIZE);

        printf("Complete Encryption \n\n");
    }

    // Clean up
    printf("Cleaning Up ... \n\n");

    memset(salt, 0, SALT);
    memset(salt, 1, SALT);
    memset(salt, 0, SALT);

    memset(iv, 0, IV);
    memset(iv, 1, IV);
    memset(iv, 0, IV);
}

/* Ű ���� */
void generateKeys(unsigned char* KEK, unsigned char* DEK) {

    // SALT�� 128 ��Ʈ�� ������ ���̴�.
    RAND_priv_bytes(salt, SALT);
    writeFile(DIR_SALT, salt, SALT);

    // IV�� 128 ��Ʈ�� ������ ���̴�.
    RAND_priv_bytes(iv, IV);
    writeFile(DIR_IV, iv, IV);
    
    // ��������� ��й�ȣ�� ���� Salt, iteration 2000ȸ, Sha256 �� ���Ͽ� KEK �� �����Ѵ�.
    generateKEK(KEK);

    // 256��Ʈ DEK�� �����Ѵ�. ������ KEK�� �ı�ȴ�.
    generateDEK(DEK);

    unsigned char encryptedDEK[KEYSIZE + BLOCKSIZE] = { 0, };

    // DEK�� KEK�� ��ȣȭ �ȴ�.
    encryptDEK(KEK, DEK, encryptedDEK);

    // DEK�� sda2 �� ����ȴ�.
    writeFile(DIR_DEK, encryptedDEK, KEYSIZE + BLOCKSIZE);

    // Ű �ı�� 0,1,0���� 3ȸ �����ȴ�.
    memset(encryptedDEK, 0, KEYSIZE + BLOCKSIZE);
    memset(encryptedDEK, 1, KEYSIZE + BLOCKSIZE);
    memset(encryptedDEK, 0, KEYSIZE + BLOCKSIZE);
}

void encryptCert(char* input, char* output, unsigned char* DEK) {
    int plainLength = getFileSize(input);
    int cipherLength = plainLength + (BLOCKSIZE - (plainLength % BLOCKSIZE));

    unsigned char* plain = (unsigned char*)malloc(plainLength);
    memset(plain, 0, plainLength);

    readFile(input, plain, plainLength);

    unsigned char* encryptedData = (unsigned char*)malloc(cipherLength);
    memset(encryptedData, 0, cipherLength);

    //DEK�� ��ȣȭ�� ������ sda2�� ����
    int writeLength = encryptData(plain, plainLength, DEK, encryptedData, cipherLength);

    writeFile(output, encryptedData, writeLength);

    free(plain);
    free(encryptedData);
}

void decryptCert(char* input, char* output) {
  
    int cipherLength = getFileSize(input);

    unsigned char* encryptedData = (unsigned char*)malloc(cipherLength);
    memset(encryptedData, 0, cipherLength);

    // ������, SALT, IV �� �о�´�.
    readFile(input, encryptedData, cipherLength);

    readFile(DIR_SALT, salt, SALT);

    readFile(DIR_IV, iv, IV);

    unsigned char KEK[KEYSIZE] = { 0, };

    // ������Ű�� ���� KEK�� �����Ѵ�.
    generateKEK(KEK);

    unsigned char encryptedDEK[KEYSIZE + BLOCKSIZE] = { 0, };

    // DEK�� �о�´�.
    readFile(DIR_DEK, encryptedDEK, KEYSIZE + BLOCKSIZE);

    unsigned char decryptedDEK[KEYSIZE + BLOCKSIZE] = { 0 , };

    // ������Ű�� DEK�� ��ȣȭ �Ѵ�.
    decryptDEK(encryptedDEK, KEK, decryptedDEK);

    unsigned char* decryptedData = (unsigned char*)malloc(cipherLength);

    memset(decryptedData, 0, cipherLength);

    //DEK�� ��ȣȭ�� ���� ��ȣȭ
    int decryptedLength = decryptData(encryptedData, cipherLength, decryptedDEK, decryptedData, cipherLength);

    // �ó����� 1. ��ȣȭ�� ������ �����ϰ� ���н��� �о� ���� �Ŀ� ������ �����.
    // �ó����� 2. ���н��� �� �ڵ带 �����Ͽ� ������ �������� �ʰ� �о���δ�.
    writeFile(output, decryptedData, decryptedLength);

    memset(decryptedDEK, 0, KEYSIZE + BLOCKSIZE);
    memset(decryptedDEK, 1, KEYSIZE + BLOCKSIZE);
    memset(decryptedDEK, 0, KEYSIZE + BLOCKSIZE);

    memset(encryptedDEK, 0, KEYSIZE + BLOCKSIZE);
    memset(encryptedDEK, 1, KEYSIZE + BLOCKSIZE);
    memset(encryptedDEK, 0, KEYSIZE + BLOCKSIZE);

    free(decryptedData);
    free(encryptedData);
}


void generateKEK(unsigned char* KEK) {

    int iter = 2000;
    int fileLength = getFileSize(DIR_MATERKEY);

    unsigned char* initialKey = (unsigned char*)malloc(fileLength);
    memset(initialKey, 0, fileLength);
    readFile(DIR_MATERKEY, initialKey, fileLength);

    PKCS5_PBKDF2_HMAC("futuer_01", strlen("futuer_01"), salt, SALT, iter, EVP_sha256(), KEYSIZE, KEK);

    memset(initialKey, 0, fileLength);
    memset(initialKey, 1, fileLength);
    memset(initialKey, 0, fileLength);

    free(initialKey);
}

void generateDEK(unsigned char* DEK) {
    RAND_priv_bytes(DEK, KEYSIZE);
}

void encryptDEK(unsigned char* KEK, unsigned char* DEK, unsigned char* encryptedDEK) {

    if (encrypt(DEK, KEYSIZE, KEK, iv, encryptedDEK) == -1) {
        printf("Encrypt Error: DEK by KEK \n");
    }
    memset(KEK, 0, KEYSIZE);
    memset(KEK, 1, KEYSIZE);
    memset(KEK, 0, KEYSIZE);
}

void decryptDEK(unsigned char* encryptedDEK, unsigned char* KEK, unsigned char* decryptedDEK) {

    if (decrypt(encryptedDEK, KEYSIZE + BLOCKSIZE, KEK, iv, decryptedDEK) == -1) {
        printf("Decrypt Error: DEK by KEK ");
    }

    memset(KEK, 0, KEYSIZE);
    memset(KEK, 1, KEYSIZE);
    memset(KEK, 0, KEYSIZE);
}

int encryptData(unsigned char* plain, int plainLength, unsigned char* decryptedDEK, unsigned char* encryptedData,int cipherLength) {

    int length = encrypt(plain, plainLength, decryptedDEK, iv, encryptedData);

    return length;
}

int decryptData(unsigned char* encryptedData, int cipherLength, unsigned char* decryptedDEK, unsigned char* decryptedData, int plainLength) {

    int length = decrypt(encryptedData, cipherLength, decryptedDEK, iv, decryptedData);

    return length;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx;

    int len;

    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int getFileSize(char* fileName) {
    int size;

    FILE* fp = fopen(fileName, "r");


    fseek(fp, 0, SEEK_END);
    size = ftell(fp);


    fclose(fp);

    return size;
}

void writeFile(char* fileName, unsigned char* data, int size) {

    FILE* fp = fopen(fileName, "wb");

    fwrite(data, size, 1, fp);

    fclose(fp);
}

void readFile(char* fileName, unsigned char* data, int fileSize) {
    int size;

    FILE* fp = fopen(fileName, "rb");

    fread(data, 1, fileSize, fp);

    fclose(fp);
}

//void XORCipher(unsigned char* data, unsigned char* key, int dataLen, int keyLen) {
//    unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * dataLen);
//
//    for (int i = 0; i < dataLen; ++i) {
//        output[i] = data[i] ^ key[i % keyLen];
//    }
//    strncpy(data, output, dataLen);
//}


//int Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
//    BIO* bio, * b64;
//    BUF_MEM* bufferPtr;
//
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_new(BIO_s_mem());
//    bio = BIO_push(b64, bio);
//
//    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
//    BIO_write(bio, buffer, length);
//    BIO_flush(bio);
//    BIO_get_mem_ptr(bio, &bufferPtr);
//    BIO_set_close(bio, BIO_NOCLOSE);
//    BIO_free_all(bio);
//
//    *b64text = (*bufferPtr).data;
//
//    return (0); //success
//}
//
//
//unsigned char* base64(unsigned char* input, int length)
//{
//    BIO* bmem, * b64;
//    BUF_MEM* bptr;
//
//    b64 = BIO_new(BIO_f_base64());
//    bmem = BIO_new(BIO_s_mem());
//    b64 = BIO_push(b64, bmem);
//    BIO_write(b64, input, length);
//    BIO_flush(b64);
//    BIO_get_mem_ptr(b64, &bptr);
//
//    unsigned char* buff = (unsigned char*)malloc(bptr->length);
//    memcpy(buff, bptr->data, bptr->length - 1);
//    buff[bptr->length - 1] = 0;
//
//    BIO_free_all(b64);
//
//    return buff;
//}

//unsigned char* unbase64(unsigned char* input, int length)
//{
//    BIO* b64, * bmem;
//
//    unsigned char* buffer = (unsigned char*)malloc(length);
//    memset(buffer, 0, length);
//
//    b64 = BIO_new(BIO_f_base64());
//    bmem = BIO_new_mem_buf(input, length);
//    bmem = BIO_push(b64, bmem);
//
//    BIO_read(bmem, buffer, length);
//
//    BIO_free_all(bmem);
//
//    return buffer;
//}
