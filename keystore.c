
//#define _CRT_SECURE_NO_WARNINGS
//#include <openssl/applink.c> // in Window

//암호화는 오픈소스를 사용한다.
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>  
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#define LOGLEVEL 1

#define logger(level, fmt, ...) logger_(level , __FUNCTION__, fmt, ##__VA_ARGS__)

#define BUFFSIZE 1024
#define TPMBUFF 120
#define BLOCKSIZE 16
#define KEYSIZE 32
#define SALT 16
#define IV 16

char* SOTRE_PATH = "/root/.store";

#pragma pack(push, 1)   
typedef struct _KEYDATA {
	int64_t sequence;
	unsigned char dek[KEYSIZE + BLOCKSIZE];
	unsigned char iv[IV];
	unsigned char salt[SALT];
}KEYDATA;
#pragma pack(pop)       

#pragma pack(push, 1)   
typedef struct _ENCRYPTDATA {
	int64_t sequence;
	unsigned char* encrypted;
}ENCRYPTDATA;
#pragma pack(pop)      


/* Generating key function */
void generateKeys(unsigned char* KEK, unsigned char* DEK, KEYDATA* kd);
void generateKEK(unsigned char* KEK, unsigned char* salt);
void generateDEK(unsigned char* DEK);

/* Encrypt function */
void encryptCert(char* input, char* output, unsigned char* DEK, KEYDATA* kd);
void encryptDEK(unsigned char* KEK, unsigned char* DEK, KEYDATA* kd);
int encryptData(unsigned char* plain, int plainLength, unsigned char* decryptedDEK, unsigned char* encryptedData, int cipherLength, char* iv);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);

/* Decrypt function */
void decryptCert(char* input, char* output);
void decryptDEK(KEYDATA* kd, unsigned char* KEK, unsigned char* decryptedDEK);
int decryptData(unsigned char* encryptedData, int cipherLength, unsigned char* decryptedDEK, unsigned char* decryptedData, int plainLength, char* iv);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

/* handle Enc/Dec Errors */
void handleErrors(void);

/* Utils */
int getFileSize(char* fileName);
void readFile(char* fileName, unsigned char* data, int fileSize);
void writeFile(char* fileName, unsigned char* data, int size);
int writeEncryptData(ENCRYPTDATA* ed, char* path);
int readEncryptData(ENCRYPTDATA* ed, char* path);
void logger_(int level, const char* funcname, void* format, ...);
void DumpHex(const void* data, int size);
int64_t generateSequence();

/* TPM */
int initTpm();
int unsealData();

/* store */
int insertStore(KEYDATA kd);
int searchStore(KEYDATA* kd, double sequence);


int main(int argc, char* argv[])
{
	openlog("Keystore", LOG_CONS, LOG_USER);

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	struct stat st = { 0 };

	//if (stat("/mnt/kernel/keystore", &st) == -1) {
	//    printf("\nKeyStrore not Exist .. \n");
	//    //mkdir("/mnt/kernel/keystore", 0777);
	//    return 0;
	//}

	//if (stat("/mnt/kernel/keystore/xenics", &st) == -1) {
	//    printf("\Xenics KeyStore not Exist .. \n");
	//    //mkdir("/mnt/kernel/keystore/xenics", 0777);
	//    return 0;
	//}

	//if (stat(DIR_MATERKEY, &st) == -1) {
	//    printf("\MasterKey not Exist .. \n");
	//    //mkdir("/mnt/kernel/keystore/xenics", 0777);
	//    return 0;
	//}



	if (strcmp(argv[1], "init") == 0) {
		// TPM 초기화
		initTpm();

	}
	else if (strcmp(argv[1], "decrypt") == 0) {

		if (stat(argv[2], &st) == -1) {
			logger(1, "Failed to Open File : %s", argv[2]);
			return 0;
		}

		// 복호화 모드 
		logger(1, "Enter Decryption Mode ...");
		decryptCert(argv[2], argv[3]);
		logger(1, "Complete Decryption");

	}
	else if (strcmp(argv[1], "encrypt") == 0) {

		if (stat(argv[2], &st) == -1) {
			logger(1, "Failed to Open File : %s", argv[2]);
			return 0;
		}

		// 암호화 모드 
		logger(1, "Enter Encryption Mode ...");

		//DEK 구조체
		KEYDATA* kd = (KEYDATA*)malloc(sizeof(KEYDATA));
		memset(kd, 0, sizeof(KEYDATA));

		//임시 KEY 변수
		unsigned char KEK[KEYSIZE] = { 0, };
		unsigned char DEK[KEYSIZE] = { 0, };

		// 키 생성
		generateKeys(KEK, DEK, kd);

		// DEK로 파일 암호화
		encryptCert(argv[2], argv[3], DEK, kd);

		//Clean up
		memset(KEK, 0, KEYSIZE);
		memset(KEK, 1, KEYSIZE);
		memset(KEK, 0, KEYSIZE);

		memset(DEK, 0, KEYSIZE);
		memset(DEK, 1, KEYSIZE);
		memset(DEK, 0, KEYSIZE);

		//완료
		logger(1, "Complete Encryption");

		closelog();

		return 0;
	}
}

/* 키 생성 */
void generateKeys(unsigned char* KEK, unsigned char* DEK, KEYDATA* kd) {

	// SALT는 128 비트의 랜덤한 값이다.
	RAND_priv_bytes(kd->salt, SALT);
	logger(4, "Generating %s", "SALT");
	logger(4, kd->salt);

	// IV는 128 비트의 랜덤한 값이다.
	RAND_priv_bytes(kd->iv, IV);
	logger(4, "Generating %s", "IV");
	logger(4, kd->iv);
	//writeFile(DIR_IV, iv, IV);

	// 사용자최초 비밀번호로 부터 Salt, iteration 2000회, Sha256 을 통하여 KEK 를 생성한다.
	generateKEK(KEK, kd->salt);


	// 256비트 DEK를 생성한다.
	generateDEK(DEK);


	// DEK는 KEK로 암호화 된다.
	encryptDEK(KEK, DEK, kd);
}

void encryptCert(char* input, char* output, unsigned char* DEK, KEYDATA* kd) {

	logger(1, "Start Encrypt Data");

	ENCRYPTDATA* ed = (ENCRYPTDATA*)malloc(sizeof(ENCRYPTDATA));
	memset(ed, 0, sizeof(ENCRYPTDATA));

	int plainLength = getFileSize(input);
	logger(2, "plainLength : %d", plainLength);

	int cipherLength = plainLength + (BLOCKSIZE - (plainLength % BLOCKSIZE));
	logger(2, "cipherLength : %d", cipherLength);

	unsigned char* plain = (unsigned char*)malloc(plainLength);
	memset(plain, 0, plainLength);

	readFile(input, plain, plainLength);

	unsigned char* encrypted = (unsigned char*)malloc(cipherLength);
	memset(encrypted, 0, cipherLength);
	logger(2, "Before encryptData");
	int writeLength = encryptData(plain, plainLength, DEK, encrypted, cipherLength, kd->iv);
	logger(2, "After encryptData, Length is %d", writeLength);

	int64_t sequence = generateSequence();

	ed->encrypted = encrypted;
	ed->sequence = sequence;
	kd->sequence = sequence;

	writeEncryptData(ed, output);
	insertStore(*kd);

	free(plain);
	free(encrypted);

	logger(1, "Complete Encrypt Data");
}

void decryptCert(char* input, char* output) {
	logger(1, "Start Decrypt Data");

	ENCRYPTDATA* ed = (ENCRYPTDATA*)malloc(sizeof(ENCRYPTDATA));
	KEYDATA* kd = (KEYDATA*)malloc(sizeof(KEYDATA));

	memset(ed, 0, sizeof(ENCRYPTDATA));
	memset(kd, 0, sizeof(KEYDATA));

	//암호화된 파일에서 시퀀스로 스토어에서 찾는다
	readEncryptData(ed, input);
	searchStore(kd, ed->sequence);

	int cipherLength = strlen(ed->encrypted);
	logger(2, "cipherLength : %d", cipherLength);
	unsigned char KEK[KEYSIZE] = { 0, };

	// 마스터키로 부터 KEK를 유도한다.
	generateKEK(KEK, kd->salt);

	unsigned char decryptedDEK[KEYSIZE + BLOCKSIZE] = { 0 , };

	// 마스터키로 DEK를 복호화 한다.
	decryptDEK(kd, KEK, decryptedDEK);

	unsigned char* decryptedData = (unsigned char*)malloc(cipherLength);
	memset(decryptedData, 0, cipherLength);

	//DEK로 암호화된 파일 복호화
	logger(2, "Before decryptData");
	int decryptedLength = decryptData(ed->encrypted, cipherLength, decryptedDEK, decryptedData, cipherLength, kd->iv);
	logger(2, "After decryptData, Plain Length is %d", decryptedLength);

	// 시나리오 1. 복호화된 파일을 저장하고 제닉스가 읽어 들인 후에 파일을 지운다.
	// 시나리오 2. 제닉스에 이 코드를 내장하여 파일을 저장하지 않고 읽어들인다.
	writeFile(output, decryptedData, decryptedLength);

	memset(decryptedDEK, 0, KEYSIZE + BLOCKSIZE);
	memset(decryptedDEK, 1, KEYSIZE + BLOCKSIZE);
	memset(decryptedDEK, 0, KEYSIZE + BLOCKSIZE);

	memset(KEK, 0, KEYSIZE + BLOCKSIZE);
	memset(KEK, 1, KEYSIZE + BLOCKSIZE);
	memset(KEK, 0, KEYSIZE + BLOCKSIZE);

	free(decryptedData);

	logger(1, "Complete Decrypt Data");
}


void generateKEK(unsigned char* KEK, unsigned char* salt) {

	int iter = 2000;
	char initialKey[TPMBUFF] = { 0, };

	unsealData(initialKey);

	PKCS5_PBKDF2_HMAC(initialKey, TPMBUFF, salt, SALT, iter, EVP_sha256(), KEYSIZE, KEK);

	logger(4, "Generating %s", "KEK");
	logger(4, KEK);

	memset(initialKey, 0, TPMBUFF);
	memset(initialKey, 1, TPMBUFF);
	memset(initialKey, 0, TPMBUFF);

	logger(2, "Generated %s", "KEK");
	
}

void generateDEK(unsigned char* DEK) {
	RAND_priv_bytes(DEK, KEYSIZE);

	logger(4, "Generating %s", "DEK");
	logger(4, DEK);

}

void encryptDEK(unsigned char* KEK, unsigned char* DEK, KEYDATA* kd) {

	if (encrypt(DEK, KEYSIZE, KEK, kd->iv, kd->dek) == -1) {
		printf("Encrypt Error: DEK by KEK \n");
	}
	else {
		logger(4, "Encrypted %s : IV", "DEK");
		logger(4, kd->iv);

		logger(4, "Encrypted %s : DEK", "DEK");
		logger(4, kd->dek);
	}
}

void decryptDEK(KEYDATA* kd, unsigned char* KEK, unsigned char* decryptedDEK) {
	if (decrypt(kd->dek, KEYSIZE + BLOCKSIZE, KEK, kd->iv, decryptedDEK) == -1) {
		logger(1, "Decrypt Error: DEK by KEK ");
	}
	else {
		logger(4, "Decrypted %s : IV", "DEK");
		logger(4, kd->iv);

		logger(4, "Decrypted %s : DEK", "DEK");
		logger(4, kd->dek);
	}
}

int encryptData(unsigned char* plain, int plainLength, unsigned char* decryptedDEK, unsigned char* encryptedData, int cipherLength, char* iv) {

	int length = encrypt(plain, plainLength, decryptedDEK, iv, encryptedData);

	return length;
}

int decryptData(unsigned char* encryptedData, int cipherLength, unsigned char* decryptedDEK, unsigned char* decryptedData, int plainLength, char* iv) {

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
	if (fp == NULL) {
		logger(1, "File Open Error : %s", fileName);
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);


	fclose(fp);

	return size;
}

void writeFile(char* fileName, unsigned char* data, int size) {

	FILE* fp = fopen(fileName, "wb");
	if (fp == NULL) {
		logger(1, "File Open Error : %s", fileName);
		return 0;
	}
	fwrite(data, size, 1, fp);

	fclose(fp);
	logger(2, "File write complete");
}

void readFile(char* fileName, unsigned char* data, int fileSize) {
	int size;

	FILE* fp = fopen(fileName, "rb");
	if (fp == NULL) { 
		logger(1, "File Open Error : %s", fileName);
		return 0;
	}
	fread(data, 1, fileSize, fp);

	fclose(fp);
	logger(2, "File read complete");
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

//retrun 1 = error 0= success
//int validationCheck(char* password) {
//    char* KEYBOARD1 = "QWERTYUIOP";
//    char* KEYBOARD2 = "ASDFGHJKL";
//    char* KEYBOARD3 = "ZXCVBNM";
//
//    /* 보안요구사항 1.3.1*/
//     
//    /* 1) 9자리 이상의 길이 확보 */
//    if (sizeof(password) < 9 ){
//        printf("PASSWORD is too short");
//        return 1;
//    }
//
//    /* 2) 숫자, 대문자(영문), 소문자(영문), 특수문자가 각 1개 이상 포함 */
//    int isLower = 0; 
//    int isUpper = 0;
//    int isSpecial = 0;
//    int isDigit = 0;
//
//    for (int i = 0; password[i]; i++)   
//    {
//        if (65 <= password[i] && password[i] <= 90) {
//            isLower = 1;
//        }
//        else if (97 <= password[i] && password[i] <= 122) {
//            isUpper = 1;
//            //lower
//        }
//        else if (48 <= password[i] && password[i] <= 57) {
//            isSpecial = 1;
//        }
//        else {
//            isDigit = 1;
//        }
//    }
//
//    if (!isLower) { printf("PASSWORD is not include LowerCase");  return 1; }
//    if (!isUpper) { printf("PASSWORD is not include UpperCase");  return 1; }
//    if (!isSpecial) { printf("PASSWORD is not include SepcialCharacter");  return 1; }
//    if (!isDigit) { printf("PASSWORD is not include Digit");  return 1; }
//
//    /* 3) 사용자 계정(ID)과 동일한 패스워드 설정 금지 */ 
//    if (!strcmp(password, "admin")) {    
//        printf("PASSWORD is equal to ID");
//        return 1;
//    }
//
//    /* 4) 동일한 문자, 숫자의 연속적인 반복입력 금지 */
//    for (int i = 1; password[i]; i++)
//    {
//        if (password[i-1] == password[i]) {
//            printf("PASSWORD is Continuos");
//            return 1;
//        }
//    }
//
//    /* 5) 동일한 문자, 숫자의 연속적인 반복입력 금지 */
//    char temp[100] = { 0, };
//    for (int i = 1; password[i]; i++)
//    {
//        temp[i] = password[i];
//        if (strstr(KEYBOARD1, temp) != NULL) {
//            printf("PASSWORD is include Continuos Letter on Keyboard");
//        }
//
//        if (strstr(KEYBOARD2, temp) != NULL) {
//            printf("PASSWORD is include Continuos Letter on Keyboard");
//        }
//
//        if (strstr(KEYBOARD3, temp) != NULL) {
//            printf("PASSWORD is include Continuos Letter on Keyboard");
//        }
//    }
//
//
//    /* 6) 직전 사용된 패스워드 재사용 금지, */
//    if (!strcmp(password, "future_01")) {
//        printf("PASSWORD is using default Password");
//        return 1;
//    }
//
//    printf("Validation Success");
//    return 0;
//}

int initTpm() {
	logger(1, "Start initTpm");
	/* if (system("mount /dev/sda2 /mnt/kernel")) {
		 printf("Failed to mount \n");
		 return 1;
	 }*/

	chdir("/mnt/kernel/keystore");

	system("tpm2_createprimary --hierarchy=o --key-algorithm=rsa --key-context=prim.ctx");
	logger(1, "tpm2_createprimary completed.. ");

	char initialKey[TPMBUFF] = { 0, };
	RAND_priv_bytes(initialKey, TPMBUFF);
	logger(4, "Generating %s ", "initialKey");
	logger(4, initialKey);

	writeFile("/mnt/kernel/keystore/disk.key", initialKey, TPMBUFF);
	logger(1, "Create initialKey completed.. ");

	system("tpm2_create -Q -g sha256 -u seal.pub -r seal.priv -i disk.key -C prim.ctx");
	logger(1, "tpm2_create completed.. ");

	system("tpm2_load -Q -C prim.ctx -u seal.pub -r seal.priv -n seal.name -c seal.ctx");
	logger(1, "tpm2_load completed.. ");

	system("cp seal.ctx /root/.seal.ctx");
	system("rm /mnt/kernel/keystore/disk.key");

	//if (system("umount /mnt/kernel")) {
	//    printf("Failed to umount\n");
	//    return 1;
	//}
	logger(1, "Complete initTpm");
	return 0;
}

int unsealData(char* initialKey) {
	logger(1, "Unsealing initialKey");

	FILE* fp;

	fp = popen("tpm2_unseal -Q -c /root/.seal.ctx", "r");
	if (fp == NULL) {
		logger(1, "File Open Error : /root/.seal.ctx");
		return -1;
	}

	fgets(initialKey, TPMBUFF, fp);

	pclose(fp);

	logger(4, "Unsealed %s ", "initialKey");
	logger(4, initialKey);

	return 0;

}


int insertStore(KEYDATA kd) {
	logger(2, "Insert Store");
	FILE* out = fopen(SOTRE_PATH, "ab");
	if (out == NULL) {
		logger(1, "File Open Error : %s", SOTRE_PATH);
		return -1;
	}
	fwrite(&kd, sizeof(KEYDATA), 1, out);

	fclose(out);

	logger(4, "Insert %lld ,%s", kd.sequence ,"");
	logger(4, "Insert %s ", "DEK");
	logger(4, kd.dek);
	logger(4, "Insert %s ", "IV");
	logger(4, kd.iv);
	logger(4, "Insert %s ", "SALT");
	logger(4, kd.salt);

	return 0;
}

int searchStore(KEYDATA* kd, double sequence) {
	logger(2, "Search Store");

	FILE* in = fopen(SOTRE_PATH, "rb");
	if (in == NULL) {
		logger(1, "File Open Error : %s", SOTRE_PATH);
		return -1;
	}
	while (1) {
		fread(kd, 1, sizeof(KEYDATA), in);
		if (feof(in)) { break; }

		if (kd->sequence == sequence) {
			logger(4, "Search %lld  %s ", kd->sequence ,"");

			logger(4, "Search %s ", "DEK");
			logger(4, kd->dek);
			logger(4, "Search %s ", "IV");
			logger(4, kd->iv);
			logger(4, "Search %s ", "SALT");
			logger(4, kd->salt);

			return 0;
		}
	}
	fclose(in);

	memset(kd, 0, sizeof(KEYDATA));
	return 1;
}

int writeEncryptData(ENCRYPTDATA* ed, char* path) {
	logger(2, "Write Read Encrypt");
	FILE* out = fopen(path, "w");
	if (out == NULL) {
		logger(1, "File Open Error : %s", path);
		return -1;
	}
	size_t length;

	fwrite(&ed->sequence, sizeof(ed->sequence), 1, out);

	length = strlen(ed->encrypted) + 1;
	fwrite(&length, sizeof(length), 1, out);
	fwrite(ed->encrypted, 1, length, out);

	fclose(out);

	logger(4, "writeEncryptData %lld  %s ", ed->sequence ,"");

	logger(4, "writeEncryptData %s ", "encrypted");
	logger(4, ed->encrypted);

	return 0;
}

int readEncryptData(ENCRYPTDATA* ed, char* path) {
	logger(2, "Start Read Encrypt");
	FILE* in = fopen(path, "r");
	if (in == NULL) {
		logger(1, "File Open Error : %s", path);
		return -1;
	}
	size_t length;

	fread(&ed->sequence, sizeof(ed->sequence), 1, in);
	fread(&length, sizeof(length), 1, in);
	ed->encrypted = malloc(length);
	fread(ed->encrypted, 1, length, in);
	fclose(in);

	logger(4, "readEncryptData %lld %s ", ed->sequence ,"");

	logger(4, "readEncryptData %s ", "encrypted");
	logger(4, ed->encrypted);

	return 0;
}

int64_t generateSequence() {
	struct timeval time;
	gettimeofday(&time, NULL);
	int64_t s1 = (int64_t)(time.tv_sec) * 1000;
	int64_t s2 = (time.tv_usec / 1000);

	logger(2, "Generate Sequence : %lld", s1 + s2);

	return s1 + s2;
}

void DumpHex(const void* data, int size) {
	char ascii[17];
	int i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void logger_(int level, const char* funcname, void* format, ...)
{
	char buf[1024] = { 0, };

	if ((level & LOGLEVEL) == 0) {
		return 0;
	}

	if (level == 1) {
		sprintf(buf, "[INFO] [FUNCNAME: %s] ", funcname);
	}
	else if (level == 2) {
		sprintf(buf, "[DEBUG] [FUNCNAME: %s] ", funcname);
	}
	else if (level == 4) {
		if (strstr(format, "%s") != NULL) {
			sprintf(buf, "[KEY] [FUNCNAME: %s] ", funcname);
		}
	}

	if (level == 4) {
		if (strstr(format, "%s") == NULL) {
			DumpHex(format, strlen(format));
			return 0;
		}
	}

	va_list va;
	va_start(va, format);
	vsprintf(buf + strlen(buf), format, va);
	va_end(va);
	syslog(LOG_INFO, buf);
	puts(buf);
}
