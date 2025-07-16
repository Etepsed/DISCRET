#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16
#define SALT_LENGTH 8
#define ITERATIONS 600000

//functions
int encrypt_file(const char *input_file, const char *output_file,const char *password);
int decrypt_file(const char *input_file, const char *output_file,const char *password);
void handleErrors(void);


int main(int argc, char *argv[]){
	if(argc != 5){
		fprintf(stderr, "use: %s <encrypt/decrypt> <password> <file_in> <file_out>\n",argv[0]);
		return 1;
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	if(strcmp(argv[1],"encrypt") == 0){
		if(encrypt_file(argv[3],argv[4],argv[2])){
			fprintf(stderr, "erro on encrypting\n");
			return 1;
		}
		printf("success in encrypting the file\n");
	}
	else if(strcmp(argv[1],"decrypt") == 0){
		if(decrypt_file(argv[3],argv[4],argv[2])){
			fprintf(stderr, "erro on decrypting\n");
			return 1;
		}
		printf("success in decrypting the file\n");
	}
	else{
		fprintf(stderr,"use: 'encrypt' or 'decrypt'\n");
		return 1;
	}
	EVP_cleanup();
	ERR_free_strings();
	return 0;
}

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt_file(const char *input_file, const char *output_file,const char *password){
	FILE *in = fopen(input_file,"rb");
	FILE *out = fopen(output_file,"wb");

	if(!in || !out){
		fprintf(stderr,"error on open file");
		return 1;
	}

	unsigned char salt[SALT_LENGTH];
	if(!RAND_bytes(salt, SALT_LENGTH)) handleErrors();

	unsigned char key[KEY_LENGTH];
	unsigned char iv[IV_LENGTH];

	if(!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATIONS, EVP_sha256(), KEY_LENGTH, key)){
		handleErrors();
	}

	if(!RAND_bytes(iv, IV_LENGTH)) handleErrors();

	fwrite( salt, 1, SALT_LENGTH, out);
	fwrite( iv, 1, IV_LENGTH, out);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx) handleErrors();

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),NULL, key, iv)){
		handleErrors();
	}

	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];

	int inlen, outlen;

	while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0){
		if(1 != EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)){
			handleErrors();
		}
		fwrite(outbuf, 1, outlen, out);
	}

	if(1 != EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) handleErrors();

	fwrite(outbuf, 1, outlen, out);

	EVP_CIPHER_CTX_free(ctx);

	fclose(in);
	fclose(out);

	return 0;
}
int decrypt_file(const char *input_file, const char *output_file,const char *password){
	FILE *in = fopen(input_file, "rb");
	FILE *out = fopen(output_file, "wb");
	
	if(!in || !out){
		fprintf(stderr, "error on open file\n");
		return 1;
	}

	unsigned char salt[SALT_LENGTH], iv[IV_LENGTH];

	fread(salt, 1, SALT_LENGTH, in);
	fread(iv, 1, IV_LENGTH, in);

	unsigned char key[KEY_LENGTH];

	if(!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LENGTH, ITERATIONS, EVP_sha256(), KEY_LENGTH, key)){
		handleErrors();
	}

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if(!ctx)handleErrors();

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
			handleErrors();
	}

	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];

	int inlen, outlen;

	while((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0){
		if(1 != EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))handleErrors();
		fwrite(outbuf, 1, outlen, out);
	}

	if(1 != EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) handleErrors();

	fwrite(outbuf, 1, outlen, out);

	EVP_CIPHER_CTX_free(ctx);

	fclose(in);
	fclose(out);

	return 0;
}


