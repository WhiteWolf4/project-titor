#ifndef TITOR_SHINFI_H
#define TITOR_SHINFI_H

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <algorithm>
using std::copy;
using std::begin;
using std::end;

#include <vector>
using std::vector;

#include <sstream>
using std::stringstream;

#include <fstream>
using std::ifstream;
using std::ofstream;


#include <string>
using std::string;

#include "arguments.hpp"

// Cryptopp dependences

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/base64.h"
#include "cryptopp/gzip.h"
using namespace CryptoPP;

#include "pem.h"

#define AES_KEY_LENGTH AES::DEFAULT_KEYLENGTH
#define RSA_PK_FILENAME ".rsapkey"
#define ENCRYPTED_FILE ".cipher"

typedef string ENC_BUFFER;
typedef string HASH_BUFFER;

namespace titor {

	typedef struct {
		string pkey;
		string cipher;
		byte iv[AES_KEY_LENGTH];
	} AES_FILE_ENC;

	typedef struct HEADER {
		char filename[100];
		char size[4];
		char iv[AES_KEY_LENGTH];
	} WWE_HEADER;

	char* size_to_chars(size_t);
	size_t chars_to_size(char *);

	class shinfi {

		public:
		shinfi(string pem):pem(pem){};
		
		AES_FILE_ENC encrypt(string);
		ENC_BUFFER pack(AES_FILE_ENC);
		HASH_BUFFER generate_hash(ENC_BUFFER);
		ENC_BUFFER encrypt_final(ENC_BUFFER, HASH_BUFFER);

		ENC_BUFFER decrypt_final(string, string);
		AES_FILE_ENC unpack(ENC_BUFFER, string);
		string decrypt(AES_FILE_ENC);

		private:
		string pem;
		AES_FILE_ENC aes_encrypt(ifstream& );
		RSA::PrivateKey get_rsa_private_key(ifstream& );
		ENC_BUFFER rsa_encrypt_key(ENC_BUFFER, RSA::PrivateKey);
		ENC_BUFFER rsa_decrypt_key(ENC_BUFFER, RSA::PrivateKey);
		byte* compress_hash_to_aes(HASH_BUFFER);
	};

}

#endif
