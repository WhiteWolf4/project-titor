#include "shinfi.hpp"

/*
 *
 * Defined global functions.
 *
 * 
 */

char* titor::size_to_chars( size_t size ) {
	char * res = new char[4];
	for(int i = 0; i < 4; i++) res[3-i] = size >> (i*8);
	return res;
}

size_t titor::chars_to_size( char* csize ) {
	size_t size = 0;
	for(int i = 0; i < 4; i++) size += (csize[3-i] << (i*8));
	return size;
}

/*
 *
 * Defined methods for class arguments
 *
 * 
 */

titor::AES_FILE_ENC titor::shinfi::encrypt(string file) {

	// Open original file and check if file can be opened.
	
	ifstream ifile( file );
	if( !ifile.is_open() ) throw 3;

	// Encode original file stream using AES-128 Algorithm.
	
	AES_FILE_ENC encoded = aes_encrypt( ifile );
	ifile.close();

	// Open PEM file used for encrypt private keyword.
	
	ifstream pfile( pem );
	if( !pfile.is_open() ) throw 4;
	RSA::PrivateKey rsa_pkey = get_rsa_private_key(pfile);
	pfile.close();

	// Encrypt private key using RSA Algorithm.
	
	encoded.pkey = rsa_encrypt_key(encoded.pkey, rsa_pkey);

	return encoded;
	
}

titor::AES_FILE_ENC titor::shinfi::aes_encrypt(ifstream& in) {

	AES_FILE_ENC result;

	// Generates a random key.
	
	AutoSeededRandomPool asrp;
	byte key[AES_KEY_LENGTH];
	asrp.GenerateBlock(key, sizeof(key));

        asrp.GenerateBlock(result.iv, sizeof(result.iv));

	string encrypted_file;

	// Encrypts orginal file.
	
	try {

		CBC_Mode<AES>::Encryption enc;
		enc.SetKeyWithIV(key, sizeof(key), result.iv);
		StringSink* ostring = new StringSink(encrypted_file);
		StreamTransformationFilter* stf = new StreamTransformationFilter(enc, ostring);
		FileSource src(in, true, stf);
		
	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	result.pkey = string( (const char*) key, AES_KEY_LENGTH);
	result.cipher = encrypted_file;
	
	return result;

}

RSA::PrivateKey titor::shinfi::get_rsa_private_key(ifstream &pemstr) {

	RSA::PrivateKey pk;
	FileSource fs( pemstr, true );
	CryptoPP::PEM_Load(fs,pk);

	return pk;

}

ENC_BUFFER titor::shinfi::rsa_encrypt_key(ENC_BUFFER key, RSA::PrivateKey pkey) {

	RSAES<PKCS1v15>::Encryptor enc(pkey);
	AutoSeededRandomPool asrn;

	string encoded_key;

	try {
		Base64Encoder *b64enc = new Base64Encoder(new StringSink(encoded_key),false);
		PK_EncryptorFilter* stf = new PK_EncryptorFilter(asrn,enc, b64enc);
		StringSource ssl( key, true, stf );

	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	return encoded_key;

}

ENC_BUFFER titor::shinfi::rsa_decrypt_key(ENC_BUFFER key, RSA::PrivateKey pkey) {

	RSAES<PKCS1v15>::Decryptor dec(pkey);
	AutoSeededRandomPool asrn;
	
	string decoded_key;

	try {
		PK_DecryptorFilter* stf = new PK_DecryptorFilter(asrn,dec, new StringSink(decoded_key));
		Base64Decoder *b64dec = new Base64Decoder(stf);
		StringSource ssl( key, true, b64dec );

	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	return decoded_key;

}

ENC_BUFFER titor::shinfi::pack(titor::AES_FILE_ENC enc_file) {

	stringstream buffer;
	buffer.clear();

	WWE_HEADER hpk;

	string fname = string(RSA_PK_FILENAME); fname.resize(100,'\0');
	copy(fname.begin(),fname.end(),begin(hpk.filename));
	char* size = titor::size_to_chars(enc_file.pkey.length());
	copy(size,size+4,hpk.size);
	delete size;
	for(int i = 0; i < sizeof(hpk.iv); ++i) hpk.iv[i] = 0;

	buffer.write( (char *) &hpk, sizeof(hpk));
	buffer << enc_file.pkey;

	WWE_HEADER hcf;

	fname.clear();
	fname = string(ENCRYPTED_FILE); fname.resize(100,'\0');
	copy(fname.begin(),fname.end(),begin(hcf.filename));
	size = titor::size_to_chars(enc_file.cipher.length());
	copy(size,size+4,hcf.size);
	delete size;
	copy(begin(enc_file.iv),end(enc_file.iv),hcf.iv);

	buffer.write( (char *) &hcf, sizeof(hcf));
	buffer << enc_file.cipher;

	string gzip_file;

	Gzip* compressor = new Gzip( new StringSink(gzip_file) );
	StringSource gzip( buffer.str(), true, compressor );

	return gzip_file;

}

HASH_BUFFER titor::shinfi::generate_hash(ENC_BUFFER efile) {

	string hash;

	SHA512 alg;
	HashFilter* hf = new HashFilter( alg, new HexEncoder( new StringSink(hash), false ) );

	StringSource sha512( efile, true, hf);

	return hash;

}

ENC_BUFFER titor::shinfi::encrypt_final(ENC_BUFFER efile, HASH_BUFFER hash) {

	byte* _hash = compress_hash_to_aes(hash);
	ENC_BUFFER fefile;
	
	byte iv[AES::BLOCKSIZE];
        for( int i = 0; i < AES::BLOCKSIZE; ++i) iv[i] = 0;

	try {

		CBC_Mode<AES>::Encryption enc;
		enc.SetKeyWithIV(_hash, AES_KEY_LENGTH, iv);
		StringSink* ostring = new StringSink(fefile);
		StreamTransformationFilter* stf = new StreamTransformationFilter(enc, ostring);
		StringSource src(efile, true, stf);
		
	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	delete[] _hash;

	return fefile;

}

byte* titor::shinfi::compress_hash_to_aes(HASH_BUFFER hash) {

	byte* rhash = new byte[AES_KEY_LENGTH];

	for( int i = 0; i < AES_KEY_LENGTH; ++i ) rhash[i] = 0;
	for( int i = 0; i < hash.length(); ++i ) rhash[i % AES_KEY_LENGTH] ^= hash[i];

	return rhash;

}

ENC_BUFFER titor::shinfi::decrypt_final(string efile, string hash) {

	string fdfile;
	byte* _hash = compress_hash_to_aes(hash);
	
	byte iv[AES::BLOCKSIZE];
        for( int i = 0; i < AES::BLOCKSIZE; ++i) iv[i] = 0;

	try {
		ifstream f( efile );
	        if(!f.is_open()) throw 2;

		CBC_Mode<AES>::Decryption dec;
		dec.SetKeyWithIV(_hash, AES_KEY_LENGTH, iv);
		StringSink* ostring = new StringSink(fdfile);
		StreamTransformationFilter* stf = new StreamTransformationFilter(dec, ostring);
		FileSource src(f, true, stf);

		f.close();
		
	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	delete[] _hash;

	return fdfile;

}

titor::AES_FILE_ENC titor::shinfi::unpack(ENC_BUFFER packed, string hash ) {

	AES_FILE_ENC result;
	
	string ungz;
	Gunzip* decompressor = new Gunzip( new StringSink(ungz) );
	StringSource gunzip( packed, true, decompressor );

	WWE_HEADER hpk;
	size_t hl = sizeof(hpk);

	size_t offset = 0;
	ungz.copy((char*) &hpk, hl, offset);
	if( string(hpk.filename).compare(0,sizeof(RSA_PK_FILENAME),RSA_PK_FILENAME) ) throw 3;

	size_t fsize = titor::chars_to_size(hpk.size);
	result.pkey = ungz.substr(offset+hl,fsize);
	
	offset += hl + fsize;
	ungz.copy((char*) &hpk, hl, offset);

	fsize = titor::chars_to_size(hpk.size);
	result.cipher = ungz.substr(offset+hl,fsize);

	string ghash = generate_hash(result.cipher);
	if( ghash != hash ) throw 4;

	copy(begin(hpk.iv),end(hpk.iv),begin(result.iv));

	return result;

}

string titor::shinfi::decrypt(titor::AES_FILE_ENC unpacked) {

	// Open PEM file used for encrypt private keyword.
	
	ifstream pfile( pem );
	if( !pfile.is_open() ) throw 5;
	RSA::PrivateKey rsa_pkey = get_rsa_private_key(pfile);
	pfile.close();

	unpacked.pkey = rsa_decrypt_key(unpacked.pkey, rsa_pkey);
	
	string decrypted_file;

	// Decrypts orginal file.
	
	try {

		CBC_Mode<AES>::Decryption dec;
		dec.SetKeyWithIV( (byte*) unpacked.pkey.c_str(),unpacked.pkey.length(), unpacked.iv);
		StringSink* ostring = new StringSink(decrypted_file);
		StreamTransformationFilter* stf = new StreamTransformationFilter(dec, ostring);
		StringSource src(unpacked.cipher, true, stf);
		
	} catch (CryptoPP::Exception &e) {
		cerr << e.what() << endl;
	}

	return decrypted_file;

}
