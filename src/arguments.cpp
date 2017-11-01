#include "arguments.hpp"

/*
 *
 * Defined methods for class arguments
 *
 * 
 */

titor::arguments::arguments(size_t len, char** argv) {

	if( len-1 < MINIMUM_ARGUMENTS_LENGTH ) { show_help(); return; }

	for( int i = 0; i < len; ++i) {
		if( !strcmp(argv[i],"-d")) this->mode = DECRYPT;
		if( !strcmp(argv[i],"-f") && i+1 < len && argv[i+1][0] != '-' ) this->file_path = std::string(argv[i+1]);
		if( !strcmp(argv[i],"-p") && i+1 < len && argv[i+1][0] != '-' ) this->pem_path = std::string(argv[i+1]);
		if( !strcmp(argv[i],"-c") && i+1 < len && argv[i+1][0] != '-' ) this->hash_path = std::string(argv[i+1]);

	}

}

void titor::arguments::show_help() {
	std::cout << std::endl << "Usage: titor -f FILEPATH -p RSA_PRIVATE_PEM [-d][-c HASHFILE_PATH]" << std::endl << std::endl;
	std::cout << "Options:" << std::endl << "  General Options:" << std::endl;
	std::cout << "\t-f\t\tPath to file to encrypt." << std::endl;
	std::cout << "\t-p\t\tPath to private PEM file." << std::endl;
	std::cout << "\t-d\t\tDecrypt mode." << std::endl;
	std::cout << "\t-c\t\tPath to file that contains validator hash (FILAPATH + '.sha512' by default)." << std::endl;
	std::cout << std::endl;
}

titor::arguments::MODE titor::arguments::get_mode() {
	return this->mode;
}

std::string titor::arguments::get_file() {
	if(this->file_path.length() > 0) return this->file_path;
	else throw 1;
}

std::string titor::arguments::get_pem() {
	if(this->pem_path.length() > 0) return this->pem_path;
	else throw 2;
}

std::string titor::arguments::get_hash() {
	if(this->hash_path.length() > 0) return this->hash_path;
	else return get_file() + ".sha512";
}
