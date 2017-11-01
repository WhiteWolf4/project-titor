#ifndef TITOR_ARGUMENTS_H
#define TITOR_ARGUMENTS_H

#define MINIMUM_ARGUMENTS_LENGTH 3

#include <iostream>
#include <cstring>

namespace titor {

	class arguments {
	
		public:
		
		arguments(size_t, char**);
		static void show_help();

		enum MODE { ENCRYPT, DECRYPT };
		MODE get_mode();
		std::string get_file();
		std::string get_pem();
		std::string get_hash();

		private:

		MODE mode = ENCRYPT;
		std::string file_path;
		std::string pem_path;
		std::string hash_path;
	
	};

}

#endif
