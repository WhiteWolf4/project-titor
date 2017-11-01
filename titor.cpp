#include <iostream>
#include <fstream>
#include "arguments.hpp"
#include "shinfi.hpp"
using namespace std;

int main( int argc, char** argv) {

	titor::arguments args = titor::arguments(argc,argv);
	try {
		titor::shinfi cipher = titor::shinfi(args.get_pem()); 

		if ( args.get_mode() == titor::arguments::ENCRYPT ){
		
			string oname = args.get_file() + ".wwe";

			cout << endl << "\t* Encrypting " << args.get_file() << "...";
			titor::AES_FILE_ENC encrypted = cipher.encrypt(args.get_file());
			cout << " ok!";

			cout << endl << "\t* Packaging file...";
			ENC_BUFFER gz_file = cipher.pack(encrypted);
			cout << " ok!";
			
			cout << endl << "\t* Generating validation hash...";
			HASH_BUFFER hash = cipher.generate_hash(encrypted.cipher);
			cout << " ok!";

			cout << endl << "\t* Re-encrypting final file...";
			ENC_BUFFER final_file = cipher.encrypt_final( gz_file, hash );
			cout << " ok!";

			cout << endl << "\t* Writing validation in " << oname << ".sha512 file...";

			ofstream hof( oname+".sha512", ios_base::out );
			if(!hof.is_open()) throw 5;
			hof << hash;
			hof.close();

			cout << " ok!";

			cout << endl << "\t* Writing encrypted in " << oname << " file...";

			ofstream of( oname, ios_base::out );
			if(!of.is_open()) throw 5;
			of << final_file;
			of.close();

			cout << " ok!";

		}
		else {

			string oname = args.get_file().substr(0, args.get_file().find_last_of('.'));
			string hash;
			ifstream hf( args.get_hash() );
			hf >> hash;
			hf.close();

			cout << endl << "\t* Using hash to decrypt file " << args.get_file() << "...";

			ENC_BUFFER buffer = cipher.decrypt_final(args.get_file(), hash);
			cout << " ok!";

			cout << endl << "\t* Validating and UnPackaging file...";
			titor::AES_FILE_ENC upck = cipher.unpack(buffer, hash);
			cout << " ok!";
			
			cout << endl << "\t* Decrypting file...";
			string decrypted = cipher.decrypt(upck);
			cout << " ok!";

			cout << endl << "\t* Storing result in " << oname << " file...";
			ofstream of( oname, ios_base::out );
			if(!of.is_open()) throw 6;
			of << decrypted;
			of.close();
			cout << " ok!";

		}
	}
	catch (int code) {
		cout << "error" << endl <<  "Error code " << code << " in execution." << endl;
	}

	cout << endl << endl;

}
