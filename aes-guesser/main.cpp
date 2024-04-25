
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include "wildcard-guesser.h"
#include "entropy.h"
#include "AES.h"
char buf_static[] = "Rounding up, we get 2 bits/per symbol. To represent a ten character string AAAAABBCDE would require 20 bits if the string were encoded optimally. Such an optimal encoding would allocate fewer bits for the frequency occuring symbols (e.g., A and B) and lon"; \
constexpr double entropy_threshold = 6.0;

std::string hexStr(const uint8_t* data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";

	return ss.str();
}

int main_demo() {

	unsigned char* buf = reinterpret_cast<unsigned char*>(&buf_static);
	unsigned char key[] = "ImNotGayIJustHaveAPenisFetish:33";
	AES aes(AESKeyLength::AES_256);
	//						      49 6d 4e 6f 74 47 61 79 49 4a 75 73 74 48 61 76 65 41 50 65 6e 69 73 46 65 74 69 73 68 3a 33 33
	std::string wildcarded_key = "49 6d 4e 6f 74 47 61 79 49 4a 75 73 74 48 61 76 65 41 50 65 6e 69 73 46 65 ?? 69 73 68 3a 33 33";
	auto c = aes.EncryptECB(buf, 256, key);
	AESGuesser guesser(wildcarded_key, c, 256);
	auto res = guesser.BruteforceKey();
	for (auto& r : res) {
		std::cout << "Possible key: " << hexStr(r.data(), 16);
	}
}

int main(int argc, char** argv) {
	if (argc == 1)
	{
		std::cout << "how 2 use: \n";
		std::cout << "./aes-guesser <path 2 encrypted shit> <wildcarded key> <entropy threshold(optional, default = 6.00)>\n";
		std::cout << "./aes-guesser demo\n";
		main_demo();
		return 0;
	}
	if (argc == 2) {
		main_demo();
		return 0; 
	}
	if (argc == 3 || argc == 4) {
		double entropy_max = 6.0;
		if (argc == 4) {
			entropy_max = std::stod(argv[3]);
		}
		AES aes(AESKeyLength::AES_256);
		std::string fname = argv[1];
		std::string wildcarded_key(argv[2]);
		std::ifstream ifs(fname, std::ifstream::ate | std::ifstream::binary);
		size_t buf_len = ifs.tellg();
		ifs.seekg(0);
		unsigned char* buf = new unsigned char[buf_len];
		ifs.read((char*)buf, buf_len);
		ifs.close();
		AESGuesser guesser(wildcarded_key, buf, buf_len);
		auto res = guesser.BruteforceKey(entropy_max);
		_wmkdir(L"./results");
		for (auto& r : res) {
			std::cout << "Possible key: " << hexStr(r.data(), 32) << "\n";
			std::ofstream ofs("./results/" + hexStr(r.data(), 32));
			
			auto d = aes.DecryptECB(buf, buf_len, r.data());
			std::cout << "Entropy: " << GetEntropy(d, buf_len) << "\n";
			ofs.write((const char*)d, buf_len);
			ofs.close();
		}
		if (res.size() == 0) {
			std::cout << "unable to find a key.";
		}
		return 0;
	}
}
