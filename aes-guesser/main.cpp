
#include <iostream>
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

int main() {

	unsigned char* buf = reinterpret_cast<unsigned char*>(&buf_static);
	unsigned char key[] = "ImNotGayIJustHaveAPenisFetish:3";
	AES aes(AESKeyLength::AES_256);
	//						      49 6d 4e 6f 74 47 61 79 49 4a 75 73 74 48 61 76 65 41 50 65 6e 69 73 46 65 74 69 73 68 3a 33 00
	std::string wildcarded_key = "49 6d 4e 6f 74 47 61 79 49 4a 75 ?? 74 48 61 76 65 41 50 65 6e 69 73 46 65 ?? 69 73 68 3a 33 00";
	std::cout << GetEntropy(buf, sizeof(buf_static)) << std::endl;
	auto c = aes.EncryptECB(buf, 256, key);
	auto d = aes.DecryptECB(c, 256, key);
	AESGuesser guesser(wildcarded_key, c, 256);
	auto res = guesser.BruteforceKey();
	for (auto& r : res) {
		std::cout << "Possible key: " << hexStr(r.data(), 16);
	}
}