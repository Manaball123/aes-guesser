#include "entropy.hpp"
#include "AES.h"
#include <iostream>

char buf_static[] = "Rounding up, we get 2 bits/per symbol. To represent a ten character string AAAAABBCDE would require 20 bits if the string were encoded optimally. Such an optimal encoding would allocate fewer bits for the frequency occuring symbols (e.g., A and B) and lon"; \
constexpr double entropy_threshold = 6.0;
int main() {

	unsigned char* buf = reinterpret_cast<unsigned char*>(&buf_static);
	unsigned char key[] = "ngldudeilikedix";
	AES aes(AESKeyLength::AES_256);
	
	std::cout << GetEntropy(buf, sizeof(buf_static)) << std::endl;
	auto c = aes.EncryptECB(buf, 256, key);
	
	for (int i = 0; i <= 0xff; i++) {
		key[15] = (char)i;
		
		auto d = aes.DecryptECB(c, 256, key);
		double cur_entropy = GetEntropy(d, sizeof(buf_static));
		if (cur_entropy <= entropy_threshold) {
			std::cout << "Key may be: " << key << " as the decrypted data block has entropy that is below the threshold(" << cur_entropy << ")\n";
		}
	}
}