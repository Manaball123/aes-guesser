#include "wildcard-guesser.h"





void AESGuesser::InitKey(const std::string& wildcarded_key) {
	
	
	key.reserve(key_len);
	std::string wildcarded_key_copy = wildcarded_key;
	//step 1: substitute all chars with 0 and mark poses
	for (unsigned int i = 0; i < key_len * 2; i++) {
		if (wildcarded_key_copy[i] == '?') {
			wildcarded_key_copy[i] = '0';
			wildcard_poses.push_back(i);
		}
	}
	//step2: convert to actual key
	for (unsigned int i = 0; i < key_len; i++) {
		std::string byteString = wildcarded_key_copy.substr(i * 2, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		key.push_back(byte);
	}
}

void AESGuesser::ModifyKey(std::vector<unsigned char>& key, int iter) const {
	unsigned char cur = iter & 0xff;
	int idx = 0;
	//go in 1 char(4 byte) increments until iter = 0

	while (cur != 0 && idx < wildcard_poses.size()) {
		cur = (iter >> (idx * 4)) & 0x0f;
		size_t pos_idx = wildcard_poses[idx];
		key[pos_idx / 2] = (cur << (pos_idx % 2 == 0 ? 4 : 0)) | this->key[pos_idx / 2];
		idx++;
	}

}


//Note that the string is not the key itself, but rather the byte representation of it(e.g. 00aacc?? would have a size of 4 bytes)
AESGuesser::AESGuesser(const std::string& wildcarded_key_unstripped, unsigned char* buf, size_t buf_len) {
	
	std::string wildcarded_key = wildcarded_key_unstripped;
	wildcarded_key.erase(remove_if(wildcarded_key.begin(), wildcarded_key.end(), isspace), wildcarded_key.end());

	key_len = wildcarded_key.size() >> 1;
	this->buf_len = buf_len;
	this->encrypted_buf = buf;
	this->reserved_dec_buf = new unsigned char[buf_len];
	aes = AES(AESKeyLength::AES_256);

	if (key_len != 32)
		throw std::exception("bad key size :(");

	InitKey(wildcarded_key);
	max_iterations = 1 << (wildcard_poses.size() * 4);
}

bool AESGuesser::IsKeyPossiblyValid(const std::vector<unsigned char>& key, double entropy_threshold) const {

	auto d = const_cast<AES&>(aes).DecryptECB(encrypted_buf, buf_len, key.data(), reserved_dec_buf);
	if (GetEntropy(d, buf_len) < entropy_threshold)
		return true;
	return false;
}

std::vector<std::vector<unsigned char>> AESGuesser::BruteforceKey(double entropy_threshold, int max_iters) const {

	if (max_iters == -1 || max_iters > max_iterations)
		max_iters = max_iterations;
	std::vector<std::vector<unsigned char>> results;
	std::vector<unsigned char> temp_key = key;
	for (int i = 0; i < max_iters; i++) {
		ModifyKey(temp_key, i);
		if (IsKeyPossiblyValid(temp_key, entropy_threshold)) {
			std::vector<unsigned char> res_key = temp_key;
			results.push_back(res_key);
		}

	}
	return results;
}