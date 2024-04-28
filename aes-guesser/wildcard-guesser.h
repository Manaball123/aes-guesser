#pragma once
#include <vector>
#include <string>
#include <exception>
#include "AES.h"
#include "entropy.h"

class AESGuesser {
	std::vector<unsigned char> key;
	size_t key_len;
	size_t buf_len;
	std::vector<size_t> wildcard_poses;
	int iteration = 0;
	int max_iterations;
	AES aes;
	unsigned char* encrypted_buf;
	unsigned char* reserved_dec_buf;


	void InitKey(const std::string& wildcarded_key);

	void ModifyKey(std::vector<unsigned char>& key, int iter) const;
public:
	
	//Note that the string is not the key itself, but rather the byte representation of it(e.g. 00aacc?? would have a size of 4 bytes)
	AESGuesser(const std::string& wildcarded_key, unsigned char* buf, size_t buf_len);

	bool IsKeyPossiblyValid(const std::vector<unsigned char>& key, double entropy_threshold) const;

	std::vector<std::vector<unsigned char>> BruteforceKey(double entropy_threshold = 6.0, int max_iters = -1) const;
	

};