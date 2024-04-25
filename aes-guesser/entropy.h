#pragma once
#include <stdlib.h>
#include <cstdlib>
#include <algorithm>

#define BYTE_BLOCK_SIZE 1
constexpr size_t n_symbols = (1 << (BYTE_BLOCK_SIZE * 8));

inline double GetEntropy(const unsigned char* buffer, size_t len) {
	int freqs[n_symbols] = { 0 };
	double probabilities[n_symbols] = { 0 };
	//std::fill(freqs, freqs + 0xff, 0);
	//std::fill(freqs, freqs + 0xff, 0);
	//count frequency
	for (size_t i = 0; i < len; i++) {
		freqs[(unsigned char)buffer[i]]++;
	}
	for (size_t i = 0; i < n_symbols; i++) {
		probabilities[i] = (double)freqs[i] / (double)len;
	}
	double entropy = 0;
	for (double prob : probabilities) {
		if (prob == 0.0)
			continue;
		entropy += prob * log2(prob);
	}
	return -entropy; 

}