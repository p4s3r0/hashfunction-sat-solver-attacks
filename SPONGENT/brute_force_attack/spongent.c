/*
 * Implementation based on the SPONGENT implementation at 
 * https://sites.google.com/site/spongenthash/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elephant_160.h"
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <math.h>

#if		defined(SPONGENT160)
#define nBits		160
#define nSBox		20 // 8 bit
#define nRounds		80 //80
#define lfsrIV	    0x75
#elif   defined(SPONGENT176)
#define nBits		176
#define nSBox		22
#define nRounds		90
#define lfsrIV	    0x45
#else
#define nBits		0
#define nSBox		0
#define nRounds		0
#define lfsrIV	    0
#endif

// Brute-force settings
unsigned long long thread_space_field;
int CRYPTO_BYTES;
// Global variables
unsigned char* hash_to_check;
unsigned char* message;
unsigned char* found_pre_image;
int brute_force_terminate = 0;
unsigned long long INPUT_LENGTH;
unsigned long long THREAD_AMOUNT = 1;

int PERMUTATION_ROUNDS;

// Function declarations
int check_if_same(unsigned char* computed_hash, unsigned char* msg);
void brute_force();
void increase_value(unsigned char* msg, unsigned long long* msg_length, unsigned long long* counter, unsigned long long init_counter);
void* thread_do(void*);
unsigned char* generate_mystery_value();
unsigned long long power(unsigned long long base, unsigned long long exponent);
void write_to_file(double elapsed_time);

#define GET_BIT(x,y) (x >> y) & 0x1

/* Spongent eight bit S-box */
int  sBoxLayer[256] = {
	0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6, 
	0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6, 
	0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6, 
	0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06, 
	0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26, 
	0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16, 
	0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46, 
	0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 
	0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76, 
	0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6, 
	0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 
	0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 
	0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96, 
	0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6, 
	0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 
	0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66 
};

void PrintState(BYTE* state)
{
	for(int i = nSBox-1; i>=0; i--)
		printf("%02X ", state[i]);
	printf("\n");
}

BYTE lCounter(BYTE lfsr)
{
	lfsr = (lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5));
	lfsr &= 0x7f; 
	return lfsr;
}

BYTE retnuoCl(BYTE lfsr)
{
	return ((lfsr & 0x01) <<7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3)
		| ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3)
		| ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7);		
}

int Pi(int i)
{
	if (i != nBits-1)
		return (i*nBits/4)%(nBits-1);
	else
		return nBits-1;
}

void pLayer(BYTE* state)
{
	int	PermutedBitNo;
	BYTE tmp[nSBox], x, y;
	
	for(int i = 0; i < nSBox; i++) tmp[i] = 0;
	
	for(int i = 0; i < nSBox; i++){
		for(int j = 0; j < 8; j++){ 
			x = GET_BIT(state[i],j);
			PermutedBitNo = Pi(8*i+j);
			y = PermutedBitNo/8;
			tmp[y] ^= x << (PermutedBitNo - 8*y);
		}
	}	
	memcpy(state, tmp, nSBox);
}

void permutation(BYTE* state)
{
	BYTE IV = lfsrIV;
	BYTE INV_IV;

	for(int i = 0; i < PERMUTATION_ROUNDS; i++){
		/* Add counter values */
		state[0] ^= IV;
		INV_IV = retnuoCl(IV);
		state[nSBox-1] ^= INV_IV;
		IV	= lCounter(IV);
		/* sBoxLayer layer */
		for(int j = 0; j < nSBox; j++)	
			state[j] =  sBoxLayer[state[j]];
		/* pLayer */
		pLayer(state);
	}
}


int main(int argc, char *argv[])
{
    if((argc != 4))
	{
		printf("Usage: ./spongent_exe ROUND_NR HASH_LENGTH[bytes] HashIndex[0-9]\n");
		return 0;
	}

	INPUT_LENGTH = 64 / 8;
	PERMUTATION_ROUNDS = strtoll(argv[1], NULL, 10);
	CRYPTO_BYTES   = strtoll(argv[2], NULL, 10) / 8;
	int HashIndex = strtoll(argv[3], NULL, 10);

	unsigned long long all_hashes[10] = {0xbea4781f, 0x01010101, 0x189a3b92, 0x71fabd382, 0x4fabe281, 0xf219462e, 0xfeba1267, 0x123f71bc, 0xb2b91842, 0xbb27194a};

    message = malloc(INPUT_LENGTH);
	for(int i = 0; i < INPUT_LENGTH/2; i++)
		message[i] = all_hashes[HashIndex] >> ((3 - i) * 8) & 0xff;
	
	hash_to_check = message;
	brute_force();
	return 0;
}



//---------------------------------------------------------------------------------------
// brute force attack -> thread function
//
void* thread_do(void* arg)
{
	unsigned char* msg;
	msg = calloc(20, sizeof(char));

	unsigned long long counter = (unsigned long long)arg;
	unsigned long long init_counter = (unsigned long long)arg;
	while(!brute_force_terminate && counter <= init_counter + thread_space_field)
	{
		msg[0] = (counter >> (8*0)) & 0xff;
		msg[1] = (counter >> (8*1)) & 0xff;
		msg[2] = (counter >> (8*2)) & 0xff;
		msg[3] = (counter >> (8*3)) & 0xff;
		msg[4] = (counter >> (8*4)) & 0xff;
		msg[5] = (counter >> (8*5)) & 0xff;
		msg[6] = (counter >> (8*6)) & 0xff;
		msg[7] = (counter >> (8*7)) & 0xff;
        msg[8] = 0x80;
        for(int i = 9; i < 20; i++)
            msg[i] = 0x00;
        unsigned char* pimg;
	    pimg = calloc(20, sizeof(char));
        memcpy(pimg, msg, 20);
		permutation(msg);
		if(check_if_same(msg, pimg))
			brute_force_terminate = 1;

		counter += 1;
	}
	free(msg);
	return (void*)"OK";
}

//---------------------------------------------------------------------------------------
// brute force method...
//
void brute_force()
{
	struct timespec BF_time_begin, BF_time_end;
    clock_gettime(CLOCK_REALTIME, &BF_time_begin);
	thread_space_field = (unsigned long long)(ULLONG_MAX / THREAD_AMOUNT);

	pthread_t threads[THREAD_AMOUNT];

	for(unsigned long long i = 0; i < THREAD_AMOUNT; i++)
	{
		pthread_create(&threads[i], NULL, thread_do, (void*)(thread_space_field * i));
	}

	for(unsigned long long i = 0; i < THREAD_AMOUNT; i++)
	{
		pthread_join(threads[i], NULL);
	}
	clock_gettime(CLOCK_REALTIME, &BF_time_end);
    double elapsed = BF_time_end.tv_sec - BF_time_begin.tv_sec + (BF_time_end.tv_nsec - BF_time_begin.tv_nsec)*1e-9;
	write_to_file(elapsed);
}

//---------------------------------------------------------------------------------------
// write result to file
//
void write_to_file(double elapsed_time)
{
	printf("{\n\thash: %d", CRYPTO_BYTES * 8);
	//printf("\n\trnd : %d", ASCON_HASH_ROUNDS);
	printf("\n\tthrd: %lld", THREAD_AMOUNT);
	printf("\n\tprec: 0x");
	for (unsigned long long i = 0; i < CRYPTO_BYTES; i++)
		printf("%02X", hash_to_check[i]);
	printf("\n\tPimg: 0x");
	for (unsigned long long i = 0; i < INPUT_LENGTH; i++)
		printf("%02X", found_pre_image[i]);
    printf("\n\trond: %d", PERMUTATION_ROUNDS);
	printf("\n\ttime: %.3fs\n}\n", elapsed_time);
	fflush(stdout);
}

//---------------------------------------------------------------------------------------
// increases the value of msg in this strange array format
//
void increase_value(unsigned char* msg, unsigned long long* msg_length, unsigned long long* counter, unsigned long long init_counter)
{
	*counter += THREAD_AMOUNT;
	if(*counter > (power(pow(16, 2), *msg_length) - 1))
	{
		*msg_length += 1;
		*counter = init_counter;
	}
	for(int i = 0; i < *msg_length; i++)
	{
		msg[i] = (*counter >> (8*i)) & 0xff;
	}
}


//---------------------------------------------------------------------------------------
// checks if two hashes are equal
//
int check_if_same(unsigned char* computed_hash, unsigned char* msg)
{
	for(unsigned long long i = 0; i < CRYPTO_BYTES; i++)
	{
		if(hash_to_check[i] != computed_hash[i])
			return 0;
	}
	
	found_pre_image = malloc(INPUT_LENGTH * sizeof(char));
	for(unsigned long long i = 0; i < INPUT_LENGTH; i++)
		found_pre_image[i] = msg[i];
	return 1;
}

//---------------------------------------------------------------------------------------
// calculates pow(base, exponent) of big numbers
//
unsigned long long power(unsigned long long base, unsigned long long exponent)
{
	unsigned long long result = 1;
	for(int i = 0; i < exponent; i++)
	{
		result *= base;
	}
	return result;
}
