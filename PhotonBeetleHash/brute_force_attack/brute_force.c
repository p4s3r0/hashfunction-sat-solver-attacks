/********************************************************************************
//  
//  				Brute Force Attack on ASCON-hash
//  
********************************************************************************/
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "crypto_hash.h"
#include "api.h"
#include <math.h>
#include <limits.h>
#include <string.h>


//----------------------------------------------------------------------------
// Brute Force Settings
unsigned long long INPUT_LENGTH  = 7;
unsigned long long THREAD_AMOUNT = 1;
unsigned long long thread_space_field;
int CRYPTO_BYTES;
int PERMUTATION_ROUNDS;
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// Function declarations
int check_if_same(unsigned char* computed_hash, unsigned char* msg);
void brute_force();
void increase_value(unsigned char* msg, unsigned long long* msg_length, unsigned long long* counter, unsigned long long init_counter);
void* thread_do(void*);
unsigned char* generate_mystery_value();
unsigned long long power(unsigned long long base, unsigned long long exponent);
void write_to_file(double elapsed_time);
int crypto_hash(
	unsigned char *out,
	const unsigned char *in,
	unsigned long long inlen
);
//----------------------------------------------------------------------------

//----------------------------------------------------------------------------
// Global variables
unsigned char* hash_to_check;
unsigned char* message;
unsigned char* found_pre_image;
int brute_force_terminate = 0;
//----------------------------------------------------------------------------


int main(int argc, char *argv[])
{

	if((argc != 4))
	{
		printf("Usage: ./photon_exe ROUND_NR HASH_LENGTH[bits] HashIndex[0-9]\n");
		return 0;
	}

	INPUT_LENGTH = 64 / 8;
	PERMUTATION_ROUNDS = strtoll(argv[1], NULL, 10);
	CRYPTO_BYTES  = strtoll(argv[2], NULL, 10) / 8;
	int HashIndex = strtoll(argv[3], NULL, 10);


	unsigned long long all_hashes[10] = {0xbea4781f, 0x01010101, 0x189a3b92, 0x71fabd382, 0x4fabe281, 0xf219462e, 0xfeba1267, 0x123f71bc, 0xb2b91842, 0xbb27194a};

	message = malloc(INPUT_LENGTH);
	for(int i = 0; i < INPUT_LENGTH/2; i++)
		message[i] = all_hashes[HashIndex] >> ((3 - i) * 8) & 0xff;
	
	hash_to_check = message;
	brute_force();
	return 0;
}

unsigned char* generate_mystery_value()
{
	srand(time(0));
	unsigned char* mystery_value = malloc(INPUT_LENGTH * sizeof(char));
	for(unsigned long long i = 0; i < INPUT_LENGTH; i++)
	{
		mystery_value[i] = (rand() % 256);
	}
	return mystery_value;
}

//---------------------------------------------------------------------------------------
// brute force attack -> thread function
//
void* thread_do(void* arg)
{
	unsigned char* msg;
	msg = calloc(INPUT_LENGTH, sizeof(char));

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

		unsigned char digest[CRYPTO_BYTES];
		crypto_hash(digest, msg, 8);

		if(check_if_same(digest, msg))
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
	for (unsigned long long i = 0; i < 8; i++)
		printf("%02X", hash_to_check[i]);
	printf("\n\tPimg: 0x");
	for (unsigned long long i = 0; i < 10; i++)
		printf("%02X", found_pre_image[i]);
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
