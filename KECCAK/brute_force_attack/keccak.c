/**
 * Based on the implementation by the Keccak Team, namely, Guido Bertoni, Joan Daemen,
 * Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "elephant_200.h"
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <pthread.h>
#include <math.h>



#define maxNrRounds 18
#define nrLanes 25
#define index(x, y) (((x)%5)+5*((y)%5))
int PERMUTATION_ROUNDS;
const BYTE KeccakRoundConstants[maxNrRounds] = {
    0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
    0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

const unsigned int KeccakRhoOffsets[nrLanes] = {
    0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};
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
//
// Function declarations
int check_if_same(unsigned char* computed_hash, unsigned char* msg);
void brute_force();
void increase_value(unsigned char* msg, unsigned long long* msg_length, unsigned long long* counter, unsigned long long init_counter);
void* thread_do(void*);
unsigned char* generate_mystery_value();
unsigned long long power(unsigned long long base, unsigned long long exponent);
void write_to_file(double elapsed_time);


#define ROL8(a, offset) ((offset != 0) ? ((((BYTE)a) << offset) ^ (((BYTE)a) >> (8-offset))) : a)


void theta(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5], D[5];

    for(x=0; x<5; x++) {
        C[x] = 0;
        for(y=0; y<5; y++)
            C[x] ^= A[index(x, y)];
    }
    for(x=0; x<5; x++)
        D[x] = ROL8(C[(x+1)%5], 1) ^ C[(x+4)%5];
    for(x=0; x<5; x++)
        for(y=0; y<5; y++)
            A[index(x, y)] ^= D[x];
}

void rho(BYTE *A)
{
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(x, y)] = ROL8(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}

void pi(BYTE *A)
{
    BYTE tempA[25];

    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            tempA[index(x, y)] = A[index(x, y)];
    for(unsigned int x=0; x<5; x++)
        for(unsigned int y=0; y<5; y++)
            A[index(0*x+1*y, 2*x+3*y)] = tempA[index(x, y)];
}

void chi(BYTE *A)
{
    unsigned int x, y;
    BYTE C[5];

    for(y=0; y<5; y++) {
        for(x=0; x<5; x++)
            C[x] = A[index(x, y)] ^ ((~A[index(x+1, y)]) & A[index(x+2, y)]);
        for(x=0; x<5; x++)
            A[index(x, y)] = C[x];
    }
}

void iota(BYTE *A, unsigned int indexRound)
{
    A[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}

void KeccakP200Round(BYTE *state, unsigned int indexRound)
{
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, indexRound);
}

void permutation(BYTE* state)
{
    for(unsigned int i=0; i<PERMUTATION_ROUNDS; i++)
        KeccakP200Round(state, i);
}


int main(int argc, char *argv[])
{
    if((argc != 4))
	{
		printf("Usage: ./ascon_exe ROUND_NR HASH_LENGTH[bytes] HashIndex[0-9]\n");
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
	msg = calloc(25, sizeof(char));

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
        for(int i = 9; i < 24; i++)
            msg[i] = 0x00;
        msg[24] = 0x01;

        unsigned char* pimg;
	    pimg = calloc(25, sizeof(char));
        memcpy(pimg, msg, 25);
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
