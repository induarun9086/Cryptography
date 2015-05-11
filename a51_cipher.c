/*
 * a51_cipher.c
 *
 *  Created on: 01-May-2015
 *      Author: Indumathi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "a51_cipher.h"

int main(int argc, char* argv[]) {

	char inputFileName[100];
	char outputFileName[100];
	struct A51Cipher a51Cipher;
	FILE* input_file = NULL;
	FILE* output_file = NULL;
	uint32 i;
	uint8 dataBits;
	uint32 file_Length;

	memset(&a51Cipher, 0, sizeof(struct A51Cipher));

	printf("A5/1 Implementation\n");

	printf("Enter the input file name: \n");
	scanf("%s", inputFileName);

	printf("Enter the output file name: \n");
	scanf("%s", outputFileName);

	input_file = fopen(inputFileName, "rb");

	output_file = fopen(outputFileName, "wb");

	if (input_file != NULL) {
		fseek(input_file, 0, SEEK_END);
		file_Length = ftell(input_file);
		fseek(input_file, 0, SEEK_SET);

		//printf("File Length = 0x%x\n", file_Length);

		for (i = 0; i < file_Length; i += dataBits) {

			a51Cipher.sessionKey = 0x5cd11d783ab2f472;
			initA51Cipher(&a51Cipher);
			generateKeyStream(&a51Cipher);

			dataBits = fread(&a51Cipher.dataStream[0], 1,
			A51_CIPHER_KEY_STREAM_ARRAY_LENGTH, input_file);

			encryptDataBits(&a51Cipher, output_file);

		}
	}
	fclose(output_file);
	printf("Completed");
	return 0;
}

void initA51Cipher(struct A51Cipher* pa51Cipher) {
	runLoop(pa51Cipher, pa51Cipher->sessionKey, A51_CIPHER_SESSIONKEY_MASK,
	A51_CIPHER_SESSIONKEY_LENGTH, false, false);
	runLoop(pa51Cipher, pa51Cipher->frameCounter, A51_CIPHER_FRAMECOUNTER_MASK,
	A51_CIPHER_FRAMECOUNTER_LENGTH, false, false);
	pa51Cipher->frameCounter = pa51Cipher->frameCounter + 1;
	runLoop(pa51Cipher, 0, 0, 100, true, false);

}

void generateKeyStream(struct A51Cipher* pa51Cipher) {
	runLoop(pa51Cipher, 0, 0, 228, true, true);

}

void runLoop(struct A51Cipher* pa51Cipher, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength, bool irregularClock,
		bool generateKeyStream) {
	uint32 i;

	for (i = 0; i < keystreamLength; i++) {
		if (!irregularClock) {
			clockRegisterOne(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);
			clockRegisterTwo(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);
			clockRegisterThree(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);

		} else {
			executeIrregularClockBlock(pa51Cipher, i, keyStream, keyStreamMask,
					keystreamLength);
		}

		if (generateKeyStream) {
			uint32 xorSum = 0;
			xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_MSB_MASK)
					>> (A51_CIPHER_LFSR1_LENGTH - 1));
			xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_MSB_MASK)
					>> (A51_CIPHER_LFSR2_LENGTH - 1));
			xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_MSB_MASK)
					>> (A51_CIPHER_LFSR3_LENGTH - 1));

			xorSum = xorSum & ((uint32) 0x00000001);

			pa51Cipher->keyStream[i / 8] = pa51Cipher->keyStream[i / 8]
					| xorSum << (i % 8);

		}

		keyStreamMask = keyStreamMask << 1;

	}

	/*if (generateKeyStream) {
	 for (i = 0; i < A51_CIPHER_KEY_STREAM_ARRAY_LENGTH; i++) {
	 printf("keystream = 0x%x\n", pa51Cipher->keyStream[i]);
	 }

	 }

	 printf("LFSR 1 = 0x%x\n", pa51Cipher->lfsr1);
	 printf("LFSR 2 = 0x%x\n", pa51Cipher->lfsr2);
	 printf("LFSR 3 = 0x%x\n\n", pa51Cipher->lfsr3);*/
}

void executeIrregularClockBlock(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength) {

	uint32 bit1 = pa51Cipher->lfsr1
			& A51_CIPHER_LFSR1_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR1_IRREGULAR_CLOCK_SHIFT;

	uint32 bit2 = pa51Cipher->lfsr2
			& A51_CIPHER_LFSR2_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR2_IRREGULAR_CLOCK_SHIFT;

	uint32 bit3 = pa51Cipher->lfsr3
			& A51_CIPHER_LFSR3_IRREGULAR_CLOCK_MASK
					>> A51_CIPHER_LFSR3_IRREGULAR_CLOCK_SHIFT;

	uint32 sum = bit1 + bit2 + bit3;

	uint32 majority = 0;

	if (sum >= 2) {
		majority = 1;
	}

	/*printf("bit1 = 0x%x\n", bit1);
	 printf("bit2 = 0x%x\n", bit2);
	 printf("bit3 = 0x%x\n\n", bit3);
	 printf("majority Bit is = 0x%x\n\n", majority);*/

	if ((bit1 != 0) == majority) {
		//printf("clock register one \n");
		clockRegisterOne(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
	if ((bit2 != 0) == majority) {
		//printf("clock register two \n");
		clockRegisterTwo(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
	if ((bit3 != 0) == majority) {
		//printf("clock register three \n");
		clockRegisterThree(pa51Cipher, i, keyStream, keyStreamMask,
				keystreamLength);
	}
}

void clockRegisterOne(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength) {
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP0_MASK)
			>> A51_CIPHER_LFSR1_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP1_MASK)
			>> A51_CIPHER_LFSR1_TAP1_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP2_MASK)
			>> A51_CIPHER_LFSR1_TAP2_SHIFT);
	xorSum += ((pa51Cipher->lfsr1 & A51_CIPHER_LFSR1_TAP3_MASK)
			>> A51_CIPHER_LFSR1_TAP3_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 << 1;
	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr1 = pa51Cipher->lfsr1 | xorSum;
}

void clockRegisterTwo(struct A51Cipher* pa51Cipher, uint32 i, uint64 keyStream,
		uint64 keyStreamMask, uint32 keystreamLength) {
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP0_MASK)
			>> A51_CIPHER_LFSR2_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr2 & A51_CIPHER_LFSR2_TAP1_MASK)
			>> A51_CIPHER_LFSR2_TAP1_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 << 1;
	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr2 = pa51Cipher->lfsr2 | xorSum;
}

void clockRegisterThree(struct A51Cipher* pa51Cipher, uint32 i,
		uint64 keyStream, uint64 keyStreamMask, uint32 keystreamLength) {
	uint32 xorSum = 0;
	xorSum += ((keyStream & keyStreamMask) >> i);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP0_MASK)
			>> A51_CIPHER_LFSR3_TAP0_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP1_MASK)
			>> A51_CIPHER_LFSR3_TAP1_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP2_MASK)
			>> A51_CIPHER_LFSR3_TAP2_SHIFT);
	xorSum += ((pa51Cipher->lfsr3 & A51_CIPHER_LFSR3_TAP3_MASK)
			>> A51_CIPHER_LFSR3_TAP3_SHIFT);

	xorSum = xorSum & ((uint32) 0x00000001);

	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 << 1;
	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 & ((uint32) 0xfffffffe);
	pa51Cipher->lfsr3 = pa51Cipher->lfsr3 | xorSum;
}

void encryptDataBits(struct A51Cipher* pa51Cipher, FILE* output_file) {
	uint32 i;
	for (i = 0; i < A51_CIPHER_KEY_STREAM_ARRAY_LENGTH; i++) {
		pa51Cipher->outputStream[i] = pa51Cipher->dataStream[i]
				^ pa51Cipher->keyStream[i];

		/*printf("dataStream[%d]=0x%x\n", i, pa51Cipher->dataStream[i]);
		 printf("keyStream[%d]=0x%x\n", i, pa51Cipher->keyStream[i]);
		 printf("outputStream[%d]=0x%x\n\n", i, pa51Cipher->outputStream[i]);*/

	}

	fwrite(pa51Cipher->outputStream, 1,
	A51_CIPHER_KEY_STREAM_ARRAY_LENGTH, output_file);

}
