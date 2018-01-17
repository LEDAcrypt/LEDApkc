/**
 *
 * @version 1.0 (September 2017)
 *
 * Reference ISO-C99 Implementation of LEDApkc cipher" using GCC built-ins.
 *
 * In alphabetical order:
 *
 * @author Marco Baldi <m.baldi@univpm.it>
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Franco Chiaraluce <f.chiaraluce@univpm.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Paolo Santini <p.santini@pm.univpm.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#include "mceliece_cca2_encrypt.h"
#include "gf2x_limbs.h"
#include "rng.h"
#include "sha3.h"

#include "constant_weight_codec.h"

#include <string.h>  // memset(...), memcpy(...)
#include <assert.h>
#include <stdio.h>

/*----------------------------------------------------------------------------*/
// It requires that the input bytestream S
// has the padding bits on the left
// It requires that the input bytestream has the padding bits on the left
static
int bytestream_into_poly_seq(DIGIT polySeq[], int numPoly,
                             const unsigned char *const S,
                             const unsigned long byteLenS
                            )
{

   if ( numPoly <= 0 || byteLenS <= 0 || byteLenS <  ( (numPoly*P +7) /8) )
      return 0;

   unsigned int slack_bits = byteLenS*8 - numPoly*P;
   unsigned int bitCursor = slack_bits;
   uint64_t buffer=0;
   for (unsigned polyIdx = 0; polyIdx < numPoly; polyIdx++) {
      for (unsigned exponent = 0; exponent < P; exponent++) {
         buffer = bitstream_read(S, 1, &bitCursor);
         gf2x_set_coeff(&polySeq[NUM_DIGITS_GF2X_ELEMENT*polyIdx],
                        exponent,
                        buffer
                       );
      }
   }

   return 1;
} // end bytestream_into_poly_seq

/*----------------------------------------------------------------------------*/

static
void encrypt_McEliece(DIGIT codeword[],           // N0   polynomials
                      const publicKeyMcEliece_t *const pk,
                      const DIGIT ptx[],          // N0-1 polynomials
                      const DIGIT err[])          // N0   polynomials
{
   memcpy(codeword, ptx, (N0-1)*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);
   memset(codeword+(N0-1)*NUM_DIGITS_GF2X_ELEMENT,
          0x00,
          NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);

   DIGIT saux[NUM_DIGITS_GF2X_ELEMENT];

   for (int i = 0; i < N0-1; i++) {
      memset(saux,0x00,NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);
      gf2x_mod_mul(saux,
                   pk->Mtr+i*NUM_DIGITS_GF2X_ELEMENT,
                   ptx+i*NUM_DIGITS_GF2X_ELEMENT);
      gf2x_mod_add(codeword+(N0-1)*NUM_DIGITS_GF2X_ELEMENT,
                   codeword+(N0-1)*NUM_DIGITS_GF2X_ELEMENT,
                   saux);
   }
   for (int i = 0; i < N0; i++) {
      gf2x_mod_add(codeword+i*NUM_DIGITS_GF2X_ELEMENT,
                   codeword+i*NUM_DIGITS_GF2X_ELEMENT,
                   err+i*NUM_DIGITS_GF2X_ELEMENT
                  );
   }
} // end encrypt_McEliece

/*----------------------------------------------------------------------------*/

static
void plaintext_constant_pad(const unsigned char *const ptx,
                            const uint32_t bitLenPtx,
                            unsigned char paddedPtx[],
                            const unsigned int paddedPtxLen)
{
   memcpy(paddedPtx+HASH_BYTE_LENGTH, ptx, (bitLenPtx+7)/8);

   if (bitLenPtx % 8 == 0) {
      paddedPtx[HASH_BYTE_LENGTH+(bitLenPtx+7)/8] = 0x80;
   } else {
      unsigned int bitsToClear = (8- bitLenPtx % 8);
      unsigned char mask = ~(((unsigned char) 0x1 << bitsToClear)-1);
      paddedPtx[HASH_BYTE_LENGTH+(bitLenPtx+7)/8-1] &= mask;
      paddedPtx[HASH_BYTE_LENGTH+(bitLenPtx+7)/8-1] |= ( 1<< (bitsToClear -1));
   }
   paddedPtx[paddedPtxLen-1] = paddedPtx[paddedPtxLen-1] |
                               (unsigned char)0x1;
}  // end plaintext_constant_pad

/*----------------------------------------------------------------------------*/

int encrypt_Kobara_Imai(unsigned char *const output,
                        const publicKeyMcEliece_t *const pk,
                        const uint32_t bitLenPtx,
                        const unsigned char *const ptx
                       )
{
   // bit lengths
   // the byte stream is thought in Big-Endian order
   // i.e., ptx[0] may store the most significant bits as padding 0s
   unsigned int be  = CONSTANT_WEIGHT_ENCODED_DATA_ACTUAL_BIT_LENGTH;

   if (bitLenPtx > KOBARA_IMAI_MAX_PTX_BIT_LENGTH) return 0;

   const unsigned int yBufferByteLength = (be+K+7)/8;
   unsigned char yBuffer[yBufferByteLength];

   unsigned char secretSeed[TRNG_BYTE_LENGTH];
   unsigned char prngSequence[(be+K+7)/8-HASH_BYTE_LENGTH];

   DIGIT  informationWord[(N0-1)*NUM_DIGITS_GF2X_ELEMENT];
   DIGIT  cwEncodedError[N0*NUM_DIGITS_GF2X_ELEMENT];

   /* continue drawing fresh randomness in case the constant weight encoding
    * fails */
   int binaryToConstantWeightOk = 0;
   do {
      /* compute random pad */
      randombytes(secretSeed, TRNG_BYTE_LENGTH);
      deterministic_random_byte_generator(prngSequence,      // this is the output
                                          (be+K+7)/8-HASH_BYTE_LENGTH,// outputLen
                                          secretSeed,
                                          TRNG_BYTE_LENGTH
                                         );
      /* pad plaintext */
      memset(yBuffer, 0x00, yBufferByteLength);
      plaintext_constant_pad(ptx, bitLenPtx,yBuffer,yBufferByteLength);


      for (unsigned i = 0; i < (be+K+7)/8-HASH_BYTE_LENGTH; i++)
         yBuffer[HASH_BYTE_LENGTH+i] ^= prngSequence[i];

      HASH_FUNCTION(yBuffer+HASH_BYTE_LENGTH,    // input
                    (be+K+7)/8-HASH_BYTE_LENGTH, // input Length
                    yBuffer                      // output -- 1st part of yBuffer
                   );

      for (unsigned i = 0; i < TRNG_BYTE_LENGTH; i++)
         yBuffer[i] ^= secretSeed[i];

      memset(informationWord, 0x00, (N0-1)*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);

      unsigned int idxMSByteOfPolySequence = yBufferByteLength - (K+7)/8;
      bytestream_into_poly_seq(informationWord,
                               N0-1,
                               yBuffer+idxMSByteOfPolySequence,
                               (K+7)/8);

      memset(cwEncodedError, 0x00, N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);

      binaryToConstantWeightOk = binary_to_constant_weight_approximate(cwEncodedError,
                                 yBuffer,
                                 CONSTANT_WEIGHT_ENCODED_DATA_ACTUAL_BIT_LENGTH
                                                                      );
   } while (binaryToConstantWeightOk == 0);

   DIGIT codeword[N0*NUM_DIGITS_GF2X_ELEMENT] = {0};
   encrypt_McEliece(codeword, pk, informationWord, cwEncodedError);

   // the output byte stream is made of N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B bytes
   memcpy(output, codeword, N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);

   return 1;
} // end encrypt_Kobara_Imai
/*----------------------------------------------------------------------------*/
