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

#include "mceliece_cca2_decrypt.h"
#include "H_Q_matrices_generation.h"
#include "gf2x_arith_mod_xPplusOne.h"
#include "bf_decoding.h"
#include "sha3.h"
#include "rng.h"
#include "constant_weight_codec.h"

#include <string.h> // memset(...), memcpy(....)
#include <assert.h>


/*----------------------------------------------------------------------------*/
static
int remove_padding_constant( unsigned char *const output,
                             unsigned int *const byteOutputLength,
                             unsigned char padded_text[],
                             const unsigned int padded_text_len)
{
   // begin of the recognition of the Constant == 10^*1
   /*  detect last one */
   if ( (padded_text[padded_text_len-1] & 1) == 0x01) {
      /* remove the trailing bit of the constant */
      padded_text[padded_text_len-1] &= 0xFE;
   } else {
      return 0; // the LSB is not 1, this is an encoding failure
   }
   /* find, starting from the last byte , the first nonzero one */
   int lastByteIdx = padded_text_len-1;
   for ( ; padded_text[lastByteIdx] == 0 &&
         lastByteIdx >= 0; lastByteIdx--);

   if (lastByteIdx < 0 ) {
      return 0; /*the first one is not present, encoding failure */
   }
   /* clear the remaining one */
   unsigned char clearMask = 1;
   unsigned char ptxBuf = padded_text[lastByteIdx];

   while ((ptxBuf & 0x01) == 0 ) {
      ptxBuf = ptxBuf >> 1;
      clearMask = clearMask << 1;
   }
   padded_text[lastByteIdx] &= ~clearMask;
   // end  of the recognition of the Constant == 10^*1
   if (clearMask == 0x80) {
      *byteOutputLength = lastByteIdx;
   } else {
      *byteOutputLength = lastByteIdx+1;
   }
   memcpy(output, padded_text, *byteOutputLength);
   return 1;
}
/*----------------------------------------------------------------------------*/

static
int decrypt_McEliece (DIGIT decoded_err[],
                      DIGIT correct_codeword[],
                      AES_XOF_struct *mceliece_keys_expander,
                      const unsigned char *const ctx)
{

   /* rebuild secret key values */

   POSITION_T HtrPosOnes[N0][DV];
   POSITION_T HPosOnes[N0][DV];
   generateHtrPosOnes(HtrPosOnes, HPosOnes, mceliece_keys_expander);

   POSITION_T QPosOnes[N0][M];
   generateQsparse(QPosOnes,mceliece_keys_expander);

   POSITION_T LPosOnes[N0][DV*M];
   for (int i = 0; i < N0; i++) {
      for (int j = 0; j< DV*M; j++) {
         LPosOnes[i][j]=INVALID_POS_VALUE;
      }
   }

   POSITION_T auxPosOnes[DV*M];
   unsigned char processedQOnes[N0] = {0};
   for (int colQ = 0; colQ < N0; colQ++) {
      for (int i = 0; i < N0; i++) {
         gf2x_mod_mul_sparse(DV*M, auxPosOnes,
                             DV, HPosOnes[i],
                             qBlockWeights[i][colQ], QPosOnes[i]+processedQOnes[i]);
         gf2x_mod_add_sparse(DV*M, LPosOnes[colQ],
                             DV*M, LPosOnes[colQ],
                             DV*M, auxPosOnes);
         processedQOnes[i] += qBlockWeights[i][colQ];
      }
   }
   /* end rebuild secret key values */

   DIGIT codewordPoly[N0*NUM_DIGITS_GF2X_ELEMENT];
   memcpy(codewordPoly, ctx, N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);
   for (unsigned i = 0; i < N0; i++) {
      gf2x_transpose_in_place(codewordPoly+i*NUM_DIGITS_GF2X_ELEMENT);
   }

   DIGIT privateSyndrome[NUM_DIGITS_GF2X_ELEMENT]; // privateSyndrome := yVar* Htr
   memset(privateSyndrome, 0x00, NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);

   DIGIT aux[NUM_DIGITS_GF2X_ELEMENT];
   for(int i = 0; i < N0; i++) {
      gf2x_mod_mul_dense_to_sparse(aux,
                                   codewordPoly+i*NUM_DIGITS_GF2X_ELEMENT,
                                   LPosOnes[i],
                                   DV*M);
      gf2x_mod_add(privateSyndrome, privateSyndrome, aux);
   } // end for i
   gf2x_transpose_in_place(privateSyndrome);

   POSITION_T QtrPosOnes[N0][M] = {{0}};
   unsigned transposed_ones_idx[N0] = {0x00};
   for(unsigned source_row_idx=0; source_row_idx < N0 ; source_row_idx++) {
      int currQoneIdx = 0; // position in the column of QtrPosOnes[][...]
      int endQblockIdx = 0;
      for (int blockIdx = 0; blockIdx < N0; blockIdx++) {
         endQblockIdx += qBlockWeights[source_row_idx][blockIdx];
         for (; currQoneIdx < endQblockIdx; currQoneIdx++) {
            QtrPosOnes[blockIdx][transposed_ones_idx[blockIdx]] = (P -
                  QPosOnes[source_row_idx][currQoneIdx]) % P;
            transposed_ones_idx[blockIdx]++;
         }
      }
   }

   memset(decoded_err,0x00, N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B);
   /*perform syndrome decoding to obtain error vector */
   int ok;
   ok = bf_decoding(decoded_err,
                    (const POSITION_T (*)[DV])HtrPosOnes,
                    (const POSITION_T (*)[M])QtrPosOnes,
                    privateSyndrome
                   );

   if ( ok == 0 ) return 0;
   /* correct input codeword */
   for (unsigned i = 0; i < N0; i++) {
      gf2x_mod_add(correct_codeword+i*NUM_DIGITS_GF2X_ELEMENT,
                   (DIGIT *) ctx+i*NUM_DIGITS_GF2X_ELEMENT,
                   decoded_err+i*NUM_DIGITS_GF2X_ELEMENT);
   }
   return 1;
}

/*----------------------------------------------------------------------------*/
static
int poly_seq_into_bytestream(unsigned char output[],
                             const unsigned int byteOutputLength,
                             DIGIT zPoly[],
                             const unsigned int numPoly)
{
   DIGIT bitValue;
   unsigned int output_bit_cursor =  byteOutputLength*8-numPoly*P;

   if (NUM_BITS_GF2X_ELEMENT*numPoly > 8*byteOutputLength) return 0;

   for (int i =  0; i <numPoly; i++) {
      for (unsigned exponent = 0; exponent < NUM_BITS_GF2X_ELEMENT; exponent++) {
         bitValue = gf2x_get_coeff(zPoly+i*NUM_DIGITS_GF2X_ELEMENT, exponent);
         bitstream_write(output, 1, &output_bit_cursor, bitValue );
      } // end for exponent
   } // end for i
   return 1;
} // end poly_seq_into_bytestream

/*----------------------------------------------------------------------------*/

int decrypt_Kobara_Imai(unsigned char *const
                        output,  // maximum ByteLength: KOBARA_IMAI_MAX_PTX_BYTE_LENGTH
                        unsigned int *const byteOutputLength,
                        AES_XOF_struct *mceliece_keys_expander,
                        const unsigned char *const
                        ctx // Fixed ByteLength: N0*NUM_DIGITS_GF2X_ELEMENT*DIGIT_SIZE_B
                       )
{
   DIGIT err[N0*NUM_DIGITS_GF2X_ELEMENT];
   DIGIT correctedCodeword[N0*NUM_DIGITS_GF2X_ELEMENT];
   if (decrypt_McEliece (err, correctedCodeword, mceliece_keys_expander,
                         ctx) == 0 ) {
      return 0;
   }

   const unsigned int be  = CONSTANT_WEIGHT_ENCODED_DATA_ACTUAL_BIT_LENGTH;
   unsigned int  k  = (N0-1)*P;
   unsigned int yBufferByteLength;
   yBufferByteLength = (CONSTANT_WEIGHT_ENCODED_DATA_ACTUAL_BIT_LENGTH+
                        (N0-1)*P+7)/8;
   unsigned char yBuffer[yBufferByteLength];
   memset(yBuffer, 0x00, yBufferByteLength);
   constant_weight_to_binary_approximate(yBuffer, err);

   unsigned int idxMSByteOfPolySequence = yBufferByteLength - (k+7)/8;
   int ok = poly_seq_into_bytestream(yBuffer+idxMSByteOfPolySequence,
                                     (k+7)/8,
                                     correctedCodeword,
                                     N0-1);
   if (ok == 0) {
      return 0;
   }

   unsigned char outputHash[HASH_BYTE_LENGTH];
   HASH_FUNCTION(yBuffer+HASH_BYTE_LENGTH,// param.s: input, inputLen, output
                 (be+k+7)/8-HASH_BYTE_LENGTH,
                 outputHash
                );

   // the first HASH_BYTE_LENGTH bytes of yBuffer is the output
   unsigned char secretSeed[TRNG_BYTE_LENGTH];
   for (int i = 0; i < TRNG_BYTE_LENGTH; ++i)
      secretSeed[i] = yBuffer[i] ^ outputHash[i];
   unsigned char prngSequence[(be+k+7)/8-HASH_BYTE_LENGTH];
   deterministic_random_byte_generator(prngSequence,
                                       (be+k+7)/8-HASH_BYTE_LENGTH,     // prngSequence[] is the output
                                       secretSeed, TRNG_BYTE_LENGTH
                                      );

   unsigned char ptxConcatenatedWithConstant[(be+k+7)/8-HASH_BYTE_LENGTH];
   for (int i = 0; i < (be+k+7)/8-HASH_BYTE_LENGTH; ++i)
      ptxConcatenatedWithConstant[i] = yBuffer[HASH_BYTE_LENGTH+i] ^ prngSequence[i];

   const unsigned int ptxCatConstantLen = (be+k+7)/8-HASH_BYTE_LENGTH;
   int removePadOk = remove_padding_constant(output,
                     byteOutputLength,
                     ptxConcatenatedWithConstant,
                     ptxCatConstantLen);
   return removePadOk;
} // end decrypt_Kobara_Imai
