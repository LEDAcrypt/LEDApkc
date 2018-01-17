/**
 *
 * <mceliece.h>
 *
 * @version 1.0 (September 2017)
 *
 * Reference ISO-C99 Implementation of LEDAkem cipher" using GCC built-ins.
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

#pragma once
#include "constant_weight_codec.h"

/*----------------------------------------------------------------------------*/

// Kobara-Imai constant must be a bit sequence  with format: 10^*1
#define KOBARA_IMAI_DOMAIN_SEPARATION_CONSTANT_MIN_BIT_LENGTH (2)

#define KOBARA_IMAI_MAX_PTX_BIT_LENGTH (                    \
        (N0-1)*P                                            \
        + CONSTANT_WEIGHT_ENCODED_DATA_ACTUAL_BIT_LENGTH    \
        - HASH_BIT_LENGTH                                   \
        - KOBARA_IMAI_DOMAIN_SEPARATION_CONSTANT_MIN_BIT_LENGTH )


/* Maximum size in bytes of the message encrypted via KI-g McEliece */
#define KOBARA_IMAI_MAX_PTX_BYTE_LENGTH ((KOBARA_IMAI_MAX_PTX_BIT_LENGTH+7)/8)

/*----------------------------------------------------------------------------*/

typedef struct {
   unsigned char prng_seed[TRNG_BYTE_LENGTH];
   // stored seed of the PRNG as obtained from the TRNG in key generation phase
} privateKeyMcEliece_t;

typedef struct {
   DIGIT Mtr[(N0-1)*NUM_DIGITS_GF2X_ELEMENT];
   // Compact representation of the dense matrix M = Ln0inv*L,
   // including (N0-1) circulant blocks.
} publicKeyMcEliece_t;

/*----------------------------------------------------------------------------*/
