# /**
#  *
#  * @version 1.0 (march 2019)
#  *
#  * Reference ISO-C99 Implementation of LEDApkc cipher" using GCC built-ins.
#  *
#  * In alphabetical order:
#  *
#  * @author Marco Baldi <m.baldi@univpm.it>
#  * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
#  * @author Franco Chiaraluce <f.chiaraluce@univpm.it>
#  * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
#  * @author Paolo Santini <p.santini@pm.univpm.it>
#  * @author Daniel Norte de Moraes <danielcheagle@gmail.com>
#  *
#  * This code is hereby placed in the public domain.
#  *
#  * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
#  * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
#  * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#  * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
#  * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#  *
#  **/

# An working example in python using the shared lib libledapkc_sl5_n04.so.1 .
# adjust it for your actual lib and remenber you can do much more. Enjoy!!

import ctypes

libledapkc = ctypes.CDLL("libledapkc_sl5_n04.so.1")

public_key_type = ctypes.c_ubyte * ctypes.c_ulonglong.in_dll(
    libledapkc, 'crypto_publickeybytes').value
secret_key_type = ctypes.c_ubyte * ctypes.c_ulonglong.in_dll(
    libledapkc, 'crypto_secretkeybytes').value
crypto_bytes_type = ctypes.c_ubyte * ctypes.c_ulonglong.in_dll(
    libledapkc, 'crypto_bytes').value

pub_key = public_key_type()
sec_key = secret_key_type()

ok = libledapkc.crypto_encrypt_keypair(ctypes.byref(pub_key),
                                       ctypes.byref(sec_key))
if ok == 0:
    print("Public_key", pub_key[:], "\n")
    print("Secret_key", sec_key[:], "\n")
else:
    print("Creating keys falied! exiting.")
    exit()

plaintext_tmp = b'This msg will be encrypted'
plaintext_length = ctypes.c_ulonglong(len(plaintext_tmp))
plaintext = (ctypes.c_ubyte * plaintext_length.value).from_buffer_copy(
    plaintext_tmp)
ciphertext = crypto_bytes_type()
ciphertext_length = ctypes.c_ulonglong(0)

ok = libledapkc.crypto_encrypt(ctypes.byref(ciphertext),
                               ctypes.byref(ciphertext_length),
                               ctypes.byref(plaintext),
                               plaintext_length,
                               ctypes.byref(pub_key))
if ok == 0:
    print("Ciphertext", ciphertext[:ciphertext_length.value], "\n")
else:
    print("Creating ciphertext falied! exiting.")
    exit()

# plaintext_decoded = ctypes.create_string_buffer(len(crypto_bytes_type()))
plaintext_decoded = crypto_bytes_type()
plaintext_decoded_length = ctypes.c_ulonglong(0)

ok = libledapkc.crypto_encrypt_open(ctypes.byref(plaintext_decoded),
                                    ctypes.byref(plaintext_decoded_length),
                                    ctypes.byref(ciphertext),
                                    ciphertext_length,
                                    ctypes.byref(sec_key))

if ok == 0:
    print("Plaintext_decoded",
          plaintext_decoded[:plaintext_decoded_length.value], "\n")
    print("Ciphertext and Plaintext_decoded are equal? ")
    print("Yes" if plaintext_decoded[:plaintext_decoded_length.value]
          == plaintext[:] else "No")
else:
    print("Creating ciphertext falied! exiting.")
    exit()

# just for fun
eita = plaintext_decoded[:plaintext_decoded_length.value]
eita2 = (ctypes.c_byte * plaintext_decoded_length.value).from_buffer_copy(
    bytearray(eita))
print(str(eita2, "ascii"))

# p.s.: Enjoy!!!
