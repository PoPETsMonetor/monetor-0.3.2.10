/**
 * \file mt_crypto.c
 *
 * This module provides a simplified interface for cryptographic operations
 * required from by the moneTor payment scheme. Since the original design of
 * moneTor does the include a fully functional cryptographic suite, the
 * high-level operations all redirect to this module. The intent is that code in
 * this module can eventually be redirected to real cryptographic libraries with
 * minimal change to the otherwise functional moneTor code body.
 *
 * A breakdown of cryptographic topics in this module are as follows. The
 * implemention is a combination of real openssl calls and approximations that
 * are sufficient for simulation purposes. In the case of simulated
 * cryptography, cpu delays are added and messages are appropriately padded to
 * size.
 *
 * - KeyGen (RSA): Openssl; fully functional. Keys are imported and exported as
 *   PEM formatted c-strings
 * - Hash Function: Openssl; fully functional
 * - Random Function: Openssl; fully functional
 * - Message Signing: Openssl; fully functional
 *
 * - Commitment: Simulation; messages are committed using a naive one-step
 *   hashing scheme that is incompatible with the final system requirements
 * - Blind Signatures: Simulation; messages are signed by not really blinded
 * - Zero-Knowledge Proofs: Simulation; no effort whatsoever to implement
 *   outside of the delay
 */

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#include <string.h>
#include <time.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "or.h"
#include "config.h"
#include "mt_crypto.h"

/*************** Crytpographic Simulaed Delays (microsec) ***************/

#define MT_DELAY_COM_COMMIT 0
#define MT_DELAY_COM_DECOMMIT 0
#define MT_DELAY_BSIG_BLIND 0
#define MT_DELAY_BSIG_UNBLIND 0
#define MT_DELAY_BSIG_VERIFY 0

// turn off delay if testing

#define MT_DELAY_ZKP_PROVE_1 8000
#define MT_DELAY_ZKP_VERIFY_1 15000
#define MT_DELAY_ZKP_PROVE_2 100000
#define MT_DELAY_ZKP_VERIFY_2 82000
#define MT_DELAY_ZKP_PROVE_3 100000
#define MT_DELAY_ZKP_VERIFY_3 82000

/******************** Stuff For MoneTorSingleCore Delays ****************/

const unsigned char key[] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static unsigned char text[] = "ransdfs;ldldfhsda;fhsda;lkfsd;lfkhadsf;lhgiug34giu3qhfiqu3qhf3u4g34puh34oupuhg34pouggh324poutth324weopfhwewopvvhm98fgroucgmoiugceoiucgerioucgreioug merwioucgmreicouogh,weiucgb3u,9guh3ccoigucbg,coiehg4oiucgh24ucgh23ciuh3m4cmg0-93ux,powhtqweeo;flxfh,3oiheoifhaerouhe[oifh3w4q8g92rh2dI[GHTQ3[[8RFH24P9UGHQE[0B842THWEPOGTHQ34PGUH34GP98T34HGPOIW;LHALGQ3PU4GHQ489WGHQWEPOIGH34PT9834HTPIQWHFO4oiggh324oih324oipghq;lo;ifo3rohg342oi2gh33;lrgh3;3o2ighigh324;oiggh3oi;fhh32oi4igh34o;igh34oigh234iogh32ugh32ugh342ough34ouugh234uogh324ugh34gou34h2gou2344hgou34hgou32pugb342ough324oiggh34poigh234oigh324opgh342goiherengui3ht93p48y439thg9hg89-3h2g9834hg9384gh34984gh23498gh239uhg34289gh24389-gh32498gh34-98gh239ugh3489gh34g8023h4g9-8432hg9834hg8-342hg3498ghprueher89gh34-8gh324-8gh342g-8342g34g3gdom text23;OIH34POTOUHQ3GUPI34HIUG34HGUPI4W5HGPUERHGPOI45HGIOERGJ4W5POHGIN3P9UGHERPGHW45OGH3ROEIUVSDFFKJGHSADV980745HG9RHGWO4I5THGSIUOBUHWT[T88TH34GP9UEWRHGP9REROBHBEWIUGMC8R7OICIGNUGCEMWROIGM349M4GHEQR,EUG9O3HMG,8G7CORIMGCG,OIMWEUHM,G9PEWRVGW";

static unsigned char enc_out[2][1024];
static AES_KEY enc_key, dec_key;

# define MICROSEC_PER_ENCRYPT 0.108

/************************************************************************/

#define PEM_LINE_SIZE 64

// global parameters for key generation
static int num_bits = 1024;
static const char* exp_str = "65537";

// random byte string used to simulate a "blinder" for bsig operations
static byte* bsig_fake_blinder = (byte*)"1234567812345678123456781234567812345678";

/**
 * Called at system setup to obtain public parameters
 */
int mt_crypt_setup(byte (*pp_out)[MT_SZ_PP]){
  AES_set_encrypt_key(key, 128, &enc_key);
  AES_set_decrypt_key(key, 128, &dec_key);
  AES_encrypt(text, enc_out[0], &enc_key);

  return mt_crypt_rand(MT_SZ_PP, *pp_out);
}

/**
 * Generate a public and private keypair outputted as RSA PEM c-strings. For
 * simulation purposes, keys are simply RSA keys. In the final implementation,
 * it may be necessary for the keys to carry extra information for ZKP scheme
 */
int mt_crypt_keygen(byte (*pp)[MT_SZ_PP], byte (*pk_out)[MT_SZ_PK], byte  (*sk_out)[MT_SZ_SK]){
  (void)pp;

    // generate the rsa struct
    BIGNUM *exponent = BN_new();
    BN_dec2bn(&exponent, exp_str);
    RSA* rsa = RSA_new();
    if(RSA_generate_key_ex(rsa, num_bits, exponent, NULL) != 1)
      return MT_ERROR;

    // write public key
    BIO* bio_pk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSA_PUBKEY(bio_pk, rsa) != 1)
	return MT_ERROR;

    int size_pk = BIO_pending(bio_pk);
    if(size_pk > MT_SZ_SK + 1)
	return MT_ERROR;

    BIO_read(bio_pk, *pk_out, size_pk);
    (*pk_out)[size_pk] = '\0';

    // write private key
    BIO* bio_sk = BIO_new(BIO_s_mem());
    if(PEM_write_bio_RSAPrivateKey(bio_sk, rsa, NULL, NULL, 0, NULL, NULL) != 1)
	return MT_ERROR;

    int size_sk = BIO_pending(bio_sk);
    if(size_pk > MT_SZ_SK + 1)
	return MT_ERROR;

    BIO_read(bio_sk, *sk_out, size_sk);
    (*sk_out)[size_sk] = '\0';

    RSA_free(rsa);
    BIO_free(bio_pk);
    BIO_free(bio_sk);

    return MT_SUCCESS;
}

/**
 * Write the specified number of random bytes to the provided buffer
 */
int mt_crypt_rand(int size, byte* rand_out){
  if(RAND_bytes(rand_out, size) != 1){
    if(RAND_pseudo_bytes(rand_out, size) != 1){
      return MT_ERROR;
    }
  }
  return MT_SUCCESS;
}

/**
 * Hash the provided message and write to the buffer
 */
int mt_crypt_hash(byte* msg, int msg_size, byte (*hash_out)[MT_SZ_HASH]){
  SHA256_CTX context;

  if(SHA256_Init(&context) != 1)
    return MT_ERROR;

  if(SHA256_Update(&context, (unsigned char*)msg, msg_size) != 1)
    return MT_ERROR;

  if(SHA256_Final(*hash_out, &context) != 1)
    return MT_ERROR;

  return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and output a signature
 */
int mt_sig_sign(byte* msg, int msg_size, byte (*sk)[MT_SZ_SK], byte (*sig_out)[MT_SZ_SIG]){

    BIO* bio = BIO_new_mem_buf(sk, strlen((char*)*sk));
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != 0)
	return MT_ERROR;

    uint sig_len;
    if(RSA_sign(NID_sha256, digest, MT_SZ_HASH, *sig_out, &sig_len, rsa) != 1)
	return MT_ERROR;

    if(sig_len != MT_SZ_SIG)
	return MT_ERROR;

    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length, compute the digest, and verify the
 * provided signature
 */
int mt_sig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte   (*sig)[MT_SZ_SIG]){

    BIO* bio = BIO_new_mem_buf(pk, strlen((char*)*pk));
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);

    if(bio == NULL || rsa == NULL)
	return MT_ERROR;

    byte digest[MT_SZ_HASH];
    if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
	return MT_ERROR;

    // signature did not verify
    if(RSA_verify(NID_sha256, digest, MT_SZ_HASH, *sig, MT_SZ_SIG, rsa) != 1)
	return MT_ERROR;

    RSA_free(rsa);
    BIO_free(bio);
    return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length along with some random bytes and compute a
 * commitment. In this simulated environment, the commitment is simply a hash of
 * the message concatenated with the random bytes
 */
int mt_com_commit(byte* msgs, int msg_size, byte (*rand)[MT_SZ_HASH], byte (*com_out)[MT_SZ_COM]){
  byte* concated = tor_malloc(msg_size + MT_SZ_HASH);
  memcpy(concated, msgs, msg_size);
  memcpy(concated + msg_size, *rand, MT_SZ_HASH);

  byte digest[MT_SZ_HASH];
  if(mt_crypt_hash(concated, msg_size + MT_SZ_HASH, &digest) != MT_SUCCESS)
    return MT_ERROR;

  // commitment in the final scheme may be larger than hash; pad the difference
  memcpy(*com_out, digest, MT_SZ_HASH);
  if(mt_crypt_rand(MT_SZ_COM - MT_SZ_HASH, (*com_out) + MT_SZ_HASH) !=  MT_SUCCESS)
    return MT_ERROR;

  mt_micro_sleep(MT_DELAY_COM_COMMIT);
  return MT_SUCCESS;
}

/**
 * Verify the commitment provided for a message of arbitrary length
 */
int mt_com_decommit(byte* msg, int msg_size, byte (*rand)[MT_SZ_HASH], byte  (*com)[MT_SZ_COM]){
  byte com_ver[MT_SZ_COM];
  if(mt_com_commit(msg, msg_size, rand, &com_ver) != MT_SUCCESS)
    return MT_ERROR;
  if(memcmp(com, com_ver, MT_SZ_HASH) != 0)
    return MT_ERROR;

  mt_micro_sleep(MT_DELAY_COM_DECOMMIT);
  return MT_SUCCESS;
}

/**
 * Accept a message of arbitrary length and "blind" it so that it can be signed
 * anonymously. In this simulated version, the blinding is simply an operation
 * with the globally visible bsig_fake_blinder string. The unblinder does
 * nothing and is simply filled with random bytes
 */
int mt_bsig_blind(byte *msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*blinded_out)[MT_SZ_BL],
		  byte(*unblinder_out)[MT_SZ_UBLR]){
  (void)pk;

  byte digest[MT_SZ_HASH];
  if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
    return MT_ERROR;

  for(int i = 0; i < MT_SZ_BL; i++)
    (*blinded_out)[i] = bsig_fake_blinder[i % MT_SZ_HASH] ^ digest[i % MT_SZ_HASH];

  if(mt_crypt_rand(MT_SZ_UBLR, *unblinder_out) != MT_SUCCESS)
    return MT_ERROR;

  mt_micro_sleep(MT_DELAY_BSIG_BLIND);
  return MT_SUCCESS;
}

/**
 * Accept a signature on a blinded message and unblind it so it can be verified
 * later. Since we do not having a real blinding scheme, this simply copies over
 * the "blinded" signature to the "unblinded" buffer.
 */
int mt_bsig_unblind(byte (*pk)[MT_SZ_PK], byte (*blinded_sig)[MT_SZ_SIG], byte (*unblinder)[MT_SZ_UBLR],
		    byte (*unblinded_sig_out)[MT_SZ_SIG]){
  (void)pk;
  (void)unblinder;

  memcpy(*unblinded_sig_out, *blinded_sig, MT_SZ_SIG);
  mt_micro_sleep(MT_DELAY_BSIG_UNBLIND);
  return MT_SUCCESS;
}

/**
 * Verify an unblinded signature on the original message. This is easy for the
 * simulated version since the message simply needs to be put through the fake
 * blinding process to verify with the signature.
 */
int mt_bsig_verify(byte* msg, int msg_size, byte (*pk)[MT_SZ_PK], byte (*unblinded_sig)[MT_SZ_SIG]){

  byte blinded[MT_SZ_BL];

  byte digest[MT_SZ_HASH];
  if(mt_crypt_hash(msg, msg_size, &digest) != MT_SUCCESS)
    return MT_ERROR;

  for(int i = 0; i < MT_SZ_BL; i++)
    blinded[i] = bsig_fake_blinder[i % MT_SZ_HASH] ^ digest[i % MT_SZ_HASH];

  if(mt_sig_verify(blinded, MT_SZ_BL, pk, unblinded_sig) != MT_SUCCESS)
    return MT_ERROR;

  mt_micro_sleep(MT_DELAY_BSIG_VERIFY);
  return MT_SUCCESS;
}

/**
 * Accept some inputs and compute a zero-knowledge proof on some statements
 * about the input. We do not even attempt to implement this in the simulated
 * scheme. Only the bare minimum computations are done so that proofs are not
 * accidently rejected or confused with other proofs in the simulation.
 */
int mt_zkp_prove(mt_zkp_type_t type, byte (*pp)[MT_SZ_PP],
		 byte* public_inputs, int public_size,
		 byte* hidden_inputs, int hidden_size,
		 byte (*zkp_out)[MT_SZ_ZKP]){

  // fake zkp are divided into 4 more or less equal sized chunks (depending on rounding)
  //    - truncated hash of type
  //    - truncated hash of pp
  //    - truncated hash of hidden inputs
  //    - truncated hash of public inputs

  memset(*zkp_out, '\0', MT_SZ_ZKP);

  byte digest1[MT_SZ_HASH];
  byte digest2[MT_SZ_HASH];
  byte digest3[MT_SZ_HASH];
  byte digest4[MT_SZ_HASH];

  int errors = 0;
  errors += mt_crypt_hash((byte*)&type, sizeof(mt_zkp_type_t), &digest1);
  errors += mt_crypt_hash(*pp, MT_SZ_PP, &digest2);
  errors += mt_crypt_hash(public_inputs, public_size, &digest3);
  errors += mt_crypt_hash(hidden_inputs, hidden_size, &digest4);

  if(errors != MT_SUCCESS * 4)
    return MT_ERROR;

  int section_size = MT_SZ_ZKP / 4;
  int copy_size = section_size < MT_SZ_HASH ? section_size : MT_SZ_HASH;

  memcpy(*zkp_out, digest1, copy_size);
  memcpy(*zkp_out + copy_size, digest2, copy_size);
  memcpy(*zkp_out + copy_size * 2, digest3, copy_size);
  memcpy(*zkp_out + copy_size * 3, digest4, copy_size);

  switch(type){
    case MT_ZKP_TYPE_1:
      mt_micro_sleep(MT_DELAY_ZKP_PROVE_1);
      break;
    case MT_ZKP_TYPE_2:
      mt_micro_sleep(MT_DELAY_ZKP_PROVE_2);
      break;
    case MT_ZKP_TYPE_3:
      mt_micro_sleep(MT_DELAY_ZKP_PROVE_3);
      break;
  }

  return MT_SUCCESS;
}

/**
 * Accept some zero-knowledge proof and verify its correctness. In the simulated
 * version, we do a simple sanity check to make sure that the proof was at least
 * likely to be generated on purpose in some other part of the simulation.
 */
int mt_zkp_verify(mt_zkp_type_t type, byte (*pp)[MT_SZ_PP],
		  byte* public_inputs, int public_size,
		  byte (*zkp)[MT_SZ_ZKP]){

  byte zkp_test[MT_SZ_ZKP];
  mt_zkp_prove(type, pp, public_inputs, public_size, NULL, 0, &zkp_test);
  int result = memcmp(zkp, zkp_test, MT_SZ_ZKP / 4 * 3) == 0 ? MT_SUCCESS : MT_ERROR;

  switch(type){
    case MT_ZKP_TYPE_1:
      mt_micro_sleep(MT_DELAY_ZKP_VERIFY_1);
      break;
    case MT_ZKP_TYPE_2:
      mt_micro_sleep(MT_DELAY_ZKP_VERIFY_2);
      break;
    case MT_ZKP_TYPE_3:
      mt_micro_sleep(MT_DELAY_ZKP_VERIFY_3);
      break;
  }

  return result;
}

/**
 * Call system nanosleep() to delay the thread for given the microseconds
 */
MOCK_IMPL(void, mt_micro_sleep, (uint microsecs)){

  if(!get_options()->MoneTorSingleCore){
    struct timespec delay;
    delay.tv_sec = microsecs / 1000000;
    delay.tv_nsec = (microsecs % 1000000) * 1000;
    nanosleep(&delay, NULL);
  }
  else{
    // simulate delay by idling AES_encrypt; should be intercepted by shadow
    for(int i = 0; i < microsecs / MICROSEC_PER_ENCRYPT; i++){
      AES_encrypt(enc_out[i % 2], enc_out[(i + 1) % 2], &enc_key);
    }
  }
}

/**
 * Don't do anything; useful to speed up tests via the mock functionality
 */
void mock_micro_sleep(uint microsecs){
  (void)microsecs;
  return;
}
