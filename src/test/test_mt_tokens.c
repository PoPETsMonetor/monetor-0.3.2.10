#define MT_TEST

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"
#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

static  void write_random_bytes(void* data, int size){
  byte* str = (byte*)data;
  for(int i = 0; i < size; i++){
    str[i] = (byte)rand();
  }
}

static void test_mt_tokens(void *arg)
{
  (void) arg;

  MOCK(mt_micro_sleep, mock_micro_sleep);

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  mt_crypt_setup(&pp);
  mt_crypt_keygen(&pp, &pk, &sk);

  byte proto_id[DIGEST_LEN];
  write_random_bytes(proto_id, DIGEST_LEN);

  /*************************** Sign/Verify Messages ****************************/

  byte* msg = (byte*)"This a random message to be signed";
  byte* signed_msg;

  int signed_msg_size = mt_create_signed_msg(msg, strlen((char*)msg), &pk, &sk, &signed_msg);
  tt_assert(signed_msg_size != MT_ERROR);

  byte pk_out[MT_SZ_PK];
  byte* msg_out;
  int msg_size = mt_verify_signed_msg(signed_msg, signed_msg_size, &pk_out, &msg_out);
  tt_assert(msg_size != MT_ERROR);
  tt_assert(memcmp(pk, pk_out, MT_SZ_PK) == 0);
  tt_assert(memcmp(msg, msg_out, msg_size) == 0);

  free(signed_msg);
  free(msg_out);

  /**************************** Pack/Unpack Tokens *****************************/

  // declare each type of token
  mac_aut_mint_t tk1_mac_aut_mint;
  mac_any_trans_t tk1_mac_any_trans;
  chn_end_setup_t tk1_chn_end_setup;
  chn_int_setup_t tk1_chn_int_setup;
  chn_int_reqclose_t tk1_chn_int_reqclose;
  chn_end_close_t tk1_chn_end_close;
  chn_int_close_t tk1_chn_int_close;
  chn_end_cashout_t tk1_chn_end_cashout;
  chn_int_cashout_t tk1_chn_int_cashout;

  // fill the tokens with random info so we don't get any trivial blank tokens
  write_random_bytes(&tk1_mac_aut_mint, sizeof(mac_aut_mint_t));
  write_random_bytes(&tk1_mac_any_trans, sizeof(mac_any_trans_t));
  write_random_bytes(&tk1_chn_end_setup, sizeof(chn_end_setup_t));
  write_random_bytes(&tk1_chn_int_setup, sizeof(chn_int_setup_t));
  write_random_bytes(&tk1_chn_int_reqclose, sizeof(chn_int_reqclose_t));
  write_random_bytes(&tk1_chn_end_close, sizeof(chn_end_close_t));
  write_random_bytes(&tk1_chn_int_close, sizeof(chn_int_close_t));
  write_random_bytes(&tk1_chn_end_cashout, sizeof(chn_end_cashout_t));
  write_random_bytes(&tk1_chn_int_cashout, sizeof(chn_int_cashout_t));

  // string pointers that will point to the network sendable strings
  byte* str_mac_aut_mint;
  byte* str_mac_any_trans;
  byte* str_chn_end_setup;
  byte* str_chn_int_setup;
  byte* str_chn_int_reqclose;
  byte* str_chn_end_close;
  byte* str_chn_int_close;
  byte* str_chn_end_cashout;
  byte* str_chn_int_cashout;

  // pack the original tokens into the strings
  int size_mac_aut_mint =  pack_mac_aut_mint(&tk1_mac_aut_mint, &proto_id, &str_mac_aut_mint);
  int size_mac_any_trans =  pack_mac_any_trans(&tk1_mac_any_trans, &proto_id, &str_mac_any_trans);
  int size_chn_end_setup =  pack_chn_end_setup(&tk1_chn_end_setup, &proto_id, &str_chn_end_setup);
  int size_chn_int_setup =  pack_chn_int_setup(&tk1_chn_int_setup, &proto_id, &str_chn_int_setup);
  int size_chn_int_reqclose =  pack_chn_int_reqclose(&tk1_chn_int_reqclose, &proto_id, &str_chn_int_reqclose);
  int size_chn_end_close =  pack_chn_end_close(&tk1_chn_end_close, &proto_id, &str_chn_end_close);
  int size_chn_int_close =  pack_chn_int_close(&tk1_chn_int_close, &proto_id, &str_chn_int_close);
  int size_chn_end_cashout =  pack_chn_end_cashout(&tk1_chn_end_cashout, &proto_id, &str_chn_end_cashout);
  int size_chn_int_cashout =  pack_chn_int_cashout(&tk1_chn_int_cashout, &proto_id, &str_chn_int_cashout);

  // declare each type of token
  mac_aut_mint_t tk2_mac_aut_mint;
  mac_any_trans_t tk2_mac_any_trans;
  chn_end_setup_t tk2_chn_end_setup;
  chn_int_setup_t tk2_chn_int_setup;
  chn_int_reqclose_t tk2_chn_int_reqclose;
  chn_end_close_t tk2_chn_end_close;
  chn_int_close_t tk2_chn_int_close;
  chn_end_cashout_t tk2_chn_end_cashout;
  chn_int_cashout_t tk2_chn_int_cashout;

  // extract new tokens from the strings
  unpack_mac_aut_mint(str_mac_aut_mint, size_mac_aut_mint, &tk2_mac_aut_mint, &proto_id);
  unpack_mac_any_trans(str_mac_any_trans, size_mac_any_trans, &tk2_mac_any_trans, &proto_id);
  unpack_chn_end_setup(str_chn_end_setup, size_chn_end_setup, &tk2_chn_end_setup, &proto_id);
  unpack_chn_int_setup(str_chn_int_setup, size_chn_int_setup, &tk2_chn_int_setup, &proto_id);
  unpack_chn_int_reqclose(str_chn_int_reqclose, size_chn_int_reqclose, &tk2_chn_int_reqclose, &proto_id);
  unpack_chn_end_close(str_chn_end_close, size_chn_end_close, &tk2_chn_end_close, &proto_id);
  unpack_chn_int_close(str_chn_int_close, size_chn_int_close, &tk2_chn_int_close, &proto_id);
  unpack_chn_end_cashout(str_chn_end_cashout, size_chn_end_cashout, &tk2_chn_end_cashout, &proto_id);
  unpack_chn_int_cashout(str_chn_int_cashout, size_chn_int_cashout, &tk2_chn_int_cashout, &proto_id);

  // tt_assert that the original tokens are identical to the new torkns
  tt_assert(memcmp(&tk1_mac_aut_mint, &tk2_mac_aut_mint, sizeof(mac_aut_mint_t)) == 0);
  tt_assert(memcmp(&tk1_mac_any_trans, &tk2_mac_any_trans, sizeof(mac_any_trans_t)) == 0);
  tt_assert(memcmp(&tk1_chn_end_setup, &tk2_chn_end_setup, sizeof(chn_end_setup_t)) == 0);
  tt_assert(memcmp(&tk1_chn_int_setup, &tk2_chn_int_setup, sizeof(chn_int_setup_t)) == 0);
  tt_assert(memcmp(&tk1_chn_int_reqclose, &tk2_chn_int_reqclose, sizeof(chn_int_reqclose_t)) == 0);
  tt_assert(memcmp(&tk1_chn_end_close, &tk2_chn_end_close, sizeof(chn_end_close_t)) == 0);
  tt_assert(memcmp(&tk1_chn_int_close, &tk2_chn_int_close, sizeof(chn_int_close_t)) == 0);
  tt_assert(memcmp(&tk1_chn_end_cashout, &tk2_chn_end_cashout, sizeof(chn_end_cashout_t)) == 0);
  tt_assert(memcmp(&tk1_chn_int_cashout, &tk2_chn_int_cashout,   sizeof(chn_int_cashout_t)) == 0);

 done:
  tor_free(str_mac_aut_mint);
  tor_free(str_mac_any_trans);
  tor_free(str_chn_end_setup);
  tor_free(str_chn_int_setup);
  tor_free(str_chn_int_reqclose);
  tor_free(str_chn_end_close);
  tor_free(str_chn_int_close);
  tor_free(str_chn_end_cashout);
  tor_free(str_chn_int_cashout);

  UNMOCK(mt_micro_sleep);
}

struct testcase_t mt_tokens_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_tokens", test_mt_tokens, 0, NULL, NULL },
  END_OF_TESTCASES
};
