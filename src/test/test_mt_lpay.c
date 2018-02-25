#pragma GCC diagnostic ignored "-Wswitch-enum"
#pragma GCC diagnostic ignored "-Wstack-protector"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "or.h"
#include "config.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_lpay.h"
#include "test.h"

int send_intercept_1;
int send_intercept_2;

static int mock_send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){
  (void)desc;
  (void)type;
  (void)msg;
  (void)size;
  return MT_SUCCESS;
}

static int send_ledger(byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK], mt_desc_t* desc, mt_ntype_t type, void* tkn){

  byte proto_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, proto_id);

  byte* packed_msg;
  int packed_msg_size;

  switch(type){
    case MT_NTYPE_MAC_AUT_MINT:
      packed_msg_size = pack_mac_aut_mint((mac_aut_mint_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_MAC_ANY_TRANS:
      packed_msg_size = pack_mac_any_trans((mac_any_trans_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_SETUP:
      packed_msg_size = pack_chn_end_setup((chn_end_setup_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_SETUP:
      packed_msg_size = pack_chn_int_setup((chn_int_setup_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_REQCLOSE:
      packed_msg_size = pack_chn_int_reqclose((chn_int_reqclose_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_CLOSE:
      packed_msg_size = pack_chn_end_close((chn_end_close_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_CLOSE:
      packed_msg_size = pack_chn_int_close((chn_int_close_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_END_CASHOUT:
      packed_msg_size = pack_chn_end_cashout((chn_end_cashout_t*)tkn, &proto_id, &packed_msg);
      break;
    case MT_NTYPE_CHN_INT_CASHOUT:
      packed_msg_size = pack_chn_int_cashout((chn_int_cashout_t*)tkn, &proto_id, &packed_msg);
      break;
    default:
      packed_msg_size = MT_ERROR;
  }

  if(packed_msg_size == MT_ERROR)
    return MT_ERROR;

  byte* signed_msg;
  int signed_msg_size = mt_create_signed_msg(packed_msg, packed_msg_size, pk, sk, &signed_msg);

  if(signed_msg_size == MT_ERROR){
    tor_free(packed_msg);
    return MT_ERROR;
  }

  int result = mt_lpay_recv(desc, type, signed_msg, signed_msg_size);
  tor_free(packed_msg);
  tor_free(signed_msg);

  return result;
}


static void test_mt_lpay(void *arg)
{
  (void)arg;
  return;
  MOCK(mt_send_message, mock_send_message);
  MOCK(mt_milli_sleep, mock_milli_sleep);

  //----------------------------------- Setup ---------------------------------//

  // setup aut
  byte pp[MT_SZ_PP];
  byte aut_0_pk[MT_SZ_PK];
  byte aut_0_sk[MT_SZ_SK];
  mt_desc_t aut_0_desc;

  byte* pp_temp;
  byte* aut_0_pk_temp;
  byte* aut_0_sk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_AUT_PK_HEX, &aut_0_pk_temp) == MT_SZ_PK);
  tor_assert(mt_hex2bytes(MT_AUT_SK_HEX, &aut_0_sk_temp) == MT_SZ_SK);

  memcpy(pp, pp_temp, MT_SZ_PP);
  memcpy(aut_0_pk, aut_0_pk_temp, MT_SZ_PK);
  memcpy(aut_0_sk, aut_0_sk_temp, MT_SZ_SK);

  free(pp_temp);
  free(aut_0_pk_temp);
  free(aut_0_sk_temp);

  aut_0_desc.id[0] = 1;
  aut_0_desc.party = MT_PARTY_AUT;

  mt_lpay_init();
  mt_payment_public_t public = mt_lpay_get_payment_public();

  // set up end user
  byte end_1_pk[MT_SZ_PK];
  byte end_1_sk[MT_SZ_SK];
  byte end_1_addr[MT_SZ_ADDR];
  mt_desc_t end_1_desc = {.party = MT_PARTY_CLI};
  mt_crypt_keygen(&pp, &end_1_pk, &end_1_sk);
  mt_pk2addr(&end_1_pk, &end_1_addr);
  mt_crypt_rand(sizeof(end_1_desc), (byte*)&end_1_desc);

  // set up intermediary
  byte int_1_pk[MT_SZ_PK];
  byte int_1_sk[MT_SZ_SK];
  byte int_1_addr[MT_SZ_ADDR];
  mt_desc_t int_1_desc = {.party = MT_PARTY_INT};
  mt_crypt_keygen(&pp, &int_1_pk, &int_1_sk);
  mt_pk2addr(&int_1_pk, &int_1_addr);
  mt_crypt_rand(sizeof(int_1_desc), (byte*)&int_1_desc);

  // set up channel
  byte chn_1_addr[MT_SZ_ADDR];
  mt_crypt_rand(MT_SZ_ADDR, chn_1_addr);

  // hash chain for nanopayments
  int n = 1000;
  byte head[MT_SZ_HASH];
  byte hc[n][MT_SZ_HASH];
  mt_crypt_rand(MT_SZ_HASH, head);
  mt_hc_create(n, &head, &hc);
  int k = 58;

  byte aut_0_addr[MT_SZ_ADDR];
  mt_pk2addr(&aut_0_pk, &aut_0_addr);

  //expected
  int exp_aut_0_bal = 0;
  int exp_end_1_bal = 0;
  int exp_int_1_bal = 0;
  int exp_end_1_esc = 0;
  int exp_int_1_esc = 0;

  //---------------------------------- Mint -----------------------------------//

  // Mint First Token
  int mint_val_1 = 1000 * 100;
  int mint_val_2 = 1500 * 100;

  exp_aut_0_bal = mint_val_1 + mint_val_2;

  // mint first token
  mac_aut_mint_t mint_1 = {.value = mint_val_1};
  tt_assert(send_ledger(&aut_0_pk, &aut_0_sk, &aut_0_desc, MT_NTYPE_MAC_AUT_MINT, &mint_1) == MT_SUCCESS);

  // mint second token
  mac_aut_mint_t mint_2 = {.value = mint_val_2};
  tt_assert(send_ledger(&aut_0_pk, &aut_0_sk, &aut_0_desc, MT_NTYPE_MAC_AUT_MINT, &mint_2) == MT_SUCCESS);

  //------------------------------ Transfer -----------------------------------//

  int end_val = 100 * 100;
  int int_val = 1000 * 100;

  exp_end_1_bal += end_val;
  exp_int_1_bal += int_val;
  exp_aut_0_bal -= end_val + int_val;

  // transfer to end user
  mac_any_trans_t end_trans = {.val_from = end_val + public.fee, .val_to = end_val};
  memcpy(end_trans.from, aut_0_addr, MT_SZ_ADDR);
  memcpy(end_trans.to, end_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&aut_0_pk, &aut_0_sk, &aut_0_desc, MT_NTYPE_MAC_ANY_TRANS, &end_trans) == MT_SUCCESS);

  // transfer to intermediary
  mac_any_trans_t int_trans = {.val_from = int_val + public.fee, .val_to = int_val};
  memcpy(int_trans.from, aut_0_addr, MT_SZ_ADDR);
  memcpy(int_trans.to, int_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&aut_0_pk, &aut_0_sk, &aut_0_desc, MT_NTYPE_MAC_ANY_TRANS, &int_trans) == MT_SUCCESS);

  //------------------------------- Post Escrow -------------------------------//

  int end_esc_val = 90 * 100;
  int int_esc_val = 900 * 100;

  exp_end_1_esc += end_esc_val;
  exp_int_1_esc += int_esc_val;
  exp_end_1_bal -= end_esc_val + public.fee;
  exp_int_1_bal -= int_esc_val + public.fee;
  exp_aut_0_bal += public.fee * 2;

  // end user escrow
  chn_end_setup_t end_esc = {.val_from = end_esc_val + public.fee, .val_to =   end_esc_val};
  memcpy(end_esc.from, end_1_addr, MT_SZ_ADDR);
  memcpy(end_esc.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_SETUP, &end_esc) == MT_SUCCESS);

  // intermediary escrow
  chn_int_setup_t int_esc = {.val_from = int_esc_val + public.fee, .val_to = int_esc_val};
  memcpy(int_esc.from, int_1_addr, MT_SZ_ADDR);
  memcpy(int_esc.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_SETUP, &int_esc) == MT_SUCCESS);

  //------------------------ Intermediary Request Close -----------------------//

  chn_int_reqclose_t int_reqclose;
  memcpy(int_reqclose.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_REQCLOSE, &int_reqclose) == MT_SUCCESS);


  //------------------------------ End User Close -----------------------------//

  chn_end_close_t end_close = {.last_pay_num = k};
  memcpy(end_close.chn, chn_1_addr, MT_SZ_ADDR);
  memcpy(end_close.last_hash, hc[k], MT_SZ_HASH);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_CLOSE, &end_close) == MT_SUCCESS);

  //---------------------------- Intermediary Close ---------------------------//

  chn_int_close_t int_close = {.close_code = MT_CODE_ACCEPT, .last_pay_num = k};
  memcpy(int_close.chn, chn_1_addr, MT_SZ_ADDR);
  memcpy(int_close.last_hash, hc[k], MT_SZ_HASH);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_CLOSE, &int_close) == MT_SUCCESS);

  //-------------------------------- Cash Out ---------------------------------//

  int end_cashout_val = 50 * 100;
  int int_cashout_val = 50 * 100;

  exp_end_1_bal += end_cashout_val;
  exp_int_1_bal += int_cashout_val;
  exp_end_1_esc -= end_cashout_val + public.fee;
  exp_int_1_esc -= (int)((double)int_cashout_val + (double)public.fee + int_cashout_val * public.tax);
  exp_aut_0_bal += (int)((double)public.fee * 2 + int_cashout_val * public.tax);

  // end user cash out
  chn_end_cashout_t end_cashout = {.val_from = end_cashout_val + public.fee, .val_to = end_cashout_val};
  memcpy(end_cashout.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&end_1_pk, &end_1_sk, &end_1_desc, MT_NTYPE_CHN_END_CASHOUT, &end_cashout) == MT_SUCCESS);


  // intermediary cash out
  chn_int_cashout_t int_cashout;
  int_cashout.val_from = (int)((double)int_cashout_val + (double)public.fee + (int_cashout_val * public.tax));
  int_cashout.val_to = int_cashout_val;
  memcpy(int_cashout.chn, chn_1_addr, MT_SZ_ADDR);
  tt_assert(send_ledger(&int_1_pk, &int_1_sk, &int_1_desc, MT_NTYPE_CHN_INT_CASHOUT, &int_cashout) == MT_SUCCESS);

  //------------------------------- Verify Balances ---------------------------//

  /* tt_assert(mt_lpay_query_mac_balance(&aut_0_addr) == exp_aut_0_bal); */
  /* tt_assert(mt_lpay_query_mac_balance(&end_1_addr) == exp_end_1_bal); */
  /* tt_assert(mt_lpay_query_mac_balance(&int_1_addr) == exp_int_1_bal); */
  /* tt_assert(mt_lpay_query_end_balance(&chn_1_addr) == exp_end_1_esc); */
  /* tt_assert(mt_lpay_query_int_balance(&chn_1_addr) == exp_int_1_esc); */

 done:;
  tt_assert(mt_lpay_clear() == MT_SUCCESS);

  UNMOCK(mt_send_message);
  UNMOCK(mt_milli_sleep);
}

struct testcase_t mt_lpay_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_lpay", test_mt_lpay, 0, NULL, NULL },
  END_OF_TESTCASES
};
