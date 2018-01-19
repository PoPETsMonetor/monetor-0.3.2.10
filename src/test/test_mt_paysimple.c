/**
 * \file test_mt_paysimple.c
 * \brief Isolated payment module with single client/relay/intermediary
 *
 * Run unit tests for as much functionality as possible given a single client,
 * relay, and intermediary on the same instance of Tor. Descriptors are stored
 * as static varibales within this module. The moneTor controller interface is
 * mocked to reroute messages, etc to the corresponding local destinatin.
 */

#pragma GCC diagnostic ignored "-Wstack-protector"

#include <stdio.h>
#include <unistd.h>

#include "or.h"
#include "config.h"
#include "workqueue.h"
#include "cpuworker.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_lpay.h"
#include "mt_cpay.h"
#include "mt_rpay.h"
#include "mt_ipay.h"
#include "test.h"

// declared here to be visible for mock_send_message
static mt_desc_t aut_desc;
static mt_desc_t led_desc;
static mt_desc_t cli_desc;
static mt_desc_t rel_desc;
static mt_desc_t int_desc;

// needed so send_message can track where the current message should be coming from
static mt_desc_t src_desc;
static mt_desc_t dst_desc;

/**
 * Pass a payment module call of <b>send_message<\b> to the given local instance
 * of a payment module. The variables <b>dst_desc<\b> and <b>src_desc<\b> are
 * used to track where messages are coming from and going to in order to route
 * messages properly.
 */
static int mock_send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){

  mt_desc_t temp_desc;
  memcpy(&temp_desc, desc, sizeof(mt_desc_t));
  memcpy(&src_desc, &dst_desc, sizeof(mt_desc_t));
  memcpy(&dst_desc, &temp_desc, sizeof(mt_desc_t));

  const char* type_str;
  const char* party_str;

  // assign a string for logging purposes
  switch(type){
    case MT_NTYPE_CHN_END_ESTAB1:
      type_str = "chn_end_estab1";
      break;
    case MT_NTYPE_CHN_INT_ESTAB2:
      type_str = "chn_int_estab2";
      break;
    case MT_NTYPE_CHN_END_ESTAB3:
      type_str = "chn_end_estab3";
      break;
    case MT_NTYPE_CHN_INT_ESTAB4:
      type_str = "chn_int_estab4";
      break;
    case MT_NTYPE_MIC_CLI_PAY1:
      type_str = "mic_cli_pay1";
      break;
    case MT_NTYPE_MIC_REL_PAY2:
      type_str = "mic_rel_pay2";
      break;
    case MT_NTYPE_MIC_CLI_PAY3:
      type_str = "mic_cli_pay3";
      break;
    case MT_NTYPE_MIC_INT_PAY4:
      type_str = "mic_int_pay4";
      break;
    case MT_NTYPE_MIC_CLI_PAY5:
      type_str = "mic_cli_pay5";
      break;
    case MT_NTYPE_MIC_REL_PAY6:
      type_str = "mic_rel_pay6";
      break;
    case MT_NTYPE_MIC_INT_PAY7:
      type_str = "mic_int_pay7";
      break;
    case MT_NTYPE_MIC_INT_PAY8:
      type_str = "mic_int_pay8";
      break;
    case MT_NTYPE_NAN_CLI_SETUP1:
      type_str = "nan_cli_setup1";
      break;
    case MT_NTYPE_NAN_INT_SETUP2:
      type_str = "nan_int_setup2";
      break;
    case MT_NTYPE_NAN_CLI_SETUP3:
      type_str = "nan_cli_setup3";
      break;
    case MT_NTYPE_NAN_INT_SETUP4:
      type_str = "nan_int_setup4";
      break;
    case MT_NTYPE_NAN_CLI_SETUP5:
      type_str = "nan_cli_setup5";
      break;
    case MT_NTYPE_NAN_INT_SETUP6:
      type_str = "nan_int_setup6";
      break;
    case MT_NTYPE_NAN_CLI_DESTAB1:
      type_str = "nan_cli_destab1";
      break;
    case MT_NTYPE_NAN_INT_DESTAB2:
      type_str = "nan_int_destab2";
      break;
    case MT_NTYPE_NAN_CLI_DPAY1:
      type_str = "nan_cli_dpay1";
      break;
    case MT_NTYPE_NAN_INT_DPAY2:
      type_str = "nan_int_dpay2";
      break;
    case MT_NTYPE_NAN_CLI_ESTAB1:
      type_str = "nan_cli_estab1";
      break;
    case MT_NTYPE_NAN_REL_ESTAB2:
      type_str = "nan_rel_estab2";
      break;
    case MT_NTYPE_NAN_INT_ESTAB3:
      type_str = "nan_int_estab3";
      break;
    case MT_NTYPE_NAN_REL_ESTAB4:
      type_str = "nan_rel_estab4";
      break;
    case MT_NTYPE_NAN_INT_ESTAB5:
      type_str = "nan_int_estab5";
      break;
    case MT_NTYPE_NAN_REL_ESTAB6:
      type_str = "nan_rel_estab6";
      break;
    case MT_NTYPE_NAN_CLI_PAY1:
      type_str = "nan_cli_pay1";
      break;
    case MT_NTYPE_NAN_REL_PAY2:
      type_str = "nan_rel_pay2";
      break;
    case MT_NTYPE_NAN_CLI_REQCLOSE1:
      type_str = "nan_cli_reqclose1";
      break;
    case MT_NTYPE_NAN_REL_REQCLOSE2:
      type_str = "nan_rel_reqclose2";
      break;
    case MT_NTYPE_NAN_END_CLOSE1:
      type_str = "nan_end_close1";
      break;
    case MT_NTYPE_NAN_INT_CLOSE2:
      type_str = "nan_int_close2";
      break;
    case MT_NTYPE_NAN_END_CLOSE3:
      type_str = "nan_end_close3";
      break;
    case MT_NTYPE_NAN_INT_CLOSE4:
      type_str = "nan_int_close4";
      break;
    case MT_NTYPE_NAN_END_CLOSE5:
      type_str = "nan_end_close5";
      break;
    case MT_NTYPE_NAN_INT_CLOSE6:
      type_str = "nan_int_close6";
      break;
    case MT_NTYPE_NAN_END_CLOSE7:
      type_str = "nan_end_close7";
      break;
    case MT_NTYPE_NAN_INT_CLOSE8:
      type_str = "nan_int_close8";
      break;
    case MT_NTYPE_MAC_AUT_MINT:
      type_str = "mac_aut_mint";
      break;
    case MT_NTYPE_MAC_ANY_TRANS:
      type_str = "mac_any_trans";
      break;
    case MT_NTYPE_CHN_END_SETUP:
      type_str = "chn_end_setup";
      break;
    case MT_NTYPE_CHN_INT_SETUP:
      type_str = "chn_int_setup";
      break;
    case MT_NTYPE_CHN_INT_REQCLOSE:
      type_str = "chn_int_reqclose";
      break;
    case MT_NTYPE_CHN_END_CLOSE:
      type_str = "chn_end_close";
      break;
    case MT_NTYPE_CHN_INT_CLOSE:
      type_str = "chn_int_close";
      break;
    case MT_NTYPE_CHN_END_CASHOUT:
      type_str = "chn_end_cashout";
      break;
    case MT_NTYPE_CHN_INT_CASHOUT:
      type_str = "chn_int_cashout";
      break;
    case MT_NTYPE_ANY_LED_CONFIRM:
      type_str = "any_led_confirm";
      break;
    case MT_NTYPE_MAC_LED_DATA:
      type_str = "mac_led_data";
      break;
    case MT_NTYPE_CHN_LED_DATA:
      type_str = "chn_led_data";
      break;
    case MT_NTYPE_MAC_LED_QUERY:
      type_str = "mac_led_query";
      break;
    case MT_NTYPE_CHN_LED_QUERY:
      type_str = "chn_led_query";
      break;
  }

  // assign a string for logging purposes
  switch(src_desc.party){
    case MT_PARTY_AUT:
      party_str = "aut";
      break;
    case MT_PARTY_LED:
      party_str = "led";
      break;
    case MT_PARTY_CLI:
      party_str = "cli";
      break;
    case MT_PARTY_REL:
      party_str = "rel";
      break;
    case MT_PARTY_INT:
      party_str = "int";
      break;
  }

  // invoke the corresponding recv call and log
  if(dst_desc.id[0] == aut_desc.id[0] && dst_desc.party == MT_PARTY_AUT){
    printf("%s -> aut : %s\n", party_str, type_str);
    return MT_SUCCESS;
  }

  if(dst_desc.id[0] == led_desc.id[0] && dst_desc.party == MT_PARTY_LED){
    printf("%s -> led : %s\n", party_str, type_str);
    return mt_lpay_recv(&src_desc, type, msg, size);
  }

  if(dst_desc.id[0] == cli_desc.id[0] && dst_desc.party == MT_PARTY_CLI){
    printf("%s -> cli : %s\n", party_str, type_str);
    return mt_cpay_recv(&src_desc, type, msg, size);
  }

  if(dst_desc.id[0] == rel_desc.id[0] && dst_desc.party == MT_PARTY_REL){
    printf("%s -> rel : %s\n", party_str, type_str);
    return mt_rpay_recv(&src_desc, type, msg, size);
  }

  if(dst_desc.id[0] == int_desc.id[0] && dst_desc.party == MT_PARTY_INT){
    printf("%s -> int : %s\n", party_str, type_str);
    return mt_ipay_recv(&src_desc, type, msg, size);
  }

  printf("ERROR: descriptor not recognized\n");
  return MT_ERROR;
}

/**
 * Same as send_message but for the special multidesc function
 */
static int mock_send_message_multidesc(mt_desc_t *desc1, mt_desc_t* desc2, mt_ntype_t type, byte* msg, int size){
  mt_desc_t temp_desc;
  memcpy(&temp_desc, desc1, sizeof(mt_desc_t));
  memcpy(&src_desc, &dst_desc, sizeof(mt_desc_t));
  memcpy(&dst_desc, &temp_desc, sizeof(mt_desc_t));

  if(dst_desc.id[0] == rel_desc.id[0]
     && dst_desc.party == MT_PARTY_REL
     && type == MT_NTYPE_NAN_CLI_ESTAB1){
    printf("cli - >rel : nan_cli_estab1\n");
    return mt_rpay_recv_multidesc(&src_desc, desc2, type, msg, size);
  }

  return MT_ERROR;
}

/**
 * Mock the mt_paymod_signal function
 */
static int mock_paymod_signal(mt_signal_t signal, mt_desc_t* desc){
  (void)desc;

  if(signal == MT_SIGNAL_PAYMENT_RECEIVED){
    int cli_bal = mt_cpay_mac_balance() + mt_cpay_chn_balance();
    int rel_bal = mt_rpay_mac_balance() + mt_rpay_chn_balance();
    int int_bal = mt_ipay_mac_balance() + mt_ipay_chn_balance();

    printf("Balances : cli %d; rel %d; int %d\n", cli_bal, rel_bal, int_bal);
  }
  return MT_SUCCESS;
}

/**
 * Mock a call to the cpu worker. Of course, no multithreading is actually done;
 * the requested function is executed and control is passed serially back to the
 * reply function.
 */
static workqueue_entry_t* mock_cpuworker_queue_work(workqueue_priority_t priority,
						    workqueue_reply_t (*fn)(void*, void*),
						    int (*reply_fn)(void*), void* arg){
  (void)priority;
  threadpool_t* threadpool = NULL;
  if(fn(threadpool, arg) != WQ_RPL_REPLY)
    return NULL;
  if(reply_fn(arg) != MT_SUCCESS)
    return NULL;
  return (workqueue_entry_t*)1;
}

/**
 * Execute paysimple test
 */
static void test_mt_paysimple(void *arg){

  printf("\n\n------------ begin paysimple ------------\n\n");

  (void)arg;

  // The reply_fn in the mocked cpuworker function returns an int for testing
  // convenience. This cast is used to avoid warnings in the MOCK command
  typedef workqueue_entry_t* (*cpuworker_fn)(workqueue_priority_t,
					     workqueue_reply_t (*)(void*, void*),
					     void (*)(void*), void*);
  MOCK(mt_send_message, mock_send_message);
  MOCK(mt_send_message_multidesc, mock_send_message_multidesc);
  MOCK(mt_paymod_signal, mock_paymod_signal);
  MOCK(cpuworker_queue_work, (cpuworker_fn)mock_cpuworker_queue_work);

  /****************************** Setup **********************************/

  // initial balances each party will have

  int mint_val = (MT_CLI_CHN_VAL + MT_REL_CHN_VAL + MT_INT_CHN_VAL) * 20;
  int cli_trans_val = (MT_CLI_CHN_VAL + MT_FEE) * 10;
  int rel_trans_val = (MT_REL_CHN_VAL + MT_FEE) * 10;
  int int_trans_val = (MT_INT_CHN_VAL + MT_FEE) * 10;

  // declare values to save to the disk

  byte pp[MT_SZ_PP];

  byte aut_pk[MT_SZ_PK];
  byte aut_sk[MT_SZ_SK];
  aut_desc.party = MT_PARTY_AUT;

  byte led_pk[MT_SZ_PK];
  byte led_sk[MT_SZ_SK];
  led_desc.party = MT_PARTY_LED;

  byte cli_pk[MT_SZ_PK];
  byte cli_sk[MT_SZ_SK];
  cli_desc.party = MT_PARTY_CLI;

  byte rel_pk[MT_SZ_PK];
  byte rel_sk[MT_SZ_SK];
  rel_desc.party = MT_PARTY_REL;

  byte int_pk[MT_SZ_PK];
  byte int_sk[MT_SZ_SK];
  int_desc.party = MT_PARTY_INT;

  // define values to save to disk

  mt_crypt_setup(&pp);
  mt_crypt_keygen(&pp, &aut_pk, &aut_sk);
  mt_crypt_keygen(&pp, &led_pk, &led_sk);
  mt_crypt_keygen(&pp, &cli_pk, &cli_sk);
  mt_crypt_keygen(&pp, &rel_pk, &rel_sk);
  mt_crypt_keygen(&pp, &int_pk, &int_sk);

  uint32_t ids = 0;
  aut_desc.id[0] = ids++;
  led_desc.id[0] = ids++;
  cli_desc.id[0] = ids++;
  rel_desc.id[0] = ids++;
  int_desc.id[0] = ids++;

  // write values to disk as separate files in the tor/ directory
  // TODO: this should go through torcc instead

  or_options_t* options = (or_options_t*)get_options();

  mt_bytes2hex((byte*)&led_desc.id[0], sizeof(led_desc.id[0]), &options->moneTorLedgerDesc);
  mt_bytes2hex(aut_pk, MT_SZ_PK, &options->moneTorAuthorityPK);
  mt_bytes2hex(pp, MT_SZ_PP, &options->moneTorPP);
  options->moneTorFee = MT_FEE;
  options->moneTorTax = MT_TAX;

  // initiate ledger
  mt_bytes2hex(led_pk, MT_SZ_PK, &options->moneTorPK);
  mt_bytes2hex(led_sk, MT_SZ_SK, &options->moneTorSK);
  tt_assert(mt_lpay_init() == MT_SUCCESS);

  mt_bytes2hex(cli_pk, MT_SZ_PK, &options->moneTorPK);
  mt_bytes2hex(cli_sk, MT_SZ_SK, &options->moneTorSK);
  options->moneTorBalance = cli_trans_val;
  tt_assert(mt_cpay_init() == MT_SUCCESS);

  mt_bytes2hex(rel_pk, MT_SZ_PK, &options->moneTorPK);
  mt_bytes2hex(rel_sk, MT_SZ_SK, &options->moneTorSK);
  options->moneTorBalance = rel_trans_val;
  tt_assert(mt_rpay_init() == MT_SUCCESS);

  mt_bytes2hex(int_pk, MT_SZ_PK, &options->moneTorPK);
  mt_bytes2hex(int_sk, MT_SZ_SK, &options->moneTorSK);
  options->moneTorBalance = int_trans_val;
  tt_assert(mt_ipay_init() == MT_SUCCESS);

  // decalre and define addresses for ledger interaction
  byte aut_addr[MT_SZ_ADDR];
  byte led_addr[MT_SZ_ADDR];
  byte cli_addr[MT_SZ_ADDR];
  byte rel_addr[MT_SZ_ADDR];
  byte int_addr[MT_SZ_ADDR];

  mt_pk2addr(&aut_pk, &aut_addr);
  mt_pk2addr(&led_pk, &led_addr);
  mt_pk2addr(&cli_pk, &cli_addr);
  mt_pk2addr(&rel_pk, &rel_addr);
  mt_pk2addr(&int_pk, &int_addr);

  int result; // generic variable to track function call success/failure

  // authority mints money

  mac_aut_mint_t mint = {.value = mint_val};
  byte mint_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, mint_id);

  byte* packed_mint;
  byte* signed_mint;
  int packed_mint_size = pack_mac_aut_mint(&mint, &mint_id, &packed_mint);
  int signed_mint_size = mt_create_signed_msg(packed_mint, packed_mint_size,
					      &aut_pk, &aut_sk, &signed_mint);

  memcpy(&dst_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_AUT_MINT, signed_mint, signed_mint_size);
  tt_assert(result == MT_SUCCESS);

  // send money from authority to client

  mac_any_trans_t cli_trans = {.val_to = cli_trans_val, .val_from = cli_trans_val + MT_FEE};
  memcpy(cli_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(cli_trans.to, cli_addr, MT_SZ_ADDR);
  byte cli_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, cli_trans_id);

  byte* packed_cli_trans;
  byte* signed_cli_trans;
  int packed_cli_trans_size = pack_mac_any_trans(&cli_trans, &cli_trans_id, &packed_cli_trans);
  int signed_cli_trans_size = mt_create_signed_msg(packed_cli_trans, packed_cli_trans_size,
						   &aut_pk, &aut_sk, &signed_cli_trans);
  memcpy(&dst_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_cli_trans, signed_cli_trans_size);
  tt_assert(result == MT_SUCCESS);

  // send money from authority to relay

  mac_any_trans_t rel_trans = {.val_to = rel_trans_val, .val_from = rel_trans_val + MT_FEE};
  memcpy(rel_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(rel_trans.to, rel_addr, MT_SZ_ADDR);
  byte rel_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, rel_trans_id);

  byte* packed_rel_trans;
  byte* signed_rel_trans;
  int packed_rel_trans_size = pack_mac_any_trans(&rel_trans, &rel_trans_id, &packed_rel_trans);
  int signed_rel_trans_size = mt_create_signed_msg(packed_rel_trans, packed_rel_trans_size,
						   &aut_pk, &aut_sk, &signed_rel_trans);
  memcpy(&dst_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_rel_trans, signed_rel_trans_size);
  tt_assert(result == MT_SUCCESS);

  // send money from authority to intermediary

  mac_any_trans_t int_trans = {.val_to = int_trans_val, .val_from = int_trans_val + MT_FEE};
  memcpy(int_trans.from, aut_addr, MT_SZ_ADDR);
  memcpy(int_trans.to, int_addr, MT_SZ_ADDR);
  byte int_trans_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, int_trans_id);

  byte* packed_int_trans;
  byte* signed_int_trans;
  int packed_int_trans_size = pack_mac_any_trans(&int_trans, &int_trans_id, &packed_int_trans);
  int signed_int_trans_size = mt_create_signed_msg(packed_int_trans, packed_int_trans_size,
						   &aut_pk, &aut_sk, &signed_int_trans);
  memcpy(&dst_desc, &aut_desc, sizeof(mt_desc_t));
  result = mt_send_message(&led_desc, MT_NTYPE_MAC_ANY_TRANS, signed_int_trans, signed_int_trans_size);
  tt_assert(result == MT_SUCCESS);

  // make sure balances are what we expect them to be
  tt_assert(mt_lpay_query_mac_balance(&cli_addr) == cli_trans_val);
  tt_assert(mt_lpay_query_mac_balance(&rel_addr) == rel_trans_val);
  tt_assert(mt_lpay_query_mac_balance(&int_addr) == int_trans_val);

  /**************************** Protocol Tests ***************************/

  int num_pay = 20;
  int num_dpay = 20;

  // send payments to a relay through the intermediary

  for(int i = 0; i < num_pay; i++){
    printf("\n");
    memcpy(&dst_desc, &cli_desc, sizeof(mt_desc_t));
    tt_assert(mt_cpay_pay(&rel_desc, &int_desc) == MT_SUCCESS);
  }

  // close the channel

  printf("\n");
  memcpy(&dst_desc, &cli_desc, sizeof(mt_desc_t));
  tt_assert(mt_cpay_close(&rel_desc, &int_desc) == MT_SUCCESS);

  // send direct payments to the intermediary

  for(int i = 0; i < num_dpay; i++){
    printf("\n");
    memcpy(&dst_desc, &cli_desc, sizeof(mt_desc_t));
    tt_assert(mt_cpay_pay(&int_desc, &int_desc) == MT_SUCCESS);
  }

  // close the channel

  printf("\n");
  memcpy(&dst_desc, &cli_desc, sizeof(mt_desc_t));
  tt_assert(mt_cpay_close(&int_desc, &int_desc) == MT_SUCCESS);

  // make sure channel balances are what we expect them to be;

  int cli_bal = mt_cpay_mac_balance() + mt_cpay_chn_balance();
  int rel_bal = mt_rpay_mac_balance() + mt_rpay_chn_balance();
  int int_bal = mt_ipay_mac_balance() + mt_ipay_chn_balance();

  int MT_NAN_TAX = MT_NAN_VAL * MT_TAX / 100;
  int cli_exp = cli_trans_val - (num_pay + num_dpay) * (MT_NAN_VAL + MT_NAN_TAX);
  int rel_exp = rel_trans_val + num_pay * MT_NAN_VAL;
  int int_exp = int_trans_val + num_pay * MT_NAN_TAX + num_dpay * (MT_NAN_VAL + MT_NAN_TAX);
  cli_exp -= mt_cpay_chn_number() * MT_FEE;
  rel_exp -= mt_rpay_chn_number() * MT_FEE;
  int_exp -= mt_ipay_chn_number() * MT_FEE;

  tt_assert(cli_bal == cli_exp);
  tt_assert(rel_bal == rel_exp);
  tt_assert(int_bal == int_exp);

  printf("\n-------------- end paysimple ------------\n\n");

 done:;

  tor_assert(mt_lpay_clear() == MT_SUCCESS);

  UNMOCK(mt_send_message);
  UNMOCK(mt_send_message_multidesc);
  UNMOCK(mt_paymod_signal);
  UNMOCK(cpuworker_queue_work);

  tor_free(signed_mint);
  tor_free(packed_mint);
  tor_free(packed_cli_trans);
  tor_free(signed_cli_trans);
  tor_free(packed_rel_trans);
  tor_free(signed_rel_trans);
  tor_free(packed_int_trans);
  tor_free(signed_int_trans);
}

struct testcase_t mt_paysimple_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_paysimple", test_mt_paysimple, 0, NULL, NULL },
  END_OF_TESTCASES
};
