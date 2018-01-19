/**
 * \file test_mt_paymulti.c
 * \brief Isolated payment module tests with multiple
 * client/relay/intermediaries
 *
 * Run unit tests with exstensive testing to support many different types of
 * each parties in order to ensure correct channel management. The test is
 * achieved by mocking controller methods into local message passing. Identities
 * are maintained by swapping out the static state of each payment module and
 * performing a "context switch" into them whenever necessary.
 */

#pragma GCC diagnostic ignored "-Wswitch-enum"

#include <stdio.h>
#include <stdlib.h>

#include "or.h"
#include "config.h"
#include "container.h"
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

#define NON_NULL 1

#define CLI_NUM 16
#define REL_NUM 8
#define INT_NUM 4

#define REL_CONNS 4

typedef struct {
  mt_desc_t desc;
  byte* state;
} context_t;

typedef enum {
  CALL_PAY,
  CALL_CLOSE,
  SEND_LED,
  SEND_CLI,
  SEND_REL,
  SEND_RELMULTIDESC,
  SEND_INT,
  CPU_PROCESS,
} event_type_t;

typedef struct {
  // event initiator
  event_type_t type;
  mt_desc_t src;

  // params for CALL
  mt_desc_t desc1;
  mt_desc_t desc2;

  // extram params for SEND
  mt_ntype_t msg_type;
  byte* msg;
  int msg_size;

  // params for cpu worker
  workqueue_reply_t (*fn)(void*, void*);
  int (*reply_fn)(void*);
  void* arg;
} event_t;


static int sim_time = 0;
static int max_time = 1000;

static mt_desc_t cur_desc;
static mt_desc_t aut_desc;
static mt_desc_t led_desc;

static digestmap_t* cli_ctx;           // digest(cli_desc) -> context_t*
static digestmap_t* rel_ctx;           // digest(rel_desc) -> context_t*
static digestmap_t* int_ctx;           // digest(int_desc) -> context_t*

static smartlist_t* event_queue;
static digestmap_t* connections;        // digest(cli_desc) -> (digest(rel_desc) -> digest(int_desc))
static digestmap_t* exp_balance;

static int mock_send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){

  // define event type
  event_type_t event_type;
  switch(desc->party){
    case MT_PARTY_AUT:
      return MT_SUCCESS;
    case MT_PARTY_LED:
      event_type = SEND_LED;
      break;
    case MT_PARTY_CLI:
      event_type = SEND_CLI;
      break;
    case MT_PARTY_REL:
      event_type = SEND_REL;
      break;
    case MT_PARTY_INT:
      event_type = SEND_INT;
      break;
    default:
      return MT_ERROR;
  }

  event_t* event = tor_malloc(sizeof(event_t));
  event->type = event_type;
  event->src = cur_desc;

  // save parameters
  event->desc1 = *desc;
  event->msg_type = type;
  event->msg_size = size;
  event->msg = tor_malloc(size);
  memcpy(event->msg, msg, size);

  // add event to queue
  smartlist_add(event_queue, event);
  return MT_SUCCESS;
}

static int mock_send_message_multidesc(mt_desc_t *desc1, mt_desc_t* desc2,  mt_ntype_t type, byte* msg, int size){

  if(desc1->party != MT_PARTY_REL)
    return MT_ERROR;

  event_t* event = tor_malloc(sizeof(event_t));
  event->type = SEND_RELMULTIDESC;
  event->src = cur_desc;

  // save parameters
  event->desc1 = *desc1;
  event->desc2 = *desc2;
  event->msg_type = type;
  event->msg_size = size;
  event->msg = tor_malloc(size);
  memcpy(event->msg, msg, size);

  // add event to queue
  smartlist_add(event_queue, event);
  return MT_SUCCESS;
}

static workqueue_entry_t* mock_cpuworker_queue_work(workqueue_priority_t priority,
						    workqueue_reply_t (*fn)(void*, void*),
						    int (*reply_fn)(void*), void* arg){
  (void)priority;
  event_t* event = tor_malloc(sizeof(event_t));
  event->type = CPU_PROCESS;
  event->src = cur_desc;

  // save parameters
  event->fn = fn;
  event->reply_fn = reply_fn;
  event->arg = arg;

  // add event to queue
  smartlist_add(event_queue, event);
  return (void*)NON_NULL;
}

static int mock_paymod_signal(mt_signal_t signal, mt_desc_t* desc){

  // need to get idesc somehow;

  switch(signal){
    case MT_SIGNAL_PAYMENT_SUCCESS:;

      byte cdigest[DIGEST_LEN];
      byte rdigest[DIGEST_LEN];
      mt_desc2digest(&cur_desc, &cdigest);
      mt_desc2digest(desc, &rdigest);

      digestmap_t* rel2int = digestmap_get(connections, (char*)cdigest);
      mt_desc_t* idesc = digestmap_get(rel2int, (char*)rdigest);

      // as long as there is still time keep making payments, otherwise close
      if(sim_time < max_time){

	event_t* event = tor_malloc(sizeof(event_t));
	event->type = CALL_PAY;
	event->src = cur_desc;
	event->desc1 = *desc;
	event->desc2 = *idesc;

	smartlist_add(event_queue, event);
      }
      else {
	event_t* event = tor_malloc(sizeof(event_t));
	event->type = CALL_CLOSE;
	event->src = cur_desc;
	event->desc1 = *desc;
	event->desc2 = *idesc;

	smartlist_add(event_queue, event);
      }

    default:;
  }

  return MT_SUCCESS;
}

/**
 * Return a random element from the given digestmap
 */
static void* digestmap_rand(digestmap_t* map){
  int target = rand() % digestmap_size(map);
  int i = 0;

  MAP_FOREACH(digestmap_, map, const char*, digest, void*, val){
    if(i == target)
      return val;
    i++;
  } MAP_FOREACH_END;

  return NULL;
}

static char* party_string(mt_desc_t* desc){

  const char* party_str = "";

  switch(desc->party){
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
    case MT_PARTY_IDK:
      party_str = "idk";
      break;
  }

  char* result = tor_malloc(strlen(party_str) + 1);
  memcpy(result, party_str, strlen(party_str));
  result[strlen(party_str)] = '\0';
  return result;
}

static char* type_string(mt_ntype_t type){

  const char* type_str = "";

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

  char* result = tor_malloc(strlen(type_str) + 1);
  memcpy(result, type_str, strlen(type_str));
  result[strlen(type_str)] = '\0';
  return result;
}

static void print_sent_message(mt_desc_t* src, mt_desc_t* dst, mt_ntype_t type){
  char* src_party = party_string(src);
  char* dst_party = party_string(dst);
  char* type_str = type_string(type);

  printf("%s (%02d) -> %s (%02d) : %s\n", src_party, (int)src->id, dst_party, (int)dst->id, type_str);

  tor_free(src_party);
  tor_free(dst_party);
  tor_free(type_str);
}

static int compare_random(const void **a, const void **b){
  (void)a;
  (void)b;
  if(rand() % 2 == 0)
    return 1;
  return -1;
}

static void set_up_main_loop(void){
  MAP_FOREACH(digestmap_, cli_ctx, const char*, digest, context_t*, ctx){
    mt_cpay_import(ctx->state);
    tor_free(ctx->state);

    digestmap_t* rel2int = digestmap_new();
    digestmap_set(connections, digest, rel2int);

    // populate random subset of relays
    mt_desc_t unique_rel_descs[REL_CONNS];
    int index = 0;
    while(index < REL_CONNS){

      mt_desc_t relay = ((context_t*)digestmap_rand(rel_ctx))->desc;
      unique_rel_descs[index] = relay;

      for(int j = 0; j < index; j++){
	if(unique_rel_descs[j].id[0] == relay.id[0]){
	  index--;
	}
      }
      index++;
    }

    // make indirect payments
    for(int i = 0; i < REL_CONNS; i++){
      event_t* event = tor_malloc(sizeof(event_t));
      event->type = CALL_PAY;
      event->src = ctx->desc;
      event->desc1 = unique_rel_descs[i];
      event->desc2 = ((context_t*)digestmap_rand(int_ctx))->desc;
      smartlist_add(event_queue, event);

      // record the relay -> intermediary pairing
      byte rdigest[DIGEST_LEN];
      mt_desc_t* idesc = tor_malloc(sizeof(mt_desc_t));
      mt_desc2digest(&event->desc1, &rdigest);
      memcpy(idesc, &event->desc2, sizeof(mt_desc_t));
      digestmap_set(rel2int, rdigest, idesc);
    }

    // make direct payments
    event_t* event = tor_malloc(sizeof(event_t));
    event->type = CALL_PAY;
    event->src = ctx->desc;
    event->desc1 = ((context_t*)digestmap_rand(int_ctx))->desc;
    event->desc2 = event->desc1;
    smartlist_add(event_queue, event);

    byte idigest[DIGEST_LEN];
    mt_desc_t* idesc = tor_malloc(sizeof(mt_desc_t));
    mt_desc2digest(&event->desc1, idigest);
    memcpy(idesc, &event->desc2, sizeof(mt_desc_t));
    digestmap_set(rel2int, idigest, idesc);

    mt_cpay_export(&ctx->state);
  } MAP_FOREACH_END;

}

static int do_main_loop_once(void){

  // shuffle events for fun
  smartlist_sort(event_queue, compare_random);

  // remove the first element in the smartlist
  smartlist_reverse(event_queue);
  event_t* event = smartlist_pop_last(event_queue);
  smartlist_reverse(event_queue);

  int result;

  byte src_digest[DIGEST_LEN];
  mt_desc2digest(&event->src, &src_digest);

  byte dst_digest[DIGEST_LEN];
  mt_desc2digest(&event->desc1, &dst_digest);

  context_t* ctx;

  byte int_digest[DIGEST_LEN];
  mt_desc2digest(&event->desc2, &int_digest);
  int MT_NAN_TAX = MT_NAN_VAL * MT_TAX / 100;

  // update expected balances for pay
  if(event->type == CALL_PAY && memcmp(dst_digest, int_digest, DIGEST_LEN) != 0){
    *(int*)digestmap_get(exp_balance, (char*)src_digest) -= MT_NAN_VAL + MT_NAN_TAX;
    *(int*)digestmap_get(exp_balance, (char*)dst_digest) += MT_NAN_VAL;
    *(int*)digestmap_get(exp_balance, (char*)int_digest) += MT_NAN_TAX;
  }

  // update expected balances for direct pay
  if(event->type == CALL_PAY && memcmp(dst_digest, int_digest, DIGEST_LEN) == 0){
    *(int*)digestmap_get(exp_balance, (char*)src_digest) -= MT_NAN_VAL + MT_NAN_TAX;
    *(int*)digestmap_get(exp_balance, (char*)int_digest) += MT_NAN_VAL + MT_NAN_TAX;
  }

  switch(event->type){
    case CALL_PAY:
      ctx = digestmap_get(cli_ctx, (char*)src_digest);
      mt_cpay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->src;
      printf("cli (%02d) : call pay (%02d)\n", (int)event->src.id[0], (int)event->desc1.id[0]);
      result = mt_cpay_pay(&event->desc1, &event->desc2);
      mt_cpay_export(&ctx->state);
      break;

    case CALL_CLOSE:
      ctx = digestmap_get(cli_ctx, (char*)src_digest);
      mt_cpay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->src;
      printf("cli (%02d) : call close (%02d)\n", (int)event->src.id[0], (int)event->desc1.id[0]);
      result = mt_cpay_close(&event->desc1, &event->desc2);
      mt_cpay_export(&ctx->state);
      break;

    case SEND_LED:
      cur_desc = event->desc1;
      result = mt_lpay_recv(&event->src, event->msg_type, event->msg, event->msg_size);
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      break;

    case SEND_CLI:
      ctx = digestmap_get(cli_ctx, (char*)dst_digest);
      mt_cpay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->desc1;
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      result = mt_cpay_recv(&event->src, event->msg_type, event->msg, event->msg_size);
      mt_cpay_export(&ctx->state);
      break;

    case SEND_REL:
      ctx = digestmap_get(rel_ctx, (char*)dst_digest);
      mt_rpay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->desc1;
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      result = mt_rpay_recv(&event->src, event->msg_type, event->msg, event->msg_size);
      mt_rpay_export(&ctx->state);
      break;

    case SEND_RELMULTIDESC:
      ctx = digestmap_get(rel_ctx, (char*)dst_digest);
      mt_rpay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->desc1;
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      result = mt_rpay_recv_multidesc(&event->src, &event->desc2, event->msg_type, event->msg,
				      event->msg_size);
      mt_rpay_export(&ctx->state);
      break;

    case SEND_INT:
      ctx = digestmap_get(int_ctx, (char*)dst_digest);
      mt_ipay_import(ctx->state);
      tor_free(ctx->state);
      cur_desc = event->desc1;
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      result = mt_ipay_recv(&event->src, event->msg_type, event->msg, event->msg_size);
      mt_ipay_export(&ctx->state);
      break;

    case CPU_PROCESS:
      if(event->src.party == MT_PARTY_CLI){
	ctx = digestmap_get(cli_ctx, (char*)src_digest);
	mt_cpay_import(ctx->state);
	tor_free(ctx->state);
	event->fn(NULL, event->arg);
	cur_desc = event->src;
	printf("cli (%02d) : make zkp\n", event->src.id[0]);
	result = event->reply_fn(event->arg);
	mt_cpay_export(&ctx->state);
      }
      else if(event->src.party == MT_PARTY_REL){
	ctx = digestmap_get(rel_ctx, (char*)src_digest);
	mt_rpay_import(ctx->state);
	tor_free(ctx->state);
	event->fn(NULL, event->arg);
	cur_desc = event->src;
	printf("rel (%02d) : make zkp\n", event->src.id[0]);
	result = event->reply_fn(event->arg);
	mt_rpay_export(&ctx->state);
      }
      else{
	printf("something went wrong\n");
	result = MT_ERROR;
      }
      break;

    default:
      printf("something went wrong\n");
      result = MT_ERROR;
  }

  sim_time++;
  return result;
}

static void test_mt_paymulti(void *arg){
  (void)arg;

  typedef workqueue_entry_t* (*cpuworker_fn)(workqueue_priority_t,
					     workqueue_reply_t (*)(void*, void*),
					     void (*)(void*), void*);

  MOCK(mt_send_message, mock_send_message);
  MOCK(mt_send_message_multidesc, mock_send_message_multidesc);
  MOCK(mt_paymod_signal, mock_paymod_signal);
  MOCK(cpuworker_queue_work, (cpuworker_fn)mock_cpuworker_queue_work);

  cli_ctx = digestmap_new();
  rel_ctx = digestmap_new();
  int_ctx = digestmap_new();

  event_queue = smartlist_new();
  exp_balance = digestmap_new();
  connections = digestmap_new();

  // seed random number so we get repeatable results
  srand(42);

  // make sure we have enough relays to connect to
  tt_assert(REL_NUM >= REL_CONNS);

  int result;

  /****************************** Setup **********************************/

  int mint_val = (MT_CLI_CHN_VAL + MT_REL_CHN_VAL + MT_INT_CHN_VAL) * 2000;
  int cli_trans_val = (MT_CLI_CHN_VAL + MT_FEE) * 100;
  int rel_trans_val = (MT_REL_CHN_VAL + MT_FEE) * 100;
  int int_trans_val = (MT_INT_CHN_VAL + MT_FEE) * 100;

  // setup all of the parties and add to _ctx maps

  byte pp[MT_SZ_PP];

  byte aut_pk[MT_SZ_PK];
  byte aut_sk[MT_SZ_SK];
  aut_desc.party = MT_PARTY_AUT;

  byte led_pk[MT_SZ_PK];
  byte led_sk[MT_SZ_SK];
  led_desc.party = MT_PARTY_LED;

  mt_crypt_setup(&pp);
  mt_crypt_keygen(&pp, &aut_pk, &aut_sk);
  mt_crypt_keygen(&pp, &led_pk, &led_sk);

  uint32_t ids = 0;
  aut_desc.id[0] = ids++;
  led_desc.id[0] = ids++;

  or_options_t* options = (or_options_t*)get_options();

  mt_bytes2hex((byte*)&led_desc.id[0], sizeof(led_desc.id[0]), &options->moneTorLedgerDesc);
  mt_bytes2hex(aut_pk, MT_SZ_PK, &options->moneTorAuthorityPK);

  mt_bytes2hex(pp, MT_SZ_PP, &options->moneTorPP);
  mt_bytes2hex(led_pk, MT_SZ_PK, &options->moneTorPK);
  mt_bytes2hex(led_sk, MT_SZ_SK, &options->moneTorSK);

  options->moneTorFee = MT_FEE;
  options->moneTorTax = MT_TAX;

  byte aut_addr[MT_SZ_ADDR];
  byte led_addr[MT_SZ_ADDR];
  mt_pk2addr(&aut_pk, &aut_addr);
  mt_pk2addr(&led_pk, &led_addr);

  // initialize ledger and save relevant "public" values
  tt_assert(mt_lpay_init() == MT_SUCCESS);

  // authority mints money

  mac_aut_mint_t mint = {.value = mint_val};
  byte mint_id[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, mint_id);

  byte* packed_mint;
  byte* signed_mint;
  int packed_mint_size = pack_mac_aut_mint(&mint, &mint_id, &packed_mint);
  int signed_mint_size = mt_create_signed_msg(packed_mint, packed_mint_size,
					      &aut_pk, &aut_sk, &signed_mint);

  result = mt_lpay_recv(&aut_desc, MT_NTYPE_MAC_AUT_MINT, signed_mint, signed_mint_size);
  tt_assert(result == MT_SUCCESS);

  // initialize clients

  for(int i = 0; i < CLI_NUM; i++){

    mt_desc_t cli_desc;
    byte cli_pk[MT_SZ_PK];
    byte cli_sk[MT_SZ_SK];
    cli_desc.party = MT_PARTY_CLI;
    mt_crypt_keygen(&pp, &cli_pk, &cli_sk);
    cli_desc.id[0] = ids++;

    mt_bytes2hex(cli_pk, MT_SZ_PK, &options->moneTorPK);
    mt_bytes2hex(cli_sk, MT_SZ_SK, &options->moneTorSK);
    options->moneTorBalance = cli_trans_val;
    tt_assert(mt_cpay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&cli_desc, &digest);

    byte* export;
    tt_assert(mt_cpay_export(&export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = cli_desc, .state = export};
    digestmap_set(cli_ctx, (char*)digest, ctx);

    // send money from authority to client

    byte cli_addr[MT_SZ_ADDR];
    mt_pk2addr(&cli_pk, &cli_addr);

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
    result = mt_lpay_recv(&aut_desc, MT_NTYPE_MAC_ANY_TRANS, signed_cli_trans, signed_cli_trans_size);
    tt_assert(result == MT_SUCCESS);
    tt_assert(mt_lpay_query_mac_balance(&cli_addr) == cli_trans_val);

    int* balance = tor_malloc(sizeof(int));
    *balance = cli_trans.val_to;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  // initialize relays

  for(int i = 0; i < REL_NUM; i++){

    mt_desc_t rel_desc;
    byte rel_pk[MT_SZ_PK];
    byte rel_sk[MT_SZ_SK];
    rel_desc.party = MT_PARTY_REL;
    mt_crypt_keygen(&pp, &rel_pk, &rel_sk);
    rel_desc.id[0] = ids++;

    mt_bytes2hex(rel_pk, MT_SZ_PK, &options->moneTorPK);
    mt_bytes2hex(rel_sk, MT_SZ_SK, &options->moneTorSK);
    options->moneTorBalance = rel_trans_val;
    tt_assert(mt_rpay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&rel_desc, &digest);

    byte* export;
    tt_assert(mt_rpay_export(&export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = rel_desc, .state = export};
    digestmap_set(rel_ctx, (char*)digest, ctx);

    // send money from authority to relay

    byte rel_addr[MT_SZ_ADDR];
    mt_pk2addr(&rel_pk, &rel_addr);

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
    result = mt_lpay_recv(&aut_desc, MT_NTYPE_MAC_ANY_TRANS, signed_rel_trans, signed_rel_trans_size);
    tt_assert(result == MT_SUCCESS);
    tt_assert(mt_lpay_query_mac_balance(&rel_addr) == rel_trans_val);

    int* balance = tor_malloc(sizeof(int));
    *balance = rel_trans.val_to;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  // initialize intermediaries

  for(int i = 0; i < INT_NUM; i++){

    mt_desc_t int_desc;
    byte int_pk[MT_SZ_PK];
    byte int_sk[MT_SZ_SK];
    int_desc.party = MT_PARTY_INT;
    mt_crypt_keygen(&pp, &int_pk, &int_sk);
    int_desc.id[0] = ids++;

    mt_bytes2hex(int_pk, MT_SZ_PK, &options->moneTorPK);
    mt_bytes2hex(int_sk, MT_SZ_SK, &options->moneTorSK);
    options->moneTorBalance = int_trans_val;
    tt_assert(mt_ipay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&int_desc, &digest);

    byte* export;
    tt_assert(mt_ipay_export(&export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = int_desc, .state = export};
    digestmap_set(int_ctx, (char*)digest, ctx);

    // send money from authority to intermediary

    byte int_addr[MT_SZ_ADDR];
    mt_pk2addr(&int_pk, &int_addr);

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
    result = mt_lpay_recv(&aut_desc, MT_NTYPE_MAC_ANY_TRANS, signed_int_trans, signed_int_trans_size);
    tt_assert(result == MT_SUCCESS);
    tt_assert(mt_lpay_query_mac_balance(&int_addr) == int_trans_val);

    int* balance = tor_malloc(sizeof(int));
    *balance = int_trans.val_to;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  /**************************** Protocol Tests ***************************/

  printf("\n");

  // start events
  set_up_main_loop();

  // main loop
  while(smartlist_len(event_queue) > 0){
    tt_assert(do_main_loop_once() == MT_SUCCESS);
  }

  // do it again
  sim_time = 0;
  set_up_main_loop();

  while(smartlist_len(event_queue) > 0){
    tt_assert(do_main_loop_once() == MT_SUCCESS);
  }

  // assert final balances

  MAP_FOREACH(digestmap_, cli_ctx, const char*, digest, context_t*, ctx){
    mt_cpay_import(ctx->state);
    int bal = mt_cpay_mac_balance() + mt_cpay_chn_balance();
    int exp = *(int*)digestmap_get(exp_balance, digest) - MT_FEE * mt_cpay_chn_number();
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

  MAP_FOREACH(digestmap_, rel_ctx, const char*, digest, context_t*, ctx){
    mt_rpay_import(ctx->state);
    int bal = mt_rpay_mac_balance() + mt_rpay_chn_balance();
    int exp = *(int*)digestmap_get(exp_balance, digest) - MT_FEE * mt_rpay_chn_number();
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

  MAP_FOREACH(digestmap_, int_ctx, const char*, digest, context_t*, ctx){
    mt_ipay_import(ctx->state);
    int bal =  mt_ipay_mac_balance() + mt_ipay_chn_balance();
    int exp = *(int*)digestmap_get(exp_balance, digest) - MT_FEE * mt_ipay_chn_number();
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

 done:;

  tor_assert(mt_lpay_clear() == MT_SUCCESS);

  UNMOCK(mt_send_message);
  UNMOCK(mt_send_message_multidesc);
  UNMOCK(mt_paymod_signal);
  UNMOCK(cpuworker_queue_work);

  // free maps
}

struct testcase_t mt_paymulti_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
  { "mt_paymulti", test_mt_paymulti, 0, NULL, NULL },
  END_OF_TESTCASES
};
