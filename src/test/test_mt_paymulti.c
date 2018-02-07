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
#include "mt_messagebuffer.h"
#include "test.h"

#define NON_NULL 1

#define CLI_NUM 16
#define REL_NUM 8
#define INT_NUM 4
#define REL_CONNS 4

#define DISCONNECT_PERCENT 5

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
  DESC_ACTIVATE,
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

  // params for desc activiation
  mt_desc_t activate_desc;
} event_t;


static int sim_time = 0;
static int max_time = 1000 * (CLI_NUM * (REL_CONNS + 1));

static mt_desc_t cur_desc;
static mt_desc_t aut_desc;
static mt_desc_t led_desc;

static digestmap_t* cli_ctx;           // digest(cli_desc) -> context_t*
static digestmap_t* rel_ctx;           // digest(rel_desc) -> context_t*
static digestmap_t* int_ctx;           // digest(int_desc) -> context_t*

static smartlist_t* event_queue;
static digestmap_t* connections;        // digest(cli_desc) -> (digest(rel_desc) -> digest(int_desc))
static digestmap_t* exp_balance;

static digestmap_t* statuses;

int num_payment_messages;
int num_other_messages;

static int mock_send_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  // if desc is unavailable make it available later and return ERROR for now
  if(*(int*)digestmap_get(statuses, (char*)digest) == 0){

    // inform the payment module that the desc is unavailable
    if(cur_desc.party == MT_PARTY_LED)
      mt_lpay_set_status(desc, 0);
    else if(cur_desc.party == MT_PARTY_CLI)
      mt_cpay_set_status(desc, 0);
    else if(cur_desc.party == MT_PARTY_REL)
      mt_rpay_set_status(desc, 0);
    else if(cur_desc.party == MT_PARTY_INT)
      mt_ipay_set_status(desc, 0);
    else
      tor_assert(0);

    event_t* activate = tor_malloc(sizeof(event_t));
    activate->type = DESC_ACTIVATE;
    activate->src = cur_desc;
    activate->activate_desc = *desc;
    smartlist_add(event_queue, activate);
    return MT_ERROR;
  }

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

  event_t* send = tor_malloc(sizeof(event_t));
  send->type = event_type;
  send->src = cur_desc;

  // save parameters
  send->desc1 = *desc;
  send->msg_type = type;
  send->msg_size = size;
  send->msg = tor_malloc(size);
  memcpy(send->msg, msg, size);

  // add event to queue
  smartlist_add(event_queue, send);

  // track number of payment vs non-payment messages
  if(type == MT_NTYPE_NAN_CLI_PAY1 || type == MT_NTYPE_NAN_REL_PAY2 ||
     type == MT_NTYPE_NAN_CLI_DPAY1 || type == MT_NTYPE_NAN_INT_DPAY2)
    num_payment_messages++;
  else
    num_other_messages++;

  return MT_SUCCESS;
}

static int mock_send_message_multidesc(mt_desc_t *desc1, mt_desc_t* desc2,  mt_ntype_t type, byte* msg, int size){

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc1, &digest);

  // if desc is unavailable make it available later and return ERROR for now
  if(*(int*)digestmap_get(statuses, (char*)digest) == 0){

    // inform the payment module that the desc is unavailable
    if(cur_desc.party == MT_PARTY_LED)
      mt_lpay_set_status(desc1, 0);
    else if(cur_desc.party == MT_PARTY_CLI)
      mt_cpay_set_status(desc1, 0);
    else if(cur_desc.party == MT_PARTY_REL)
      mt_rpay_set_status(desc1, 0);
    else if(cur_desc.party == MT_PARTY_INT)
      mt_ipay_set_status(desc1, 0);
    else
      tor_assert(0);

    event_t* activate = tor_malloc(sizeof(event_t));
    activate->type = DESC_ACTIVATE;
    activate->src = cur_desc;
    activate->activate_desc = *desc1;
    smartlist_add(event_queue, activate);
    return MT_ERROR;
  }

  if(desc1->party != MT_PARTY_REL)
    return MT_ERROR;

  event_t* send = tor_malloc(sizeof(event_t));
  send->type = SEND_RELMULTIDESC;
  send->src = cur_desc;

  // save parameters
  send->desc1 = *desc1;
  send->desc2 = *desc2;
  send->msg_type = type;
  send->msg_size = size;
  send->msg = tor_malloc(size);
  memcpy(send->msg, msg, size);

  // add event to queue
  smartlist_add(event_queue, send);
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
    default:
      return NULL;

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

  printf("%s (%02d) -> %s (%02d) : %s\n", src_party, (int)src->id[0], dst_party, (int)dst->id[0], type_str);

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
      digestmap_set(rel2int, (char*)rdigest, idesc);
    }

    // Make direct payments
    event_t* event = tor_malloc(sizeof(event_t));
    event->type = CALL_PAY;
    event->src = ctx->desc;
    event->desc1 = ((context_t*)digestmap_rand(int_ctx))->desc;
    event->desc2 = event->desc1;
    smartlist_add(event_queue, event);

    byte idigest[DIGEST_LEN];
    mt_desc_t* idesc = tor_malloc(sizeof(mt_desc_t));
    mt_desc2digest(&event->desc1, &idigest);
    memcpy(idesc, &event->desc2, sizeof(mt_desc_t));
    digestmap_set(rel2int, (char*)idigest, idesc);

    mt_cpay_export(&ctx->state);
  } MAP_FOREACH_END;

}

static int do_main_loop_once(void){

  // shuffle events for fun
  smartlist_sort(event_queue, compare_random);

  // randomly make some descriptors unavailable
  MAP_FOREACH(digestmap_, statuses, const char*, digest, int*, status){
    if(rand() % 100 < DISCONNECT_PERCENT)
      *status = 0;
  } MAP_FOREACH_END;


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
      print_sent_message(&event->src, &event->desc1, event->msg_type);
      result = mt_lpay_recv(&event->src, event->msg_type, event->msg, event->msg_size);
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
	printf("cli (%02d) : make zkp\n", (int)event->src.id[0]);
	result = event->reply_fn(event->arg);
	mt_cpay_export(&ctx->state);
      }
      else if(event->src.party == MT_PARTY_REL){
	ctx = digestmap_get(rel_ctx, (char*)src_digest);
	mt_rpay_import(ctx->state);
	tor_free(ctx->state);
	event->fn(NULL, event->arg);
	cur_desc = event->src;
	printf("rel (%02d) : make zkp\n", (int)event->src.id[0]);
	result = event->reply_fn(event->arg);
	mt_rpay_export(&ctx->state);
      }
      else{
	printf("something went wrong\n");
	result = MT_ERROR;
      }
      break;

    case DESC_ACTIVATE:;
      byte digest[DIGEST_LEN];
      mt_desc2digest(&event->activate_desc, &digest);
      int* status = digestmap_get(statuses, (char*)digest);
      tor_assert(status);
      *status = 1;
      cur_desc = event->src;
      printf("desc (%02d) : activating (%02d) \n", (int)event->src.id[0],
	     (int)event->activate_desc.id[0]);

      if(cur_desc.party == MT_PARTY_LED){
	// only one ledger so we don't have to owrry about context switching
	result = mt_lpay_set_status(&event->activate_desc, 1);
      }
      else if(cur_desc.party == MT_PARTY_CLI){
	ctx = digestmap_get(cli_ctx, (char*)src_digest);
	mt_cpay_import(ctx->state);
	tor_free(ctx->state);
	result = mt_cpay_set_status(&event->activate_desc, 1);
	mt_cpay_export(&ctx->state);
      }
      else if(cur_desc.party == MT_PARTY_REL){
	ctx = digestmap_get(rel_ctx, (char*)src_digest);
	mt_rpay_import(ctx->state);
	tor_free(ctx->state);
	result = mt_rpay_set_status(&event->activate_desc, 1);
	mt_rpay_export(&ctx->state);
      }
      else if(cur_desc.party == MT_PARTY_INT){
	ctx = digestmap_get(int_ctx, (char*)src_digest);
	mt_ipay_import(ctx->state);
	tor_free(ctx->state);
	result = mt_ipay_set_status(&event->activate_desc, 1);
	mt_ipay_export(&ctx->state);
      }
      else{
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
  statuses = digestmap_new();

  // seed random number so we get repeatable results
  srand(42);

  // make sure we have enough relays to connect to
  tt_assert(REL_NUM >= REL_CONNS);

  /****************************** Setup **********************************/

  // setup all of the parties and add to _ctx maps
  uint32_t ids = 1;

  byte pp[MT_SZ_PP];

  byte led_pk[MT_SZ_PK];
  byte led_sk[MT_SZ_SK];
  led_desc.party = MT_PARTY_LED;
  led_desc.id[0] = 0;
  led_desc.id[1] = 0;

  byte led_digest[DIGEST_LEN];
  mt_desc2digest(&led_desc, &led_digest);
  int* led_status = tor_malloc(sizeof(int));
  *led_status = 1;
  digestmap_set(statuses, (char*)led_digest, led_status);

  byte aut_pk[MT_SZ_PK];
  byte aut_sk[MT_SZ_SK];
  aut_desc.party = MT_PARTY_AUT;
  aut_desc.id[0] = ids++;
  aut_desc.id[1] = 0;

  byte aut_digest[DIGEST_LEN];
  mt_desc2digest(&aut_desc, &aut_digest);
  int* aut_status = tor_malloc(sizeof(int));
  *aut_status = 1;
  digestmap_set(statuses, (char*)aut_digest, aut_status);

  mt_crypt_keygen(&pp, &led_pk, &led_sk);

  or_options_t* options = (or_options_t*)get_options();
  options->MoneTorPublicMint = 1;

  byte* pp_temp;
  byte* aut_pk_temp;
  byte* aut_sk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_AUT_PK_HEX, &aut_pk_temp) == MT_SZ_PK);
  tor_assert(mt_hex2bytes(MT_AUT_SK_HEX, &aut_sk_temp) == MT_SZ_SK);

  memcpy(pp, pp_temp, MT_SZ_PP);
  memcpy(aut_pk, aut_pk_temp, MT_SZ_PK);
  memcpy(aut_sk, aut_sk_temp, MT_SZ_SK);

  free(pp_temp);
  free(aut_pk_temp);
  free(aut_sk_temp);

  byte led_addr[MT_SZ_ADDR];
  mt_pk2addr(&led_pk, &led_addr);

  // initialize ledger and save relevant "public" values
  tt_assert(mt_lpay_init() == MT_SUCCESS);

  // initialize clients
  for(int i = 0; i < CLI_NUM; i++){
    mt_desc_t cli_desc;
    cli_desc.party = MT_PARTY_CLI;
    cli_desc.id[0] = ids++;
    cli_desc.id[1] = 0;

    tt_assert(mt_cpay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&cli_desc, &digest);

    int* status = tor_malloc(sizeof(int));
    *status = 1;
    digestmap_set(statuses, (char*)digest, status);

    byte* pay_export;
    tt_assert(mt_cpay_export(&pay_export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = cli_desc, .state = pay_export};
    digestmap_set(cli_ctx, (char*)digest, ctx);

    int* balance = tor_malloc(sizeof(int));
    *balance = 0;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  // initialize relays
  for(int i = 0; i < REL_NUM; i++){

    mt_desc_t rel_desc;
    rel_desc.party = MT_PARTY_REL;
    rel_desc.id[0] = ids++;
    rel_desc.id[1] = 0;

    tt_assert(mt_rpay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&rel_desc, &digest);

    int* status = tor_malloc(sizeof(int));
    *status = 1;
    digestmap_set(statuses, (char*)digest, status);

    byte* pay_export;
    tt_assert(mt_rpay_export(&pay_export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = rel_desc, .state = pay_export};
    digestmap_set(rel_ctx, (char*)digest, ctx);

    int* balance = tor_malloc(sizeof(int));
    *balance = 0;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  // initialize intermediaries
  for(int i = 0; i < INT_NUM; i++){

    mt_desc_t int_desc;
    int_desc.party = MT_PARTY_INT;
    int_desc.id[0] = ids++;
    int_desc.id[1] = ids++;

    tt_assert(mt_ipay_init() == MT_SUCCESS);

    byte digest[DIGEST_LEN];
    mt_desc2digest(&int_desc, &digest);

    int* status = tor_malloc(sizeof(int));
    *status = 1;
    digestmap_set(statuses, (char*)digest, status);

    byte* pay_export;
    tt_assert(mt_ipay_export(&pay_export) != MT_ERROR);
    context_t* ctx = tor_malloc(sizeof(context_t));
    *ctx = (context_t){.desc = int_desc, .state = pay_export};
    digestmap_set(int_ctx, (char*)digest, ctx);

    int* balance = tor_malloc(sizeof(int));
    *balance = 0;
    digestmap_set(exp_balance, (char*)digest, balance);
  }

  // set client statuses to offline to begin testing
  MAP_FOREACH(digestmap_, cli_ctx, const char*, cli_digest, context_t*, cli_context){
    (void)cli_context;
    *(int*)digestmap_get(statuses, (char*)cli_digest) = 0;
  } MAP_FOREACH_END;

  // set relay statuses to offline to begin testing
  MAP_FOREACH(digestmap_, rel_ctx, const char*, rel_digest, context_t*, rel_context){
    (void)rel_context;
    *(int*)digestmap_get(statuses, (char*)rel_digest) = 0;
  } MAP_FOREACH_END;

  // set intermediary statuses to offline to begin testing
  MAP_FOREACH(digestmap_, int_ctx, const char*, int_digest, context_t*, int_context){
    (void)int_context;
    *(int*)digestmap_get(statuses, (char*)int_digest) = 0;
  } MAP_FOREACH_END;


  /**************************** Protocol Tests ***************************/

  printf("\n\n------------ begin paymulti ------------\n\n");

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
    int exp = *(int*)digestmap_get(exp_balance, digest);
    exp -= MT_FEE * mt_cpay_chn_number();
    exp += mt_cpay_chn_number() * (MT_CLI_CHN_VAL + MT_FEE);
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

  MAP_FOREACH(digestmap_, rel_ctx, const char*, digest, context_t*, ctx){
    mt_rpay_import(ctx->state);
    int bal = mt_rpay_mac_balance() + mt_rpay_chn_balance();
    int exp = *(int*)digestmap_get(exp_balance, digest);
    exp -= MT_FEE * mt_rpay_chn_number();
    exp += mt_rpay_chn_number() * (MT_REL_CHN_VAL + MT_FEE);
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

  MAP_FOREACH(digestmap_, int_ctx, const char*, digest, context_t*, ctx){
    mt_ipay_import(ctx->state);
    int bal =  mt_ipay_mac_balance() + mt_ipay_chn_balance();
    int exp = *(int*)digestmap_get(exp_balance, digest);
    exp -= MT_FEE * (mt_ipay_cli_chn_number() + mt_ipay_rel_chn_number());
    exp += mt_ipay_cli_chn_number() * MT_FEE;
    exp += mt_ipay_rel_chn_number() * (MT_INT_CHN_VAL + MT_FEE);
    printf("exp %d bal %d\n", exp, bal);
    tor_assert(bal == exp);
  } MAP_FOREACH_END;

  printf("payment messages %d\n", num_payment_messages);
  printf("other messages %d\n", num_other_messages);

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
