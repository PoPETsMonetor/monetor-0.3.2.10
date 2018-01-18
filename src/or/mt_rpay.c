/**
 * \file mt_rpay.c
 *
 * Implement logic for the relay role in the moneTor payment scheme. The module
 * interacts with other payment code (<b>mt_cpay<\b>, <b>mt_rpay<\b>,
 * <b>mt_ipay<\b>) across the Tor network. The module only interacts with two
 * other parts of the Tor code base: the corresponding moneTor controller and
 * the cpuworker. Interactions with controllers are managed through descriptors
 * defined by the struct <b>mt_desc_t<\b>. These descriptors serve as unique
 * payment identifies for the payment module such that the controller can
 * abstract away all network connection details.
 *
 * The following interface is made available to the controller:
 *   <ul>
 *     <li>mt_rpay_init();
 *     <li>mt_rpay_recv()
 *   <\ul>
 *
 * Conversely, the module requires access to the following controller interface:
 *   <ul>
 *     <li>mt_send_message()
 *     <li>mt_send_message_multidesc()
 *     <li>mt_alert_payment()
 *   <\ul>
 *
 * The payment module manages a collection of payment channels each of which is
 * roughly implemented as a state machine. Channels only have a well-defined
 * state inbetween protocol executions; inbetween then are in a limbo
 * "transition" state. These active protocols are tracked by protocol ids (pid)s
 * that are probabilistically assumed to be globally unique
 *
 * The code features a "re-entrancy" pattern whereby the same function is called
 * again and again via callbacks until the channel is in the right state to
 * complete the task.
 */

#pragma GCC diagnostic ignored "-Wswitch-enum"

#include<pthread.h>

#include "or.h"
#include "config.h"
#include "cpuworker.h"
#include "workqueue.h"
#include "mt_common.h"
#include "mt_rpay.h"

/**
 * Prototype for multi-thread function used to generate the expensive zkp proof
 */
typedef void (*work_task)(void*);

/**
 * Hold function and arguments necessary to execute callbacks on a channel once
 * the current protocol has completed
 */
typedef struct {
  int (*fn)(mt_desc_t*, mt_ntype_t, byte*, int);
  mt_desc_t dref1;
  mt_ntype_t arg2;
  byte* arg3;
  int arg4;
} mt_callback_t;

/**
 * Hold information necessary to maintain a single payment channel
 */
typedef struct {
  mt_desc_t cdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_callback_t callback;
} mt_channel_t;

/**
 * Hold arguments need to run the multi-thread workqueue for the expensive zkp
 * proof generation
 */
typedef struct {
  mt_channel_t* chn;
  byte pid[DIGEST_LEN];
} mt_wcom_args_t;

/**
 * Single instance of a relay payment object
 */
typedef struct {

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte addr[MT_SZ_ADDR];
  int mac_balance;
  int chn_balance;
  int chn_number;

  mt_desc_t ledger;
  int fee;

  // channel states are encoded by which of these containers they are held
  digestmap_t* chns_setup;       // digest(idesc) -> smartlist of channels
  digestmap_t* chns_estab;       // digest(idesc) -> smartlist of channels
  digestmap_t* nans_estab;       // digest(nan_pub) -> channel
  smartlist_t* chns_spent;

  // special container to hold channels in the middle of a protocol
  digestmap_t* chns_transition;  // pid -> channel

  // map
  digestmap_t* clis_idesc; // digest(cdesc) -> int desc
} mt_rpay_t;

// functions to initialize new protocols
static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);

// functions to handle incoming recv messages
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_cli_reqclose1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]);

// special helper functions for protocol steps involving a zkp proof generation
static int help_chn_end_estab1(void* args);
static int help_chn_int_estab4(void* args);
static int help_nan_int_close8(void *args);

// miscallaneous helper functions
static mt_channel_t* new_channel(void);
static workqueue_reply_t wcom_task(void* thread, void* arg);
static void digestmap_smartlist_add(digestmap_t* map, char* key, void* val);
static void* digestmap_smartlist_pop_last(digestmap_t* map, char* key);

static mt_rpay_t relay;

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_rpay_init(void){

  byte pp[MT_SZ_PP];
  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  mt_desc_t ledger;
  int fee;
  int rel_bal;

  /********************************************************************/
  // load values from torrc

  const or_options_t* options = get_options();

  byte* temp_pp;
  byte* temp_pk;
  byte* temp_sk;
  byte* temp_led;

  fee = options->moneTorFee;
  rel_bal = options->moneTorBalance;
  ledger.party = MT_PARTY_LED;

  tor_assert(mt_hex2bytes(options->moneTorLedgerDesc, &temp_led) == sizeof(ledger.id));
  tor_assert(mt_hex2bytes(options->moneTorPP, &temp_pp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(options->moneTorPK, &temp_pk) == MT_SZ_PK);
  tor_assert(mt_hex2bytes(options->moneTorSK, &temp_sk) == MT_SZ_SK);

  memcpy(pp, temp_pp, MT_SZ_PP);
  memcpy(pk, temp_pk, MT_SZ_PK);
  memcpy(sk, temp_sk, MT_SZ_SK);
  memcpy(&ledger.id, temp_led, sizeof(ledger.id));

  free(temp_pp);
  free(temp_pk);
  free(temp_sk);
  free(temp_led);

  /********************************************************************/

  // copy macro-level crypto fields
  memcpy(relay.pp, pp, MT_SZ_PP);
  memcpy(relay.pk, pk, MT_SZ_PK);
  memcpy(relay.sk, sk, MT_SZ_SK);
  mt_pk2addr(&relay.pk, &relay.addr);
  relay.ledger = ledger;
  relay.fee = fee;
  relay.mac_balance = rel_bal;
  relay.chn_balance = 0;
  relay.chn_number = 0;

  // initiate containers
  relay.chns_setup = digestmap_new();
  relay.chns_estab = digestmap_new();
  relay.nans_estab = digestmap_new();
  relay.chns_spent = smartlist_new();
  relay.chns_transition = digestmap_new();
  relay.clis_idesc = digestmap_new();

  return MT_SUCCESS;
}

/**
 * Handle an incoming message from the given client descriptor that is also
 * associated with a new intermediary descriptor. Currently, this is only needed
 * for the singular nan_cli_estab1 message.
 */
int mt_rpay_recv_multidesc(mt_desc_t* cdesc, mt_desc_t* idesc, mt_ntype_t type, byte* msg, int size){

  byte digest[DIGEST_LEN];
  mt_desc2digest(cdesc, &digest);
  mt_desc_t* int_desc = tor_malloc(sizeof(mt_desc_t));
  memcpy(int_desc, idesc, sizeof(mt_desc_t));

  digestmap_set(relay.clis_idesc, (char*)digest, int_desc);
  return mt_rpay_recv(cdesc, type, msg, size);
}

/**
 * Handle an incoming message from the given descriptor
 */
int mt_rpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

  int result;
  byte pid[DIGEST_LEN];

  // unpack the token and delegate to appropriate handler
  switch(type){
    case MT_NTYPE_ANY_LED_CONFIRM:;
      any_led_confirm_t any_led_confirm_tkn;
      if(unpack_any_led_confirm(msg, size, &any_led_confirm_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_any_led_confirm(desc, &any_led_confirm_tkn, &pid);
      break;

    case MT_NTYPE_CHN_INT_ESTAB2:;
      chn_int_estab2_t chn_int_estab2_tkn;
      if(unpack_chn_int_estab2(msg, size, &chn_int_estab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab2(desc, &chn_int_estab2_tkn, &pid);
      break;

    case MT_NTYPE_CHN_INT_ESTAB4:;
      chn_int_estab4_t chn_int_estab4_tkn;
      if(unpack_chn_int_estab4(msg, size, &chn_int_estab4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_estab4(desc, &chn_int_estab4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_ESTAB1:;
      nan_cli_estab1_t nan_cli_estab1_tkn;
      if(unpack_nan_cli_estab1(msg, size, &nan_cli_estab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_estab1(desc, &nan_cli_estab1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_ESTAB3:;
      nan_int_estab3_t nan_int_estab3_tkn;
      if(unpack_nan_int_estab3(msg, size, &nan_int_estab3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab3(desc, &nan_int_estab3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_ESTAB5:;
      nan_int_estab5_t nan_int_estab5_tkn;
      if(unpack_nan_int_estab5(msg, size, &nan_int_estab5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_estab5(desc, &nan_int_estab5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_PAY1:;
      nan_cli_pay1_t nan_cli_pay1_tkn;
      if(unpack_nan_cli_pay1(msg, size, &nan_cli_pay1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_pay1(desc, &nan_cli_pay1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_REQCLOSE1:;
      nan_cli_reqclose1_t nan_cli_reqclose1_tkn;
      if(unpack_nan_cli_reqclose1(msg, size, &nan_cli_reqclose1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_reqclose1(desc, &nan_cli_reqclose1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE2:;
      nan_int_close2_t nan_int_close2_tkn;
      if(unpack_nan_int_close2(msg, size, &nan_int_close2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close2(desc, &nan_int_close2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE4:;
      nan_int_close4_t nan_int_close4_tkn;
      if(unpack_nan_int_close4(msg, size, &nan_int_close4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close4(desc, &nan_int_close4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE6:;
      nan_int_close6_t nan_int_close6_tkn;
      if(unpack_nan_int_close6(msg, size, &nan_int_close6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close6(desc, &nan_int_close6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_CLOSE8:;
      nan_int_close8_t nan_int_close8_tkn;
      if(unpack_nan_int_close8(msg, size, &nan_int_close8_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_close8(desc, &nan_int_close8_tkn, &pid);
      break;

    default:
      result = MT_ERROR;
  }
  return result;
}

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_rpay_mac_balance(void){
  return relay.mac_balance;
}

/**
 * Return the balance of money locked up in channels
 */
int mt_rpay_chn_balance(void){
  return relay.chn_balance;
}

/**
 * Return the number of channels currently open
 */
int mt_rpay_chn_number(void){
  return relay.chn_number;
}

/**
 * Delete the state of the payment module
 */
int mt_rpay_clear(void){
  // Need to implement
  tor_assert(0);
  return MT_ERROR;
}

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_rpay_export(byte** export_out){
  *export_out = tor_malloc(sizeof(relay));
  memcpy(*export_out, &relay, sizeof(relay));
  return sizeof(relay);
}

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_rpay_import(byte* import){
  memcpy(&relay, import, sizeof(relay));
  return MT_SUCCESS;
}


/******************************* Channel Escrow *************************/

static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // TODO finish initializing channel

  // initialize setup token
  chn_end_setup_t token;
  token.val_from = MT_REL_CHN_VAL + relay.fee;
  token.val_to = MT_REL_CHN_VAL;
  memcpy(token.from, relay.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->data.addr, MT_SZ_ADDR);
  // skip public for now

  // update local data
  relay.chn_number ++;
  relay.mac_balance -= token.val_from;
  relay.chn_balance += token.val_to;

  // send setup message
  byte* msg;
  byte* signed_msg;
  int msg_size = pack_chn_end_setup(&token, pid, &msg);
  int signed_msg_size = mt_create_signed_msg(msg, msg_size,
					     &chn->data.pk, &chn->data.sk, &signed_msg);

  int result = mt_send_message(&relay.ledger, MT_NTYPE_CHN_END_SETUP, signed_msg, signed_msg_size);
  tor_free(msg);
  tor_free(signed_msg);
  return result;
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  if(desc->id != relay.ledger.id || desc->party != MT_PARTY_LED)
    return MT_ERROR;

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_smartlist_add(relay.chns_setup, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    int result = cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
    //tor_free(cb.arg3);
    return result;
  }
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_chn_end_estab1, args))
    return MT_ERROR;
  return MT_SUCCESS;

}

static int help_chn_end_estab1(void* args){

  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  tor_free(args);

  chn_end_estab1_t token;
  memcpy(token.addr, chn->data.addr, MT_SZ_ADDR);

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, &pid, &msg);
  int result = mt_send_message(&chn->idesc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }
  chn->data.int_balance = token->balance;

  // check validity of incoming message;

  chn_end_estab3_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_chn_end_estab3(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_CHN_END_ESTAB3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  // prepare nanopayment channel token now
  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_chn_int_estab4, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_chn_int_estab4(void* args){

  // extract parameters
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  tor_free(args);

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)pid);
  digestmap_smartlist_add(relay.chns_estab, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    int result = cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
    tor_free(cb.arg3);
    return result;
  }
  return MT_SUCCESS;
}


/****************************** Nano Establish **************************/

static int handle_nan_cli_estab1(mt_desc_t* desc, nan_cli_estab1_t* token, byte (*pid)[DIGEST_LEN]){
  mt_channel_t* chn;
  byte cdigest[DIGEST_LEN];
  mt_desc2digest(desc, &cdigest);

  mt_desc_t* intermediary = digestmap_get(relay.clis_idesc, (char*)cdigest);
  byte idigest[DIGEST_LEN];
  mt_desc2digest(intermediary, &idigest);

  // we have a tor_free channel with this intermediary
  if((chn = digestmap_smartlist_pop_last(relay.chns_estab, (char*)idigest))){

    // if the channel doesn't have enough money then move it to spent and retry
    if(chn->data.int_balance < token->nan_public.val_to * token->nan_public.num_payments){
      smartlist_add(relay.chns_spent, chn);
      return handle_nan_cli_estab1(desc, token, pid);
    }

    digestmap_set(relay.chns_transition, (char*)*pid, chn);
    chn->cdesc = *desc;
    chn->callback.fn = NULL;

    // save the nanopayment channel token
    memcpy(&chn->data.nan_public, &token->nan_public, sizeof(nan_any_public_t));
    chn->data.nan_state.num_payments = 0;

    nan_rel_estab2_t reply;

    // send message
    byte* msg;
    int msg_size = pack_nan_rel_estab2(&reply, pid, &msg);
    int result = mt_send_message(&chn->idesc, MT_NTYPE_NAN_REL_ESTAB2, msg, msg_size);
    tor_free(msg);
    return result;
  }

  byte rpid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, rpid);

  // if we have a channel setup then establish it
  if((chn = digestmap_smartlist_pop_last(relay.chns_setup, (char*)idigest))){
    digestmap_set(relay.chns_transition, (char*)rpid, chn);
    chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc, .arg2 = MT_NTYPE_NAN_CLI_ESTAB1};
    chn->callback.arg4 = pack_nan_cli_estab1(token, pid, &chn->callback.arg3);
    return init_chn_end_estab1(chn, &rpid);
  }

  // setup a new channel with the intermediary
  chn = new_channel();
  digestmap_set(relay.chns_transition, (char*)rpid, chn);
  chn->idesc = *intermediary;
  chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc, .arg2 = MT_NTYPE_NAN_CLI_ESTAB1};
  chn->callback.arg4 = pack_nan_cli_estab1(token, pid, &chn->callback.arg3);
  return init_chn_end_setup(chn, &rpid);
}

static int handle_nan_int_estab3(mt_desc_t* desc, nan_int_estab3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_rel_estab4_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_rel_estab4(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_REL_ESTAB4, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_estab5(mt_desc_t* desc, nan_int_estab5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&chn->data.nan_public, &digest);
  digestmap_remove(relay.chns_transition, (char*)*pid);
  digestmap_set(relay.nans_estab, (char*)digest, chn);

  nan_rel_estab6_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_rel_estab6(&reply, pid, &msg);
  int result = mt_send_message(&chn->cdesc, MT_NTYPE_NAN_REL_ESTAB6, msg, msg_size);
  tor_free(msg);
  return result;
}

/******************************* Nano Pay *******************************/

static int handle_nan_cli_pay1(mt_desc_t* desc, nan_cli_pay1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;

  // check validity of incoming message;

  nan_rel_pay2_t reply;

  // fill reply with correct values;

  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);
  mt_channel_t* chn = digestmap_get(relay.nans_estab, (char*)digest);
  if(!chn){
    log_debug(LD_MT, "client descriptor not recognized");
    return MT_ERROR;
  }

  // update channel data
  relay.chn_balance += chn->data.nan_public.val_to;
  chn->data.balance += chn->data.nan_public.val_to;
  chn->data.nan_state.num_payments ++;

  //mt_alert_payment(desc);
  mt_paymod_signal(MT_SIGNAL_PAYMENT_RECEIVED, desc);

  byte* msg;
  int msg_size = pack_nan_rel_pay2(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_REL_PAY2, msg, msg_size);
  tor_free(msg);
  return result;
}

/*************************** Nano Req Close *****************************/

static int handle_nan_cli_reqclose1(mt_desc_t* desc, nan_cli_reqclose1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;

  // check validity of incoming message;

  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);

  if((chn = digestmap_remove(relay.nans_estab, (char*)digest))){
    digestmap_set(relay.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_rpay_recv, .dref1 = *desc};
    chn->callback.arg2 = MT_NTYPE_NAN_CLI_REQCLOSE1;
    chn->callback.arg4 = pack_nan_cli_reqclose1(token, pid, &chn->callback.arg3);
    return init_nan_end_close1(chn, pid);
  }

  nan_rel_reqclose2_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_rel_reqclose2(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_REL_REQCLOSE2, msg, msg_size);
  tor_free(msg);
  return result;
}

/******************************* Nano Close *****************************/

static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // intiate token
  nan_end_close1_t token;
  token.total_val = -(chn->data.nan_state.num_payments * chn->data.nan_public.val_to);
  token.num_payments = chn->data.nan_state.num_payments;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));

  // TODO finish making token;

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, pid, &msg);
  int result = mt_send_message(&chn->idesc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close3_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_end_close3(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close5_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_end_close5(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE5, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;

  nan_end_close7_t reply;

  // fill reply with correct values;

  byte* msg;
  int msg_size = pack_nan_end_close7(&reply, pid, &msg);
  int result = mt_send_message(desc, MT_NTYPE_NAN_END_CLOSE7, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(relay.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;


  mt_wcom_args_t* args = tor_malloc(sizeof(mt_wcom_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  if(!cpuworker_queue_work(WQ_PRI_HIGH, wcom_task, (work_task)help_nan_int_close8, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_nan_int_close8(void *args){
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_wcom_args_t*)args)->pid, DIGEST_LEN);
  tor_free(args);

  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->idesc, &digest);
  digestmap_remove(relay.chns_transition, (char*)pid);
  digestmap_smartlist_add(relay.chns_estab, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    int result = cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
    tor_free(cb.arg3);
    return result;
  }
  return MT_SUCCESS;
}

/*************************** Helper Functions ***************************/

static mt_channel_t* new_channel(void){
  // initialize new channel
  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(chn->data.pk, relay.pk, MT_SZ_PK);
  memcpy(chn->data.sk, relay.sk, MT_SZ_SK);
  mt_crypt_rand(MT_SZ_ADDR, chn->data.addr);
  return chn;
}
/**
 * Append a value to the appropriate list in a digestmap of smartlists
 */
static void digestmap_smartlist_add(digestmap_t* map, char* key, void* val){
  smartlist_t* list = digestmap_get(map, (char*)key);
  if(list == NULL){
    digestmap_set(map, (char*)key, smartlist_new());
    list = digestmap_get(map, (char*)key);
  }
  smartlist_add(list, val);
}

/**
 * Pop the last item from the appropriate list in a digestmap of smartlists
 */
static void* digestmap_smartlist_pop_last(digestmap_t* map, char* key){
  smartlist_t* list = digestmap_get(map, (char*)key);
  if(!list)
    return NULL;
  return smartlist_pop_last(list);
}

static workqueue_reply_t wcom_task(void* thread, void* args){
  (void)thread;

  // extract parameters
  mt_channel_t* chn = ((mt_wcom_args_t*)args)->chn;
  (void)chn;

  // call mt_commit_wallet here
  return WQ_RPL_REPLY;
}
