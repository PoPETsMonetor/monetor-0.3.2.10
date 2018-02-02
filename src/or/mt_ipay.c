/**
 * \file mt_ipay.c
 *
 * Implement logic for the intermediary in the moneTor payment scheme. The module
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
 *     <li>mt_ipay_init();
 *     <li>mt_ipay_recv()
 *   <\ul>
 *
 * Conversely, the module requires access to the following controller interface:
 *   <ul>
 *     <li>mt_buffer_message()
 *     <li>mt_buffer_message_multidesc()
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

#include "or.h"
#include "config.h"
#include "workqueue.h"
#include "cpuworker.h"
#include "mt_common.h"
#include "mt_messagebuffer.h"
#include "mt_ipay.h"

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
  byte addr[MT_SZ_ADDR];
  int balance;

  mt_desc_t edesc;
  chn_int_public_t chn_public;

  mt_callback_t callback;
} mt_channel_t;

/**
 * Single instance of an intermediary payment object
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

  chn_int_state_t chn_state;
  nan_int_state_t nan_state;

  digestmap_t* chns_setup;       // digest(edesc) -> chn
  digestmap_t* chns_estab;       // digest(edesc) -> chn

  digestmap_t* chns_transition;  // proto_id -> chn

  // structure to run message buffering functionality
  mt_msgbuf_t* msgbuf;

  // module-level callback (not associated with particular channel)
  byte faucet_pk[MT_SZ_PK];
  byte faucet_sk[MT_SZ_SK];
  byte faucet_addr[MT_SZ_ADDR];
  mt_callback_t mod_callback;
} mt_ipay_t;


// functions to initialize new protocols
static int init_mac_any_trans(void);
static int init_chn_int_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);

// functions to handle incoming recv messages
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_destab1(mt_desc_t* desc, nan_cli_destab1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_cli_dpay1(mt_desc_t* desc, nan_cli_dpay1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close1(mt_desc_t* desc, nan_end_close1_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close3(mt_desc_t* desc, nan_end_close3_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close5(mt_desc_t* desc, nan_end_close5_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_end_close7(mt_desc_t* desc, nan_end_close7_t* token, byte (*pid)[DIGEST_LEN]);

// miscallaneous helper functions
static mt_channel_t* new_channel(byte (*chn_addr)[MT_SZ_ADDR]);

static mt_ipay_t intermediary;

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_ipay_init(void){

  // TODO: get this to work
   cpu_init();

  intermediary.msgbuf = mt_messagebuffer_init();

  // load in hardcoded values
  byte* pp_temp;
  byte* faucet_pk_temp;
  byte* faucet_sk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_FAUCET_PK_HEX, &faucet_pk_temp) == MT_SZ_PK);
  tor_assert(mt_hex2bytes(MT_FAUCET_SK_HEX, &faucet_sk_temp) == MT_SZ_SK);

  memcpy(intermediary.pp, pp_temp, MT_SZ_PP);
  memcpy(intermediary.faucet_pk, faucet_pk_temp, MT_SZ_PK);
  memcpy(intermediary.faucet_sk, faucet_sk_temp, MT_SZ_SK);

  free(pp_temp);
  free(faucet_pk_temp);
  free(faucet_sk_temp);

  // setup crypto keys
  mt_crypt_keygen(&intermediary.pp, &intermediary.pk, &intermediary.sk);
  mt_pk2addr(&intermediary.pk, &intermediary.addr);
  mt_pk2addr(&intermediary.faucet_pk, &intermediary.faucet_addr);

  // set ledger
  intermediary.ledger.id[0] = 0;
  intermediary.ledger.id[1] = 0;
  intermediary.ledger.party = MT_PARTY_LED;

  // setup system parameters
  intermediary.fee = MT_FEE;
  intermediary.mac_balance = MT_INT_CHN_VAL * 10000;
  intermediary.chn_balance = 0;
  intermediary.chn_number = 0;

  // initialize channel containers
  intermediary.chns_setup = digestmap_new();
  intermediary.chns_estab = digestmap_new();
  intermediary.chns_transition = digestmap_new();
  intermediary.nan_state.map = digestmap_new();
  return MT_SUCCESS;
}

/**
 * Handle an incoming message from the given descriptor
 */
int mt_ipay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

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

    case MT_NTYPE_CHN_END_ESTAB1:;
      chn_end_estab1_t chn_end_estab1_tkn;
      if(unpack_chn_end_estab1(msg, size, &chn_end_estab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_estab1(desc, &chn_end_estab1_tkn, &pid);
      break;

    case MT_NTYPE_CHN_END_ESTAB3:;
      chn_end_estab3_t chn_end_estab3_tkn;
      if(unpack_chn_end_estab3(msg, size, &chn_end_estab3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_estab3(desc, &chn_end_estab3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP1:;
      nan_cli_setup1_t nan_cli_setup1_tkn;
      if(unpack_nan_cli_setup1(msg, size, &nan_cli_setup1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup1(desc, &nan_cli_setup1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP3:;
      nan_cli_setup3_t nan_cli_setup3_tkn;
      if(unpack_nan_cli_setup3(msg, size, &nan_cli_setup3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup3(desc, &nan_cli_setup3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_SETUP5:;
      nan_cli_setup5_t nan_cli_setup5_tkn;
      if(unpack_nan_cli_setup5(msg, size, &nan_cli_setup5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_setup5(desc, &nan_cli_setup5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB2:;
      nan_rel_estab2_t nan_rel_estab2_tkn;
      if(unpack_nan_rel_estab2(msg, size, &nan_rel_estab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab2(desc, &nan_rel_estab2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB4:;
      nan_rel_estab4_t nan_rel_estab4_tkn;
      if(unpack_nan_rel_estab4(msg, size, &nan_rel_estab4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab4(desc, &nan_rel_estab4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_DESTAB1:;
      nan_cli_destab1_t nan_cli_destab1_tkn;
      if(unpack_nan_cli_destab1(msg, size, &nan_cli_destab1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_destab1(desc, &nan_cli_destab1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_CLI_DPAY1:;
      nan_cli_dpay1_t nan_cli_dpay1_tkn;
      if(unpack_nan_cli_dpay1(msg, size, &nan_cli_dpay1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_cli_dpay1(desc, &nan_cli_dpay1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE1:;
      nan_end_close1_t nan_end_close1_tkn;
      if(unpack_nan_end_close1(msg, size, &nan_end_close1_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close1(desc, &nan_end_close1_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE3:;
      nan_end_close3_t nan_end_close3_tkn;
      if(unpack_nan_end_close3(msg, size, &nan_end_close3_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close3(desc, &nan_end_close3_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE5:;
      nan_end_close5_t nan_end_close5_tkn;
      if(unpack_nan_end_close5(msg, size, &nan_end_close5_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close5(desc, &nan_end_close5_tkn, &pid);
      break;

    case MT_NTYPE_NAN_END_CLOSE7:;
      nan_end_close7_t nan_end_close7_tkn;
      if(unpack_nan_end_close7(msg, size, &nan_end_close7_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_end_close7(desc, &nan_end_close7_tkn, &pid);
      break;

    default:
      result = MT_ERROR;
  }

  return result;
}

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_ipay_mac_balance(void){
  return intermediary.mac_balance;
}

/**
 * Return the balance of money locked up in channels
 */
int mt_ipay_chn_balance(void){
  return intermediary.chn_balance;
}

/**
 * Return the number of channels currently open
 */
int mt_ipay_chn_number(void){
  return intermediary.chn_number;
}

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_ipay_set_status(mt_desc_t* desc, int status){
  return mt_set_desc_status(intermediary.msgbuf, desc, status);
}


/**
 * Delete the state of the payment module
 */
int mt_ipay_clear(void){
  // Need to implement
  return MT_ERROR;
}

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_ipay_export(byte** export_out){
  *export_out = tor_malloc(sizeof(intermediary));
  memcpy(*export_out, &intermediary, sizeof(intermediary));
  return sizeof(intermediary);
}

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_ipay_import(byte* import){
  memcpy(&intermediary, import, sizeof(intermediary));
  return MT_SUCCESS;
}

/***************************** Ledger Calls *****************************/

static int init_mac_any_trans(void){

  byte pid[DIGEST_LEN] = {0};

  // initialize transfer token
  mac_any_trans_t token;
  token.val_from = MT_INT_CHN_VAL * 50;
  token.val_to = token.val_from - intermediary.fee;
  memcpy(token.from, intermediary.faucet_addr, MT_SZ_ADDR);
  memcpy(token.to, intermediary.addr, MT_SZ_ADDR);

  // update local data
  intermediary.mac_balance += token.val_to;

  // send setup message
  byte* msg;
  byte* signed_msg;
  int msg_size = pack_mac_any_trans(&token, &pid, &msg);
  int signed_msg_size = mt_create_signed_msg(msg, msg_size, &intermediary.faucet_pk,
					     &intermediary.faucet_sk, &signed_msg);
  int result = mt_buffer_message(intermediary.msgbuf, &intermediary.ledger, MT_NTYPE_MAC_ANY_TRANS,
				 signed_msg, signed_msg_size);
  tor_free(msg);
  tor_free(signed_msg);
  return result;
}

static int init_chn_int_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // initialize setup token
  chn_int_setup_t token;

  if(chn->edesc.party == MT_PARTY_CLI){
    token.val_from = intermediary.fee;
    token.val_to = 0;
  }
  else{
    token.val_from = MT_INT_CHN_VAL + intermediary.fee;
    token.val_to = MT_INT_CHN_VAL;
  }

  chn->balance = token.val_to;
  memcpy(token.from, intermediary.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->addr, MT_SZ_ADDR);
  // ignore channel token for now

  // update local data;
  intermediary.chn_number ++;
  intermediary.mac_balance -= token.val_from;
  intermediary.chn_balance += token.val_to;

  // send setup message
  byte* msg;
  byte* signed_msg;
  int msg_size = pack_chn_int_setup(&token, pid, &msg);
  int signed_msg_size = mt_create_signed_msg(msg, msg_size,
					     &intermediary.pk, &intermediary.sk, &signed_msg);
  int result = mt_buffer_message(intermediary.msgbuf, &intermediary.ledger, MT_NTYPE_CHN_INT_SETUP,
				 signed_msg, signed_msg_size);
  tor_free(msg);
  tor_free(signed_msg);
  return result;
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){

  if(mt_desc_comp(desc, &intermediary.ledger) != 0)
    return MT_ERROR;

  // if this is confirmation of a module-level ledger call then return the module callback
  byte zeros[DIGEST_LEN] = {0};
  if(memcmp(*pid, zeros, DIGEST_LEN) == 0){
    return MT_SUCCESS;
  }

  // if this is confirmation of mac_any_trans call then ignore and return success
  mt_channel_t* chn = digestmap_get(intermediary.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  // move channel to chns_setup
  byte digest[DIGEST_LEN];
  mt_desc2digest(&chn->edesc, &digest);
  digestmap_remove(intermediary.chns_transition, (char*)*pid);
  digestmap_set(intermediary.chns_setup, (char*)digest, chn);

  if(chn->callback.fn){
    mt_callback_t cb = chn->callback;
    int result = cb.fn(&cb.dref1, cb.arg2, cb.arg3, cb.arg4);
    tor_free(cb.arg3);
    return result;
  }
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int handle_chn_end_estab1(mt_desc_t* desc, chn_end_estab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  // setup chn
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  byte ipid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, ipid);

  // if existing channel is setup with this address then start establish protocol
  if((chn = digestmap_remove(intermediary.chns_setup, (char*)digest))){
    digestmap_set(intermediary.chns_transition, (char*)pid, chn);
    chn->callback.fn = NULL;

    chn_int_estab2_t reply;

    // fill out token
    reply.balance = chn->balance;

    byte* msg;
    int msg_size = pack_chn_int_estab2(&reply, pid, &msg);
    int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_CHN_INT_ESTAB2, msg, msg_size);
    tor_free(msg);
    return result;
  }

  // setup new channel at requested address
  if(intermediary.mac_balance >= intermediary.fee){
    chn = new_channel(&token->addr);
    chn->edesc = *desc;
    chn->callback = (mt_callback_t){.fn = mt_ipay_recv, .dref1 = *desc,
				    .arg2 = MT_NTYPE_CHN_END_ESTAB1};
    chn->callback.arg4 = pack_chn_end_estab1(token, pid, &chn->callback.arg3);
    digestmap_set(intermediary.chns_transition, (char*)ipid, chn);
    return init_chn_int_setup(chn, &ipid);
  }

  log_debug(LD_MT, "insufficient funds to start channel\n");
  return MT_ERROR;
}

static int handle_chn_end_estab3(mt_desc_t* desc, chn_end_estab3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  mt_channel_t* chn = digestmap_get(intermediary.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(intermediary.chns_transition, (char*)*pid);
  digestmap_set(intermediary.chns_estab, (char*)digest, chn);

  chn_int_estab4_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_chn_int_estab4(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_CHN_INT_ESTAB4, msg, msg_size);
  tor_free(msg);
  return result;
}

/******************************** Nano Setup ****************************/

static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]){
  printf("here\n");
  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);
  printf("here\n");

  nan_end_state_t* end_state = tor_calloc(1, sizeof(nan_end_state_t));
  digestmap_set(intermediary.nan_state.map, (char*)digest, end_state);
  printf("here\n");

  nan_int_setup2_t reply;

  // fill out token

  byte* msg;
  printf("here\n");
  int msg_size = pack_nan_int_setup2(&reply, pid, &msg);
  printf("here\n");
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP2, msg, msg_size);
  printf("here\n");
  tor_free(msg);
  return result;
}

static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity

  nan_int_setup4_t reply;

  // fill msg with correct values

  byte* msg;
  int msg_size = pack_nan_int_setup4(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP4, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity

  nan_int_setup6_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_setup6(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP6, msg, msg_size);
  tor_free(msg);
  return result;
}

/**************************** Nano Establish ****************************/

static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity

  nan_int_estab3_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_estab3(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_ESTAB3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  nan_int_estab5_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_estab5(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_ESTAB5, msg, msg_size);
  tor_free(msg);
  return result;
}

/************************ Nano Direct Establish *************************/

static int handle_nan_cli_destab1(mt_desc_t* desc, nan_cli_destab1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity

  nan_int_destab2_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_destab2(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_DESTAB2, msg, msg_size);
  tor_free(msg);
  return result;
}

/**************************** Nano Direct Pay ***************************/

static int handle_nan_cli_dpay1(mt_desc_t* desc, nan_cli_dpay1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity

  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);

  nan_end_state_t* end_state = digestmap_get(intermediary.nan_state.map, (char*)digest);
  if(!end_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  intermediary.chn_balance += token->nan_public.val_from;
  end_state->num_payments ++;

  nan_int_dpay2_t reply;

  // fill out token

  //mt_alert_payment(desc);
  mt_paymod_signal(MT_SIGNAL_PAYMENT_RECEIVED, desc);

  byte* msg;
  int msg_size = pack_nan_int_dpay2(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_DPAY2, msg, msg_size);
  tor_free(msg);
  return result;
}

/******************************* Nano Close *****************************/

static int handle_nan_end_close1(mt_desc_t* desc, nan_end_close1_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  nan_int_close2_t reply;
  // fill out token

  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);

  nan_end_state_t* end_state = digestmap_get(intermediary.nan_state.map, (char*)digest);
  if(!end_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // if channel was NOT a direct payment then update balance
  if(end_state->num_payments == 0){
    intermediary.chn_balance += token->total_val;
  }

  byte* msg;
  int msg_size = pack_nan_int_close2(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_CLOSE2, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_end_close3(mt_desc_t* desc, nan_end_close3_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  nan_int_close4_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_close4(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_CLOSE4, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_end_close5(mt_desc_t* desc, nan_end_close5_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  nan_int_close6_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_close6(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_CLOSE6, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_end_close7(mt_desc_t* desc, nan_end_close7_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  // verify token validity

  nan_int_close8_t reply;

  // fill out token

  byte* msg;
  int msg_size = pack_nan_int_close8(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_CLOSE8, msg, msg_size);
  tor_free(msg);
  return result;
}

/*************************** Helper Functions ***************************/

static mt_channel_t* new_channel(byte (*chn_addr)[MT_SZ_ADDR]){
  // initialize new channel
  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));
  memcpy(chn->addr, *chn_addr, MT_SZ_ADDR);
  return chn;
}
