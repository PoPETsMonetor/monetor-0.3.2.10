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
#pragma GCC diagnostic ignored "-Wstack-protector"

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
  mt_desc_t edesc;
  chn_int_data_t data;
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
  int mac_bal;
  int chn_bal;
  int chn_number;

  mt_desc_t led_desc;
  byte led_pk[MT_SZ_PK];

  int fee;
  int tax;

  digestmap_t* chn_states;
  digestmap_t* nan_states;

  digestmap_t* chns_setup;       // digest(edesc) -> chn
  digestmap_t* chns_estab;       // digest(edesc) -> chn

  digestmap_t* chns_transition;  // proto_id -> chn

  // structure to run message buffering functionality
  mt_msgbuf_t* msgbuf;
} mt_ipay_t;


// functions to initialize new protocols
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

  intermediary.msgbuf = mt_messagebuffer_init();

  // load in hardcoded values
  byte* pp_temp;
  byte* led_pk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_LED_PK_HEX, &led_pk_temp) == MT_SZ_PK);

  memcpy(intermediary.pp, pp_temp, MT_SZ_PP);
  memcpy(intermediary.led_pk, led_pk_temp, MT_SZ_PK);

  tor_free(pp_temp);
  tor_free(led_pk_temp);

  // setup crypto keys
  mt_crypt_keygen(&intermediary.pp, &intermediary.pk, &intermediary.sk);
  mt_pk2addr(&intermediary.pk, &intermediary.addr);

  // set ledger
  intermediary.led_desc.id[0] = 0;
  intermediary.led_desc.id[1] = 0;
  intermediary.led_desc.party = MT_PARTY_LED;

  // setup system parameters
  intermediary.fee = MT_FEE;
  intermediary.tax = MT_TAX;
  intermediary.mac_bal = 0;
  intermediary.chn_bal = 0;
  intermediary.chn_number = 0;

  // initialize channel containers
  intermediary.chns_setup = digestmap_new();
  intermediary.chns_estab = digestmap_new();
  intermediary.chns_transition = digestmap_new();
  intermediary.chn_states = digestmap_new();
  intermediary.nan_states = digestmap_new();
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
int mt_ipay_mac_bal(void){
  return intermediary.mac_bal;
}

/**
 * Return the balance of money locked up in channels
 */
int mt_ipay_chn_bal(void){
  return intermediary.chn_bal;
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

static int init_chn_int_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // initialize setup token
  chn_int_setup_t token;
  token.val_to = chn->data.public.int_bal;
  token.val_from = token.val_to + intermediary.fee;
  memcpy(token.from, intermediary.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->data.public.addr, MT_SZ_ADDR);
  memcpy(&token.chn_public, &chn->data.public, sizeof(chn_int_public_t));

  // update local data;
  intermediary.mac_bal -= get_options()->MoneTorPublicMint ? 0 : token.val_from;
  intermediary.chn_bal += token.val_to;

  // send setup message
  byte* msg;
  byte* signed_msg;
  int msg_size = pack_chn_int_setup(&token, pid, &msg);
  int signed_msg_size = mt_create_signed_msg(msg, msg_size,
					     &intermediary.pk, &intermediary.sk, &signed_msg);
  int result = mt_buffer_message(intermediary.msgbuf, &intermediary.led_desc, MT_NTYPE_CHN_INT_SETUP,
				 signed_msg, signed_msg_size);
  tor_free(msg);
  tor_free(signed_msg);
  return result;
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){

  if(mt_desc_comp(desc, &intermediary.led_desc) != 0)
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

  intermediary.chn_number++;
  memcpy(&chn->data.wallet.receipt, &token->receipt, sizeof(any_led_receipt_t));

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

  // setup chn
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  // if existing channel is setup with this address then start establish protocol
  if((chn = digestmap_remove(intermediary.chns_setup, (char*)digest))){

    digestmap_set(intermediary.chns_transition, (char*)pid, chn);
    chn->callback.fn = NULL;

    chn_int_estab2_t reply;

    // fill out reply token
    reply.verified = MT_CODE_VERIFIED;
    memcpy(reply.int_pk, intermediary.pk, MT_SZ_PK);
    memcpy(&reply.receipt, &chn->data.wallet.receipt, sizeof(any_led_receipt_t));

    // send reply token
    byte* msg;
    int msg_size = pack_chn_int_estab2(&reply, pid, &msg);
    int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_CHN_INT_ESTAB2, msg, msg_size);
    tor_free(msg);
    return result;
  }

  // setup new channel at requested address
  if((intermediary.mac_bal >= intermediary.fee) || get_options()->MoneTorPublicMint){

    int public_size = sizeof(int) + MT_SZ_COM;
    byte public[public_size];
    memcpy(public, &token->end_bal, sizeof(int));
    memcpy(public + sizeof(int), token->wcom, MT_SZ_COM);

    if(mt_zkp_verify(MT_ZKP_TYPE_1, &intermediary.pp, public, public_size, &token->zkp) != MT_SUCCESS)
      return MT_ERROR;

    byte ipid[DIGEST_LEN];
    mt_crypt_rand(DIGEST_LEN, ipid);

    chn = new_channel(&token->addr);
    chn->edesc = *desc;
    chn->data.public.end_bal = token->end_bal;
    chn->data.public.int_bal = token->int_bal;
    // save wcom
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

  mt_channel_t* chn = digestmap_get(intermediary.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_debug(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // verify wcom == wcom

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(intermediary.chns_transition, (char*)*pid);
  digestmap_set(intermediary.chns_estab, (char*)digest, chn);

  // fill out token
  chn_int_estab4_t reply;
  reply.success = MT_CODE_SUCCESS;
  if(mt_sig_sign(token->wcom, MT_SZ_COM, &intermediary.sk, &reply.sig) != MT_SUCCESS)
    return MT_ERROR;

  byte* msg;
  int msg_size = pack_chn_int_estab4(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_CHN_INT_ESTAB4, msg, msg_size);
  tor_free(msg);
  return result;
}

/******************************** Nano Setup ****************************/

static int handle_nan_cli_setup1(mt_desc_t* desc, nan_cli_setup1_t* token, byte (*pid)[DIGEST_LEN]){

  // make sure wallet has not been used before
  byte wpk_digest[DIGEST_LEN];
  mt_bytes2digest(token->wpk, MT_SZ_PK, &wpk_digest);

  if(digestmap_get(intermediary.chn_states, (char*)wpk_digest))
    return MT_ERROR;

  // only accept consensus values
  if(token->nan_public.val_from != MT_NAN_VAL + (MT_NAN_VAL * intermediary.tax) / 100)
    return MT_ERROR;

  if(token->nan_public.val_to != MT_NAN_VAL)
    return MT_ERROR;

  // public zkp parameters
  int cli_val = -token->nan_public.val_from;
  int public_size = MT_SZ_PK + sizeof(int) + MT_SZ_PK + MT_SZ_COM;
  byte public[public_size];
  memcpy(public, intermediary.pk, MT_SZ_PK);
  memcpy(public + MT_SZ_PK, &cli_val, sizeof(int));
  memcpy(public + MT_SZ_PK + sizeof(int), token->wpk, MT_SZ_PK);
  memcpy(public + MT_SZ_PK + sizeof(int) + MT_SZ_PK, token->wcom, MT_SZ_COM);

  if(mt_zkp_verify(MT_ZKP_TYPE_2, &intermediary.pp, public, public_size, &token->zkp) != MT_SUCCESS)
    return MT_ERROR;

  byte nwpk_digest[DIGEST_LEN];
  mt_bytes2digest(token->nwpk, MT_SZ_PK, &nwpk_digest);

  byte nan_digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &nan_digest);

  // update local intermediary state
  chn_int_state_t* chn_state = tor_calloc(1, sizeof(chn_int_state_t));
  chn_state->nan_public = token->nan_public;
  digestmap_set(intermediary.chn_states, (char*)wpk_digest, chn_state);

  chn_int_state_t* nchn_state = tor_calloc(1, sizeof(chn_int_state_t));
  digestmap_set(intermediary.chn_states, (char*)nwpk_digest, nchn_state);

  nan_int_state_t* nan_state = tor_calloc(1, sizeof(nan_int_state_t));
  memcpy(nan_state->data.wcom, token->wcom, MT_SZ_COM);
  nan_state->nan_public = token->nan_public;
  digestmap_set(intermediary.nan_states, (char*)nan_digest, nan_state);

  // create and send reply token
  nan_int_setup2_t reply;
  reply.verified = MT_CODE_VERIFIED;

  byte* msg;
  int msg_size = pack_nan_int_setup2(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP2, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_cli_setup3(mt_desc_t* desc, nan_cli_setup3_t* token, byte (*pid)[DIGEST_LEN]){

  // verify token
  if(token->refund_msg[0] != MT_CODE_REFUND)
    return MT_ERROR;

  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states,
					 (char*)(token->refund_msg + sizeof(byte)));
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  if(memcmp(nan_state->data.wcom, token->refund_msg + sizeof(byte) + DIGEST_LEN, MT_SZ_COM) != 0)
    return MT_ERROR;

  memset(nan_state, '\0', sizeof(nan_int_state_t));

  // create and send reply token
  nan_int_setup4_t reply;
  if(mt_sig_sign(token->refund_msg, sizeof(token->refund_msg), &intermediary.sk, &reply.sig)
     != MT_SUCCESS){
    return MT_ERROR;
  }

  byte* msg;
  int msg_size = pack_nan_int_setup4(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP4, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_cli_setup5(mt_desc_t* desc, nan_cli_setup5_t* token, byte (*pid)[DIGEST_LEN]){

  byte wpk[MT_SZ_PK];
  memcpy(wpk, token->revocation.msg + sizeof(byte), MT_SZ_PK);
  byte wpk_digest[DIGEST_LEN];
  mt_bytes2digest(token->revocation.msg + sizeof(byte), MT_SZ_PK, &wpk_digest);

  chn_int_state_t* chn_state = digestmap_get(intermediary.chn_states, (char*)wpk_digest);
  if(!chn_state){
    log_debug(LD_MT, "micropayment channel not recognized");
    return MT_ERROR;
  }

  if(mt_sig_verify(token->revocation.msg, sizeof(token->revocation.msg), &wpk, &token->revocation.sig)
     != MT_SUCCESS){
    return MT_ERROR;
  }

  // update local data
  byte nan_digest[DIGEST_LEN];
  mt_nanpub2digest(&chn_state->nan_public, &nan_digest);
  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states, (char*)nan_digest);
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  chn_state->revocation = token->revocation;
  nan_state->status = MT_CODE_READY;

  // create and fill out token
  nan_int_setup6_t reply;
  reply.success = MT_CODE_SUCCESS;

  byte* msg;
  int msg_size = pack_nan_int_setup6(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_SETUP6, msg, msg_size);
  tor_free(msg);
  return result;
}

/**************************** Nano Establish ****************************/

static int handle_nan_rel_estab2(mt_desc_t* desc, nan_rel_estab2_t* token, byte (*pid)[DIGEST_LEN]){

  // make sure wallet has not been used before
  byte wpk_digest[DIGEST_LEN];
  mt_bytes2digest(token->wpk, MT_SZ_PK, &wpk_digest);

  /** TEMPORARY DISABLE UNTIL CLOSE SWITCHES OUT WALLETS**/
  /* if(digestmap_get(intermediary.chn_states, (char*)wpk_digest)) */
  /*   return MT_ERROR; */

  // make sure nanopayment channel was already initialized by the client
  byte nan_digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &nan_digest);
  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states, (char*)nan_digest);
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // make sure that nanopayment channel is in the "ready" state
  if(nan_state->status != MT_CODE_READY){
    log_debug(LD_MT, "nanopayment channel is not accepting connections");
    return MT_ERROR;
  }

  // public zkp parameters
  int rel_val = token->nan_public.val_to;
  int public_size = MT_SZ_PK + sizeof(int) + MT_SZ_PK + MT_SZ_COM;
  byte public[public_size];
  memcpy(public, intermediary.pk, MT_SZ_PK);
  memcpy(public + MT_SZ_PK, &rel_val, sizeof(int));
  memcpy(public + MT_SZ_PK + sizeof(int), token->wpk, MT_SZ_PK);
  memcpy(public + MT_SZ_PK + sizeof(int) + MT_SZ_PK, token->wcom, MT_SZ_COM);

  if(mt_zkp_verify(MT_ZKP_TYPE_2, &intermediary.pp, public, public_size, &token->zkp) != MT_SUCCESS)
    return MT_ERROR;

  byte nwpk_digest[DIGEST_LEN];
  mt_bytes2digest(token->nwpk, MT_SZ_PK, &nwpk_digest);

  // update local intermediary state
  chn_int_state_t* chn_state = tor_calloc(1, sizeof(chn_int_state_t));
  digestmap_set(intermediary.chn_states, (char*)wpk_digest, chn_state);

  chn_int_state_t* nchn_state = tor_calloc(1, sizeof(chn_int_state_t));
  digestmap_set(intermediary.chn_states, (char*)nwpk_digest, nchn_state);

  memcpy(nan_state->data.wcom, token->wcom, MT_SZ_COM);

  // create and send reply token
  nan_int_estab3_t reply;
  reply.verified = MT_CODE_VERIFIED;

  byte* msg;
  int msg_size = pack_nan_int_estab3(&reply, pid, &msg);
  int result = mt_buffer_message(intermediary.msgbuf, desc, MT_NTYPE_NAN_INT_ESTAB3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_rel_estab4(mt_desc_t* desc, nan_rel_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;

  // verify token validity
  if(token->refund_msg[0] != MT_CODE_REFUND)
    return MT_ERROR;

  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states,
					 (char*)(token->refund_msg + sizeof(byte)));
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // update local info
  memset(nan_state, '\0', sizeof(nan_int_state_t));
  nan_state->data.end_state.num_payments = 0;
  memcpy(nan_state->data.end_state.last_hash, nan_state->nan_public.hash_tail, MT_SZ_HASH);
  nan_state->status = MT_CODE_ESTABLISHED;

  // create and send reply token
  nan_int_estab5_t reply;
  reply.success = MT_CODE_SUCCESS;
  mt_sig_sign(token->refund_msg, sizeof(token->refund_msg), &intermediary.sk, &reply.sig);

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
  byte digest[DIGEST_LEN];
  mt_nanpub2digest(&token->nan_public, &digest);

  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states, (char*)digest);
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // make sure that nanopayment channel is in the "ready" state
  if(nan_state->status != MT_CODE_READY){
    log_debug(LD_MT, "nanopayment channel is not accepting connections");
    return MT_ERROR;
  }

  // update local data
  nan_state->status = MT_CODE_DESTABLISHED;

  nan_int_destab2_t reply;
  reply.success = MT_CODE_SUCCESS;

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

  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states, (char*)digest);
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // update local information
  intermediary.chn_bal += token->nan_public.val_from;
  nan_state->data.end_state.num_payments ++;

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

  nan_int_state_t* nan_state = digestmap_get(intermediary.nan_states, (char*)digest);
  if(!nan_state){
    log_debug(LD_MT, "nanopayment channel not recognized");
    return MT_ERROR;
  }

  // if channel was NOT a direct payment then update balance
  if(nan_state->status != MT_CODE_DESTABLISHED){
    intermediary.chn_bal += token->total_val;
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

  mt_channel_t* chn = tor_malloc(sizeof(mt_channel_t));

  // initialize channel wallet info
  memcpy(chn->data.wallet.csk, intermediary.sk, MT_SZ_SK);

  // initialize channel public info
  chn->data.public.end_bal = 0;
  chn->data.public.int_bal = 0;
  memcpy(chn->data.public.cpk, intermediary.pk, MT_SZ_PK);
  memcpy(chn->data.public.addr, *chn_addr, MT_SZ_ADDR);
  return chn;
}
