// TODO: load in hard coded ledger keys and use them to verify receipts

/**
 * \file mt_cpay.c
 *
 * Implement logic for the client role in the moneTor payment scheme. The module
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
 *     <li>mt_cpay_init();
 *     <li>mt_cpay_pay()
 *     <li>mt_cpay_close()
 *     <li>mt_cpay_recv()
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "or.h"
#include "config.h"
#include "workqueue.h"
#include "cpuworker.h"
#include "mt_messagebuffer.h"
#include "mt_common.h"
#include "mt_cpay.h"
#include "mt_cclient.h"

#define NON_NULL 1

/**
 * Prototype for multi-thread function used to generate the expensive zkp proof
 */
typedef void (*work_task)(void*);
/**
 * Hold function and arguments necessary to execute callbacks on a channel once
 * the current protocol has completed
 */
typedef struct {
  // callback function
  int (*fn)(mt_desc_t*, mt_desc_t*);

  // args
  mt_desc_t dref1;
  mt_desc_t dref2;
} mt_callback_t;

typedef struct {
  int relay_type;
  int num_payments;

  struct timeval start_estab;
  struct timeval end_estab;
  struct timeval start_pay;
  struct timeval end_pay;
  struct timeval start_close;
} mt_log_info_t;

/**
 * Hold information necessary to maintain a single payment channel
 */
typedef struct {
  mt_desc_t rdesc;
  mt_desc_t idesc;
  chn_end_data_t data;

  mt_callback_t callback;

  mt_log_info_t log;
} mt_channel_t;

/**
 * Hold arguments need to run the multi-thread workqueue for the expensive zkp
 * proof generation
 */
typedef struct {
  mt_channel_t* chn;
  byte pid[DIGEST_LEN];
} mt_zkp_args_t;

/**
 * Single instance of a client payment object
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

  // channel states are encoded by which of these containers they are held
  smartlist_t* chns_setup;
  smartlist_t* chns_estab;
  smartlist_t* nans_setup;
  digestmap_t* nans_estab;        // digest(rdesc) -> channel
  digestmap_t* nans_destab;       // digest(rdesc) -> channel
  digestmap_t* nans_reqclosed;    // digest(rdesc) -> channel
  smartlist_t* chns_spent;

  // special container to hold channels in the middle of a protocol
  digestmap_t* chns_transition;   // pid -> channel

  // structure to run message buffering functionality
  mt_msgbuf_t* msgbuf;
} mt_cpay_t;

// functions to initialize new protocols
static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_setup1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_pay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_destab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_dpay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_cli_reqclose1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);
static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]);

// functions to handle incoming recv messages
static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup2(mt_desc_t* desc, nan_int_setup2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup4(mt_desc_t* desc, nan_int_setup4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_setup6(mt_desc_t* desc, nan_int_setup6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_estab6(mt_desc_t* desc, nan_rel_estab6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_pay2(mt_desc_t* desc, nan_rel_pay2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_destab2(mt_desc_t* desc, nan_int_destab2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_dpay2(mt_desc_t* desc, nan_int_dpay2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_rel_reqclose2(mt_desc_t* desc, nan_rel_reqclose2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]);
static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]);

// special helper functions for protocol steps involving a zkp proof generation
static int help_chn_end_estab1(void* args);
static int help_chn_int_estab4(void* args);
static int help_nan_end_close1(void* args);
static int help_nan_int_close8(void* args);

// miscallaneous helper functions
static int pay_helper(mt_desc_t* rdesc, mt_desc_t* idesc);
static int dpay_helper(mt_desc_t* rdesc, mt_desc_t* idesc);
static int estab_helper(mt_desc_t* rdesc, mt_desc_t* idesc);
static int destab_helper(mt_desc_t* rdesc, mt_desc_t* idesc);
static double timeval_diff(struct timeval t1, struct timeval t2);

static mt_channel_t* new_channel(void);
static int compare_chn_end_data(const void** a, const void** b);
static mt_channel_t* smartlist_idesc_remove(smartlist_t* list, mt_desc_t* desc);
static workqueue_reply_t cpu_task_estab(void* thread, void* arg);
static workqueue_reply_t cpu_task_nanestab(void* thread, void* arg);
static workqueue_reply_t cpu_task_nanclose(void* thread, void* arg);
static int pay_finish(mt_desc_t* rdesc, mt_desc_t* idesc);
static int estab_finish(mt_desc_t* rdesc, mt_desc_t* idesc);
static int close_finish(mt_desc_t* rdesc, mt_desc_t* idesc);

static mt_cpay_t client;

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_cpay_init(void){

  client.msgbuf = mt_messagebuffer_init();

  // load in hardcoded values
  byte* pp_temp;
  byte* led_pk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_LED_PK_HEX, &led_pk_temp) == MT_SZ_PK);

  memcpy(client.pp, pp_temp, MT_SZ_PP);
  memcpy(client.led_pk, led_pk_temp, MT_SZ_PK);

  tor_free(pp_temp);
  tor_free(led_pk_temp);

  // setup crypto keys
  mt_crypt_keygen(&client.pp, &client.pk, &client.sk);
  mt_pk2addr(&client.pk, &client.addr);

  // set ledger
  client.led_desc.id[0] = 0;
  client.led_desc.id[1] = 0;
  client.led_desc.party = MT_PARTY_LED;

  // setup system parameters
  client.fee = MT_FEE;
  client.tax = MT_WINDOW;
  client.mac_bal = 0;
  client.chn_bal = 0;
  client.chn_number = 0;

  // initialize channel containers
  client.chns_setup = smartlist_new();
  client.chns_estab = smartlist_new();
  client.nans_setup = smartlist_new();
  client.nans_estab = digestmap_new();
  client.nans_destab = digestmap_new();
  client.nans_reqclosed = digestmap_new();
  client.chns_spent = smartlist_new();
  client.chns_transition = digestmap_new();
  return MT_SUCCESS;
}

/**
 * Establish a channel wit hthe relay through a given intermediary. If
 * <b>rdesc<\b> and <b>idesc<\b> are equal, then the payment module will make a
 * direct payment to the intermediary module.
 */
int mt_cpay_establish(mt_desc_t* rdesc, mt_desc_t* idesc){

  // determine whether this is a standard or direct payment
  if(mt_desc_comp(rdesc, idesc) != 0){
    return estab_helper(rdesc, idesc);
  }
  else{
    return destab_helper(rdesc, idesc);
  }
}


/**
 * Send a single payment to the relay through a given intermediary. If
 * <b>rdesc<\b> and <b>idesc<\b> are equal, then the payment module will make a
 * direct payment to the intermediary module. If a payment request to a given
 * relay is made with a different intermediary BEFORE the previous
 * relay/intermediary payment pair was closed, then this function will return an
 * error.
 */
int mt_cpay_pay(mt_desc_t* rdesc, mt_desc_t* idesc){

   // determine whether this is a standard or direct payment
  if(mt_desc_comp(rdesc, idesc) != 0){
    return pay_helper(rdesc, idesc);
  }
  else{
    return dpay_helper(rdesc, idesc);
  }
}

/**
 * Handle standard establish from mt_cpay_estab(). Re-enter this payment again and
 * again until the establish is successful and estab_finish is called.
 */
static int estab_helper(mt_desc_t* rdesc, mt_desc_t* idesc){
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  // establish nanopayment channel if possible; callback pay_helper
  if((chn = smartlist_pop_last(client.nans_setup))){
    log_info(LD_MT, "MoneTor: Trying to establish a nanopayment channel ~ Callback estab_finish");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->rdesc = *rdesc;
    chn->callback = (mt_callback_t){.fn = estab_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_estab1(chn, &pid);
  }

  // set up nanopayment channel if possible; callback estab_helper
  if((chn = smartlist_pop_last(client.chns_estab))){
    log_info(LD_MT, "MoneTor: Trying to set up the nanopayment channel ~ Callback estab_helper");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = estab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_setup1(chn, &pid);
  }

  // establish channel if possible; callback estab_helper
  if((chn = smartlist_pop_last(client.chns_setup))){
    log_info(LD_MT, "MoneTor: Trying to establish a channel ~ Callback estab_helper");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = estab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_estab1(chn, &pid);
  }

  // set up channel if possible; callback estab_helper
  if((client.mac_bal >= MT_CHN_VAL_CLI + client.fee) || get_options()->MoneTorPublicMint){
    log_info(LD_MT, "MoneTor: Trying to set up the channel ~ Callback estab_helper");
    chn = new_channel();
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->idesc = *idesc;    // set channel intermediary
    chn->callback = (mt_callback_t){.fn = estab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_setup(chn, &pid);
  }

  log_warn(LD_MT, "MoneTor: insufficient funds to start channel");
  return MT_ERROR;
}

/**
 * Handle direct establish from mt_cpay_destab(). Re-enter this payment again and
 * again until the establish is successful and estab_finish is called.
 */
static int destab_helper(mt_desc_t* rdesc, mt_desc_t* idesc){
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  // establish nanopayment channel if possible; callback destab_finish
  if((chn = smartlist_idesc_remove(client.nans_setup, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->rdesc = *rdesc;
    chn->callback = (mt_callback_t){.fn = estab_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_destab1(chn, &pid);
  }

  // set up nanopayment channel if possible; callback destab_helper
  if((chn = smartlist_idesc_remove(client.chns_estab, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = destab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_setup1(chn, &pid);
  }

  // establish channel if possible; callback destab_helper
  if((chn = smartlist_idesc_remove(client.chns_setup, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = destab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_estab1(chn, &pid);
  }

  // setup channel if possible; callback destab_helper
  if((client.mac_bal >= MT_CHN_VAL_CLI + client.fee) || get_options()->MoneTorPublicMint){
    chn = new_channel();
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->idesc = *idesc;
    chn->callback = (mt_callback_t){.fn = destab_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_setup(chn, &pid);
  }

  log_warn(LD_MT, "MoneTor: insufficient funds to start channel");
  return MT_ERROR;
}

/**
 * Handle standard payments from mt_cpay_pay(). Re-enter this payment again and
 * again until the payment is successful and pay_finish is called.
 */
static int pay_helper(mt_desc_t* rdesc, mt_desc_t* idesc){
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  // close the standard nanopayment channel if possible; callback close_finish
  if((chn = digestmap_remove(client.nans_reqclosed, (char*)digest))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

  // if maximum payments reached then close the current channel
  if((chn = digestmap_get(client.nans_estab, (char*)digest)) &&
     chn->data.nan_state.num_payments == chn->data.nan_public.num_payments){
    log_info(LD_MT, "MoneTor: Maximum payments reached, we close the channel");
    digestmap_remove(client.nans_estab, (char*)digest);
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_reqclose1(chn, &pid);
  }

  // make payment if possible; callback pay_finish
  if((chn = digestmap_remove(client.nans_estab, (char*)digest))){
    log_info(LD_MT, "MoneTor: Trying to make the payment and set pay_finish as callback");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_pay1(chn, &pid);
  }

  // establish nanopayment channel if possible; callback pay_helper
  if((chn = smartlist_pop_last(client.nans_setup))){
    log_info(LD_MT, "MoneTor: Trying to establish a nanopayment channel ~ Callback pay_helper");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->rdesc = *rdesc;
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_estab1(chn, &pid);
  }

  // set up nanopayment channel if possible; callback pay_helper
  if((chn = smartlist_pop_last(client.chns_estab))){
    log_info(LD_MT, "MoneTor: Trying to set up the nanopayment channel ~ Callback pay_helper");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_setup1(chn, &pid);
  }

  // establish channel if possible; callback pay_helper
  if((chn = smartlist_pop_last(client.chns_setup))){
    log_info(LD_MT, "MoneTor: Trying to establish a channel ~ Callback pay_helper");
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_estab1(chn, &pid);
  }

  // set up channel if possible; callback pay_helper
  if((client.mac_bal >= MT_CHN_VAL_CLI + client.fee) || get_options()->MoneTorPublicMint){
    log_info(LD_MT, "MoneTor: Trying to set up the channel ~ Callback pay_helper");
    chn = new_channel();
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->idesc = *idesc;    // set channel intermediary
    chn->callback = (mt_callback_t){.fn = pay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_setup(chn, &pid);
  }

  log_warn(LD_MT, "MoneTor: insufficient funds to start channel");
  return MT_ERROR;
}

/**
 * Handle direct payments from mt_cpay_pay(). Re-enter this payment again and
 * again until the payment is successful and pay_finish is called.
 */
static int dpay_helper(mt_desc_t* rdesc, mt_desc_t* idesc){
  mt_channel_t* chn;
  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);
  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  // if maximum payments reached then close the current channel
  if((chn = digestmap_get(client.nans_destab, (char*)digest)) &&
     chn->data.nan_state.num_payments == chn->data.nan_public.num_payments){
    digestmap_remove(client.nans_destab, (char*)digest);
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

  // if maximum payments reached then close the current channel
  if((chn = digestmap_remove(client.nans_estab, (char*)digest)) &&
     chn->data.nan_state.num_payments == chn->data.nan_public.num_payments){
    digestmap_remove(client.nans_estab, (char*)digest);
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_reqclose1(chn, &pid);
  }

  // make direct payment if possible; callback pay_finish
  if((chn = digestmap_remove(client.nans_destab, (char*)digest))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = pay_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_dpay1(chn, &pid);
  }

  // establish nanopayment channel if possible; callback dpay_helper
  if((chn = smartlist_idesc_remove(client.nans_setup, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->rdesc = *rdesc;
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_destab1(chn, &pid);
  }

  // set up nanopayment channel if possible; callback dpay_helper
  if((chn = smartlist_idesc_remove(client.chns_estab, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_setup1(chn, &pid);
  }

  // establish channel if possible; callback dpay_helper
  if((chn = smartlist_idesc_remove(client.chns_setup, rdesc))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_estab1(chn, &pid);
  }

  // setup channel if possible; callback dpay_helper
  if((client.mac_bal >= MT_CHN_VAL_CLI + client.fee) || get_options()->MoneTorPublicMint){
    chn = new_channel();
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->idesc = *idesc;
    chn->callback = (mt_callback_t){.fn = dpay_helper, .dref1 = *rdesc, .dref2 = *idesc};
    return init_chn_end_setup(chn, &pid);
  }

  log_warn(LD_MT, "MoneTor: insufficient funds to start channel");
  return MT_ERROR;
}

/**
 * Close an existing payment channel with the given relay/intermediary pair
 */
int mt_cpay_close(mt_desc_t* rdesc, mt_desc_t* idesc){
  byte digest[DIGEST_LEN];
  mt_desc2digest(rdesc, &digest);

  byte pid[DIGEST_LEN];
  mt_crypt_rand(DIGEST_LEN, pid);

  mt_channel_t* chn;

  // close the standard nanopayment channel if possible; callback close_finish
  if((chn = digestmap_remove(client.nans_reqclosed, (char*)digest))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = close_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

  // send a request to close the channel if possible; callback close_helper
  if((chn = digestmap_remove(client.nans_estab, (char*)digest))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = mt_cpay_close, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_cli_reqclose1(chn, &pid);
  }

  // close the direct nanopayment channel if possible; callback close_finish
  if((chn = digestmap_remove(client.nans_destab, (char*)digest))){
    digestmap_set(client.chns_transition, (char*)pid, chn);
    chn->callback = (mt_callback_t){.fn = close_finish, .dref1 = *rdesc, .dref2 = *idesc};
    return init_nan_end_close1(chn, &pid);
  }

  log_warn(LD_MT, "descriptor is in an incorrect state to perform the requested action");
  return MT_ERROR;
}

/**
 * Handle an incoming message from the given descriptor
 */
int mt_cpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

  log_info(LD_MT, "MoneTor: Received %s from %s %" PRIu64 ".%" PRIu64 "",
	   mt_token_describe(type), mt_party_describe(desc->party),
	   desc->id[0], desc->id[1]);

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

    case MT_NTYPE_NAN_INT_SETUP2:;
      nan_int_setup2_t nan_int_setup2_tkn;
      if(unpack_nan_int_setup2(msg, size, &nan_int_setup2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup2(desc, &nan_int_setup2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_SETUP4:;
      nan_int_setup4_t nan_int_setup4_tkn;
      if(unpack_nan_int_setup4(msg, size, &nan_int_setup4_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup4(desc, &nan_int_setup4_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_SETUP6:;
      nan_int_setup6_t nan_int_setup6_tkn;
      if(unpack_nan_int_setup6(msg, size, &nan_int_setup6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_setup6(desc, &nan_int_setup6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_ESTAB6:;
      nan_rel_estab6_t nan_rel_estab6_tkn;
      if(unpack_nan_rel_estab6(msg, size, &nan_rel_estab6_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_estab6(desc, &nan_rel_estab6_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_PAY2:;
      nan_rel_pay2_t nan_rel_pay2_tkn;
      if(unpack_nan_rel_pay2(msg, size, &nan_rel_pay2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_pay2(desc, &nan_rel_pay2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_DESTAB2:;
      nan_int_destab2_t nan_int_destab2_tkn;
      if(unpack_nan_int_destab2(msg, size, &nan_int_destab2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_destab2(desc, &nan_int_destab2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_INT_DPAY2:;
      nan_int_dpay2_t nan_int_dpay2_tkn;
      if(unpack_nan_int_dpay2(msg, size, &nan_int_dpay2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_int_dpay2(desc, &nan_int_dpay2_tkn, &pid);
      break;

    case MT_NTYPE_NAN_REL_REQCLOSE2:;
      nan_rel_reqclose2_t nan_rel_reqclose2_tkn;
      if(unpack_nan_rel_reqclose2(msg, size, &nan_rel_reqclose2_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_nan_rel_reqclose2(desc, &nan_rel_reqclose2_tkn,  &pid);
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
      break;
  }

  if(result == MT_ERROR){
    log_warn(LD_MT, "MoneTor: protocoal error processing message");
  }
  return result;
}

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_cpay_mac_bal(void){
  return client.mac_bal;
}

/**
 * Return the balance of money locked up in channels
 */
int mt_cpay_chn_bal(void){
  return client.chn_bal;
}

/**
 * Return the number of channels currently open
 */
int mt_cpay_chn_number(void){
  return client.chn_number;
}

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_cpay_set_status(mt_desc_t* desc, int status){
  return mt_set_desc_status(client.msgbuf, desc, status);
}

/**
 * Delete the state of the payment module
 */
int mt_cpay_clear(void){
  // Need to implement
  return MT_ERROR;
}

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_cpay_export(byte** export_out){
  *export_out = tor_malloc(sizeof(client));
  memcpy(*export_out, &client, sizeof(client));
  return sizeof(client);
}

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_cpay_import(byte* import){
  memcpy(&client, import, sizeof(client));
  return MT_SUCCESS;
}

/**************************** Ledger Calls ******************************/

static int init_chn_end_setup(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // initialize setup token
  chn_end_setup_t token;
  token.val_to = chn->data.public.end_bal;
  token.val_from = token.val_to + client.fee;
  memcpy(token.from, client.addr, MT_SZ_ADDR);
  memcpy(token.chn, chn->data.public.addr, MT_SZ_ADDR);
  memcpy(&token.chn_public, &chn->data.public, sizeof(chn_end_public_t));

  // update local data
  client.chn_number ++;
  client.mac_bal -= get_options()->MoneTorPublicMint ? 0 : token.val_from;
  client.chn_bal += token.val_to;

  // send setup message
  byte* msg;
  byte* signed_msg;
  int msg_size = pack_chn_end_setup(&token, pid, &msg);
  int signed_msg_size = mt_create_signed_msg(msg, msg_size,
					     &chn->data.public.cpk, &chn->data.wallet.csk, &signed_msg);
  int result = mt_buffer_message(client.msgbuf, &client.led_desc, MT_NTYPE_CHN_END_SETUP,
				 signed_msg, signed_msg_size);
  tor_free(msg);
  tor_free(signed_msg);
  return result;
}

static int handle_any_led_confirm(mt_desc_t* desc, any_led_confirm_t* token, byte (*pid)[DIGEST_LEN]){

  if(mt_desc_comp(desc, &client.led_desc) != 0)
    return MT_ERROR;

  // if this is confirmation of mac_any_trans call then ignore and return success
  byte zeros[DIGEST_LEN] = {0};
  if(memcmp(*pid, zeros, DIGEST_LEN) == 0){
    return MT_SUCCESS;
  }

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.chns_setup, chn);

  if(chn->callback.fn){
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  }
  return MT_SUCCESS;
}

/****************************** Channel Establish ***********************/

static int init_chn_end_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // create arg list
  mt_zkp_args_t* args = tor_malloc(sizeof(mt_zkp_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  // if single threaded then just call procedures in series
  if(get_options()->MoneTorSingleThread){
    if(cpu_task_estab(NULL, args) != WQ_RPL_REPLY)
       return MT_ERROR;
    return help_chn_end_estab1(args);
  }

  // if not single threaded then offload task to a different cpu task/reply flow
  if(!cpuworker_queue_work(WQ_PRI_HIGH, cpu_task_estab, (work_task)help_chn_end_estab1, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_chn_end_estab1(void* args){

  // extract parameters
  mt_zkp_args_t* zkp_args = (mt_zkp_args_t*)args;
  mt_channel_t* chn = zkp_args->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, zkp_args->pid, DIGEST_LEN);
  tor_free(args);

  // create reply token
  chn_end_estab1_t token;
  token.end_bal = chn->data.wallet.end_bal;
  token.int_bal = chn->data.wallet.int_bal;
  memcpy(token.addr, chn->data.public.addr, MT_SZ_ADDR);
  memcpy(token.wcom, chn->data.public.wcom, MT_SZ_COM);
  memcpy(token.zkp, chn->data.wallet.zkp, MT_SZ_ZKP);

  // send message
  byte* msg;
  int msg_size = pack_chn_end_estab1(&token, &pid, &msg);
  int result =  mt_buffer_message(client.msgbuf, &chn->idesc, MT_NTYPE_CHN_END_ESTAB1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_chn_int_estab2(mt_desc_t* desc, chn_int_estab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // validate token
  if(token->verified != MT_CODE_VERIFIED)
    return MT_ERROR;

  byte int_addr[MT_SZ_ADDR];
  mt_pk2addr(&token->int_pk, &int_addr);

  // verify receipt to make sure the intermediary deposited claimed funds
  if(mt_receipt_verify(&token->receipt, &client.led_pk) != MT_SUCCESS ||
     token->receipt.val != chn->data.public.int_bal ||
     memcmp(token->receipt.from, int_addr, MT_SZ_ADDR) != 0 ||
     memcmp(token->receipt.to, chn->data.public.addr, MT_SZ_ADDR) != 0){
    return MT_ERROR;
   }

  memcpy(chn->data.wallet.int_pk, token->int_pk, MT_SZ_PK);

  // create and fill reply token
  chn_end_estab3_t reply;
  memcpy(reply.wcom, chn->data.wallet.wcom, MT_SZ_COM);

  // send reply message
  byte* msg;
  int msg_size = pack_chn_end_estab3(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_CHN_END_ESTAB3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_chn_int_estab4(mt_desc_t* desc, chn_int_estab4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message;
  if(mt_sig_verify(chn->data.wallet.wcom, MT_SZ_COM, &chn->data.wallet.int_pk, &token->sig)
     != MT_SUCCESS){
    return MT_ERROR;
  }

  // prepare nanopayment channel token now
  mt_zkp_args_t* args = tor_malloc(sizeof(mt_zkp_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  // if single threaded then just call procedures in series
  if(get_options()->MoneTorSingleThread){
    if(cpu_task_nanestab(NULL, args) != WQ_RPL_REPLY)
       return MT_ERROR;
    return help_chn_int_estab4(args);
  }

  // if not single threaded then offload task to a different cpu task/reply flow
  if(!cpuworker_queue_work(WQ_PRI_HIGH, cpu_task_nanestab, (work_task)help_chn_int_estab4, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_chn_int_estab4(void* args){

  // extract parameters
  mt_channel_t* chn = ((mt_zkp_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_zkp_args_t*)args)->pid, DIGEST_LEN);
  tor_free(args);

  // save token to channel
  digestmap_remove(client.chns_transition, (char*)pid);
  smartlist_add(client.chns_estab, chn);

  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************** Nano Setup ****************************/

static int init_nan_cli_setup1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // create hash chain and save it to local state
  byte hc_head[MT_SZ_HASH];
  mt_crypt_rand(MT_SZ_HASH, hc_head);
  mt_hc_create(MT_NAN_LEN, &hc_head, &chn->data.nan_wallet.hc);

  // define nanopayment parameters in local state
  chn->data.nan_public.val_from = MT_NAN_VAL + (MT_NAN_VAL * client.tax) / 100;
  chn->data.nan_public.val_to = MT_NAN_VAL;
  chn->data.nan_public.num_payments = MT_NAN_LEN;
  memcpy(chn->data.nan_public.hash_tail, chn->data.nan_wallet.hc[0], MT_SZ_HASH);

  // make token
  nan_cli_setup1_t token;
  memcpy(token.wpk, chn->data.wallet.wpk, MT_SZ_PK);
  memcpy(token.wpk_nan, chn->data.wallet_nan.wpk, MT_SZ_PK);
  memcpy(token.wcom, chn->data.wallet_nan.wcom, MT_SZ_COM);
  memcpy(token.zkp, chn->data.wallet_nan.zkp, MT_SZ_ZKP);
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));

  // update channel data
  memcpy(&chn->data.nan_public, &token.nan_public, sizeof(nan_any_public_t));
  memcpy(chn->data.nan_state.last_hash, chn->data.nan_wallet.hc[0], MT_SZ_HASH);
  chn->data.nan_state.num_payments = 0;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_setup1(&token, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->idesc, MT_NTYPE_NAN_CLI_SETUP1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_setup2(mt_desc_t* desc, nan_int_setup2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message
  if(token->verified != MT_CODE_VERIFIED)
    return MT_ERROR;

  // Fill in refund token
  chn_end_refund_t* refund = &chn->data.refund;
  memset(refund, '\0', sizeof(chn_end_refund_t));
  refund->code = MT_CODE_REFUND;
  memcpy(refund->wpk, chn->data.wallet_nan.wpk, MT_SZ_PK);
  refund->end_bal = chn->data.wallet_nan.end_bal;

  // Parts of refund token involved in blind signature
  byte nan_digest[DIGEST_LEN];
  mt_nanpub2digest(&chn->data.nan_public, &nan_digest);
  refund->msg[0] = (byte)refund->code;
  memcpy(refund->msg + sizeof(byte), nan_digest, DIGEST_LEN);
  memcpy(refund->msg + sizeof(byte) + DIGEST_LEN, chn->data.wallet_nan.wcom, MT_SZ_COM);

  // Create and send reply token
  nan_cli_setup3_t reply;
  memcpy(reply.refund_msg, refund->msg, sizeof(refund->msg));

  byte* msg;
  int msg_size = pack_nan_cli_setup3(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_NAN_CLI_SETUP3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_setup4(mt_desc_t* desc, nan_int_setup4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check validity of incoming message
  if(mt_sig_verify(chn->data.refund.msg, sizeof(chn->data.refund.msg),
		   &chn->data.wallet_nan.int_pk, &token->sig) != MT_SUCCESS){
    return MT_ERROR;
  }

  // create and send reply message
  nan_cli_setup5_t reply;
  reply.revocation.msg[0] = (byte)MT_CODE_REVOCATION;
  memcpy(reply.revocation.msg + sizeof(byte), &chn->data.wallet.wpk, MT_SZ_PK);
  mt_sig_sign(reply.revocation.msg, sizeof(reply.revocation.msg), &chn->data.wallet.wsk,
  	      &reply.revocation.sig);

  byte* msg;
  int msg_size = pack_nan_cli_setup5(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_NAN_CLI_SETUP5, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_setup6(mt_desc_t* desc, nan_int_setup6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  digestmap_remove(client.chns_transition, (char*)*pid);
  smartlist_add(client.nans_setup, chn);

  if(chn->callback.fn){
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  }
  return MT_SUCCESS;
}

/**************************** Nano Establish ****************************/

static int init_nan_cli_estab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record start of nanopayment channel for log
  chn->log.relay_type = mt_cclient_relay_type(&chn->rdesc);
  tor_assert(chn->log.relay_type == MT_MIDDLE || chn->log.relay_type == MT_EXIT);
  tor_gettimeofday(&chn->log.start_estab);

  // make token
  nan_cli_estab1_t token;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_estab1(&token, pid, &msg);
  int result = mt_buffer_message_multidesc(client.msgbuf, &chn->rdesc, &chn->idesc,
					   MT_NTYPE_NAN_CLI_ESTAB1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_rel_estab6(mt_desc_t* desc, nan_rel_estab6_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check token validity
  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  // update local data
  chn->data.nan_state.num_payments = 0;
  memcpy(chn->data.nan_state.last_hash, chn->data.nan_public.hash_tail, MT_SZ_HASH);

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)digest, chn);

  // record start of nanopayment channel for log
  tor_gettimeofday(&chn->log.end_estab);

  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************* Nano Pay *******************************/

static int init_nan_cli_pay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record logging info
  if(!chn->log.start_pay.tv_sec && !chn->log.start_pay.tv_usec)
    tor_gettimeofday(&chn->log.start_pay);

  // make token
  nan_cli_pay1_t token;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));
  memcpy(token.preimage, &chn->data.nan_wallet.hc[chn->data.nan_state.num_payments], MT_SZ_HASH);

  // update channel data
  client.chn_bal -= chn->data.nan_public.val_from;
  chn->data.wallet.end_bal -= chn->data.nan_public.val_from;
  chn->data.nan_state.num_payments ++;
  memcpy(chn->data.nan_state.last_hash, token.preimage, MT_SZ_HASH);

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_pay1(&token, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->rdesc, MT_NTYPE_NAN_CLI_PAY1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_rel_pay2(mt_desc_t* desc, nan_rel_pay2_t* token, byte (*pid)[DIGEST_LEN]){

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_estab, (char*)digest, chn);

  // record logging info
  if(!chn->log.end_pay.tv_sec && !chn->log.end_pay.tv_usec){
    tor_gettimeofday(&chn->log.end_pay);
  }
  chn->log.num_payments++;

  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/************************ Nano Direct Establish *************************/

static int init_nan_cli_destab1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record start of nanopayment channel for log
  chn->log.relay_type = mt_cclient_relay_type(&chn->idesc);
  tor_assert(chn->log.relay_type == MT_GUARD);
  tor_gettimeofday(&chn->log.start_estab);

  // intiate token
  nan_cli_destab1_t token;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_destab1(&token, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->idesc, MT_NTYPE_NAN_CLI_DESTAB1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_destab2(mt_desc_t* desc, nan_int_destab2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // check token validity
  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_destab, (char*)digest, chn);

  // record start of nanopayment channel for log
  tor_gettimeofday(&chn->log.end_estab);

  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/**************************** Nano Direct Pay ***************************/

static int init_nan_cli_dpay1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record logging info
  if(!chn->log.start_pay.tv_sec && !chn->log.start_pay.tv_usec)
    tor_gettimeofday(&chn->log.start_pay);

  // intiate token
  nan_cli_dpay1_t token;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));
  memcpy(token.preimage, chn->data.nan_wallet.hc[chn->data.nan_state.num_payments], MT_SZ_HASH);

  // update balances
  client.chn_bal -= chn->data.nan_public.val_from;
  chn->data.wallet.end_bal -= chn->data.nan_public.val_from;
  chn->data.nan_state.num_payments ++;
  memcpy(chn->data.nan_state.last_hash, token.preimage, MT_SZ_HASH);

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_dpay1(&token, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->idesc, MT_NTYPE_NAN_CLI_DPAY1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_dpay2(mt_desc_t* desc, nan_int_dpay2_t* token, byte (*pid)[DIGEST_LEN]){

  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_destab, (char*)digest, chn);

  // record logging info
  if(!chn->log.end_pay.tv_sec && !chn->log.end_pay.tv_usec)
    tor_gettimeofday(&chn->log.end_pay);
  chn->log.num_payments++;

  if(chn->callback.fn){
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  }
  return MT_SUCCESS;
}

/****************************** Nano Req Close **************************/

static int init_nan_cli_reqclose1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record time at the start of closing for log
  if(chn->log.relay_type == MT_MIDDLE || chn->log.relay_type == MT_EXIT)
    tor_gettimeofday(&chn->log.start_close);

  // intiate token
  nan_cli_reqclose1_t token;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));
  token.reqclose = MT_CODE_REQCLOSE;

  // send message
  byte* msg;
  int msg_size = pack_nan_cli_reqclose1(&token, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->rdesc, MT_NTYPE_NAN_CLI_REQCLOSE1, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_rel_reqclose2(mt_desc_t* desc, nan_rel_reqclose2_t* token, byte (*pid)[DIGEST_LEN]){
  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);
  digestmap_remove(client.chns_transition, (char*)*pid);
  digestmap_set(client.nans_reqclosed, (char*)digest, chn);

  // check validity incoming message
  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/******************************* Nano Close *****************************/

static int init_nan_end_close1(mt_channel_t* chn, byte (*pid)[DIGEST_LEN]){

  // record time at the start of closing for log
  if(chn->log.relay_type == MT_GUARD)
    tor_gettimeofday(&chn->log.start_close);

  mt_zkp_args_t* args = tor_malloc(sizeof(mt_zkp_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  // if single threaded then just call procedures in series
  if(get_options()->MoneTorSingleThread){
    if(cpu_task_nanclose(NULL, args) != WQ_RPL_REPLY)
       return MT_ERROR;
    return help_nan_end_close1(args);
  }

  // if not single threaded then offload task to a different cpu task/reply flow
  if(!cpuworker_queue_work(WQ_PRI_HIGH, cpu_task_nanclose, (work_task)help_nan_end_close1, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_nan_end_close1(void* args){
  // extract parameters
  mt_zkp_args_t* zkp_args = (mt_zkp_args_t*)args;
  mt_channel_t* chn = zkp_args->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, zkp_args->pid, DIGEST_LEN);
  tor_free(args);

  // intiate token
  nan_end_close1_t token;
  token.total_val = chn->data.nan_state.num_payments * chn->data.nan_public.val_from;
  token.num_payments = chn->data.nan_state.num_payments;
  memcpy(&token.nan_public, &chn->data.nan_public, sizeof(nan_any_public_t));
  memcpy(token.wpk, chn->data.wallet.wpk, MT_SZ_PK);
  memcpy(token.wcom_new, chn->data.wallet_new.wcom, MT_SZ_COM);
  memcpy(token.preimage, chn->data.nan_state.last_hash, MT_SZ_HASH);
  memcpy(token.zkp_new, chn->data.wallet_new.zkp, MT_SZ_ZKP);

  // send message
  byte* msg;
  int msg_size = pack_nan_end_close1(&token, &pid, &msg);
  int result = mt_buffer_message(client.msgbuf, &chn->idesc, MT_NTYPE_NAN_END_CLOSE1, msg, msg_size);
  tor_free(msg);
  return result;
}


static int handle_nan_int_close2(mt_desc_t* desc, nan_int_close2_t* token, byte (*pid)[DIGEST_LEN]){
  (void)desc;


  if(token->verified != MT_CODE_SUCCESS)
    return MT_ERROR;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // refund message to be signed
  nan_end_close3_t reply;
  reply.refund_msg[0] = (byte)MT_CODE_REFUND;
  memcpy(reply.refund_msg + sizeof(byte), chn->data.wallet_new.wcom, MT_SZ_COM);
  memcpy(&reply.nan_public, &chn->data.nan_public, sizeof(reply.nan_public));

  byte* msg;
  int msg_size = pack_nan_end_close3(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_NAN_END_CLOSE3, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close4(mt_desc_t* desc, nan_int_close4_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  //verify signature
  byte refund_msg[sizeof(byte) + MT_SZ_COM];
  refund_msg[0] = (byte)MT_CODE_REFUND;
  memcpy(refund_msg + sizeof(byte), chn->data.wallet_new.wcom, MT_SZ_COM);

  if(mt_sig_verify(refund_msg, sizeof(refund_msg),
		   &chn->data.wallet_new.int_pk, &token->sig) != MT_SUCCESS){
    return MT_ERROR;
  }

  // create reply message
  nan_end_close5_t reply;
  memcpy(reply.wpk_nan, chn->data.wallet_nan.wpk, MT_SZ_PK);
  reply.revocation.msg[0] = (byte)MT_CODE_REVOCATION;
  memcpy(reply.revocation.msg + sizeof(byte), &chn->data.wallet_nan.wpk, MT_SZ_PK);
  mt_sig_sign(reply.revocation.msg, sizeof(reply.revocation.msg), &chn->data.wallet_nan.wsk,
  	      &reply.revocation.sig);

  byte* msg;
  int msg_size = pack_nan_end_close5(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_NAN_END_CLOSE5, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close6(mt_desc_t* desc, nan_int_close6_t* token, byte (*pid)[DIGEST_LEN]){


  if(token->verified != MT_CODE_VERIFIED)
    return MT_ERROR;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  nan_end_close7_t reply;
  memcpy(&reply.nan_public, &chn->data.nan_public, sizeof(reply.nan_public));
  memcpy(reply.wcom_new, chn->data.wallet_new.wcom, sizeof(reply.wcom_new));

  byte* msg;
  int msg_size = pack_nan_end_close7(&reply, pid, &msg);
  int result = mt_buffer_message(client.msgbuf, desc, MT_NTYPE_NAN_END_CLOSE7, msg, msg_size);
  tor_free(msg);
  return result;
}

static int handle_nan_int_close8(mt_desc_t* desc, nan_int_close8_t* token, byte (*pid)[DIGEST_LEN]){
  (void)token;
  (void)desc;

  mt_channel_t* chn = digestmap_get(client.chns_transition, (char*)*pid);
  if(chn == NULL){
    log_warn(LD_MT, "protocol id not recognized");
    return MT_ERROR;
  }

  // verify token validity
  if(token->success != MT_CODE_SUCCESS)
    return MT_ERROR;
  if(mt_sig_verify(chn->data.wallet_new.wcom, MT_SZ_COM, &chn->data.wallet_new.int_pk, &token->sig)
     != MT_SUCCESS)
    return MT_ERROR;

  // new wallet becomes current wallet
  memcpy(&chn->data.wallet, &chn->data.wallet_new, sizeof(chn->data.wallet));

  mt_zkp_args_t* args = tor_malloc(sizeof(mt_zkp_args_t));
  args->chn = chn;
  memcpy(args->pid, *pid, DIGEST_LEN);

  // if single threaded then just call procedures in series
  if(get_options()->MoneTorSingleThread){
    if(cpu_task_nanestab(NULL, args) != WQ_RPL_REPLY)
       return MT_ERROR;
    return help_nan_int_close8(args);
  }

  // if not single threaded then offload task to a different cpu task/reply flow
  if(!cpuworker_queue_work(WQ_PRI_HIGH, cpu_task_nanestab, (work_task)help_nan_int_close8, args))
    return MT_ERROR;
  return MT_SUCCESS;
}

static int help_nan_int_close8(void* args){
  mt_channel_t* chn = ((mt_zkp_args_t*)args)->chn;
  byte pid[DIGEST_LEN];
  memcpy(pid, ((mt_zkp_args_t*)args)->pid, DIGEST_LEN);
  tor_free(args);
  digestmap_remove(client.chns_transition, (char*)pid);

  // if sufficient funds left then move channel to establish state, otherwise move to spent
  if(chn->data.wallet.end_bal >= MT_NAN_LEN * (MT_NAN_VAL + (MT_NAN_VAL * client.tax) / 100)){
    //new wallet becomes old wallet
    smartlist_add(client.chns_estab, chn);
  }
  else{
    smartlist_add(client.chns_spent, chn);
  }

  // log nanopayment channel statistics for analysis
  const char* type_str;
  if(chn->log.relay_type == MT_GUARD)
    type_str = "guard";
  else if(chn->log.relay_type == MT_MIDDLE)
    type_str = "middle";
  else if(chn->log.relay_type == MT_EXIT)
    type_str = "exit";
  else
    tor_assert(0);

  struct timeval now;
  tor_gettimeofday(&now);

  double lifetime = timeval_diff(now, chn->log.start_estab);
  double tt_establish = timeval_diff(chn->log.end_estab, chn->log.start_estab);
  double tt_payment = timeval_diff(chn->log.end_pay, chn->log.start_pay);
  double tt_close = timeval_diff(now, chn->log.start_close);

  log_info(LD_MT, "MoneTor: mt_log_nanochannel: {time: %ld, type: %s, numpayments: %d, lifetime: %lf, ttestablish: %lf, ttpayment: %lf, ttclose: %lf}",
	   approx_time(),
	   type_str,
	   chn->log.num_payments,
	   lifetime,
	   tt_establish,
	   tt_payment,
	   tt_close);

  memset(&chn->log, '\0', sizeof(chn->log));

  if(chn->callback.fn)
    return chn->callback.fn(&chn->callback.dref1, &chn->callback.dref2);
  return MT_SUCCESS;
}

/***************************** Helper Functions *************************/

static mt_channel_t* new_channel(void){

  mt_channel_t* chn = tor_calloc(1, sizeof(mt_channel_t));

  // initialize channel wallet info
  chn->data.wallet.end_bal = MT_CHN_VAL_CLI;
  chn->data.wallet.int_bal = 0;
  memcpy(chn->data.wallet.csk, client.sk, MT_SZ_SK);
  mt_crypt_keygen(&client.pp, &chn->data.wallet.wpk, &chn->data.wallet.wsk);
  mt_crypt_rand(MT_SZ_HASH, chn->data.wallet.rand);

  // initialize channel public info
  chn->data.public.end_bal = chn->data.wallet.end_bal;
  chn->data.public.int_bal = 0;
  memcpy(chn->data.public.cpk, client.pk, MT_SZ_PK);
  mt_crypt_rand(MT_SZ_ADDR, chn->data.public.addr);

  // create wallet commitment
  byte msg[MT_SZ_PK + sizeof(int)];
  memcpy(msg, chn->data.wallet.wpk, MT_SZ_PK);
  memcpy(msg + MT_SZ_PK, &chn->data.wallet.end_bal, sizeof(int));
  mt_com_commit(msg, MT_SZ_PK + sizeof(int), &chn->data.wallet.rand, &chn->data.wallet.wcom);
  memcpy(chn->data.public.wcom, chn->data.wallet.wcom, MT_SZ_COM);

  return chn;
}

static int compare_chn_end_data(const void** a, const void** b){

  if(((mt_channel_t*)(*a))->data.wallet.end_bal > ((mt_channel_t*)(*b))->data.wallet.end_bal)
    return -1;

  if(((mt_channel_t*)(*a))->data.wallet.end_bal < ((mt_channel_t*)(*b))->data.wallet.end_bal)
    return 1;

  return MT_SUCCESS;
}

static workqueue_reply_t cpu_task_estab(void* thread, void* args){
  (void)thread;

  mt_zkp_args_t* zkp_args = (mt_zkp_args_t*)args;
  mt_channel_t* chn = zkp_args->chn;

  // public zkp parameters
  int public_size = sizeof(int) + MT_SZ_COM;
  byte public[public_size];
  memcpy(public, &chn->data.wallet.end_bal, sizeof(int));
  memcpy(public + sizeof(int), chn->data.wallet.wcom, MT_SZ_COM);

  // prove knowledge of the following values
  int hidden_size = MT_SZ_PK + MT_SZ_SK + MT_SZ_HASH;
  byte hidden[hidden_size];
  memcpy(hidden, chn->data.wallet.wpk, MT_SZ_PK);
  memcpy(hidden + MT_SZ_PK, chn->data.wallet.wsk, MT_SZ_SK);
  memcpy(hidden + MT_SZ_PK + MT_SZ_SK, chn->data.wallet.rand, MT_SZ_HASH);

  // record zkp
  mt_zkp_prove(MT_ZKP_TYPE_1, &client.pp, public, public_size,
	       hidden, hidden_size, &chn->data.wallet.zkp);

  return WQ_RPL_REPLY;
}

static workqueue_reply_t cpu_task_nanestab(void* thread, void* args){
  (void)thread;

  mt_channel_t* chn = ((mt_zkp_args_t*)args)->chn;

  if(mt_wallet_create(&client.pp, -(MT_NAN_VAL + (MT_NAN_VAL * client.tax) / 100),
		      &chn->data.wallet, &chn->data.wallet_nan) != MT_SUCCESS)
    return WQ_RPL_ERROR;
  return WQ_RPL_REPLY;
}

static workqueue_reply_t cpu_task_nanclose(void* thread, void* args){
  (void)thread;

  // extract parameters
  mt_channel_t* chn = ((mt_zkp_args_t*)args)->chn;
  if(mt_wallet_create(&client.pp, -(MT_NAN_VAL + (MT_NAN_VAL * client.tax) / 100),
		      &chn->data.wallet, &chn->data.wallet_new) != MT_SUCCESS)
    return WQ_RPL_ERROR;
  return WQ_RPL_REPLY;
}

static int estab_finish(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)idesc;
  return mt_paymod_signal(MT_SIGNAL_ESTABLISH_SUCCESS, rdesc);
}

static int pay_finish(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)idesc;
  return mt_paymod_signal(MT_SIGNAL_PAYMENT_SUCCESS, rdesc);
}

static int close_finish(mt_desc_t* rdesc, mt_desc_t* idesc){
  (void)idesc;

  smartlist_sort(client.nans_setup, compare_chn_end_data);
  //return mt_close_success(rdesc, idesc, MT_SUCCESS);
  return mt_paymod_signal(MT_SIGNAL_CLOSE_SUCCESS, rdesc);
}

static mt_channel_t* smartlist_idesc_remove(smartlist_t* list, mt_desc_t* desc){

  SMARTLIST_FOREACH_BEGIN(list, mt_channel_t*, elm){
    if(mt_desc_comp(&elm->idesc, desc) == 0){
      smartlist_remove(list, elm);
      elm_sl_len--;
      return elm;
    }
  } SMARTLIST_FOREACH_END(elm);
  return NULL;
}

static double timeval_diff(struct timeval t1, struct timeval t2){
  time_t sec_diff = t1.tv_sec - t2.tv_sec;
  long usec_diff = t1.tv_usec - t2.tv_usec;
  return (sec_diff * 1000000.0 + usec_diff) / 1000000.0;
}
