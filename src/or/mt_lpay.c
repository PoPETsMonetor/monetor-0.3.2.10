/**
 * \file mt_pay.c
 * \brief Implement a simple ledger for operating the moneTor payment
 * system. It most closely models the Ethereum ledger paradigm in which accounts
 * are maintained in the form of address->data pairings. This means that the
 * entire state of the system is immediately accessible at any time, which
 * stands in contrast to bitcoin model which keeps a permanent log of historical
 * events. The moneTor ledger currently recognizes two types of addresses:
 *
 *     Standard - Normal address owned by a user which can be used to transfer
 *     funds on the ledger
 *
 *     Channel - Special address that is used by two people to hold
 *     ledger-information about an open micropayment channel between the two
 *     parties. Channels are modeled as a simple state machine (states
 *     enumerated in chn_state) with some external information about balances
 *     and timeouts.
 *
 * The outward-facing interface for the ledger consist of two methods:
 *
 *     post() - Accepts a message to update the ledger state
 *     query() - Accepts a message to retrieve information about the ledger
 *
 * Unless otherwise noted, all functions return 0 for success or -1 for failure.
 */

#pragma GCC diagnostic ignored "-Wswitch-enum"
#pragma GCC diagnostic ignored "-Wstack-protector"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "or.h"
#include "config.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_messagebuffer.h"
#include "mt_lpay.h"

//TODO move resolve to separate algs file
//TODO enforce nonce

/**
 * Single instance of a ledger payment object.
 */
typedef struct {

  digestmap_t* mac_accounts;
  digestmap_t* chn_accounts;

  byte pp[MT_SZ_PP];
  int fee;
  int tax;
  int epoch;
  int window;

  byte aut_pk[MT_SZ_PK];
  byte aut_addr[MT_SZ_ADDR];

  byte pk[MT_SZ_PK];
  byte sk[MT_SZ_SK];
  byte led_addr[MT_SZ_ADDR];

  // structure to run message buffering functionality
  mt_msgbuf_t* msgbuf;
} mt_lpay_t;

static mt_lpay_t ledger;
static mt_payment_public_t public;

// private token handlers
int handle_mac_aut_mint(mac_aut_mint_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_mac_any_trans(mac_any_trans_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_end_setup(chn_end_setup_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_int_setup(chn_int_setup_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_int_reqclose(chn_int_reqclose_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_end_close(chn_end_close_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_int_close(chn_int_close_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_end_cashout(chn_end_cashout_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);
int handle_chn_int_cashout(chn_int_cashout_t* token, byte(*addr)[MT_SZ_ADDR], any_led_receipt_t* rec);

// helper functions
int transfer(int* bal_from, int* bal_to, int val_from, int val_to, int val_auth);
int close_channel(chn_led_data_t* data);

// formal protocol algorithm to resolve disputes (this will replaced with algs call)
void resolve(byte (*pp)[MT_SZ_PP], chn_end_public_t T_E, chn_int_public_t T_I,
	     chn_end_close_t rc_E, chn_int_close_t rc_I, int* end_bal, int*  int_bal);

/**
 * Called at the system setup to create brand new ledger.
 */
int mt_lpay_init(void){

  ledger.msgbuf = mt_messagebuffer_init();

  // initialize state
  ledger.mac_accounts = digestmap_new();
  ledger.chn_accounts = digestmap_new();

  // set ledger attributes
  byte* pp_temp;
  byte* led_pk_temp;
  byte* led_sk_temp;
  byte* aut_pk_temp;

  tor_assert(mt_hex2bytes(MT_PP_HEX, &pp_temp) == MT_SZ_PP);
  tor_assert(mt_hex2bytes(MT_LED_PK_HEX, &led_pk_temp) == MT_SZ_PK);
  tor_assert(mt_hex2bytes(MT_LED_SK_HEX, &led_sk_temp) == MT_SZ_SK);
  tor_assert(mt_hex2bytes(MT_AUT_PK_HEX, &aut_pk_temp) == MT_SZ_PK);

  memcpy(ledger.pp, pp_temp, MT_SZ_PP);
  memcpy(ledger.pk, led_pk_temp, MT_SZ_PK);
  memcpy(ledger.sk, led_sk_temp, MT_SZ_SK);
  memcpy(ledger.aut_pk, aut_pk_temp, MT_SZ_PK);

  tor_free(pp_temp);
  tor_free(led_pk_temp);
  tor_free(led_sk_temp);
  tor_free(aut_pk_temp);

  ledger.fee = MT_FEE;
  ledger.tax = MT_TAX;
  ledger.window = MT_WINDOW;
  ledger.epoch = 0;

  mt_pk2addr(&ledger.aut_pk, &ledger.aut_addr);
  mt_pk2addr(&ledger.pk, &ledger.led_addr);

  // save values to publically available information
  public.fee = ledger.fee;
  public.tax = ledger.tax;
  public.window = ledger.window;
  memcpy(public.pp, ledger.pp, MT_SZ_PP);
  memcpy(public.aut_pk, ledger.aut_pk, MT_SZ_PK);

  // add authority as first node on the tree
  digestmap_set(ledger.mac_accounts, (char*)ledger.aut_addr, calloc(1, sizeof(mac_led_data_t)));

  return MT_SUCCESS;
}

/**
 * Request to publish any type of information at all go to this function. The
 * function is responsible for parsing the message to interpret what should be
 * done with the request.
 */
int mt_lpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size){

  log_info(LD_MT, "MoneTor: (msg) ------------ recv %s %" PRIu64 ".%" PRIu64 ", %s",
	   mt_party_describe(desc->party), desc->id[0], desc->id[1], mt_token_describe(type));

  // verify signed message, produce addr to pass into handlers
  byte pk[MT_SZ_PK];
  byte addr[MT_SZ_ADDR];

  byte* raw_msg;
  int raw_size = mt_verify_signed_msg(msg, size, &pk, &raw_msg);
  if(raw_size == MT_ERROR)
    return MT_ERROR;

  mt_pk2addr(&pk, &addr);

  byte pid[DIGEST_LEN];
  any_led_receipt_t rec;
  int result;

  switch(type){
    case MT_NTYPE_MAC_AUT_MINT:;
      mac_aut_mint_t mac_aut_mint_tkn;
      if(unpack_mac_aut_mint(raw_msg, raw_size, &mac_aut_mint_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mac_aut_mint(&mac_aut_mint_tkn, &addr, &rec);
      break;

    case MT_NTYPE_MAC_ANY_TRANS:;
      mac_any_trans_t mac_any_trans_tkn;
      if(unpack_mac_any_trans(raw_msg, raw_size, &mac_any_trans_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_mac_any_trans(&mac_any_trans_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_END_SETUP:;
      chn_end_setup_t chn_end_setup_tkn;
      if(unpack_chn_end_setup(raw_msg, raw_size, &chn_end_setup_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_setup(&chn_end_setup_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_INT_SETUP:;
      chn_int_setup_t chn_int_setup_tkn;
      if(unpack_chn_int_setup(raw_msg, raw_size, &chn_int_setup_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_setup(&chn_int_setup_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_INT_REQCLOSE:;
      chn_int_reqclose_t chn_int_reqclose_tkn;
      if(unpack_chn_int_reqclose(raw_msg, raw_size, &chn_int_reqclose_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_reqclose(&chn_int_reqclose_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_END_CLOSE:;
      chn_end_close_t chn_end_close_tkn;
      if(unpack_chn_end_close(raw_msg, raw_size, &chn_end_close_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_close(&chn_end_close_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_INT_CLOSE:;
      chn_int_close_t chn_int_close_tkn;
      if(unpack_chn_int_close(raw_msg, raw_size, &chn_int_close_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_close(&chn_int_close_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_END_CASHOUT:;
      chn_end_cashout_t chn_end_cashout_tkn;
      if(unpack_chn_end_cashout(raw_msg, raw_size, &chn_end_cashout_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_end_cashout(&chn_end_cashout_tkn, &addr, &rec);
      break;

    case MT_NTYPE_CHN_INT_CASHOUT:;
      chn_int_cashout_t chn_int_cashout_tkn;
      if(unpack_chn_int_cashout(raw_msg, raw_size, &chn_int_cashout_tkn, &pid) != MT_SUCCESS)
	return MT_ERROR;
      result = handle_chn_int_cashout(&chn_int_cashout_tkn, &addr, &rec);
      break;

    default:
      result = MT_ERROR;
      break;
  }

  // create confirmation message
  any_led_confirm_t response;
  response.success = (result == MT_SUCCESS) ? MT_CODE_SUCCESS : MT_CODE_FAILURE;
  memcpy(&response.receipt, &rec, sizeof(any_led_receipt_t));

  // send confirmation message
  byte* response_msg;
  int response_size = pack_any_led_confirm(&response, &pid, &response_msg);

  if(mt_buffer_message(ledger.msgbuf, desc, MT_NTYPE_ANY_LED_CONFIRM, response_msg, response_size)
     != MT_SUCCESS){
    tor_free(raw_msg);
    tor_free(response_msg);
    return MT_ERROR;
  }

  tor_free(raw_msg);
  tor_free(response_msg);

  if(result == MT_ERROR){
    log_warn(LD_MT, "MoneTor: protocoal error processing message");
  }
  return result;
}

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_lpay_set_status(mt_desc_t* desc, int status){
  return mt_set_desc_status(ledger.msgbuf, desc, status);
}

//---------------------------- Transaction Handler Functions ----------------------------//

/**
 * Mints the specified amount of new funds and adds it to auth's account.
 */
int handle_mac_aut_mint(mac_aut_mint_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  // make sure the message is signed by the ledger authority
  if(memcmp(ledger.aut_addr, addr, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  // make sure value isn't negative for some reason
  if(token->value < 0)
    return MT_ERROR;

  // address is guaranteed to exist if module was setup with init()
  mac_led_data_t* data = digestmap_get(ledger.mac_accounts, (char*)ledger.aut_addr);
  data->bal += token->value;

  // write the transaction receipt
  rec->type = MT_NTYPE_MAC_AUT_MINT;
  rec->val = token->value;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, *addr, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Handles a transfer of funds between two standard balances.
 */
int handle_mac_any_trans(mac_any_trans_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  // check that the message originates from the payer
  if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  mac_led_data_t* data_from = digestmap_get(ledger.mac_accounts, (char*)token->from);

  // check that the "from" address exists
  if(data_from == NULL)
    return MT_ERROR;

  mac_led_data_t* data_to = digestmap_get(ledger.mac_accounts, (char*)token->to);
  // if the address doesn't exist then create it

  if(data_to == NULL){
    data_to = calloc(1, sizeof(mac_led_data_t));
    digestmap_set(ledger.mac_accounts, (char*)token->to, data_to);
  }

  int* bal_from = &(data_from->bal);
  int* bal_to = &(data_to->bal);
  if(transfer(bal_from, bal_to, token->val_from, token->val_to, ledger.fee) != MT_SUCCESS)
    return MT_ERROR;

  // write the transaction receipt
  rec->type = MT_NTYPE_MAC_ANY_TRANS;
  rec->val = token->val_to;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->to, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Initializes a new channel address using escrowed funds from a standard
 * address. The initializing user is considered to be the end user in this
 * channel. At this point, the channel is not very useful since the intermediary
 * has not completed the setup, but the funds are still recoverable.
 */
int handle_chn_end_setup(chn_end_setup_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  // check that the message originates from the payer
  if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  // check that the token public data is internally consistent
  byte token_addr[MT_SZ_ADDR];
  mt_pk2addr(&token->chn_public.cpk, &token_addr);
  if(token->val_to != token->chn_public.end_bal ||
     memcmp(token_addr, *addr, MT_SZ_ADDR) != 0 ||
     memcmp(token->chn_public.addr, token->chn, MT_SZ_ADDR) != 0){
    return MT_ERROR;
  }

  mac_led_data_t* data_from = digestmap_get(ledger.mac_accounts, (char*)token->from);
  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // if MoneTorPublicMint is on then user can set up channels for free
  if(!get_options()->MoneTorPublicMint){
    if(data_from == NULL)
      return MT_ERROR;
  }
  else {
    if(data_from == NULL){
      data_from = calloc(1, sizeof(mac_led_data_t));
      digestmap_set(ledger.mac_accounts, (char*)token->from, data_from);
    }
    data_from->bal += token->val_from;
  }

  // if the channel doesn't exist then create one
  if(data_chn == NULL){
    data_chn = calloc(1, sizeof(chn_led_data_t));
    data_chn->state = MT_LSTATE_EMPTY;
    digestmap_set(ledger.chn_accounts, (char*)token->chn, data_chn);
  }

  // check that we have a new and unused channel address
  if(data_chn->state != MT_LSTATE_EMPTY)
    return MT_ERROR;

  int* bal_from = &(data_from->bal);
  int* bal_to = &(data_chn->end_bal);

  // check that the escrow transfer goes through
  if(transfer(bal_from, bal_to, token->val_from, token->val_to, ledger.fee) == MT_ERROR){
    return MT_ERROR;
  }

  memcpy(data_chn->end_addr, addr, MT_SZ_ADDR);
  data_chn->end_public = token->chn_public;
  data_chn->state = MT_LSTATE_INIT;

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_END_SETUP;
  rec->val = token->val_to;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Respond to an existing initialized channel to serve as the channel
 * intermediary. Once this operation completes, the channel is considered open
 * for micro/nanopayment processing. Funds will not be recoverable until the
 * channel closure protocol is completed by both parties.
 */
int handle_chn_int_setup(chn_int_setup_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  // check that the message originates from the payer
  if(memcmp(addr, token->from, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  mac_led_data_t* data_from = digestmap_get(ledger.mac_accounts, (char*)token->from);
  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the token public data is internally consistent
  byte token_addr[MT_SZ_ADDR];
  mt_pk2addr(&token->chn_public.cpk, &token_addr);
  if(token->val_to != token->chn_public.int_bal ||
     memcmp(token_addr, *addr, MT_SZ_ADDR) != 0 ||
     memcmp(token->chn_public.addr, token->chn, MT_SZ_ADDR) != 0){
    return MT_ERROR;
  }

  // if MoneTorPublicMint is on then user can set up channels for free
  if(!get_options()->MoneTorPublicMint){
    if(data_from == NULL)
      return MT_ERROR;
  }
  else {
    if(data_from == NULL){
      data_from = calloc(1, sizeof(mac_led_data_t));
      digestmap_set(ledger.mac_accounts, (char*)token->from, data_from);
    }
    data_from->bal += token->val_from;
  }

  if(data_chn == NULL)
    return MT_ERROR;

  // check that the channel address is in the right state
  if(data_chn->state != MT_LSTATE_INIT)
    return MT_ERROR;

  // check that end user and intermediary's public channel tokens agree
  if(token->chn_public.end_bal != data_chn->end_public.end_bal)
    return MT_ERROR;
  if(token->chn_public.int_bal != data_chn->end_public.int_bal)
    return MT_ERROR;

  int* bal_from = &(data_from->bal);
  int* bal_to = &(data_chn->int_bal);

  // check that the escrow transfer goes through
  if(transfer(bal_from, bal_to, token->val_from, token->val_to, ledger.fee) == MT_ERROR)
    return MT_ERROR;

  memcpy(data_chn->int_addr, addr, MT_SZ_ADDR);
  data_chn->int_public = token->chn_public;
  data_chn->state = MT_LSTATE_OPEN;

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_INT_SETUP;
  rec->val = token->val_to;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Request by the intermediary to close out a channel. At this point, the
 * intermediary does not know what the final balances should be. As a result,
 * the end user must respond with a closure message within the specified time
 * limit or risk losing the entire balance of her funds.
 */
int handle_chn_int_reqclose(chn_int_reqclose_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the channel address exists
  if(data_chn == NULL)
    return MT_ERROR;

  // check that message is coming from the intermediary
  if(memcmp(data_chn->int_addr, addr, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  // check that the channel is in the right state
  if(!(data_chn->state == MT_LSTATE_OPEN))
    return MT_ERROR;

  data_chn->close_epoch = ledger.epoch + ledger.window;
  data_chn->state = MT_LSTATE_INT_REQCLOSED;

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_INT_REQCLOSE;
  rec->val = 0;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Request by the end user to close out a channel. The end user posts her view
 * of the current channel balance. The intermediary now has some specified time
 * limit to refute the claim before the channel can be cashed out.
 */
int handle_chn_end_close(chn_end_close_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the channel address exists
  if(data_chn == NULL)
    return MT_ERROR;

  // check that message is coming from the end user
  if(memcmp(data_chn->end_addr, addr, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  // check that the channel is in the right state
  if(!(data_chn->state == MT_LSTATE_OPEN || data_chn->state == MT_LSTATE_INT_REQCLOSED))
    return MT_ERROR;

  data_chn->end_close_token = *token;
  data_chn->close_epoch = ledger.epoch + ledger.window;
  data_chn->state = MT_LSTATE_END_CLOSED;

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_END_CLOSE;
  rec->val = 0;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Operation by the intermediary to either accept the end user's view of the
 * channel balances or refute the claim with another view. The network resolves
 * the dispute and outputs the final channel balances.
 */
int handle_chn_int_close(chn_int_close_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the channel address exists and is a channel address
  if(data_chn == NULL)
    return MT_ERROR;

  // check that message is coming from the intermediary
  if(memcmp(data_chn->int_addr, addr, MT_SZ_ADDR) != 0)
    return MT_ERROR;

  // check that the channel address is in the right state
  if(!(data_chn->state == MT_LSTATE_END_CLOSED))
    return MT_ERROR;

  data_chn->int_close_token = *token;
  data_chn->state = MT_LSTATE_INT_CLOSED;

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_INT_CLOSE;
  rec->val = 0;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return MT_SUCCESS;
}

/**
 * Operation by the end user to cash out of a payment channel. This can only be
 * done by the end user if the channel has not been initialized by the
 * intermediary or after the channel has/should be closed.
 */
int handle_chn_end_cashout(chn_end_cashout_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the channel address exists
  if(data_chn == NULL)
    return MT_ERROR;

  // check that the from address is the channel end user
  if(memcmp(addr, data_chn->end_addr, MT_SZ_ADDR))
    return MT_ERROR;

  mac_led_data_t* data_to = digestmap_get(ledger.mac_accounts, (char*)addr);

  // attempt to close the channel if it isn't already
  if(close_channel(data_chn) == MT_ERROR)
    return MT_ERROR;

  int* bal_from = &(data_chn->end_bal);
  int* bal_to = &(data_to->bal);

  // check that the transfer goes through
  int result = transfer(bal_from, bal_to, token->val_from, token->val_to, ledger.fee);

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_END_CASHOUT;
  rec->val = 0;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return result;
}

/**
 * Operation by the intermediary to cash out of a payment channel. This can only
 * be done after the channel has/should be closed.
 */
int handle_chn_int_cashout(chn_int_cashout_t* token, byte (*addr)[MT_SZ_ADDR], any_led_receipt_t* rec){

  chn_led_data_t* data_chn = digestmap_get(ledger.chn_accounts, (char*)token->chn);

  // check that the channel address exists
  if(data_chn == NULL)
    return MT_ERROR;

  // check that the from address is the channel intermediary
  if(memcmp(addr, data_chn->int_addr, MT_SZ_ADDR))
    return MT_ERROR;

  mac_led_data_t* data_to = digestmap_get(ledger.mac_accounts, (char*)addr);

  // attempt to close the channel if it isn't already
  if(close_channel(data_chn) == MT_ERROR)
    return MT_ERROR;

  int* bal_from = &(data_chn->int_bal);
  int* bal_to = &(data_to->bal);

  // check that the transfer goes through
  int aut_charge = ledger.fee + (token->val_to * ledger.tax) / 100;
  int result = transfer(bal_from, bal_to, token->val_from, token->val_to, aut_charge);

  // write the transaction receipt
  rec->type = MT_NTYPE_CHN_INT_CASHOUT;
  rec->val = 0;
  memcpy(rec->from, *addr, MT_SZ_ADDR);
  memcpy(rec->to, token->chn, MT_SZ_ADDR);
  tor_assert(mt_receipt_sign(rec, &ledger.sk) == MT_SUCCESS);

  return result;
}

//------------------------------- Helper Functions --------------------------------------//

mt_payment_public_t mt_lpay_get_payment_public(void){
  return public;
}

/**
 * Transfer the specified amounts from one balance to another (provided in
 * pointers). Ensure that the value difference covers the ledger's specified
 * cost of transaction.
 */
int transfer(int* bal_from, int* bal_to, int val_from, int val_to, int val_auth){

  // check that values make sense
  if(!(val_from >= val_to && val_to >= 0))
    return MT_ERROR;

  // check that the payer has a sufficient balance
  if(*bal_from < val_from)
    return MT_ERROR;
  // check that the payment different covers the ledger profit
  if(val_from - val_to < val_auth)
    return MT_ERROR;

  *bal_from -= val_from;
  *bal_to += val_to;

  mac_led_data_t* aut_data = digestmap_get(ledger.mac_accounts, (char*)ledger.aut_addr);
  aut_data->bal += (val_from - val_to);
  return MT_SUCCESS;
}

/**
 * Process a request to close the given channel. This function considers all
 * possible states of the channel. If channel closure is allowed, then it marks
 * the channel as closed and updates the final balances.
 */
int close_channel(chn_led_data_t* data){

  // channel is already closed
  if(data->state == MT_LSTATE_RESOLVED)
    return MT_SUCCESS;

  // cannot close channel
  if(data->state == MT_LSTATE_EMPTY || data->state == MT_LSTATE_OPEN)
    return MT_ERROR;

  // one part has closed the channel but not enough time has passed
  if((data->state == MT_LSTATE_INT_REQCLOSED || data->state == MT_LSTATE_END_CLOSED) &&
     data->close_epoch + ledger.window < ledger.epoch)
    return MT_ERROR;

  int* end_bal = NULL;
  int* int_bal = NULL;
  resolve(&ledger.pp, data->end_public, data->int_public,
	  data->end_close_token, data->int_close_token, end_bal, int_bal);

  if(end_bal != NULL && int_bal != NULL){
    data->end_bal = *end_bal;
    data->int_bal = *int_bal;
  }

  data->state = MT_LSTATE_RESOLVED;
  return MT_SUCCESS;
}


//------------------------------- moneTor Algorithms ------------------------------------//

/**
 * Resolve algorithm implemente from the moneTor protocol algorithms. Accepts
 * channel information at closure and makes a determination on the final balances.
 */
void resolve(byte (*pp)[MT_SZ_PP], chn_end_public_t T_E, chn_int_public_t T_I,
	     chn_end_close_t rc_E, chn_int_close_t rc_I, int* end_bal, int*   int_bal){

  (void) pp;
  (void) T_E;
  (void) T_I;
  (void) rc_E;
  (void) rc_I;
  (void) end_bal;
  (void) int_bal;
}

/********************** Instance Management ***********************/

int mt_lpay_clear(void){

  const char* key;
  void* val;
  digestmap_iter_t* i;

  // tor_free all mac accounts
  for(i = digestmap_iter_init(ledger.mac_accounts); !(digestmap_iter_done(i)); ){
    digestmap_iter_get(i, &key, &val);
    i = digestmap_iter_next_rmv(ledger.mac_accounts, i);
    tor_free(val);
  }

  // tor_free all channel accounts
  for(i = digestmap_iter_init(ledger.chn_accounts); !(digestmap_iter_done(i)); ){
    digestmap_iter_get(i, &key, &val);
    i = digestmap_iter_next_rmv(ledger.chn_accounts, i);
    tor_free(val);
  }

  // overwrite ledger state with zeros
  memset(&ledger, 0, sizeof(ledger));
  return MT_SUCCESS;
}

int mt_lpay_export(byte** export_out){
  *export_out = tor_malloc(sizeof(ledger));
  memcpy(*export_out, &ledger, sizeof(ledger));
  return sizeof(ledger);
}
int mt_lpay_import(byte* import){
  memcpy(&ledger, import, sizeof(ledger));
  return MT_SUCCESS;
}

//--------------------------------- Testing Functions -----------------------------------//

int mt_lpay_query_mac_balance(byte (*addr)[MT_SZ_ADDR]){
  mac_led_data_t* mac_ptr = digestmap_get(ledger.mac_accounts, (char*)addr);
  if(mac_ptr == NULL)
    return MT_ERROR;
  return mac_ptr->bal;
}

int mt_lpay_query_end_balance(byte (*addr)[MT_SZ_ADDR]){
  chn_led_data_t* chn_ptr = digestmap_get(ledger.chn_accounts, (char*)addr);
  if(chn_ptr == NULL)
    return MT_ERROR;
  return chn_ptr->end_bal;
}

int mt_lpay_query_int_balance(byte (*addr)[MT_SZ_ADDR]){
  chn_led_data_t* chn_ptr = digestmap_get(ledger.chn_accounts, (char*)addr);
  if(chn_ptr == NULL)
    return MT_ERROR;
  return chn_ptr->int_bal;
}

int mt_lpay_set_balance(byte (*addr)[MT_SZ_ADDR], int balance){
  mac_led_data_t* entry = calloc(1, sizeof(mac_led_data_t));
  entry->bal = balance;
  digestmap_set(ledger.mac_accounts, (char*)(*addr), entry);
  return MT_SUCCESS;
}
