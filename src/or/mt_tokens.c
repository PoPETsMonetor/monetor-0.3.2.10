/**
 * \file token_lib.c
 *
 * Implementation of pack()/unpack() functionality for each multi-party token
 * that enable conversion between semantically meaningful c structs and network
 * sendable byte strings.
 *
 * The current definitions do straightforward casting between structs and byte
 * strings. It may be necessary in more mature versions to explictly define byte
 * allocation in the messages for portability and to add additional meta
 * information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mt_crypto.h"
#include "mt_tokens.h"

int pack_token(mt_ntype_t type, void* ptr, int tkn_size, byte(*pid)[DIGEST_LEN], byte** str_out);
int unpack_token(mt_ntype_t type, byte* str, int tkn_size, void* tkn_out, byte(*pid_out)[DIGEST_LEN]);

/*************************** Sign/Verify Messages ****************************/

int mt_create_signed_msg(byte* msg, int size, byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
			 byte** signed_out){

  *signed_out = tor_malloc(size + MT_SZ_PK + MT_SZ_SIG);
  memcpy(*signed_out, msg, size);
  memcpy(*signed_out + size, *pk, MT_SZ_PK);

  byte sig[MT_SZ_SIG];
  if(mt_sig_sign(msg, size, sk, &sig) != MT_SUCCESS)
    return MT_ERROR;

  memcpy(*signed_out + size + MT_SZ_PK, sig, MT_SZ_SIG);
  return size + MT_SZ_PK + MT_SZ_SIG;
}

int mt_verify_signed_msg(byte* signed_msg, int size, byte(*pk_out)[MT_SZ_PK], byte** msg_out){
  int msg_size = size - MT_SZ_PK - MT_SZ_SIG;

  byte sig[MT_SZ_SIG];
  memcpy(*pk_out, signed_msg + msg_size, MT_SZ_PK);
  memcpy(sig, signed_msg + msg_size + MT_SZ_PK, MT_SZ_SIG);

  if(mt_sig_verify(signed_msg, msg_size, pk_out, &sig) != MT_SUCCESS)
    return MT_ERROR;

  *msg_out = tor_malloc(msg_size);
  memcpy(*msg_out, signed_msg, msg_size);
  return msg_size;
}

/**************************** Pack/Unpack Tokens *****************************/

int pack_mac_aut_mint(mac_aut_mint_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MAC_AUT_MINT, token, sizeof(*token), pid, str_out);
}

int pack_mac_any_trans(mac_any_trans_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MAC_ANY_TRANS, token, sizeof(*token), pid, str_out);
}

int pack_chn_end_setup(chn_end_setup_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_END_SETUP, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_setup(chn_int_setup_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_SETUP, token, sizeof(*token), pid, str_out);
}

int pack_any_led_confirm(any_led_confirm_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_ANY_LED_CONFIRM, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_reqclose(chn_int_reqclose_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_REQCLOSE, token, sizeof(*token), pid, str_out);
}

int pack_chn_end_close(chn_end_close_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_END_CLOSE, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_close(chn_int_close_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_CLOSE, token, sizeof(*token), pid, str_out);
}

int pack_chn_end_cashout(chn_end_cashout_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_END_CASHOUT, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_cashout(chn_int_cashout_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_CASHOUT, token, sizeof(*token), pid, str_out);
}

int pack_mac_led_data(mac_led_data_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MAC_LED_DATA, token, sizeof(*token), pid, str_out);
}

int pack_chn_led_data(chn_led_data_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_LED_DATA, token, sizeof(*token), pid, str_out);
}

int pack_mac_led_query(mac_led_query_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MAC_LED_QUERY, token, sizeof(*token), pid, str_out);
}

int pack_chn_led_query(chn_led_query_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_LED_QUERY, token, sizeof(*token), pid, str_out);
}

int pack_chn_end_estab1(chn_end_estab1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_END_ESTAB1, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_estab2(chn_int_estab2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_ESTAB2, token, sizeof(*token), pid, str_out);
}

int pack_chn_end_estab3(chn_end_estab3_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_END_ESTAB3, token, sizeof(*token), pid, str_out);
}

int pack_chn_int_estab4(chn_int_estab4_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_CHN_INT_ESTAB4, token, sizeof(*token), pid, str_out);
}

int pack_mic_cli_pay1(mic_cli_pay1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_CLI_PAY1, token, sizeof(*token), pid, str_out);
}

int pack_mic_rel_pay2(mic_rel_pay2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_REL_PAY2, token, sizeof(*token), pid, str_out);
}

int pack_mic_cli_pay3(mic_cli_pay3_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_CLI_PAY3, token, sizeof(*token), pid, str_out);
}

int pack_mic_int_pay4(mic_int_pay4_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_INT_PAY4, token, sizeof(*token), pid, str_out);
}

int pack_mic_cli_pay5(mic_cli_pay5_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_CLI_PAY5, token, sizeof(*token), pid, str_out);
}

int pack_mic_rel_pay6(mic_rel_pay6_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_REL_PAY6, token, sizeof(*token), pid, str_out);
}

int pack_mic_int_pay7(mic_int_pay7_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_INT_PAY7, token, sizeof(*token), pid, str_out);
}

int pack_mic_int_pay8(mic_int_pay8_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_MIC_INT_PAY8, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_setup1(nan_cli_setup1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_SETUP1, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_setup2(nan_int_setup2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_SETUP2, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_setup3(nan_cli_setup3_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_SETUP3, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_setup4(nan_int_setup4_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_SETUP4, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_setup5(nan_cli_setup5_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_SETUP5, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_setup6(nan_int_setup6_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_SETUP6, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_estab1(nan_cli_estab1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_ESTAB1, token, sizeof(*token), pid, str_out);
}

int pack_nan_rel_estab2(nan_rel_estab2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_REL_ESTAB2, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_estab3(nan_int_estab3_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_ESTAB3, token, sizeof(*token), pid, str_out);
}

int pack_nan_rel_estab4(nan_rel_estab4_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_REL_ESTAB4, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_estab5(nan_int_estab5_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_ESTAB5, token, sizeof(*token), pid, str_out);
}

int pack_nan_rel_estab6(nan_rel_estab6_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_REL_ESTAB6, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_pay1(nan_cli_pay1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_PAY1, token, sizeof(*token), pid, str_out);
}

int pack_nan_rel_pay2(nan_rel_pay2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_REL_PAY2, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_reqclose1(nan_cli_reqclose1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_REQCLOSE1, token, sizeof(*token), pid, str_out);
}

int pack_nan_rel_reqclose2(nan_rel_reqclose2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_REL_REQCLOSE2, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_destab1(nan_cli_destab1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_DESTAB1, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_destab2(nan_int_destab2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_DESTAB2, token, sizeof(*token), pid, str_out);
}

int pack_nan_cli_dpay1(nan_cli_dpay1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_CLI_DPAY1, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_dpay2(nan_int_dpay2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_DPAY2, token, sizeof(*token), pid, str_out);
}

int pack_nan_end_close1(nan_end_close1_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_END_CLOSE1, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_close2(nan_int_close2_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_CLOSE2, token, sizeof(*token), pid, str_out);
}

int pack_nan_end_close3(nan_end_close3_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_END_CLOSE3, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_close4(nan_int_close4_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_CLOSE4, token, sizeof(*token), pid, str_out);
}

int pack_nan_end_close5(nan_end_close5_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_END_CLOSE5, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_close6(nan_int_close6_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_CLOSE6, token, sizeof(*token), pid, str_out);
}

int pack_nan_end_close7(nan_end_close7_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_END_CLOSE7, token, sizeof(*token), pid, str_out);
}

int pack_nan_int_close8(nan_int_close8_t* token, byte(*pid)[DIGEST_LEN], byte** str_out){
    return pack_token(MT_NTYPE_NAN_INT_CLOSE8, token, sizeof(*token), pid, str_out);
}


//--------------------------------- Unpack --------------------------------//

int unpack_mac_aut_mint(byte* str, int size, mac_aut_mint_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MAC_AUT_MINT, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mac_any_trans(byte* str, int size, mac_any_trans_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MAC_ANY_TRANS, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_end_setup(byte* str, int size, chn_end_setup_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_END_SETUP, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_int_setup(byte* str, int size, chn_int_setup_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_SETUP, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_any_led_confirm(byte* str, int size, any_led_confirm_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_ANY_LED_CONFIRM, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_int_reqclose(byte* str, int size, chn_int_reqclose_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_REQCLOSE, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_end_close(byte* str, int size, chn_end_close_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_END_CLOSE, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_int_close(byte* str, int size, chn_int_close_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_CLOSE, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_end_cashout(byte* str, int size, chn_end_cashout_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_END_CASHOUT, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_int_cashout(byte* str, int size, chn_int_cashout_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_CASHOUT, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mac_led_data(byte* str, int size, mac_led_data_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MAC_LED_DATA, str, sizeof(*tkn_out), tkn_out, pid_out);
}
int unpack_chn_led_data(byte* str, int size, chn_led_data_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_LED_DATA, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mac_led_query(byte* str, int size, mac_led_query_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MAC_LED_QUERY, str, sizeof(*tkn_out), tkn_out, pid_out);
}
int unpack_chn_led_query(byte* str, int size, chn_led_query_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_LED_QUERY, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_end_estab1(byte* str, int size, chn_end_estab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_END_ESTAB1, str, sizeof(*tkn_out), tkn_out, pid_out);
}
int unpack_chn_int_estab2(byte* str, int size, chn_int_estab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_ESTAB2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_end_estab3(byte* str, int size, chn_end_estab3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_END_ESTAB3, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_chn_int_estab4(byte* str, int size, chn_int_estab4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_CHN_INT_ESTAB4, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_cli_pay1(byte* str, int size, mic_cli_pay1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_CLI_PAY1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_rel_pay2(byte* str, int size, mic_rel_pay2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_REL_PAY2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_cli_pay3(byte* str, int size, mic_cli_pay3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_CLI_PAY3, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_int_pay4(byte* str, int size, mic_int_pay4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_INT_PAY4, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_cli_pay5(byte* str, int size, mic_cli_pay5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_CLI_PAY5, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_rel_pay6(byte* str, int size, mic_rel_pay6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_REL_PAY6, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_int_pay7(byte* str, int size, mic_int_pay7_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_INT_PAY7, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_mic_int_pay8(byte* str, int size, mic_int_pay8_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_MIC_INT_PAY8, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_setup1(byte* str, int size, nan_cli_setup1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_SETUP1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_setup2(byte* str, int size, nan_int_setup2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_SETUP2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_setup3(byte* str, int size, nan_cli_setup3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_SETUP3, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_setup4(byte* str, int size, nan_int_setup4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_SETUP4, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_setup5(byte* str, int size, nan_cli_setup5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_SETUP5, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_setup6(byte* str, int size, nan_int_setup6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_SETUP6, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_estab1(byte* str, int size, nan_cli_estab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_ESTAB1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_rel_estab2(byte* str, int size, nan_rel_estab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_REL_ESTAB2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_estab3(byte* str, int size, nan_int_estab3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_ESTAB3, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_rel_estab4(byte* str, int size, nan_rel_estab4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_REL_ESTAB4, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_estab5(byte* str, int size, nan_int_estab5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_ESTAB5, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_rel_estab6(byte* str, int size, nan_rel_estab6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_REL_ESTAB6, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_pay1(byte* str, int size, nan_cli_pay1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_PAY1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_rel_pay2(byte* str, int size, nan_rel_pay2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_REL_PAY2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_reqclose1(byte* str, int size, nan_cli_reqclose1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_REQCLOSE1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_rel_reqclose2(byte* str, int size, nan_rel_reqclose2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_REL_REQCLOSE2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_destab1(byte* str, int size, nan_cli_destab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_DESTAB1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_destab2(byte* str, int size, nan_int_destab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_DESTAB2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_cli_dpay1(byte* str, int size, nan_cli_dpay1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_CLI_DPAY1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_dpay2(byte* str, int size, nan_int_dpay2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_DPAY2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_end_close1(byte* str, int size, nan_end_close1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_END_CLOSE1, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_close2(byte* str, int size, nan_int_close2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_CLOSE2, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_end_close3(byte* str, int size, nan_end_close3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_END_CLOSE3, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_close4(byte* str, int size, nan_int_close4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_CLOSE4, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_end_close5(byte* str, int size, nan_end_close5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_END_CLOSE5, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_close6(byte* str, int size, nan_int_close6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_CLOSE6, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_end_close7(byte* str, int size, nan_end_close7_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_END_CLOSE7, str, sizeof(*tkn_out), tkn_out, pid_out);
}

int unpack_nan_int_close8(byte* str, int size, nan_int_close8_t* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  if(size != sizeof(mt_ntype_t) + sizeof(*tkn_out) + DIGEST_LEN)
    return MT_ERROR;
  return unpack_token(MT_NTYPE_NAN_INT_CLOSE8, str, sizeof(*tkn_out), tkn_out, pid_out);
}

//------------------------------ Helper Functions ---------------------------//

int pack_token(mt_ntype_t type, void *ptr, int tkn_size, byte(*pid)[DIGEST_LEN], byte** str_out){
    int str_size = sizeof(mt_ntype_t) + tkn_size + DIGEST_LEN;
    byte* str = tor_malloc(str_size);
    memcpy(str, &type, sizeof(type));
    memcpy(str + sizeof(mt_ntype_t), ptr, tkn_size);
    memcpy(str + sizeof(mt_ntype_t) + tkn_size, *pid, DIGEST_LEN);

    *str_out = str;
    return str_size;
}

int unpack_token(mt_ntype_t type, byte* str, int tkn_size, void* tkn_out, byte(*pid_out)[DIGEST_LEN]){
  // message is not the type it clai)
  if(type != *((mt_ntype_t*)str))
    return MT_ERROR;

  memcpy(tkn_out, str + sizeof(mt_ntype_t), tkn_size);
  memcpy(*pid_out, str + sizeof(mt_ntype_t) + tkn_size, DIGEST_LEN);
  return MT_SUCCESS;
}

/*
 * This function shoud return the payload size of a given mt_ntype_t.
 * This should match the size of data sent through the network minus
 * the size of the header.
 */

size_t mt_token_get_size_of(mt_ntype_t type) {
  //Used of test unit - To change later
  size_t strlen = sizeof(mt_ntype_t)+DIGEST_LEN;
  switch(type) {
    case MT_NTYPE_CHN_END_ESTAB1:
      return sizeof(chn_end_estab1_t)+strlen;
    case MT_NTYPE_CHN_END_ESTAB3:
      return sizeof(chn_end_estab3_t)+strlen;
    case MT_NTYPE_CHN_INT_ESTAB2:
      return sizeof(chn_int_estab2_t)+strlen;
    case MT_NTYPE_CHN_INT_ESTAB4:
      return sizeof(chn_int_estab4_t)+strlen;
    case MT_NTYPE_MIC_CLI_PAY1:
      return sizeof(mic_cli_pay1_t)+strlen;
    case MT_NTYPE_MIC_REL_PAY2:
      return sizeof(mic_rel_pay2_t)+strlen;
    case MT_NTYPE_MIC_CLI_PAY3:
      return sizeof(mic_cli_pay3_t)+strlen;
    case MT_NTYPE_MIC_INT_PAY4:
      return sizeof(mic_int_pay4_t)+strlen;
    case MT_NTYPE_MIC_CLI_PAY5:
      return sizeof(mic_cli_pay5_t)+strlen;
    case MT_NTYPE_MIC_REL_PAY6:
      return sizeof(mic_rel_pay6_t)+strlen;
    case MT_NTYPE_MIC_INT_PAY7:
      return sizeof(mic_int_pay7_t)+strlen;
    case MT_NTYPE_MIC_INT_PAY8:
      return sizeof(mic_int_pay8_t)+strlen;
    case MT_NTYPE_NAN_CLI_SETUP1:
      return sizeof(nan_cli_setup1_t)+strlen;
    case MT_NTYPE_NAN_INT_SETUP2:
      return sizeof(nan_int_setup2_t)+strlen;
    case MT_NTYPE_NAN_CLI_SETUP3:
      return sizeof(nan_cli_setup3_t)+strlen;
    case MT_NTYPE_NAN_INT_SETUP4:
      return sizeof(nan_int_setup4_t)+strlen;
    case MT_NTYPE_NAN_CLI_SETUP5:
      return sizeof(nan_cli_setup5_t)+strlen;
    case MT_NTYPE_NAN_INT_SETUP6:
      return sizeof(nan_int_setup6_t)+strlen;
    case MT_NTYPE_NAN_CLI_DESTAB1:
      return sizeof(nan_cli_destab1_t)+strlen;
    case MT_NTYPE_NAN_INT_DESTAB2:
      return sizeof(nan_int_destab2_t)+strlen;
    case MT_NTYPE_NAN_CLI_DPAY1:
      return sizeof(nan_cli_dpay1_t)+strlen;
    case MT_NTYPE_NAN_INT_DPAY2:
      return sizeof(nan_int_dpay2_t)+strlen;
    case MT_NTYPE_NAN_CLI_ESTAB1:
      return sizeof(nan_cli_estab1_t)+strlen+sizeof(int_id_t)+sizeof(mt_desc_t);
    case MT_NTYPE_NAN_REL_ESTAB2:
      return sizeof(nan_rel_estab2_t)+strlen;
    case MT_NTYPE_NAN_INT_ESTAB3:
      return sizeof(nan_int_estab3_t)+strlen;
    case MT_NTYPE_NAN_REL_ESTAB4:
      return sizeof(nan_rel_estab4_t)+strlen;
    case MT_NTYPE_NAN_INT_ESTAB5:
      return sizeof(nan_int_estab5_t)+strlen;
    case MT_NTYPE_NAN_REL_ESTAB6:
      return sizeof(nan_rel_estab6_t)+strlen;
    case MT_NTYPE_NAN_CLI_PAY1:
      return sizeof(nan_cli_pay1_t)+strlen;
    case MT_NTYPE_NAN_REL_PAY2:
      return sizeof(nan_rel_pay2_t)+strlen;
    case MT_NTYPE_NAN_CLI_REQCLOSE1:
      return sizeof(nan_cli_reqclose1_t)+strlen;
    case MT_NTYPE_NAN_REL_REQCLOSE2:
      return sizeof(nan_rel_reqclose2_t)+strlen;
    case MT_NTYPE_NAN_END_CLOSE1:
      return sizeof(nan_end_close1_t)+strlen;
    case MT_NTYPE_NAN_INT_CLOSE2:
      return sizeof(nan_int_close2_t)+strlen;
    case MT_NTYPE_NAN_END_CLOSE3:
      return sizeof(nan_end_close3_t)+strlen;
    case MT_NTYPE_NAN_INT_CLOSE4:
      return sizeof(nan_int_close4_t)+strlen;
    case MT_NTYPE_NAN_END_CLOSE5:
      return sizeof(nan_end_close5_t)+strlen;
    case MT_NTYPE_NAN_INT_CLOSE6:
      return sizeof(nan_int_close6_t)+strlen;
    case MT_NTYPE_NAN_END_CLOSE7:
      return sizeof(nan_end_close7_t)+strlen;
    case MT_NTYPE_NAN_INT_CLOSE8:
      return sizeof(nan_int_close8_t)+strlen;
    case MT_NTYPE_MAC_AUT_MINT:
      return sizeof(mac_aut_mint_t)+strlen;
    /** Any signed message have also MT_SZ_PK+MT_SZ_SIG */
    case MT_NTYPE_MAC_ANY_TRANS:
      return sizeof(mac_any_trans_t)+MT_SZ_PK+MT_SZ_SIG+strlen;
    case MT_NTYPE_CHN_END_SETUP:
      return sizeof(chn_end_setup_t)+MT_SZ_PK+MT_SZ_SIG+strlen;
    case MT_NTYPE_CHN_INT_SETUP:
      return sizeof(chn_int_setup_t)+MT_SZ_PK+MT_SZ_SIG+strlen;
    case MT_NTYPE_CHN_INT_REQCLOSE:
      return sizeof(chn_int_reqclose_t)+strlen;
    case MT_NTYPE_CHN_END_CLOSE:
      return sizeof(chn_end_close_t)+strlen;
    case MT_NTYPE_CHN_INT_CLOSE:
      return sizeof(chn_int_close_t)+strlen;
    case MT_NTYPE_CHN_END_CASHOUT:
      return sizeof(chn_end_cashout_t)+strlen;
    case MT_NTYPE_CHN_INT_CASHOUT:
      return sizeof(chn_int_cashout_t)+strlen;
    case MT_NTYPE_ANY_LED_CONFIRM:
      return sizeof(any_led_confirm_t)+strlen;
    case MT_NTYPE_MAC_LED_DATA:
      return sizeof(mac_led_data_t)+strlen;
    case MT_NTYPE_CHN_LED_DATA:
      return sizeof(chn_led_data_t)+strlen;
    case MT_NTYPE_MAC_LED_QUERY:
      return sizeof(mac_led_query_t)+strlen;
    case MT_NTYPE_CHN_LED_QUERY:
      return sizeof(chn_led_query_t)+strlen;
    default:
      log_warn(LD_MT, "BUG - unknown type %hhx", type);
      return 0;
  }
}
