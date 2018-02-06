/**
 * \file mt_tokens.h
 * \brief Header file for mt_tokens.c
 **/

#ifndef mt_tokens_h
#define mt_tokens_h

#include "or.h"

typedef struct {
  byte* msg;
  byte pk[MT_SZ_PK];
  byte sig[MT_SZ_SIG];
} mt_signed_msg_t;

int mt_create_signed_msg(byte* msg, int size, byte (*pk)[MT_SZ_PK], byte (*sk)[MT_SZ_SK],
			 byte** signed_out);
int mt_verify_signed_msg(byte* signed_msg, int size, byte(*pk_out)[MT_SZ_PK],  byte** msg_out);

//-------------------------- Pack/Unpack Functions --------------------------//

/**
 * Convert a token struct into a byte string and sign it with the given
 * keypair. String, along with the public key and signature, and
 * copied into a freshly malloc'd byte string that is assigned to str_out
 *
 * returns the size of byte string output or -1 upon failure
 */
int pack_mac_aut_mint(mac_aut_mint_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mac_any_trans(mac_any_trans_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_end_setup(chn_end_setup_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_setup(chn_int_setup_t* tkn, byte(*pid)[DIGEST_LEN],  byte** str_out);
int pack_any_led_confirm(any_led_confirm_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_reqclose(chn_int_reqclose_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_end_close(chn_end_close_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_close(chn_int_close_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_end_cashout(chn_end_cashout_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_cashout(chn_int_cashout_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);

int pack_mac_led_data(mac_led_data_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_led_data(chn_led_data_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mac_led_query(mac_led_query_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_led_query(chn_led_query_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);

int pack_chn_end_estab1(chn_end_estab1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_estab2(chn_int_estab2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_end_estab3(chn_end_estab3_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_chn_int_estab4(chn_int_estab4_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_cli_pay1(mic_cli_pay1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_rel_pay2(mic_rel_pay2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_cli_pay3(mic_cli_pay3_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_int_pay4(mic_int_pay4_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_cli_pay5(mic_cli_pay5_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_rel_pay6(mic_rel_pay6_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_int_pay7(mic_int_pay7_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_mic_int_pay8(mic_int_pay8_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_setup1(nan_cli_setup1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_setup2(nan_int_setup2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_setup3(nan_cli_setup3_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_setup4(nan_int_setup4_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_setup5(nan_cli_setup5_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_setup6(nan_int_setup6_t* tkn, byte(*pid)[DIGEST_LEN],  byte** str_out);
int pack_nan_cli_estab1(nan_cli_estab1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_rel_estab2(nan_rel_estab2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_estab3(nan_int_estab3_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_rel_estab4(nan_rel_estab4_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_estab5(nan_int_estab5_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_rel_estab6(nan_rel_estab6_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_pay1(nan_cli_pay1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_rel_pay2(nan_rel_pay2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_reqclose1(nan_cli_reqclose1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_rel_reqclose2(nan_rel_reqclose2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_destab1(nan_cli_destab1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_destab2(nan_int_destab2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_cli_dpay1(nan_cli_dpay1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_dpay2(nan_int_dpay2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_end_close1(nan_end_close1_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_close2(nan_int_close2_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_end_close3(nan_end_close3_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_close4(nan_int_close4_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_end_close5(nan_end_close5_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_close6(nan_int_close6_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_end_close7(nan_end_close7_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
int pack_nan_int_close8(nan_int_close8_t* tkn, byte(*pid)[DIGEST_LEN], byte** str_out);
/**
 * Convert a byte string that was generated using the corresponding
 * "pack" functions into the original token structs. The public key,
 * which is verified with the provided signture, is also outputted.
 *
 * returns 0 on success
 */
int unpack_mac_aut_mint(byte* str, int size, mac_aut_mint_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mac_any_trans(byte* str, int size, mac_any_trans_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_end_setup(byte* str, int size, chn_end_setup_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_setup(byte* str, int size, chn_int_setup_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);
int unpack_any_led_confirm(byte* str, int size, any_led_confirm_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_reqclose(byte* str, int size, chn_int_reqclose_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_end_close(byte* str, int size, chn_end_close_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_close(byte* str, int size, chn_int_close_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_end_cashout(byte* str, int size, chn_end_cashout_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_cashout(byte* str, int size, chn_int_cashout_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);

int unpack_mac_led_data(byte* str, int size, mac_led_data_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_led_data(byte* str, int size, chn_led_data_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mac_led_query(byte* str, int size, mac_led_query_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_led_query(byte* str, int size, chn_led_query_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);

int unpack_chn_end_estab1(byte* str, int size, chn_end_estab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_estab2(byte* str, int size, chn_int_estab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_end_estab3(byte* str, int size, chn_end_estab3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_chn_int_estab4(byte* str, int size, chn_int_estab4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_cli_pay1(byte* str, int size, mic_cli_pay1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_rel_pay2(byte* str, int size, mic_rel_pay2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_cli_pay3(byte* str, int size, mic_cli_pay3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_int_pay4(byte* str, int size, mic_int_pay4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_cli_pay5(byte* str, int size, mic_cli_pay5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_rel_pay6(byte* str, int size, mic_rel_pay6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_int_pay7(byte* str, int size, mic_int_pay7_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_mic_int_pay8(byte* str, int size, mic_int_pay8_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_setup1(byte* str, int size, nan_cli_setup1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_setup2(byte* str, int size, nan_int_setup2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_setup3(byte* str, int size, nan_cli_setup3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_setup4(byte* str, int size, nan_int_setup4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_setup5(byte* str, int size, nan_cli_setup5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_setup6(byte* str, int size, nan_int_setup6_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_estab1(byte* str, int size, nan_cli_estab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_rel_estab2(byte* str, int size, nan_rel_estab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_estab3(byte* str, int size, nan_int_estab3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_rel_estab4(byte* str, int size, nan_rel_estab4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_estab5(byte* str, int size, nan_int_estab5_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_rel_estab6(byte* str, int size, nan_rel_estab6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_pay1(byte* str, int size, nan_cli_pay1_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_rel_pay2(byte* str, int size, nan_rel_pay2_t* tkn_out,  byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_reqclose1(byte* str, int size, nan_cli_reqclose1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_rel_reqclose2(byte* str, int size, nan_rel_reqclose2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_destab1(byte* str, int size, nan_cli_destab1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_destab2(byte* str, int size, nan_int_destab2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_cli_dpay1(byte* str, int size, nan_cli_dpay1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_dpay2(byte* str, int size, nan_int_dpay2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_end_close1(byte* str, int size, nan_end_close1_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_close2(byte* str, int size, nan_int_close2_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_end_close3(byte* str, int size, nan_end_close3_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_close4(byte* str, int size, nan_int_close4_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_end_close5(byte* str, int size, nan_end_close5_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_close6(byte* str, int size, nan_int_close6_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_end_close7(byte* str, int size, nan_end_close7_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);
int unpack_nan_int_close8(byte* str, int size, nan_int_close8_t* tkn_out, byte(*pid_out)[DIGEST_LEN]);

size_t mt_token_get_size_of(mt_ntype_t type);
const char* mt_token_describe(mt_ntype_t type);

#endif
