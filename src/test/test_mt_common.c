#define MT_CCLIENT_PRIVATE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "test.h"
#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "mt_common.h"
#include "mt_cclient.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "buffers.h"

static void test_mt_common(void *arg)
{
  (void) arg;

    byte pp[MT_SZ_PP];
    byte pk[MT_SZ_PK];
    byte sk[MT_SZ_SK];

    mt_crypt_setup(&pp);
    mt_crypt_keygen(&pp, &pk, &sk);

    //----------------------------- Test PK to Address ---------------------------//

    byte pk_copy[MT_SZ_PK];
    byte pk_diff[MT_SZ_PK];
    byte sk_diff[MT_SZ_SK];

    memcpy(pk_copy, pk, MT_SZ_PK);
    mt_crypt_keygen(&pp, &pk_diff, &sk_diff);

    byte addr[MT_SZ_ADDR];
    byte addr_copy[MT_SZ_ADDR];
    byte addr_diff[MT_SZ_ADDR];

    mt_pk2addr(&pk, &addr);
    mt_pk2addr(&pk_copy, &addr_copy);
    mt_pk2addr(&pk_diff, &addr_diff);

    tt_assert(memcmp(addr, addr_copy, MT_SZ_ADDR) == 0);
    tt_assert(memcmp(addr, addr_diff, MT_SZ_ADDR) != 0);

    //----------------------------- Test Address to Hex --------------------------//

    byte* addr_str = (byte*)"20 bytes ++)(*_*)///";
    const char* expected_hex = "0x3230206279746573202B2B29282A5F2A292F2F2F\0";
    char* hex;

    tt_assert(mt_bytes2hex(addr_str, 20, &hex) == MT_SUCCESS);
    tt_assert(memcmp(expected_hex, hex, 43) == 0);

    byte* bytes;
    tt_assert(mt_hex2bytes(hex, &bytes) == 20);
    tt_assert(memcmp(bytes, addr_str, 20) == 0);

    free(hex);
    free(bytes);

    //----------------------------- Test Hash Chains -----------------------------//

    int hc_size = 1000;
    byte head[MT_SZ_HASH];
    byte hc[1000][MT_SZ_HASH];

    mt_crypt_rand(MT_SZ_HASH, head);
    mt_hc_create(hc_size, &head, &hc);

    // make sure correct hashes are correct
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[0]), 0) == MT_SUCCESS);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 2) == MT_SUCCESS);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), hc_size - 1) == MT_SUCCESS);

    // make sure incorrect hashes are incorrect
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size - 1]), 0) == MT_ERROR);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[hc_size / 2]), hc_size / 3 - 1) == MT_ERROR);
    tt_assert(mt_hc_verify(&(hc[0]), &(hc[0]), hc_size) == MT_ERROR);

 done:;
}

static void
mt_cclient_process_received_msg_mock(origin_circuit_t *circ, crypt_path_t *cpath,
    mt_ntype_t pcommand, byte *msg, size_t msg_len) {
  (void) circ;
  (void) cpath;
  (void) pcommand;
  (void) msg;
  (void) msg_len;
  return;
}

static void test_mt_process_msg(void *args) {
  (void) args;
  origin_circuit_t *circ = origin_circuit_new();
  relay_header_t *rh = tor_malloc_zero(sizeof(relay_header_t));
  relay_pheader_t *rph = tor_malloc_zero(sizeof(relay_pheader_t));
  cell_t cell;
  memset(&cell, 0, sizeof(cell_t));

  if (!circ->ppath) {
    circ->ppath = circuit_init_ppath(NULL);
    circ->ppath->next = circuit_init_ppath(circ->ppath);
    circ->ppath->next->next = circuit_init_ppath(circ->ppath->next);
  }
  if (!circ->cpath) {
    circ->cpath = tor_malloc_zero(sizeof(crypt_path_t));
    circ->cpath->next = tor_malloc_zero(sizeof(crypt_path_t));
  }
  MOCK(mt_cclient_process_received_msg, mt_cclient_process_received_msg_mock);
  byte *msg1 = tor_malloc_zero(1000*sizeof(byte));
  size_t msg_len1 = mt_token_get_size_of(MT_NTYPE_NAN_CLI_SETUP1);
  byte *msg2 = tor_malloc_zero(RELAY_PPAYLOAD_SIZE*sizeof(byte));
  size_t msg_len2 = RELAY_PPAYLOAD_SIZE;
  byte *msg3 = tor_malloc_zero(20*sizeof(byte));
  size_t msg_len3 = 20;

  rh->command = RELAY_COMMAND_MT;
  rh->length = RELAY_PPAYLOAD_SIZE + RELAY_PHEADER_SIZE;
  rph->pcommand = MT_NTYPE_NAN_CLI_SETUP1; // get_token_sz should return 1000;
  rph->length = RELAY_PPAYLOAD_SIZE;

  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_C_GENERAL;
  int i = 0;
  int bytes_remains = msg_len1;
  do {
    mt_process_received_relaycell(TO_CIRCUIT(circ), rh, rph,
        circ->cpath->next, cell.payload+RELAY_HEADER_SIZE+RELAY_PHEADER_SIZE);
    bytes_remains -= RELAY_PPAYLOAD_SIZE;
    if (bytes_remains < RELAY_PPAYLOAD_SIZE) {
      rph->length = bytes_remains;
    }
    i++;
  } while (buf_datalen(circ->ppath->next->buf) != 0 && i < 10);

  tt_int_op(i, OP_EQ, msg_len1/RELAY_PPAYLOAD_SIZE + 1);
  tt_int_op(buf_datalen(circ->ppath->next->buf), OP_EQ, 0);

  mt_cclient_init();
  node_t node;
  memset(&node, 0, sizeof(node_t));
  extend_info_t ei;
  memset(&ei, 0, sizeof(extend_info_t));
  intermediary_t *inter = intermediary_new(&node, &ei, 0);
  add_intermediary(inter);
  /* testing the other code path */
  circ->inter_ident = tor_malloc_zero(sizeof(intermediary_identity_t));
  memcpy(circ->inter_ident->identity, inter->identity->identity, DIGEST_LEN);
  TO_CIRCUIT(circ)->purpose = CIRCUIT_PURPOSE_C_INTERMEDIARY;
  circ->buf = buf_new_with_capacity(RELAY_PPAYLOAD_SIZE);
  rph->length = RELAY_PPAYLOAD_SIZE;
  bytes_remains = msg_len1;
  i = 0;
  do {
    mt_process_received_relaycell(TO_CIRCUIT(circ), rh, rph,
        circ->cpath->next, cell.payload+RELAY_HEADER_SIZE+RELAY_PHEADER_SIZE);
    bytes_remains -= RELAY_PPAYLOAD_SIZE;
    if (bytes_remains < RELAY_PPAYLOAD_SIZE) {
      rph->length = bytes_remains;
    }
    i++;
  } while (buf_datalen(circ->buf) != 0 && i < 10);
  tt_int_op(i, OP_EQ, msg_len1/RELAY_PPAYLOAD_SIZE+1);
  tt_int_op(buf_datalen(circ->buf), OP_EQ, 0);

 done:
  UNMOCK(mt_cclient_process_received_msg);
  tor_free(circ->cpath->next);
  tor_free(circ->cpath);
  circuit_free(TO_CIRCUIT(circ));
  tor_free(msg1);
  tor_free(msg2);
  tor_free(msg3);
}

struct testcase_t mt_common_tests[] = {
  /* This test is named 'strdup'. It's implemented by the test_strdup
   * function, it has no flags, and no setup/teardown code. */
{ "mt_common", test_mt_common, 0, NULL, NULL },
{ "process_msg", test_mt_process_msg, 0, NULL, NULL },
  END_OF_TESTCASES
};
