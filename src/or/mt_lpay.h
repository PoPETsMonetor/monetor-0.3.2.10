/**
 * \file mt_lpay.h
 * \brief Header file for mt_lpay.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_lpay_h
#define mt_lpay_h

#pragma GCC diagnostic ignored "-Waggregate-return"

#include "or.h"

#define MT_FEE 5
#define MT_TAX 5
#define MT_WINDOW 5

typedef struct {
  byte pp[MT_SZ_PP];
  int fee;
  int tax;
  int window;
  byte aut_pk[MT_SZ_PK];

  byte led_pk[MT_SZ_PK];
} mt_payment_public_t;

/**
 * Initialize a ledger instance given public input parameters
 * <b>pp<\b>, a per-ledger-post fee <b>fee<\b>, an intermediary tax
 * <b>tax<\b>, the number of epochs allowed for counterparties to
 * close a channel <b>window<\b>, and the public key of the tor
 * tax collector authority <b>auth_pk<\b>
 */
int mt_lpay_init(void);

/**
 * Handle an incoming message. Requires the message sender, type, and size.
 */
int mt_lpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Retrieve public parameters that define the ledger
 */
mt_payment_public_t mt_lpay_get_payment_public(void);

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_lpay_set_status(mt_desc_t* desc, int status);


/********************** Instance Management ***********************/

/**
 * Delete the state of the payment module
 */
int mt_lpay_clear(void);

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_lpay_export(byte** export_out);

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_lpay_import(byte* import);

/*********************** Testing Functions ************************/

int mt_lpay_query_mac_balance(byte (*addr)[MT_SZ_ADDR]);
int mt_lpay_query_end_balance(byte (*addr)[MT_SZ_ADDR]);
int mt_lpay_query_int_balance(byte (*addr)[MT_SZ_ADDR]);

#endif
