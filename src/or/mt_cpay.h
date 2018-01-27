/**
 * \file mt_tokens.h
 * \brief Header file for mt_tokens.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_cpay_h
#define mt_cpay_h

#include "or.h"

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_cpay_init(void);

/**
 * Send a single payment to the relay through a given intermediary. If
 * <b>rdesc<\b> and <b>idesc<\b> are equal, then the payment module will make a
 * direct payment to the intermediary module. If a payment request to a given
 * relay is made with a different intermediary BEFORE the previous
 * relay/intermediary payment pair was closed, then this function will return an
 * error.
 */
int mt_cpay_pay(mt_desc_t* rdesc, mt_desc_t* idesc);

/**
 * Close an existing payment channel with the given relay/intermediary pair
 */
int mt_cpay_close(mt_desc_t* rdesc, mt_desc_t* idesc);

/**
 * Handle an incoming message from the given descriptor
 */
int mt_cpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_cpay_mac_balance(void);

/**
 * Return the balance of money locked up in channels
 */
int mt_cpay_chn_balance(void);

/**
 * Return the number of channels currently open
 */
int mt_cpay_chn_number(void);

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_cpay_set_status(mt_desc_t* desc, int status);

/********************** Instance Management ***********************/

/**
 * Delete the state of the payment module
 */
int mt_cpay_clear(void);

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_cpay_export(byte** export_out);

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_cpay_import(byte* import);

#endif
