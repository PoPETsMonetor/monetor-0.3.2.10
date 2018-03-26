/**
 * \file mt_rpay.h
 * \brief Header file for mt_rpay.c
 **/

#ifndef mt_rpay_h
#define mt_rpay_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_rpay_init(void);

/**
 * Handle an incoming message from the given descriptor
 */
int mt_rpay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Handle an incoming message from the given client descriptor that is also
 * associated with a new intermediary descriptor. Currently, this is only needed
 * for the singular nan_cli_estab1 message.
 */
int mt_rpay_recv_multidesc(mt_desc_t* cdesc, mt_desc_t* idesc, mt_ntype_t type, byte* msg, int size);

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_rpay_mac_bal(void);

/**
 * Return the balance of money locked up in channels
 */
int mt_rpay_chn_bal(void);

/**
 * Return the number of channels currently open
 */
int mt_rpay_chn_number(void);

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_rpay_set_status(mt_desc_t* desc, int status);

/********************** Instance Management ***********************/

/**
 * Delete the state of the payment module
 */
int mt_rpay_clear(void);

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_rpay_export(byte** export_out);

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_rpay_import(byte* import);

#endif
