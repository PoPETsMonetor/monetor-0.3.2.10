/**
 * \file mt_ipay.h
 * \brief Header file for mt_ipay.c
 **/

#ifndef mt_ipay_h
#define mt_ipay_h

#include "or.h"

/**
 * Initialize the module; should only be called once. All necessary variables
 * will be loaded from the torrc configuration file.
 */
int mt_ipay_init(void);

/**
 * Handle an incoming message from the given descriptor
 */
int mt_ipay_recv(mt_desc_t* desc, mt_ntype_t type, byte* msg, int size);

/**
 * Return the balance of available money to spend as macropayments
 */
int mt_ipay_mac_bal(void);

/**
 * Return the balance of money locked up in channels
 */
int mt_ipay_chn_bal(void);

/**
 * Return the number of channels currently open
 */
int mt_ipay_chn_number(void);

/**
 * Update the status of a descriptor (available/unavailable)
 */
int mt_ipay_set_status(mt_desc_t* desc, int status);

/********************** Instance Management ***********************/

/**
 * Delete the state of the payment module
 */
int mt_ipay_clear(void);

/**
 * Export the state of the payment module into a serialized malloc'd byte string
 */
int mt_ipay_export(byte** export_out);

/**
 * Overwrite the current payment module state with the provided string state
 */
int mt_ipay_import(byte* import);


#endif
