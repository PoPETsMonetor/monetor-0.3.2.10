/**
 * \file mt_cintermediary.h
 *
 * \brief Header file for mt_cintermediary.c
 */

#ifndef mt_cintermediary_h
#define mt_cintermediary_h

#include "or.h"
#include "mt_common.h"
void mt_cintermediary_init(void);


void run_cintermediary_scheduled_events(time_t now);


/********************* Circ event ********************************/

void mt_cintermediary_ledger_circ_has_opened(origin_circuit_t *circ);

void mt_cintermediary_ledger_circ_has_closed(circuit_t *circ);

/** When a CIRCUIT_PURPOSE_INTERMEDIARY closes, this function
 * should be called */

void mt_cintermediary_orcirc_has_closed(or_circuit_t *circ);

/** We've received the fist cell over what is now a CIRCUIT_PURPOSE_INTERMEDIARY
 * we initiate the new mt_desc_t and we add this circuit into our 
 * structures */
void  mt_cintermediary_init_desc_and_add(or_circuit_t *circ, mt_party_t party);

int mt_cintermediary_paymod_signal(mt_signal_t signal, mt_desc_t *desc);

void mt_cintermediary_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason);

void mt_cintermediary_orcirc_free(or_circuit_t *circ);

/********************* Utility stuffs ****************************/

ledger_t *mt_cintermediary_get_ledger(void);

/********************* Payment related messages ******************/

int mt_cintermediary_send_message(mt_desc_t* desc,
    mt_ntype_t type, byte *msg, int size);

void mt_cintermediary_process_received_msg(circuit_t *circ,
    mt_ntype_t pcommand, byte *msg, size_t msg_len);

#endif
