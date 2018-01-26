/**
 * \file mt_cledger.h
 */

#ifndef mt_cledger_h
#define mt_cledger_h

#include "or.h"
#include "mt_common.h"

void mt_cledger_init(void);


void run_cledger_scheduled_events(time_t now);

/**
 * When we received a fist payment cell over a new unused
 * or_circuit, then we create a new descriptor and add it
 * within our structure
 */
void mt_cledger_init_desc_and_add(or_circuit_t *circ, mt_party_t party);

/**
 * When a CIRCUIT_PURPOSE_LEDGER closes, this function should
 * be called
 */
void mt_cledger_orcirc_has_closed(or_circuit_t *circ);

void mt_cledger_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason);

int mt_cledger_paymod_signal(mt_signal_t signal, mt_desc_t *desc);

/******************* Payment related messages *******/


int mt_cledger_send_message(mt_desc_t* desc, mt_ntype_t type,
    byte *msg, int size);

void mt_cledger_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len);

#endif

