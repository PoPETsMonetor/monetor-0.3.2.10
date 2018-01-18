#ifndef mt_crelay_h
#define mt_crelay_h
/**** INIT ****/
void mt_crelay_init(void);

/**** Events ****/

void run_crelay_scheduled_events(time_t now);

void mt_crelay_ledger_circ_has_closed(origin_circuit_t* ocirc);

void mt_crelay_ledger_circ_has_opened(origin_circuit_t* ocirc);

void mt_crelay_intermediary_circ_has_closed(origin_circuit_t* ocirc);

void mt_crelay_intermediary_circ_has_opened(origin_circuit_t* ocirc);

void mt_crelay_init_desc_and_add(or_circuit_t *circ, mt_party_t party);

int mt_crelay_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size);

void mt_crelay_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len);

int mt_crelay_alert_payment(mt_desc_t *desc);

ledger_t * mt_crelay_get_ledger(void);

#endif
