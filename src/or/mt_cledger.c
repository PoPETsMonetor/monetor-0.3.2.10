/**
 * \file mt_cledger.c
 */

#include "or.h"
#include "buffers.h"
#include "config.h"
#include "mt_common.h"
#include "mt_cledger.h"
#include "mt_lpay.h"
#include "main.h"
#include "torlog.h"
#include "container.h"
#include "router.h"
#include "circuitlist.h"
#include "relay.h"

static digestmap_t *desc2circ = NULL;
static uint64_t count[2] = {0, 0};

void
mt_cledger_init(void) {
  log_info(LD_MT, "MoneTor: initialization of the ledger controller module");
  desc2circ = digestmap_new();
  count[0] = rand_uint64();
  count[1] = rand_uint64();
  // XXX check with Thien-Nam wheter I am responsible
  // to init.
  log_info(LD_MT, "MoneTor: initialization of the ledger payment module");
  mt_lpay_init();
}

/**
 * When we see a first payment cell over a or_circuit_t,
 * then we call this function to initialize a new desc 
 * and add it to our desc2circ structure
 */
void mt_cledger_init_desc_and_add(or_circuit_t *circ, mt_party_t party) {
  increment(count);
  circ->desc.id[0] = count[0];
  circ->desc.id[1] = count[1];
  circ->desc.party = party;
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
}

/**********************Events************************/

static void
run_cledger_housekeeping_event(time_t now) {
  (void) now;
}


void run_cledger_scheduled_events(time_t now) {
  if (!ledger_mode(get_options()))
    return;
  run_cledger_housekeeping_event(now);
}

/* XXX Todo  complete this function and add the call
 * the function in circuit_about_to_free*/
void
mt_cledger_orcirc_has_closed(or_circuit_t *circ) {
  buf_free(circ->buf);
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
  }
  else {
    log_info(LD_MT, "MoneTor: desc %s not found in our map", mt_desc_describe(&circ->desc));
  }
}

/**
 * Used by the payment module to notify a signal
 *
 * Can be:
 *  ... (no ones currently)
 *
 *  XXX
 */

int
mt_cledger_paymod_signal(mt_signal_t signal, mt_desc_t *desc) {
  (void) signal;
  (void) desc;
  return 0;
}

void mt_cledger_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason) {
  /** XXX Do we have to notify the payment module
   * for any specific circuit? Maybe that would be nice
   * for memory management */
  if (abort) {
    log_info(LD_MT, "MoneTor: aborting a circuit");
  }
  else {
    log_info(LD_MT, "MoneTor: should do a non-abort clean close of the circuit");
  }
  circuit_mark_for_close(circ, reason);
}

/**********************Payment messages***************/

int
mt_cledger_send_message(mt_desc_t* desc, mt_ntype_t type, byte *msg, int msg_len) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  if (!circ) {
    log_info(LD_MT, "MoneTor: Looks like %s is not in our map", mt_desc_describe(desc));
    return -2;
  }
  if (circ->marked_for_close) {
    log_info(LD_MT, "MoneTor: Circuit associated with desc %s marked for close", mt_desc_describe(desc));
    return -2;
  }
  if (circ->state != CIRCUIT_STATE_OPEN) {
    log_info(LD_MT, "MoneTor: Error in mt_cledger_send_message; the circuit has a problem."
      " circ state: %s", circuit_state_to_string(circ->state));
    return -1;
  }
  return relay_send_pcommand_from_edge(circ, RELAY_COMMAND_MT, type,
      NULL, (const char*) msg, msg_len);
}

void mt_cledger_process_received_msg(circuit_t *circ, mt_ntype_t type,
    byte *msg, size_t msg_len) {
  
  mt_desc_t *desc;
  or_circuit_t *orcirc;

  if (circ->purpose == CIRCUIT_PURPOSE_LEDGER && CIRCUIT_IS_ORCIRC(circ)) {
    orcirc = TO_OR_CIRCUIT(circ);
    desc = &orcirc->desc;
    log_debug(LD_MT, "MoneTor: Calling mt_lpay_t for type %s, with payload of size %lu",
        mt_token_describe(type), msg_len);
    if (mt_lpay_recv(desc, type, msg, msg_len) < 0) {
      log_warn(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %hhx", type);
      // XXX decide What to do now? 
    }
  }
  else {
    log_info(LD_MT, "MoneTor: Processing circuit with unsupported purpose %s",
        circuit_purpose_to_string(circ->purpose));
  }
}

void mt_cledger_orcirc_free(or_circuit_t *circ) {
  buf_free(circ->buf);
}
