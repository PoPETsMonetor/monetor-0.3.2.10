/**
 * \file mt_cledger.c
 */

#include "or.h"
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
  if (!authdir_mode(get_options()))
    return;
  run_cledger_housekeeping_event(now);
}

void
mt_cledger_orcirc_has_closed(or_circuit_t *circ) {
  buf_free(circ->buf);
  /* XXX Todo  complete this function and add the call
   * the function in circuit_about_to_free*/
}

/**********************Payment messages***************/

int
mt_cledger_send_message(mt_desc_t* desc, mt_ntype_t type, byte *msg, int msg_len) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  tor_assert(circ);
  if (circ->marked_for_close || circ->state != 
      CIRCUIT_STATE_OPEN) {
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

  if (circ->purpose == CIRCUIT_PURPOSE_LEDGER && CIRCUIT_IS_ORIGIN(circ)) {
    orcirc = TO_OR_CIRCUIT(circ);
    desc = &orcirc->desc;
    if (mt_lpay_recv(desc, type, msg, msg_len) < 0 ) {
      log_info(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %hhx", type);
      // XXX decide What to do now? 
    }
  }
  else {
    log_info(LD_MT, "MoneTor: Processing circuit with unsupported purpose %hhx",
        circ->purpose);
  }
}
