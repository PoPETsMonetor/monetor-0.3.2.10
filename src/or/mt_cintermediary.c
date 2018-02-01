#include "or.h"
#include "mt_cintermediary.h"
#include "mt_common.h"
#include "mt_ipay.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuituse.h"
#include "circuitlist.h"
#include "config.h"
#include "router.h"
#include "relay.h"
#include "torlog.h"
#include "nodelist.h"
#include "util.h"
#include "main.h"

STATIC void run_cintermediary_housekeeping_event(time_t now);
STATIC void run_cintermediary_build_circuit_event(time_t now);

static digestmap_t *desc2circ = NULL;

static smartlist_t *ledgercircs = NULL;
static ledger_t *ledger = NULL;
static uint64_t count[2] = {0, 0};

/********************** Once per second events ***********************/

STATIC void
run_cintermediary_housekeeping_event(time_t now) {
  (void) now;
}

/**
 * Once we have enough consensus information we try to build circuit
 * towards the ledger and maintain them open
 */

STATIC void
run_cintermediary_build_circuit_event(time_t now) {
  /* if Tor is not up, we stop  */
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;
  /* We get our ledger circuit and we built one if it is NULL */
  extend_info_t *ei = NULL;
  if (!ledger) {
    const node_t *node;
    node = node_find_ledger();
    if (!node) {
      log_info(LD_MT, "MoneTor: Hey, we do not have a ledger in our consensus?");
      return;  /** For whatever reason our consensus does not have a ledger */
    }
    ei = extend_info_from_node(node, 0);
    if (!ei) {
      log_info(LD_MT, "MoneTor: extend_info_from_node failed?");
      goto err;
    }
    ledger_init(&ledger, node, ei, now);
  }


  /* How many of them do we build? - should be linked to 
   * our consensus weight */
  origin_circuit_t *circ = NULL;
  
  while (smartlist_len(ledgercircs) < NBR_LEDGER_CIRCUITS &&
         ledger->circuit_retries < NBR_LEDGER_CIRCUITS*LEDGER_MAX_RETRIES) {
    /* this is just about load balancing */
    log_info(LD_MT, "MoneTor: We do not have enough ledger circuits - launching one more");
    int purpose = CIRCUIT_PURPOSE_I_LEDGER;
    int flags = CIRCLAUNCH_IS_INTERNAL;
    flags |= CIRCLAUNCH_NEED_UPTIME;
    circ = circuit_launch_by_extend_info(purpose, ledger->ei,
        flags);
    if (!circ) {
      ledger->circuit_retries++;
    }
    else {
      smartlist_add(ledgercircs, circ);
    }
  }
  if (ledger->circuit_retries >= NBR_LEDGER_CIRCUITS*LEDGER_MAX_RETRIES) {
    log_info(LD_MT, "MoneTor: It looks like we reach maximum cicuit launch"
        " towards the ledger. What is going on?");
  }
  return;
 err:
  extend_info_free(ei);
  ledger_free(&ledger);
  return;
}

void
run_cintermediary_scheduled_events(time_t now) {
  if (!intermediary_mode(get_options()))
    return;
  /** uselss right now */
  run_cintermediary_housekeeping_event(now);

  run_cintermediary_build_circuit_event(now);
}

/********************** circ event ***********************************/

void mt_cintermediary_ledger_circ_has_opened(origin_circuit_t *circ) {
  ledger->circuit_retries = 0;
  ledger->is_reachable = LEDGER_REACHABLE_YES;
  /* Generate new desc and add this circ into desc2circ */
  increment(count);
  circ->desc.id[0] = count[0];
  circ->desc.id[1] = count[1];
  circ->desc.party = MT_PARTY_LED;
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
}

void mt_cintermediary_ledger_circ_has_closed(circuit_t *circ) {
  time_t now;
  /* If the circuit is closed before we successfully extend
   * a general circuit towards the ledger, then we may have
   * a reachability problem.. */
  log_info(LD_MT, "MoneTor: called ledger_circ_has_closed");
  if (circ->state != CIRCUIT_STATE_OPEN) {
    now = time(NULL);
    log_info(LD_MT, "MoneTor: Looks like we did not extend a circuit successfully"
        " towards the ledger %lld", (long long) now);
    ledger->circuit_retries++;
  }
  smartlist_remove(ledgercircs, circ);
  /* XXX Todo should also remove from desc2circ */
  byte id[DIGEST_LEN];
  mt_desc2digest(&TO_ORIGIN_CIRCUIT(circ)->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
    log_info(LD_MT, "MoneTor: ledger circ has closed. Removed %s from our internal structure",
        mt_desc_describe(&TO_ORIGIN_CIRCUIT(circ)->desc));
  }
  else{
    log_info(LD_MT,
        "MoneTor: desc %s not found in our map", mt_desc_describe(&TO_ORIGIN_CIRCUIT(circ)->desc));
  }
}

void mt_cintermediary_orcirc_has_closed(or_circuit_t *circ) {
  buf_free(circ->buf);
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
    log_info(LD_MT, "MoneTor: orcirc circ has closed. Removed %s from our internal structure",
        mt_desc_describe(&circ->desc));
  }
  else {
    log_info(LD_MT, "MoneTor: desc %s not found in our map", mt_desc_describe(&circ->desc));
  }
  /* XXX TODO alert payment module to cashout? */
  /** This might happen because the circuit breaks
   * between the client and the intermediary; or the relay
   * and the intermediary. The relay (or client) should rebuild and
   * pursue the protocol. Is it possible? */
  /*mt_desc_free(&circ->desc);*/
}

/** We've received the first payment cell over that circuit 
 * init structure as well as add this circ in our structures*/

void mt_cintermediary_init_desc_and_add(or_circuit_t *circ, mt_party_t party) {
  increment(count);
  circ->desc.id[0] = count[0]; 
  circ->desc.id[1] = count[1]; 
  /*Cell received has been sent either by a relay or by a client */
  // XXX must be REL or CLI but IDK :/
  circ->desc.party = party; 
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  log_info(LD_MT, "New circuit connected to us received a payment cell."
      " Adding it to the map: %s", mt_desc_describe(&circ->desc));
}


/**
 * Used by the payment module to notify a signal
 *
 * Can be:
 *  ... (no ones currently)
 *
 *  XXX
 */

int mt_cintermediary_paymod_signal(mt_signal_t signal, mt_desc_t *desc) {
  (void) signal;
  (void) desc;
  return 0;
}

void mt_cintermediary_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason) {
  if (CIRCUIT_IS_ORIGIN(circ)) {
    /** That might be a ledger circ, just mark it as closed */
    circuit_mark_for_close(circ, reason);
  }
  else {
    or_circuit_t *orcirc = TO_OR_CIRCUIT(circ);
    if (orcirc->circuit_received_first_payment_cell && !abort) {
      /** XXX We want a proper close?*/
      log_warn(LD_MT, "MoneTor: We would like a proper close but not implemented");
      circuit_mark_for_close(circ, reason);
    }
    else {
      // XXX What if we have received cell but abort was 1? 
      if (!abort) {
        log_warn(LD_MT, "MoneTor: We would like a proper close but not implemented");
      }
      else {
        log_info(LD_MT, "MoneTor: Looks like we have to abort ~ marking this circ for close");
      }
      circuit_mark_for_close(circ, reason);
    }
  }
}

/********************** Utility stuff ********************************/

ledger_t *mt_cintermediary_get_ledger(void) {
  return ledger;
}

/********************** Payment related functions ********************/

int
mt_cintermediary_send_message(mt_desc_t *desc, mt_ntype_t pcommand,
    byte *msg, int size) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  crypt_path_t *layer_start = NULL;
  /** Might happen if the circuit has been closed */
  // We can go a bit further and re-send the command for 
  // ledger circuits when it is up again.
  if (!circ) {
    log_warn(LD_MT, "Looks like the circuit his not within our map :/");
    return -2;
  }
  if (circ->marked_for_close) {
    log_warn(LD_MT, "Looks like the circuit has been marked for close");
    return -2;
  }
  if (circ->state != CIRCUIT_STATE_OPEN) {
    log_info(LD_MT, "MoneTor: the circuit is still building?."
      " circ state: %s", circuit_state_to_string(circ->state));
    return -1;
  }
  if (circ->purpose == CIRCUIT_PURPOSE_I_LEDGER) {
    layer_start = TO_ORIGIN_CIRCUIT(circ)->cpath->prev;
  }
  return relay_send_pcommand_from_edge(circ, RELAY_COMMAND_MT,
      pcommand, layer_start, (const char*) msg, size);
}

void
mt_cintermediary_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len) {
  mt_desc_t *desc;
  or_circuit_t *orcirc;
  if (circ->purpose == CIRCUIT_PURPOSE_I_LEDGER) {
    tor_assert(ledger);
    desc = &ledger->desc;
    if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_warn(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %hhx", pcommand);
      circ->mt_priority = 0;
      log_warn(LD_MT, "MoneTor: PRIORITY DISABLED");
    }
  }
  else if (circ->purpose == CIRCUIT_PURPOSE_INTERMEDIARY) {
    orcirc = TO_OR_CIRCUIT(circ);
    desc = &orcirc->desc;
    if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_warn(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %hhx", pcommand);
      circ->mt_priority = 0;
      log_warn(LD_MT, "MoneTor: PRIORITY DISABLED");
    }
  }
  else {
    log_warn(LD_MT, "MoneTor: Processing circuit with unsupported purpose %s",
        circuit_purpose_to_string(circ->purpose));
  }
}


/*************************** init and free functions *****************/

void mt_cintermediary_init(void) {
  log_info(LD_MT, "MoneTor: Initialization of the intermediary controller module");
  desc2circ = digestmap_new();
  ledgercircs = smartlist_new();
  count[0] = rand_uint64();
  count[1] = rand_uint64();
  log_info(LD_MT, "MoneTor: Initialization of the intermediary payment module");
  /*mt_ipay_init();*/
}

