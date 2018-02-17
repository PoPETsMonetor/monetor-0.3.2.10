
#include "or.h"
#include "container.h"
#include "config.h"
#include "mt_common.h"
#include "mt_crelay.h"
#include "mt_rpay.h"
#include "mt_ipay.h"
#include "router.h"
#include "nodelist.h"
#include "circuitbuild.h"
#include "circuituse.h"
#include "circuitlist.h"
#include "relay.h"
#include "main.h"

static uint64_t count[2] = {0, 0}; 
static digestmap_t  *desc2circ = NULL;
static ledger_t *ledger = NULL;
static smartlist_t *ledgercircs = NULL;
static int intermediary_role_initiated = 0;

static void run_crelay_housekeeping_event(time_t now);
static void run_crelay_build_circuit_event(time_t now);

void
mt_crelay_init(void) {
  log_info(LD_MT, "MoneTor: initialization of controler relay code");
  ledgercircs = smartlist_new();
  desc2circ = digestmap_new();
  count[0] = rand_uint64();
  count[1] = rand_uint64();
  log_info(LD_MT, "MoneTor: initialization of payment relay code");
  mt_rpay_init();
  log_info(LD_MT, "MoneTor: initialization of payment intermediary code");
  intermediary_role_initiated = 1;
  mt_ipay_init();
}

void mt_crelay_init_desc_and_add(or_circuit_t *circ, mt_party_t party) {
  increment(count);
  circ->desc.id[0] = count[0];
  circ->desc.id[1] = count[1];
  circ->desc.party = party; // Should always be CLI
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  /* when it reaches 1000, it should receive
   * a payment from the client */
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
}

ledger_t * mt_crelay_get_ledger(void) {
  return ledger;
}

/************************** Open and close events **************/

/**
 *
 */
void
mt_crelay_ledger_circ_has_opened(origin_circuit_t *ocirc) {
  log_info(LD_MT, "MoneTor: Yay! one ledger circuit has opened");
  ledger->circuit_retries = 0;
  ledger->is_reachable = LEDGER_REACHABLE_YES;
  /* Generate new desc and add this circ into desc2circ */
  increment(count);
  /*ocirc->desc.id[0] = count[0];*/
  /*ocirc->desc.id[1] = count[1];*/
  /*ocirc->desc.party = MT_PARTY_LED;*/
  byte id[DIGEST_LEN];
  mt_desc2digest(&ledger->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(ocirc));
  mt_rpay_set_status(&ledger->desc, 1);
  if (intermediary_role_initiated) {
    mt_ipay_set_status(&ledger->desc, 1);
  }
}

void mt_crelay_ledger_circ_has_closed(origin_circuit_t *circ) {
  time_t now;
  /* If the circuit is closed before we successfully extend
   * a general circuit towards the ledger, then we may have
   * a reachability problem.. */
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    now = approx_time();
    log_info(LD_MT, "MoneTor: Looks like we did not extend a circuit successfully"
        " towards the ledger %lld", (long long) now);
    ledger->circuit_retries++;
  }
  smartlist_remove(ledgercircs, circ);
  byte id[DIGEST_LEN];
  mt_desc2digest(&ledger->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
    log_info(LD_MT, "MoneTor: ledger circ has closed. Removed %s from our internal structure",
        mt_desc_describe(&ledger->desc));
  }
  else {
    log_info(LD_MT, "MoneTor: in mt_crelay_ledger_circ_has_closed, Looks like our desc wasn't in our map? %s", mt_desc_describe(&circ->desc));
  }
  mt_rpay_set_status(&ledger->desc, 0);
  if (intermediary_role_initiated) {
    mt_ipay_set_status(&ledger->desc, 0);
  }
}

void
mt_crelay_intermediary_circ_has_closed(origin_circuit_t* ocirc) {
  /** If ocirc is not within our digestmap, it means that the payment
   * channel has been closed, then it is ok :) 
   * 
   * Careful, many payment channels might use the same intermediary circuit
   *
   * if circ within our digest map but not open, it means we not successfuly 
   * connected to the intermediary => close this circuit, launch one another and
   * log the attempt
   *
   * If circ closed but payment channel still open (the circ is still in 
   * the digestmap ~ or whatever logic which makes us certain that the channe
   * is open; launch again one circuit toward the intermediary */
  log_info(LD_MT, "MoneTor: Intermediary circ has closed");
  byte id[DIGEST_LEN];
  mt_desc2digest(ocirc->desci, &id);
  if (TO_CIRCUIT(ocirc)->state != CIRCUIT_STATE_OPEN) {
    /** Someway to indicate that we retry on an extend_info_t */
    tor_assert(ocirc->cpath);
    tor_assert(ocirc->cpath->prev);
    tor_assert(ocirc->cpath->prev->extend_info);
    /** Special case where it's already in the digestmap */
    if (digestmap_get(desc2circ, (char*) id)) {
      digestmap_remove(desc2circ, (char*) id);
    }
    else {
      log_info(LD_MT, "MoneTor: tried to remove the desc but it seems that this desc was not in our map anymore ~ bug?");
    }
    if (ocirc->cpath->prev->extend_info->retries < INTERMEDIARY_MAX_RETRIES) {
      node_t *node = 
        node_get_mutable_by_id(ocirc->cpath->prev->extend_info->identity_digest);
      extend_info_t *ei = extend_info_from_node(node, 0);
      if (!ei) {
        log_info(LD_MT, "MoneTor: Something went wrong with the extend_info");
        // XXX TODO alert the payment system to aboard

        return;
      }
      ei->retries = ++ocirc->cpath->prev->extend_info->retries;
      int purpose = CIRCUIT_PURPOSE_R_INTERMEDIARY;
      int flags = CIRCLAUNCH_IS_INTERNAL;
      flags |= CIRCLAUNCH_NEED_UPTIME;

      origin_circuit_t *circ = circuit_launch_by_extend_info(purpose, ei, flags);
      if (!circ) {
        log_warn(LD_MT, "MoneTor: Something went wrong when re-creating a circuit, we should abort");
        // XXX Todo alert the payment system to aboard
        return;
      }
      /** retrieve the pointer we change the circuit but we keep the same descriptor*/
      circ->desc = ocirc->desc;
    }
    else { /** We reache max retries */
      log_warn(LD_MT, "MoneTor: we reached the maximum allowed retry for intermediary %s"
          " .. we abort", extend_info_describe(ocirc->cpath->prev->extend_info));
      // XXX TODO alert the payement system to aboard
    }
    mt_rpay_set_status(ocirc->desci, 0);
    return;
  }
  mt_rpay_set_status(ocirc->desci, 0);
  if (!digestmap_get(desc2circ, (char*) id)) {
    // then its find
    log_warn(LD_MT, "MoneTor: Our intermerdiary circuit closed but it looks"
        " it has already been removed from our map => all payment channel should"
        " have closed: %s", mt_desc_describe(ocirc->desci));
    return;
  }
  else { //XXX TODO
    digestmap_remove(desc2circ, (char*) id);
  /** The circuit was open; so it was intentially closed by our side or someone in the path*/
    log_info(LD_MT, "MoneTor: an intermediary on the relay side has closed. Several possibilities:"
        " The circuit might have expired. The payment channel closed and made us closed this"
        " circuit (check if implemented). An error happened on the circuit and we received a destroy?");
    // Check if there is some other payment channel that use this circuit, if yes
    // then rebuild a circuit
    // XXX TODO => Thien-nam: How do we verify if a payment channel linked to
    // an intermediary is still open? 
  }
}

void 
mt_crelay_intermediary_circ_has_opened(origin_circuit_t* ocirc) {
  /** XXX Did Should notify the payment system when the intermediary is 
   * ready? */
  log_info(LD_MT, "MoneTor: Yay! An intermediary circuit opened");
  /** XXX notify payment module that the intermediary circuit is open */
  mt_rpay_set_status(ocirc->desci, 1);
}


void
mt_crelay_orcirc_has_closed(or_circuit_t *circ) {
  buf_free(circ->buf);
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
  }
  else {
    log_warn(LD_MT, "MoneTor: desc %s not found in our map", mt_desc_describe(&circ->desc));
  }

  if (circ->desci) {
    mt_rpay_set_status(circ->desci, 0);
    mt_desc2digest(circ->desci, &id);
    /** remove or intermediary map duplication */
    if (digestmap_get(desc2circ, (char*) id)) {
      digestmap_remove(desc2circ, (char*) id);
    }
    else {
      log_warn(LD_MT, "MoneTor: desc %s not found in our map", mt_desc_describe(&circ->desc));
    }
  }
}

/************************** Events *****************************/

static void
run_crelay_housekeeping_event(time_t now) {
  
  /** Checks whether we might be an intermediary
   *  we need the guard flag, though */
  /*if (!intermediary_role_initiated) {*/
    /*const node_t *me = node_get_by_id((const char*)router_get_my_id_digest());*/
    /*if (me && me->is_possible_guard) {*/
      /*log_info(LD_MT, "MoneTor: This relay can be used as a guard."*/
          /*" We initiate the ipay module");*/
      /*intermediary_role_initiated = 1;*/
      /*mt_ipay_init();*/
    /*}*/
  /*}*/
  /** On the todo-list: check for the payment window 
   * system.
   * Logic: Every second, we check if every payment windows
   * are in a correct state => Do we received our payment, etc?
   */
  log_info(LD_MT, "MoneTor: relay digestmap length: %d at time %lld", 
      digestmap_size(desc2circ), (long long) now);
  DIGESTMAP_FOREACH(desc2circ, key, circuit_t *, circ) {
    if (CIRCUIT_IS_ORCIRC(circ) && circ->mt_priority && circ->payment_window < 0) {
      /*tor_assert_nonfatal(circ->payment_window > 0);*/
      log_warn(LD_MT, "MoneTor: this circuit has negative window, this should not happen!");
    }
  } DIGESTMAP_FOREACH_END;
}

/**
 *  Ensure that ledgers circuits are up 
 *  Ensure that current circuit toward intermediaries
 *  are up ~ if not, rebuilt circuit to them. Eventually
 *  tell the payment controller that we cannot connect
 *  to the intermediary to cashout and stop prioritizing
 *  the circuit(s) related to this intermediary 
 *  
 *  Recall: Intermediary circuits are built when
 *  we receive information by a client
 *  */

static void
run_crelay_build_circuit_event(time_t now) {

  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;
  /** Note: code duplication with crelay and cclient ~ maybe do something smarter? */
  extend_info_t *ei = NULL;
  if (!ledger) {
    const node_t *node;
    node = node_find_ledger();
    if (!node) {
      log_warn(LD_MT, "MoneTor: Hey, we do not have a ledger in our consensus?");
      return;  /** For whatever reason our consensus does not have a ledger */
    }
    ei = extend_info_from_node(node, 0);
    if (!ei) {
      log_warn(LD_MT, "MoneTor: extend_info_from_node failed?");
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
    int purpose = CIRCUIT_PURPOSE_R_LEDGER;
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
    log_warn(LD_MT, "MoneTor: It looks like we reach maximum cicuit launch"
        " towards the ledger. What is going on?");
  }
  return;
 err:
  extend_info_free(ei);
  ledger_free(&ledger);
  return;
}

void
run_crelay_scheduled_events(time_t now) {
  if (intermediary_mode(get_options()) ||
      ledger_mode(get_options()))
    return;
  /* Make sure our controller is healthy */
  run_crelay_housekeeping_event(now);
  /* Make sure our ledger circuit and curent intermediary
   * circuits are up */
  run_crelay_build_circuit_event(now);
}

/************************** Payment related functions ********************/

int
mt_crelay_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  crypt_path_t *layer_start = NULL;
  
  if (!circ) {
    log_warn(LD_MT, "MoneTor: circ linked to mt_desc_t %s is not in our map, in mt_crelay_send_message"
        " for command %s", mt_desc_describe(desc), mt_token_describe(type));
    return -2;
  }

  if (circ->marked_for_close) {
    log_warn(LD_MT, "MoneTor: Tried to send a message over a circuit marked for close");
    return -2;
  }
  if (circ->state != CIRCUIT_STATE_OPEN) {
    log_info(LD_MT, "MoneTor: the circuit is not open yet."
      " circ state: %s when sending %s for desc %s", circuit_state_to_string(circ->state),
      mt_token_describe(type), mt_desc_describe(desc));
    return -1;
  }
  if (command == RELAY_COMMAND_MT) {
    if (circ->purpose == CIRCUIT_PURPOSE_R_LEDGER || 
        circ->purpose == CIRCUIT_PURPOSE_R_INTERMEDIARY) {
      /** Message for the ledger an intermediary */
      layer_start = TO_ORIGIN_CIRCUIT(circ)->cpath->prev;
    }
    return relay_send_pcommand_from_edge(circ, command,
        type, layer_start, (const char*) msg, size);
  }
  else if (command == CELL_PAYMENT){ /** CELL_PAYMENT */
    return mt_common_send_direct_cell_payment(circ, type, msg, size,
        CELL_DIRECTION_IN);
  }
  else {
    log_warn(LD_MT, "Unrecognized command %d", command);
    return -2;
  }
}

void
mt_crelay_process_received_msg(circuit_t *circ, mt_ntype_t pcommand,
    byte *msg, size_t msg_len) {
  mt_desc_t *desc;
  or_circuit_t *orcirc;
  if (CIRCUIT_IS_ORIGIN(circ)) {
  //XXX Todo
  // should be a ledger circuit or a circuit to an interemdiary
    if (circ->purpose == CIRCUIT_PURPOSE_R_LEDGER) {
      desc = &ledger->desc;
    }
    else if (circ->purpose == CIRCUIT_PURPOSE_R_INTERMEDIARY) {
      desc = TO_ORIGIN_CIRCUIT(circ)->desci;
    }
    else {
      log_warn(LD_MT, "MoneTor: no purpose matching in mt_crelay_process_received_msg");
      return;
    }
    if (mt_rpay_recv(desc, pcommand, msg, msg_len) < 0) {
      // XXX What do we do? aboard every circuit linked to this
      if (circ->purpose == CIRCUIT_PURPOSE_R_LEDGER) {
        /** Might be a LED_CONFIRM on a guard relay, for the intermediary */
        if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
          log_warn(LD_MT, "MoneTor: Payment module returned -1 for %s",
              mt_token_describe(pcommand));
        }
      }
      else if(circ->purpose == CIRCUIT_PURPOSE_R_INTERMEDIARY) {
        log_warn(LD_MT, "MoneTor: Payment module returned -1 for %s",
            mt_token_describe(pcommand));
      }
    }
  }
  else {
    /** It is not an origin circ */
    orcirc = TO_OR_CIRCUIT(circ);
    /** Guard relay are their own intermediary */
    if (mt_token_is_for_intermediary(pcommand)) {
      desc = &orcirc->desc;
      if (mt_ipay_recv(desc, pcommand, msg, msg_len) < 0) {
        log_warn(LD_MT, "MoneTor: Payment module returned -1 for command %s",
            mt_token_describe(pcommand));
      }
    }
    else if (pcommand == MT_NTYPE_NAN_CLI_ESTAB1) {
      //circ should a or_circuit_t of a normal circuit with
      //a normal client over one endpoint
      /** We just receive information to contact an intermediary */
      /** First, we unpack the identity of the intermediary we have to connect to.
       * If we already have a circuit towards that intermediary, that's nice. If not,
       * launch a new circuit and notify the payment module as soon it opens */

      /* We have to open a circuit towards the interemdiary received */
      int_id_t int_id;
      unpack_int_id(msg, &int_id);
      /* Find node with that identity and extend a circuit
       * to it */
      const node_t *ninter = node_get_by_id(int_id.identity);
      if (!ninter) {
        log_warn(LD_MT, "MoneTor: received identity %s but there is no such node"
            " in my consensus", int_id.identity);
        //XXX alert payment that something was not ok
        return;
      }

      log_info(LD_MT, "MoneTor: received intermediary identity %s", node_describe(ninter));

      /** Now, try to find a circuit to ninter of launch one */
      origin_circuit_t *oricirc = NULL;
      
      SMARTLIST_FOREACH_BEGIN(circuit_get_global_list(), circuit_t*, circtmp) {
        if (!circtmp->marked_for_close && CIRCUIT_IS_ORIGIN(circtmp) &&
            circ->purpose == CIRCUIT_PURPOSE_R_INTERMEDIARY) {
          if (!TO_ORIGIN_CIRCUIT(circtmp)->cpath)
            continue;
          if (!TO_ORIGIN_CIRCUIT(circtmp)->cpath->prev)
            continue;
          if (!TO_ORIGIN_CIRCUIT(circtmp)->cpath->prev->extend_info)
            continue;
          if (tor_memeq(TO_ORIGIN_CIRCUIT(circtmp)->cpath->prev->extend_info->identity_digest,
                int_id.identity, DIGEST_LEN)) {
            oricirc = TO_ORIGIN_CIRCUIT(circtmp);
            break;
          }
        }
      } SMARTLIST_FOREACH_END(circtmp);

      /** We didn't find a circ connected/connecting to ninter */
      mt_desc_t *desci = tor_malloc_zero(sizeof(mt_desc_t));
      memcpy(desci, msg+sizeof(int_id_t), sizeof(mt_desc_t));
      if (!oricirc) {
        log_info(LD_MT, "MoneTor: We don't have any current circuit towards %s that intermediary"
            " .. Building one. ", node_describe(ninter));
        extend_info_t *ei = NULL;
        ei = extend_info_from_node(ninter, 0);
        if (!ei) {
          log_warn(LD_MT, "MoneTor: We did not successfully produced an extend"
              " info from node %s", node_describe(ninter));
          //XXX alert payment something went wrong
          return;
        }
        int purpose = CIRCUIT_PURPOSE_R_INTERMEDIARY;
        int flags = CIRCLAUNCH_IS_INTERNAL;
        flags |= CIRCLAUNCH_NEED_UPTIME;
        oricirc = circuit_launch_by_extend_info(purpose, ei, flags);
        if (!oricirc) {
          log_warn(LD_MT, "MoneTor: Not successfully launch a circuit :/ abording");
          //XXX alert payment module
          return;
        }
        oricirc->desci = desci;
      }
      else {
        /** XXX: Should we notify the payment module about that it can send towards the
         * intermediary without waiting?*/
        log_info(LD_MT, "MoneTor: Cool, we already have a circuit towards that intermediary");
      }

      orcirc->desci = oricirc->desci;

      /** adding to digestmap desci => oricirc */
      byte id[DIGEST_LEN];
      mt_desc2digest(desci, &id);
      if (!digestmap_get(desc2circ, (char*) id)) {
        digestmap_set(desc2circ, (char*) id, oricirc);
      }

      if (mt_rpay_recv_multidesc(&orcirc->desc, desci, pcommand,
         msg+sizeof(int_id_t)+sizeof(mt_desc_t),
         msg_len-sizeof(int_id_t)-sizeof(mt_desc_t)) < 0) {
        log_warn(LD_MT, "MoneTor: Payment module returned -1"
            " we should stop prioritizing this circuit");
        circ->mt_priority = 0;
        log_warn(LD_MT, "MoneTor: PRIORITY DISABLED");
      }
    }
    else {
      desc = &orcirc->desc;
      if (mt_rpay_recv(desc, pcommand, msg, msg_len) < 0) {
        log_info(LD_MT, "MoneTor: Payment module returnerd -1"
            " for %s we should stop prioritizing this circuit",
            mt_token_describe(pcommand));
        circ->mt_priority = 0;
        log_warn(LD_MT, "MoneTor: PRIORITY DISABLED");
      }
    }
  }
}

/**
 * Called each time we relay a cell or recognize a
 * RELAY_DATA cell
 *
 * Decrease the payment_window
 */

void mt_crelay_update_payment_window(circuit_t *circ) {
  if (get_options()->EnablePayment &&
      circ->mt_priority) {
    if (--circ->payment_window < 10) {
       /*log_warn(LD_MT, "Payment window critically low: remains"*/
          /*" %d cells on relay side (negative value means we prioritize at credit!)", circ->payment_window);*/
    }
  }
}


/**
 * Called by the payment module to signal an event
 * 
 * Can be either :
 *   MT_SIGNAL_PAYMENT_INITIALIZED
 *   MT_SIGNAL_PAYMENT_RECEIVED
 *   MT_SIGNaL_INTERMEDIARY_IDLE
 *
 */

int mt_crelay_paymod_signal(mt_signal_t signal, mt_desc_t *desc) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  if (!circ) {
    log_info(LD_MT, "MoneTor: looks like desc %s is not within our map", mt_desc_describe(desc));
    return -1;
  }
  if (signal == MT_SIGNAL_PAYMENT_INITIALIZED) {
    /** Set this circuit with priority */
    if (!circ->marked_for_close) {
      circ->mt_priority = 1;
      circ->payment_window = 3000;
      log_warn(LD_MT, "MoneTor: PRIORITY ENABLED on circ n_circ_id %u", circ->n_circ_id);
    } 
    else {
      log_warn(LD_MT, "MoneTor: Seems that the circuit has been closed");
      digestmap_remove(desc2circ, (char*) id);
      return -1;
    }
  }
  else if (signal == MT_SIGNAL_PAYMENT_RECEIVED) {
    if (!circ->marked_for_close) {
      circ->mt_priority++;
      circ->payment_window += 2000;
      log_info(LD_MT, "MoneTor: Payment %u received , increasing the window", circ->mt_priority);
    }
    else {
      log_info(LD_MT, "MoneTor: Seems that the circuit has been closed, it should"
          " be freed soon");
      /*digestmap_remove(desc2circ, (char*) id);*/ //done in has_closed function
      return -1;
    }
  }
  else if (signal == MT_SIGNAL_INTERMEDIARY_IDLE) {
    /** Marking this circuit for close */
    if (!circ->marked_for_close) {
      log_info(LD_MT, "We received a SIGNAL_INTERMEDIARY_IDLE, we mark the circuit"
          " for close");
      circuit_mark_for_close(circ, END_CIRC_REASON_NONE);
    }
  }
  else {
    log_info(LD_MT, "Received a signal we can't handle on mt_crelay");
    return -1;
  }
  return 0;
}

/**
 * XXX See what to do:
 * 1) Notify the payment module with mt_rpay_abort()
 * 2) R notifies C that it is about to close (this might be implicit in the circuit destroy)
 * 3) R initializes a close with I
 * 4) C waits some amount of time then attempts to close with I (since I must close with R before it can close with C)
 * 5) If 4) fails, then C reconnects wtih R to try to request a proper close
 * 6) If either C or R fails to close for any reason, then wait for a reasonable amount of time then bring all the relevant info to close on the ledger.
 */

void mt_crelay_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason) {
  (void) abort;
  if (CIRCUIT_IS_ORIGIN(circ)) {
    /** either a ledger circ or an interemdiary circ, we close. this circuit should be
     * relaunched anyway, later */
    log_info(LD_MT, "MoneTor: marking an origin circuit for close");
    circuit_mark_for_close(circ, reason);
  }
  else {
    /** Before sending a destroy cell, let's try to close */
    log_warn(LD_MT, "MoneTor: We should properly close from relay side (not implemented), so "
        "we destroy the circuit");
    circuit_mark_for_close(circ, reason);
    // XXX No mt_rpay_close ??
  }
}
