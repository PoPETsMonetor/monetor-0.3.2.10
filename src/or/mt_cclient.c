/**
 * \file mt_cclient.c
 * Implement the controller logic for the MoneTor payment system when
 * this Tor instance is used as a client. This module interacts with
 * mt_cpay.c module to produce and verify the crypto pieces.
 *
 * This module is responsible to select, build and maintain the connections
 * towards the ledger and the intermediaries. This module is also
 * responsible to track the number of cell received and sent that have
 * been relayed alongside a payment channel and to ensure payment have
 * been made properly
 *
 * Finally, it acts as an interface to the network logic and the payment
 * logic.
 */


#include "or.h"
#include "config.h"
#include "buffers.h"
#define MT_CCLIENT_PRIVATE
#include "mt_cclient.h"
#include "mt_common.h"
#include "mt_cpay.h"
#include "mt_ipay.h"
#include "channel.h"
#include "nodelist.h"
#include "routerlist.h"
#include "util.h"
#include "container.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "relay.h"
#include "router.h"
#include "torlog.h"
#include "main.h"
#include "networkstatus.h"


/* Some forward static declaration for ease of implem */


STATIC void run_cclient_housekeeping_event(time_t now);

static void choose_intermediaries(time_t now, smartlist_t *exclude_list);

static void intermediary_need_cleanup(intermediary_t *intermediary,
    time_t now);

STATIC void run_cclient_build_circuit_event(time_t now);

static void intermediary_free(intermediary_t *intermediary);

/*List of selected intermediaries */
static smartlist_t *intermediaries = NULL;
/*Contains which origin_circuit_t is related to desc
 *a get operation will need to be done at each payment callback call
 *- Is there enough performance?? */
static digestmap_t* desc2circ = NULL; // mt_desc2digest => origin_circuit_t
/*static counter of descriptors - also used as id*/
static uint64_t count[2] =  {0, 0};
/*static ledger */
static ledger_t *ledger = NULL;
/*list of circuits to the ledger */
static smartlist_t *ledgercircs;
/**
 * Allocate on the heap a new intermediary and returns the pointer
 */

STATIC intermediary_t *
intermediary_new(const node_t *node, extend_info_t *ei, time_t now) {
  tor_assert(node);
  tor_assert(ei);
  intermediary_t *intermediary = tor_malloc_zero(sizeof(intermediary_t));
  intermediary->identity = tor_malloc_zero(sizeof(intermediary_t));
  memcpy(intermediary->identity->identity, node->identity, DIGEST_LEN);
  intermediary->is_reachable = INTERMEDIARY_REACHABLE_MAYBE;
  increment(count);
  intermediary->desc.id[0] = count[0]; 
  intermediary->desc.id[1] = count[1]; 
  intermediary->desc.party = MT_PARTY_INT;
  intermediary->chosen_at = now;
  intermediary->ei = ei;
  log_info(LD_MT, "Intermediary created at %lld", (long long) now);
  return intermediary;
}

static void
intermediary_free(intermediary_t *intermediary) {
  if (!intermediary)
    return;
  if (intermediary->ei)
    extend_info_free(intermediary->ei);
  tor_free(intermediary);
}

/*
 * Builds and returns a smartlist_t containing node_t objects
 * of intermediaries
 */
smartlist_t* get_node_t_smartlist_intermerdiaries(void) {
  smartlist_t *all_inter_nodes = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    smartlist_add(all_inter_nodes, (void *)node_get_by_id(intermediary->identity->identity));
  }SMARTLIST_FOREACH_END(intermediary);
  return all_inter_nodes;
}

/*
 * Get the first intermediary withing the list intermediaries that
 * matches linked_to to position
 */
intermediary_t* get_intermediary_by_role(position_t position) {
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    if (intermediary->linked_to == position)
      return intermediary;
  } SMARTLIST_FOREACH_END(intermediary);
  return NULL;
}

/** Get intermediary matching inter_ident
 */

intermediary_t *get_intermediary_by_identity(intermediary_identity_t *ident) {
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    if (tor_memeq(intermediary->identity->identity, 
          ident->identity, DIGEST_LEN)){
      return intermediary;
    }
  } SMARTLIST_FOREACH_END(intermediary);
  return NULL;
}

smartlist_t* get_intermediaries(int for_circuit) {
  (void)for_circuit;
  return NULL;
}

int mt_cclient_is_intermediary(const char *identity) {
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t*, intermediary) {
    if (tor_memeq(intermediary->identity->identity, identity,
          DIGEST_LEN))
      return 1;
  } SMARTLIST_FOREACH_END(intermediary);
  return 0;
}

int mt_cclient_is_ledger(const char *identity) {
  if (!ledger)
    return 0;
  return tor_memeq(ledger->identity.identity, identity, DIGEST_LEN);
}

void add_intermediary(intermediary_t *inter) {
  /**Used by unit tests*/
  smartlist_add(intermediaries, inter);
}

void
mt_cclient_init(void) {
  log_info(LD_MT, "MoneTor: initialization of controler client code");
  tor_assert(!intermediaries); //should never be called twice
  intermediaries = smartlist_new();
  desc2circ = digestmap_new();
  ledgercircs = smartlist_new();
  count[0] = rand_uint64();
  count[1] = rand_uint64();
  log_info(LD_MT, "MoneTor: initialization of payment client module");
  mt_cpay_init();
}

/**
 * Remove the intermdiary from the list we are using because
 * of one of the following reasons::
 * XXX MoneTor - FR: do we implement all of them?
 * - Node does not exist anymore in the consensus (do we care for simulation?)
 * - The intermediary maximum circuit retry count has been reached (we DO care about that)
 * - The intermediary has expired (we need to cashout and rotate => do we care?)
 */
static void
intermediary_need_cleanup(intermediary_t *intermediary, time_t now) {
  if (intermediary->circuit_retries > INTERMEDIARY_MAX_RETRIES ||
      intermediary->is_reachable == INTERMEDIARY_REACHABLE_NO) {
    
    log_warn(LD_MT, "MoneTor: Looks like we have to cleanup intermediary :/");
    /* Get all general circuit linked to this intermediary and
     * mark the payment as closed */
    // XXX MoneTor todo

    /* Remove intermediary from the list */
    SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
        inter) {
      if (tor_memeq(intermediary->identity->identity,
            inter->identity->identity, DIGEST_LEN)){
        byte id[DIGEST_LEN];
        mt_desc2digest(&intermediary->desc, &id);
        if (digestmap_get(desc2circ, (char*) id)) {
          digestmap_remove(desc2circ, (char*) id);
        }
        SMARTLIST_DEL_CURRENT(intermediaries, inter);
        intermediary_free(intermediary);
        log_info(LD_MT, "MoneTor: Removing intermediary from list %lld",
            (long long) now);
        break;
      }
    } SMARTLIST_FOREACH_END(inter);
  }
}

/*
 * This function is responsible to choose the right intermediary
 * to use with the circuit circ, create the descriptor
 * mt_desc_t * and notify the payment module that we
 * want to establish a payment circuit.
 */

void
mt_cclient_launch_payment(origin_circuit_t* circ) {
  log_info(LD_MT, "MoneTor - Initiating payment - calling payment module");
  
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit()) {
    log_warn(LD_MT, "MoneTor: Looks like we launch a payment while we still not bootstrapped?");
    return;
  }
  increment(count);
  circ->ppath->desc.id[0] = count[0];
  circ->ppath->desc.id[1] = count[1];
  circ->ppath->desc.party = MT_PARTY_REL;
  /* Choosing right intermediary */
  tor_assert(circ->ppath->next);
  pay_path_t* middle = circ->ppath->next;
  intermediary_t* intermediary_g = get_intermediary_by_role(MIDDLE);
  increment(count);
  middle->desc.id[0] = count[0];
  middle->desc.id[1] = count[1];
  middle->desc.party = MT_PARTY_REL;
  /* Log if intermediary is NULL? Should not happen*/
  if (!intermediary_g) {
    log_warn(LD_MT, "Looks like we do not have an intermediary yet ..");
    circuit_mark_for_close(TO_CIRCUIT(circ), -1);
    return;
  }

  if (intermediary_g) {
    memcpy(middle->inter_ident->identity, intermediary_g->identity->identity,
        DIGEST_LEN);
  }
  tor_assert(middle->next);
  pay_path_t* exit = middle->next;
  intermediary_t* intermediary_e = get_intermediary_by_role(EXIT);
  increment(count);
  exit->desc.id[0] = count[0];
  exit->desc.id[1] = count[1];
  exit->desc.party = MT_PARTY_REL;
  tor_assert_nonfatal(intermediary_e);
  
  if (intermediary_e) {
    memcpy(exit->inter_ident->identity, intermediary_e->identity->identity,
        DIGEST_LEN);
  }
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&circ->ppath->desc));
  /* Adding new elements to digestmap */
  byte id[DIGEST_LEN];
  mt_desc2digest(&circ->ppath->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&middle->desc));
  mt_desc2digest(&middle->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  log_info(LD_MT, "MoneTor - Adding circ's descs %s to digestmap",
      mt_desc_describe(&exit->desc));
  mt_desc2digest(&exit->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  /*Now, notify payment module that we have to start a payment*/
  int retVal;
  log_info(LD_MT, "MoneTor - Calling payment module for direct payment"
      " with param %s and %s", mt_desc_describe(&circ->ppath->desc),
      mt_desc_describe(&circ->ppath->desc));
  /* Direct payment to the guard */
  retVal = mt_cpay_pay(&circ->ppath->desc, &circ->ppath->desc);
  if (retVal < 0) {
    //XXX MoneTor - Do we mark the payment for close?
    circ->ppath->p_marked_for_close = 1;
    // If first one marked for close, do we close the others?
    log_info(LD_MT, "MoneTor: mt_cpay_pay returned -1");
  }
  log_info(LD_MT, "MoneTor - Calling payment module for payment of middle node"
      " with param %s and %s", mt_desc_describe(&middle->desc),
      mt_desc_describe(&intermediary_g->desc));
  /* Payment to the middle relay involving intermediary */
  retVal = mt_cpay_pay(&middle->desc, &intermediary_g->desc);
  if (retVal < 0) {
    middle->p_marked_for_close = 1;
    log_info(LD_MT, "MoneTor: mt_cpay_pay returned -1");
  }
  log_info(LD_MT, "MoneTor - Calling payment module for payment of exit node"
      " with param %s and %s", mt_desc_describe(&exit->desc),
      mt_desc_describe(&intermediary_e->desc));
  /* Payment to the exit relay involving intermediary */
  retVal = mt_cpay_pay(&exit->desc, &intermediary_e->desc);
  if (retVal < 0) {
    exit->p_marked_for_close = 1;
    log_info(LD_MT, "MoneTor: mt_cpay_pay returned -1");
  }
}


/*
 * Fill the intermediaries smartlist_t with selected
 * intermediary_t
 *
 * XXX MoneTor - parse the state file to recover previously
 *               intermediaries
 *
 * If no intermediaries in the statefile, select new ones
 */
static void
choose_intermediaries(time_t now, smartlist_t *exclude_list) {
  if (smartlist_len(intermediaries) == MAX_INTERMEDIARY_CHOSEN)
    return;
  log_info(LD_MT, "MoneTor: Choosing intermediaries");
  /*We do not have enough node, let's pick some.*/
  const node_t *node = NULL;
  /*Handling extend info here is going to ease my life - great idea of the day*/
  extend_info_t *ei = NULL;
  intermediary_t *intermediary = NULL;
  int count_middle = 0, count_exit = 0;
  /*Normal intermediary flags - We just need uptime*/
  router_crn_flags_t flags = CRN_NEED_INTERMEDIARY;

  node = router_choose_random_node(exclude_list, get_options()->ExcludeNodes,
      flags);
  
  if (!node) {
    log_warn(LD_MT, "MoneTor - Something went wrong, we did not select any intermediary");
    goto err;
  }
  log_info(LD_MT, "MoneTor: Chosen relay %s as intermediary", node_describe(node));
  
  /* Since we have to provide extend_info for clients to connect as a 4th relay from a 3-hop
   * path, let's extract it now? */
  ei = extend_info_from_node(node, 0);

  if (!ei) {
    goto err;
  }
  /* Check how much we have for each position and give this
   * new intermediary the position value matching the smaller
   * value */
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      inter) {
    if (inter->linked_to == MIDDLE)
      count_middle++;
    if (inter->linked_to == EXIT)
      count_exit++;
  } SMARTLIST_FOREACH_END(inter);
  /* Create the intermediary object */
  log_info(LD_MT, "MoneTor: Chose an intermediary: %s at time %ld", extend_info_describe(ei),
      (long) now);
  intermediary = intermediary_new(node, ei, now);
  if (count_middle < count_exit)
    intermediary->linked_to = MIDDLE;
  else
    intermediary->linked_to = EXIT;
  //tor_assert(count_middle+counter_exit <= MAX_INTERMEDIARY_CHOSEN);
  smartlist_add(intermediaries, intermediary);
  log_info(LD_MT, "MoneTor: added intermediary to list with role: %d", intermediary->linked_to);
  return;
 err:
  extend_info_free(ei);
  intermediary_free(intermediary);
  return;
}

/* Scheduled event run from the main loop every second.
 * Make sure our controller is healthy, including
 * intermediaries status, payment status, etc
 */
STATIC void
run_cclient_housekeeping_event(time_t now) {

  /* Check intermediary health*/
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_NO) {
      /* intermediary is not reachable for a reason, checks
       * what's happening, log some information and rotate
       * the intermediary */
      log_info(LD_MT, "MoneTor: Intermediary marked as not reachable"
          " calling cleanup now %ld", (long) now);
      intermediary_need_cleanup(intermediary, now);
    }
  } SMARTLIST_FOREACH_END(intermediary);
   
  /*log_info(LD_MT, "MoneTor: relay digestmap length: %d", digestmap_size(desc2circ));*/
  /*DIGESTMAP_FOREACH(desc2circ, key, circuit_t *, circ) {*/
    /*if (!CIRCUIT_IS_ORIGIN(circ) && !TO_ORIGIN_CIRCUIT(circ)->ppath) {*/
      /*continue;*/
    /*}*/
    /*[>* Verify if we have enough remaining window <]*/
    /*pay_path_t *ppath_tmp = TO_ORIGIN_CIRCUIT(circ)->ppath;*/
    /*int hop = 1;*/
    /*while (ppath_tmp != NULL) {*/
      /*if (ppath_tmp->window < LIMIT_PAYMENT_WINDOW &&*/
          /*!ppath_tmp->payment_is_processing &&*/
          /*!ppath_tmp->p_marked_for_close) {*/
        /*[>* pay :-) <]*/
        /*intermediary_t* intermediary = get_intermediary_by_role(ppath_tmp->position);*/
        /*log_info(LD_MT, "MoneTor: Calling mt_cpay_pay because window is %d", ppath_tmp->window);*/
        /*ppath_tmp->payment_is_processing = 1;*/
        /*if (hop == 1) {*/
          /*[>* We must do a direct payment, using same descriptor <]*/
          /*if (mt_cpay_pay(&ppath_tmp->desc, &ppath_tmp->desc) < 0) {*/
            /*log_warn(LD_MT, "MoneTor: direct payment mt_cpay_pay failed");*/
            /*ppath_tmp->p_marked_for_close = 1;*/
            /*ppath_tmp->last_mt_cpay_succeeded = 0;*/
          /*}*/
        /*}*/
        /*else {*/
          /*if (mt_cpay_pay(&ppath_tmp->desc, &intermediary->desc) < 0) {*/
            /*log_warn(LD_MT, "MoneTor: mt_cpay_pay failed");*/
            /*ppath_tmp->p_marked_for_close = 1;*/
            /*ppath_tmp->last_mt_cpay_succeeded = 0;*/
          /*}*/
        /*}*/
      /*}*/
      /*else if (!ppath_tmp->last_mt_cpay_succeeded) {*/
        /*log_warn(LD_MT, "MoneTor: Last payment did not succeeded yet for hop %d.", hop);*/
      /*}*/
      /*ppath_tmp = ppath_tmp->next;*/
      /*hop++;*/
    /*}*/
  /*} DIGESTMAP_FOREACH_END;*/
}

/*
 * Scheduled event run from the main loop every second.
 * Makes sure we always have circuits build towards
 * the intermediaries
 */
STATIC void
run_cclient_build_circuit_event(time_t now) {
  /*If Tor is not fully up (can takes 30 sec), we do not consider
   *building circuits*/
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit())
    return;

  /*Do we have enough intermediaries? if not, select new ones */
  /*exclude list is the intermediary list. Do we have any reason to extend this list
    to other relays?*/
  smartlist_t *excludesmartlist = get_node_t_smartlist_intermerdiaries();
  choose_intermediaries(now, excludesmartlist);
  smartlist_free(excludesmartlist);

  /*For each intermediary in our list, verifies that we have a circuit
   *up and running. If not, build one.*/
  origin_circuit_t *circ = NULL;
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *,
      intermediary) {
    // XXX MoneTor - make unit test for this function
    circ = circuit_get_by_intermediary_ident(intermediary->identity);
    /* If no circ, launch one */
    if (!circ) {
      log_info(LD_MT, "MoneTor: No circ towards intermediary %s",
          extend_info_describe(intermediary->ei));
      int purpose = CIRCUIT_PURPOSE_C_INTERMEDIARY;
      int flags = CIRCLAUNCH_IS_INTERNAL;
      flags |= CIRCLAUNCH_NEED_UPTIME;
      circ = circuit_launch_by_extend_info(purpose, intermediary->ei,
          flags);
      if (!circ) {
        /*intermediary->circuit_retries++;*/
        //problems going to be handled by a function called
        //by cicuit_about_to_free
        log_warn(LD_MT, "MoneTor: something bad happened when launching a circuit");
        continue;
      }
      /*We have circuit building - mark the intermediary*/
      log_info(LD_MT, "MoneTor: Building intermediary circuit towards %s", 
          node_describe(node_get_by_id(intermediary->identity->identity)));
      circ->inter_ident = tor_malloc_zero(sizeof(intermediary_identity_t));
      memcpy(circ->inter_ident->identity,
          intermediary->identity->identity, DIGEST_LEN);
    }
  } SMARTLIST_FOREACH_END(intermediary);
  
  /* Ledger stuff now  - We initiate ou ledger if not already done and we 
   * ensure enough circuit are built to it*/

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
      log_warn(LD_MT, "Monetor: extend_info_from_node failed?");
      goto err;
    }
    ledger_init(&ledger, node, ei, now);
  }
  /* How many of them do we build? ~ Default 1 */
  while (smartlist_len(ledgercircs) < NBR_LEDGER_CIRCUITS &&
         ledger->circuit_retries < NBR_LEDGER_CIRCUITS*LEDGER_MAX_RETRIES) {
    /* this is just about load balancing */
    log_info(LD_MT, "MoneTor: We do not have enough ledger circuits - launching one more");
    int purpose = CIRCUIT_PURPOSE_C_LEDGER;
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


ledger_t *
mt_cclient_get_ledger(void) {
  return ledger;
}

/** Get the intermediary connected at the other end of this origin_circuit_t
 */

intermediary_t* mt_cclient_get_intermediary_from_ocirc(origin_circuit_t *ocirc) {
  intermediary_identity_t *inter_ident = ocirc->inter_ident;
  intermediary_t *intermediary = NULL;
  SMARTLIST_FOREACH_BEGIN(intermediaries, intermediary_t *, intermediary_tmp) {
    if (tor_memeq(inter_ident->identity, intermediary_tmp->identity->identity,
          DIGEST_LEN)) {
      intermediary = intermediary_tmp;
      break;
    }
  } SMARTLIST_FOREACH_END(intermediary_tmp);
  /* This should be considered as a bug ?*/
  return intermediary;
}

void
run_cclient_scheduled_events(time_t now) {
  /* If we're a authority or a relay,
   * we don't enable payment */
  if (ledger_mode(get_options()) ||
      server_mode(get_options()))
    return;
  /*Make sure our controller is healthy*/
  run_cclient_housekeeping_event(now);
  /*Make sure our intermediaries are up*/
  run_cclient_build_circuit_event(now);
}


void mt_cclient_ledger_circ_has_closed(origin_circuit_t *circ) {
  
  time_t now;
  /* If the circuit is closed before we successfully extend
   * a general circuit towards the ledger, then we may have
   * a reachability problem.. */
  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    now = approx_time();
    log_warn(LD_MT, "MoneTor: Looks like we did not extend a circuit successfully"
        " towards the ledger %lld", (long long) now);
    ledger->circuit_retries++;
    smartlist_remove(ledgercircs, circ);
    /** the ledger is only added when the circuit is opened */
    return;
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
    log_warn(LD_MT, "MoneTor: in ledger_circ_has_closed, looks like we didn't have this desc in our map %s", mt_desc_describe(&ledger->desc));
  }
  mt_cpay_set_status(&ledger->desc, 0);
}



void mt_cclient_update_payment_window(circuit_t *circ) {
  if (get_options()->EnablePayment && CIRCUIT_IS_ORIGIN(circ)) {
    pay_path_t *ppath_tmp = TO_ORIGIN_CIRCUIT(circ)->ppath;
    int hop = 1;
    while(ppath_tmp) {
      if(ppath_tmp->first_payment_succeeded) {
        if (--ppath_tmp->window  < LIMIT_PAYMENT_WINDOW 
            && !ppath_tmp->payment_is_processing &&
            !ppath_tmp->p_marked_for_close) {
        /** pay :-) */
          intermediary_t* intermediary = get_intermediary_by_role(ppath_tmp->position);
          if (!intermediary) {
            log_warn(LD_MT, "MoneTor: get_intermediary_by_role returned NULL :/");
            if (hop > 1)
              break;
          }
          log_info(LD_MT, "MoneTor: Calling mt_cpay_pay because window is %d on hop %d with on desc: %s",
              ppath_tmp->window, hop, mt_desc_describe(&intermediary->desc));
          ppath_tmp->payment_is_processing = 1;
          if (hop == 1) {
            /** We must do a direct payment, using same descriptor */
            if (mt_cpay_pay(&ppath_tmp->desc, &ppath_tmp->desc) < 0) {
              log_warn(LD_MT, "MoneTor: direct payment mt_cpay_pay failed");
              ppath_tmp->p_marked_for_close = 1;
              ppath_tmp->last_mt_cpay_succeeded = 0;
            }
          }
          else {
            if (mt_cpay_pay(&ppath_tmp->desc, &intermediary->desc) < 0) {
              log_warn(LD_MT, "MoneTor: mt_cpay_pay failed");
              ppath_tmp->p_marked_for_close = 1;
              ppath_tmp->last_mt_cpay_succeeded = 0;
            }
          }
        }
      }
      else { /** even if the payment is processing, we have to discount current cell */
        --ppath_tmp->window;
      }
      hop++;
      ppath_tmp = ppath_tmp->next;
    }
  }
}


/**
 * Called by the payment module to signal an event
 * 
 * Can be either:
 *   MT_SIGNAL_PAYMENT_SUCCESS
 *   MT_SIGNAL_PAYMENT_FAILURE
 *   MT_SIGNAL_CLOSE_SUCCESS
 *   MT_SIGNAL_CLOSE_FAILURE
 */

int mt_cclient_paymod_signal(mt_signal_t signal, mt_desc_t *desc) {
  
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  origin_circuit_t *oricirc = NULL;
  if (!circ) {
    log_info(LD_MT, "MoneTor: received a signal linked to a desc "
        " which is not in our map anymore?");
    return -1;
  }
  oricirc = TO_ORIGIN_CIRCUIT(circ);
  if (signal == MT_SIGNAL_PAYMENT_SUCCESS) {
    /** Which one? */
    pay_path_t *ppath_tmp = oricirc->ppath;
    int hop = 1;
    while (ppath_tmp) {
      if (mt_desc_eq(&ppath_tmp->desc, desc)) {
        if (!ppath_tmp->first_payment_succeeded) {
          log_info(LD_MT, "MoneTor: Yay! First payment succeeded for hop %d", hop);
          ppath_tmp->first_payment_succeeded = 1;
          ppath_tmp->window = 3000;
        }
        else {
          ppath_tmp->window += 2000;
        }
        ppath_tmp->last_mt_cpay_succeeded = 1;
        ppath_tmp->payment_is_processing = 0;
        log_info(LD_MT, "MoneTor: payment succeeded for hop %d :)", hop);
        break;
      }
      ppath_tmp = ppath_tmp->next;
      hop++;
    }
  }
  else if (signal == MT_SIGNAL_PAYMENT_FAILURE) {
    pay_path_t *ppath_tmp = oricirc->ppath;
    while (ppath_tmp) {
      if (mt_desc_eq(&ppath_tmp->desc, desc)) {
        ppath_tmp->last_mt_cpay_succeeded = 0;
        ppath_tmp->payment_is_processing = 0;
        log_warn(LD_MT, "MoneTor: We got a payment failure!");
        break;
      }
      ppath_tmp = ppath_tmp->next;
    }
  }
  else if (signal == MT_SIGNAL_CLOSE_SUCCESS ||
           signal == MT_SIGNAL_CLOSE_FAILURE) {
    tor_assert(oricirc->ppath);
    pay_path_t *ppath_tmp = oricirc->ppath;
    int has_closed = 0;
    while (ppath_tmp) {
      if (mt_desc_eq(&ppath_tmp->desc, desc)) {
        ppath_tmp->p_has_closed = 1;
        log_info(LD_MT, "MoneTor: Marking p_has_closed to 1 for circ");
      }
      has_closed += (int) ppath_tmp->p_has_closed;
      ppath_tmp = ppath_tmp->next;
    }
    /** We mark the circuit for close once each mt_cpay_close
     * succeeded of failed with each circuit member */
    if (has_closed == 3) {
      circuit_mark_for_close(circ, END_CIRC_REASON_NONE);
    }
  }
  else {
    log_warn(LD_MT, "MoneTor: unhandled signal value");
    return -1;
  }
  return 0;
}
/**
 *
 * Note: when this method is called, the payement channel must already
 * be closed or we just abort
 */

void mt_cclient_general_circ_has_closed(origin_circuit_t *oricirc) {
  if (oricirc->ppath) {
    log_info(LD_MT, "MoneTor: a general circuit has closed");
    byte id[DIGEST_LEN];
    crypt_path_t *cpath_tmp = oricirc->cpath;
    pay_path_t *ppath_tmp = oricirc->ppath;
    while (cpath_tmp->next != oricirc->cpath && ppath_tmp) {
      mt_desc2digest(&ppath_tmp->desc, &id);
      if (digestmap_get(desc2circ, (char*) id)) {
        digestmap_remove(desc2circ, (char*) id);
      }
      else {
        log_warn(LD_MT, "MoneTor: A descriptor is missing from our map?");
      }
      ppath_tmp = ppath_tmp->next;
    }
  }
}


/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has closed
 *  - Is this a remote close?
 *  - Is this a local close due to a timeout error or a circuit failure?
 */
void mt_cclient_intermediary_circ_has_closed(origin_circuit_t *circ) {
  intermediary_t* intermediary = NULL;
  intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
  if (!intermediary) {
    log_warn(LD_MT, "MoneTor: mt_cclient_get_intermediary returned NULL");
    return;
  }
  time_t now;
  mt_cpay_set_status(&intermediary->desc, 0);

  if (TO_CIRCUIT(circ)->state != CIRCUIT_STATE_OPEN) {
    // means that we did not reach the intermediary point for whatever reason
    // (probably timeout -- retry)
    intermediary->circuit_retries++;
    if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_YES)
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_MAYBE;
    else if (intermediary->is_reachable == INTERMEDIARY_REACHABLE_MAYBE &&
        intermediary->circuit_retries > INTERMEDIARY_MAX_RETRIES) {
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_NO;
      goto cleanup;
    }

    node_t* node = node_get_mutable_by_id(intermediary->identity->identity);
    extend_info_t *ei = extend_info_from_node(node, 0);
    if (!ei) {
      intermediary->is_reachable = INTERMEDIARY_REACHABLE_NO;
      goto cleanup;
    }
    extend_info_free(intermediary->ei);
    intermediary->ei = ei;
    return;
  }
  byte id[DIGEST_LEN];
  mt_desc2digest(&intermediary->desc, &id);
  if (digestmap_get(desc2circ, (char*) id)) {
    digestmap_remove(desc2circ, (char*) id);
    log_info(LD_MT, "MoneTor: removing desc %s linked to an interemdiary circuit",
        mt_desc_describe(&intermediary->desc));
  }
  else {
    log_warn(LD_MT, "MoneTor: in intermediary_circ_has_closed, desc %s not in our map?", mt_desc_describe(&intermediary->desc));
  }
  return;
cleanup:
  /* Do we need to cleanup our intermediary? */
  if (intermediary) {
    now = approx_time();
    intermediary_need_cleanup(intermediary, now);
  }
}

void 
mt_cclient_ledger_circ_has_opened(origin_circuit_t *circ) {
  log_info(LD_MT, "MoneTor: Yay! one ledger circuit has opened");
  ledger->circuit_retries = 0;
  ledger->is_reachable = LEDGER_REACHABLE_YES;
  /*Circ is already in the smartlist*/
  /*Need  a new desc and add this circ in desc2circ */
  increment(count);
  /*circ->desc.id[0] = count[0]; // To change later */
  /*circ->desc.id[1] = count[1];*/
  /*circ->desc.party = MT_PARTY_LED;*/
  byte id[DIGEST_LEN];
  mt_desc2digest(&ledger->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  mt_cpay_set_status(&ledger->desc, 1);
}

/**
 * We got notified that a CIRCUIT_PURPOSE_C_INTERMEDIARY has opened
 */
void 
mt_cclient_intermediary_circ_has_opened(origin_circuit_t *circ) {
  log_info(LD_MT, "MoneTor: Yay! intermediary circuit opened");
  intermediary_t* intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
  if (!intermediary) {
    log_warn(LD_MT, "MoneTor: mt_cclient_get_intermediary_from_ocirc returned NULL~that should not happen");
    return;
  }
  /* reset circuit_retries counter */
  intermediary->circuit_retries = 0;
  byte id[DIGEST_LEN];
  mt_desc2digest(&intermediary->desc, &id);
  digestmap_set(desc2circ, (char*) id, TO_CIRCUIT(circ));
  mt_cpay_set_status(&intermediary->desc, 1);
  /*XXX MoneTor - What do we do? notify payment, wait to full establishement of all circuits?*/
}


/**
 * Mark the payment channel for close and try to close it.
 *
 * If the circuit does not hold a payment channel, just mark
 * the circuit for close */
void mt_cclient_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason) {
  origin_circuit_t *oricirc = NULL;
  if (circ->purpose != CIRCUIT_PURPOSE_C_GENERAL || abort) {
    if (abort) {
      log_info(LD_MT, "We should abort the payment channel");
    }
    circuit_mark_for_close(circ, reason);
  }
  else {
    /** We have a general circuit, let's see if we have
     * a payment channel over it */
    oricirc = TO_ORIGIN_CIRCUIT(circ);
    if (oricirc->ppath) {
      pay_path_t *ppath_tmp = oricirc->ppath;
      while (ppath_tmp) {
        if (!ppath_tmp->p_marked_for_close) {
          ppath_tmp->p_marked_for_close = 1;
          log_info(LD_MT, "MoneTor: Trying to close the nanopayment channel");
          intermediary_t *intermediary = get_intermediary_by_identity(ppath_tmp->inter_ident);
          if (mt_cpay_close(&ppath_tmp->desc, &intermediary->desc) < 0) {
            log_info(LD_MT, "MoneTor: We tried to close the channel and we got"
                  " an error from the payment module. We mark this channel as closed");
              /** XXX Ask thien-Nam if mt_cpay_close which returns -1 also send a
               * signal FAILURE? */
            ppath_tmp->p_has_closed = 1;
          }
        }
        ppath_tmp = ppath_tmp->next;
      }
    }
    else {
      circuit_mark_for_close(circ, reason);
    }
  }
}

/**
 * Sending messages to intermediaries, relays and ledgers
 */

int
mt_cclient_send_message(mt_desc_t* desc, uint8_t command, mt_ntype_t type,
    byte* msg, int size) {
  /* init and stuff */
  byte id[DIGEST_LEN];
  mt_desc2digest(desc, &id);
  circuit_t *circ = digestmap_get(desc2circ, (char*) id);
  if (!circ) {
    log_warn(LD_MT, "MoneTor: in mt_cclient_send_message, digestmap_get failed to return a circ for descriptor"
        " %s", mt_desc_describe(desc));
    return -2;
  } 
  if(circ->marked_for_close) {
    log_warn(LD_MT, "MoneTor: This circuit is about to be freed");
    return -2;
  }
  if (circ->state != CIRCUIT_STATE_OPEN) {
    /*If send_message is called by an event added by a worker
      thread, it is possible that our circuit has just been
      marked for close for whatever reason - It is unlikely, though
      we return -1*/
    /** The proper way to handle this would be to try again to send
     * the message once a new circ is up (in the case of a ledger
     * circuit or an intermediary circuit)*/
    log_warn(LD_MT, "MoneTor: Circ is not open: state: %s", circuit_state_to_string(circ->state));
    return -1;
  }
  if (command == RELAY_COMMAND_MT) {
    crypt_path_t *layer_start; //layer of destination hop
    tor_assert(TO_ORIGIN_CIRCUIT(circ)->cpath);
    int hop = 4;
    if (circ->purpose == CIRCUIT_PURPOSE_C_INTERMEDIARY ||
        circ->purpose == CIRCUIT_PURPOSE_C_LEDGER) {
      /* We will have 4 relay_crypt */
      layer_start = TO_ORIGIN_CIRCUIT(circ)->cpath->prev;
    }
    else {
      /** Then its a message for one of the relay within the circuit, find it*/
      layer_start = TO_ORIGIN_CIRCUIT(circ)->cpath;
      pay_path_t *ppath_tmp = TO_ORIGIN_CIRCUIT(circ)->ppath;
      int found = 0;
      hop = 1;
      do {
        if (mt_desc_eq(desc, &ppath_tmp->desc)) {
          found = 1;
          break;
        }
        hop++;
        layer_start = layer_start->next;
        ppath_tmp = ppath_tmp->next;
      } while(layer_start != TO_ORIGIN_CIRCUIT(circ)->cpath && ppath_tmp);
      if (BUG(!found))
        return -2;
    }
    log_debug(LD_MT, "MoneTor: Sending message type %s with payload size of %d bytes to hop %d %s",
        mt_token_describe(type), size, hop, extend_info_describe(layer_start->extend_info));
    return relay_send_pcommand_from_edge(circ, command, (uint8_t) type,
        layer_start, (const char*) msg, size);
  }
  else if (command == CELL_PAYMENT) {
    log_debug(LD_MT, "MoneTor: calling direct_cell_payment for %s and payload size %d", mt_token_describe(type), size);
    return mt_common_send_direct_cell_payment(circ, type, msg, size, CELL_DIRECTION_OUT) ;
  }
  else {
    log_warn(LD_MT, "Unrecognized command %d", command);
    return -2;
  }
}

/**
 * Send message intermediary's information to the right relay in the path
 */
int
mt_cclient_send_message_multidesc(mt_desc_t *desc1, mt_desc_t *desc2, 
    mt_ntype_t type, byte* msg, int size) {
  byte id[DIGEST_LEN];
  mt_desc2digest(desc1, &id);
  crypt_path_t *layer_start;
  pay_path_t *ppath_tmp;
  circuit_t *circ = digestmap_get(desc2circ, (char *) id);
  if (!circ) {
    log_warn(LD_MT, "MoneTor: digestmap_get failed to return a circ for descriptor"
        " %s", mt_desc_describe(desc1));
    return -2;
  }
  layer_start = TO_ORIGIN_CIRCUIT(circ)->cpath;
  ppath_tmp = TO_ORIGIN_CIRCUIT(circ)->ppath;
  /* Get the appropriate ppath+layer_start and identify related intermediary */
  int found = 0;
  do {
    if (mt_desc_eq(desc1, &ppath_tmp->desc)) {
      found = 1;
      break;
    }
    layer_start = layer_start->next;
    ppath_tmp = ppath_tmp->next;
  } while(layer_start != TO_ORIGIN_CIRCUIT(circ)->cpath && ppath_tmp);

  if (!found) {
    log_warn(LD_MT, "MoneTor: didn't find right ppath in mt_cclient_send_message_multidesc");
    return -2;
  }
  intermediary_t *intermediary = get_intermediary_by_identity(ppath_tmp->inter_ident);
  if (!intermediary) {
    log_warn(LD_MT, "MoneTor: get_intermediary_by_identity failed for identity %s",
        ppath_tmp->inter_ident->identity);
    return -2;
  }
  // Now we have layer_start as well as the right intermediary
  /* Sends intermediary's fingerprint, as well as desc2 and msg */
  log_info(LD_MT, "MoneTor: Now send intermediary's fingerprint as well as desc2 and msg of size %d", size);
  int_id_t int_id;
  memcpy(int_id.identity, intermediary->identity->identity, DIGEST_LEN);
  byte *msg_int_id;
  int size_int_id = pack_int_id(&msg_int_id, &int_id);
  
  byte *msg_with_desc = tor_malloc_zero(size+size_int_id+sizeof(mt_desc_t));
  memcpy(msg_with_desc, msg_int_id, size_int_id);
  memcpy(msg_with_desc+size_int_id, desc2, sizeof(mt_desc_t)); // XXX not safe over network ~ byte ordering
  memcpy(msg_with_desc+sizeof(mt_desc_t)+size_int_id, msg, size);

  int ret = mt_cclient_send_message(desc1, RELAY_COMMAND_MT, type, msg_with_desc, size+size_int_id+sizeof(mt_desc_t));
  tor_free(msg_with_desc);
  return ret;
}

/** Process received msg from either relay, intermediary
 * or ledger - Call the payment module and decides what
 * to do upon failure
 */
MOCK_IMPL(void,
mt_cclient_process_received_msg, (origin_circuit_t *circ, crypt_path_t *layer_hint, 
    mt_ntype_t pcommand, byte *msg, size_t msg_len)) {
  mt_desc_t *desc;
  /*What type of node sent us this cell? relay, intermediary or ledger? */
  if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_INTERMEDIARY) {
    intermediary_t *intermediary = mt_cclient_get_intermediary_from_ocirc(circ);
    desc = &intermediary->desc;
    log_info(LD_MT, "MoneTor: Processed a complete msg sent by our intermediary %s - calling mt_ipay_recv",
        extend_info_describe(intermediary->ei));
    if (mt_cpay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_info(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %s", mt_token_describe(pcommand));
      // XXX Do we mark this circuit for close and complain about
      // intermediary?
      // XXX Do we notify all general circuit that the payment will not complete?

    }
    /*tor_free(msg);*/ //should be freed by mt_common
  }
  else if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_LEDGER) {
    desc = &ledger->desc;
    log_info(LD_MT, "MoneTor: Processed a msg send by the ledger ");
    if (mt_cpay_recv(desc, pcommand, msg, msg_len) < 0) {
      log_info(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %s", mt_token_describe(pcommand));
    }
  }
  else if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_GENERAL) {

    pay_path_t *ppath = circ->ppath;
    crypt_path_t *cpath = circ->cpath;
    tor_assert(ppath);
    tor_assert(cpath);

    /* find the right ppath */
    while (cpath != layer_hint && ppath) {
      cpath = cpath->next;
      ppath = ppath->next;
    }
    tor_assert(ppath);
    /* get the right desc */
    desc = &ppath->desc;
    log_info(LD_MT, "MoneTor: Processed a msg sent by relay linked to desc %s - calling mt_cpay_recv",
        mt_desc_describe(desc));
    if (mt_cpay_recv(desc, pcommand, msg, msg_len) < 0) {
      /* De we retry or close? Let's assume easiest things -> we close*/
      log_warn(LD_MT, "MoneTor: Payment module returned -1 for mt_ntype_t %s", mt_token_describe(pcommand));
      ppath->p_marked_for_close = 1; //XXX probably need to do more than just marking this ppath
    }
    /*tor_free(msg);*/ // should be freed by mt_common
  }
  else {
    log_warn(LD_MT, "MoneTor: Unsupported purpose in mt_cclient_process_received_msg");
  }
}

/*************************** Object creation and cleanup *******************************/


static void
pay_path_free(pay_path_t* ppath) {
  if (!ppath)
    return;
  tor_free(ppath->inter_ident);
  buf_free(ppath->buf);
  /* Recursive call to explore the linked list */
  pay_path_free(ppath->next);
}

/*
 * XXX MoneTor - Todo: call them in appropriate place
 */
void 
mt_cclient_general_circuit_free(origin_circuit_t* circ) {
  if (!circ)
    return;
  pay_path_free(circ->ppath);
}

void 
mt_cclient_intermediary_circuit_free(origin_circuit_t* circ) {
  if (!circ)
    return;
  tor_free(circ->inter_ident);
}

