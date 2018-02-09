/**
 * \file mt_common.h
 * \brief Header file for mt_common.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated.
 **/

#ifndef mt_common_h
#define mt_common_h

#include "or.h"
#include "mt_crypto.h"
#include "mt_tokens.h"
#include "buffers.h"


#define LIMIT_PAYMENT_WINDOW 1000

#define INTERMEDIARY_REACHABLE_NO 0
#define INTERMEDIARY_REACHABLE_YES 1
#define INTERMEDIARY_REACHABLE_MAYBE 2
#define INTERMEDIARY_MAX_RETRIES 3

#define INTERMEDIARY_COOKIE_LEN 16

typedef struct intermediary_t {
  intermediary_identity_t* identity;
  unsigned int is_reachable : 2;
  time_t chosen_at;
  extend_info_t *ei;
  /*Used by the payment module*/
  mt_desc_t desc;
  /*
   * Whether this intermediary is used
   * to pay for middle or exit
   */
  position_t linked_to;
  /* how many times we try to build a circuit
   * with that intermediary */
  uint32_t circuit_retries;

} intermediary_t;

/********************* Ledger struct *****************************/

#define LEDGER_REACHABLE_NO 0
#define LEDGER_REACHABLE_YES 1
#define LEDGER_REACHABLE_MAYBE 2
#define LEDGER_MAX_RETRIES 3

#define NBR_LEDGER_CIRCUITS 1



typedef struct ledger_identity_t {
  char identity[DIGEST_LEN];
} ledger_identity_t;

typedef struct ledger_t {
  ledger_identity_t identity;

  unsigned int is_reachable:2;
  extend_info_t *ei;

  mt_desc_t desc;

  uint32_t circuit_retries;
} ledger_t;

void mt_desc_free(mt_desc_t *desc);

/**
 * Convert a mt public key into an mt address
 */
int mt_pk2addr(byte (*pk)[MT_SZ_PK], byte (*addr_out)[MT_SZ_ADDR]);

/**
 * Convert a moneTor descriptor into a digest for digestmap_t
 */
void mt_desc2digest(mt_desc_t* desc, byte (*digest_out)[DIGEST_LEN]);

/**
 * Convert a moneTor nan_any_public_t into a digest for digestmap_t
 */
void mt_nanpub2digest(nan_any_public_t* token, byte (*digest_out)[DIGEST_LEN]);

/**
 * Convert an mt address into a printable hexidecimal c-string
 */
int mt_bytes2hex(byte* bytes, int size, char** hex_out);

/**
 * Converts a hex digest (c-string) into a malloc'd byte string
 */
int mt_hex2bytes(const char* hex, byte** bytes_out);

/**
 * Create malloc'd hash chain of the given size using the given head
 */
int mt_hc_create(int size, byte (*head)[MT_SZ_HASH], byte (*hc_out)[][MT_SZ_HASH]);

/**
 * Verify that a given preimage is indeed the kth preimage of the
 * given hash chain tail
 */
int mt_hc_verify(byte (*tail)[MT_SZ_HASH], byte (*preimage)[MT_SZ_HASH], int k);

/**
 * Compare two descriptors and return 0 if they are equal or some other number
 * (canonically sortable) if they are not
 */
int mt_desc_comp(mt_desc_t* desc1, mt_desc_t* desc2);

/** Canibalize a general circuit => extends it to
 *  the intermediary point described by ei
 *
 *  ret 0 on success
 */
int mt_circuit_launch_intermediary(extend_info_t* ei);

/** Callback function called when an intermediary
 *  circuit is open
 */
void mt_circuit_intermediary_has_opened(origin_circuit_t* circuit);

void mt_init(void);

void ledger_init(ledger_t **ledger, const node_t *node, extend_info_t *ei,
    time_t now);
void ledger_free(ledger_t **ledger);
/**
 * Has enough funds to pay for prioritization? returns 1 or 0
 */
int mt_check_enough_fund(void);

/**
 * gets called by the main loop every second.
 */
void monetor_run_scheduled_events(time_t now);


/**
 * Pack the relay header containing classical relay_header_t
 * and our payment header
 */
void relay_pheader_pack(uint8_t *dest, const relay_header_t* rh,
    relay_pheader_t* rph);


/** Unpack the network order buffer src into relay_pheader_t
 * struct
 */
void relay_pheader_unpack(relay_pheader_t *desc, const uint8_t *src);


void direct_pheader_pack(uint8_t *dest, relay_pheader_t *rph);


/** Pack and unpack int_id_t */

int pack_int_id(byte **msg, int_id_t *ind_id);

void unpack_int_id(byte *str, int_id_t* ind_id_out);

/**
 * gives a string description of this mt_desc_t*
 */
const char* mt_desc_describe(mt_desc_t *desc);

/**
 * Returns 1 if both structure have the same digest
 * 0 otherwise
 */

int mt_desc_eq(mt_desc_t* desc1, mt_desc_t* desc2);
/**
 * Gives a string description of mt_signal_t
 */
const char* mt_signal_describe(mt_signal_t signal);

/**
 * Increment the counter described by 2 long unsigned
 */
void increment(long unsigned *id);

/** randomize a 64 bit uint by 3 call to rand() */
uint64_t rand_uint64(void);

/** Interface to the payment module to send a payment cell.
 *  This function dispaches to the right controller.
 */
MOCK_DECL(void, mt_process_received_relaycell, (circuit_t *circ, relay_header_t* rh,
    relay_pheader_t *rph, crypt_path_t* layer_hint, uint8_t* payload));

/** Interface to the payment module
 * Dispatches to client controller or Intermediary controller
 */

int mt_process_received_directpaymentcell(circuit_t *circ, cell_t *cell);


int mt_common_send_direct_cell_payment(circuit_t *circ, mt_ntype_t type,
    byte *msg, int size, cell_direction_t direction);


void mt_update_payment_window(circuit_t *circ);

/************ Tor - Payment event interface *********************/

/**
 * Alert the relay controller that a payment was received by the specified client
 *
 * This function is invoked by the relay payment module every time that a
 * successful payment has been made. The <b>desc</b> parameter contains the
 * identity of the paying client. This client should be familiar to the
 * controller through previous protocol executions.
 */
MOCK_DECL(int, mt_alert_payment, (mt_desc_t *desc));


/**
 * Send a message to the given descriptor
 *
 * This function is invoked by a payment module when it needs to send a message
 * to another payment module of the network. The message should be sent to the
 * Tor instance identifed by <b>desc</b>. The possible descriptors are:
 *   <ul>
 *     <li> The ledger, which is loaded in via torrc config
 *     <li> Any descriptor that has been given by the controller via <b>recv</b>
 *     or <b>pay</b> commands
 *   </ul>
 * The remaining parameters correspond to the type, size, and message
 * itself. The <b>msg</b> pointer is dynamically allocated but will be freed by
 * the payment module upon return.
 *
 * The intent is that the controller will simply send the message along the
 * network such that it is passed into <b>mt_*pay_recv</b> on the other side.
 */
MOCK_DECL(int, mt_send_message, (mt_desc_t *desc, mt_ntype_t type, byte* msg, int size));

/**
 * Send a message to the given descriptor attaching info about a 2nd descriptor
 *
 * This function is identical to mt_send_message except that a second descriptor
 * is associated with the message. The controller does NOT need to sedn anything
 * to <b>desc2</b>. Instead, it sends the message along with the value of
 * <b>desc2</b> to <b>desc1</b>. On the other side of the network, the
 * controller should invoke <b>mt_*pay_recv_multidesc</b>
 */
MOCK_DECL(int, mt_send_message_multidesc, (mt_desc_t *desc1, mt_desc_t* desc2, mt_ntype_t type, byte* msg, int size));

/**
 * Inform the controller of events that happen within the payment module. See
 * the definitions of <b>mt_signal_t</b> in <b>or.h</b> for details of possible
 * signals.
 */
MOCK_DECL(int, mt_paymod_signal, (mt_signal_t signal, mt_desc_t *desc));


/**
 * Should try to close the nanopayment channel
 */
void circuit_mark_payment_channel_for_close(circuit_t *circ, int abort, int reason);

#endif
