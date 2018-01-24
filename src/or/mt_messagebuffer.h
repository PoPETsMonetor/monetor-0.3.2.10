/**
 * \file mt_messagebuffer.h
 * \brief Header file for mt_messagebuffer.c
 *
 * All functions return MT_SUCCESS/MT_ERROR unless void or otherwise stated
 */

#ifndef mt_messagebuffer_h
#define mt_messagebuffer_h

#include "or.h"

/**
 * Set the status of the descriptor as either available (1) or
 * unavailable (0)
 */
int mt_set_desc_status(mt_desc_t* desc, int status);

/**
 * Attempt to invoke an <b>mt_send_message</b> call. If the attempt
 * returns and ERROR, then queue the request and try again later.
 */
int mt_buffer_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size);

/**
 * Attempt to invoke an <b>mt_send_message_multidesci</b> call. If the
 * attempt returns and ERROR, then queue the request and try again
 * later.
 */
int mt_buffer_message_multidesc(mt_desc_t* desc1, mt_desc_t* desc2, mt_ntype_t type,
				byte* msg, int size);

#endif
