/**
 * \file mt_messagebuffer.c
 *
 * Provide functionality for buffer messages from payment modules to
 * invoke message sending without having to worry about whether the
 * circuit is ready. The messages are sent immediately if possible. If
 * not, they are stored in a buffer until the circuit becomes
 * available.
 */

#include "container.h"
#include "mt_common.h"
#include "mt_messagebuffer.h"

typedef struct {
  int is_multidesc;
  mt_desc_t desc1;
  mt_desc_t desc2;
  mt_ntype_t type;
  byte* msg;
  int size;
} message_t;

static digestmap_t* desc_status;
static digestmap_t* desc_buffer;

/**
 * Initialize the module. This function can be safely called multiple
 * times.
 */
void init(){
  if(!desc_status)
    desc_status = digestmap_new();
  if(!desc_buffer)
    desc_buffer = digestmap_new();
}

/**
 * Set the status of the descriptor as either available (1) or
 * unavailable (0)
 */
int mt_set_desc_status(mt_desc_t* desc, int status_new){

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  int* status = digestmap_get(desc_status, (char*)digest);
  if(!status){
    status = tor_calloc(1, sizeof(int));
    digestmap_set(desc_status, (char*)digest, status);
  }

  *status = status_new;

  smartlist_t* buffer;
  if(*status && (buffer = digestmap_get(desc_buffer, (char*)digest))){
    SMARTLIST_FOREACH_BEGIN(buffer, message_t*, elm){
      int result;
      if(!elm->is_multidesc)
	result = mt_send_message(&elm->desc1, elm->type, elm->msg, elm->size);
      else
	result = mt_send_message_multidesc(&elm->desc1, &elm->desc2, elm->type,
					   elm->msg, elm->size);

      if(result == 0){
	smartlist_remove(buffer, elm);
	tor_free(elm);
	elm_sl_len--;
      }

      else{
	log_info(LD_MT, "Descriptor disconnected while sending messages\n");
	*status = 0;
	break;
      }
    } SMARTLIST_FOREACH_END(elm);
  }

  return 0;
}

/**
 * Helper function for <b>mt_send_message</b> and
 * <b>mt_send_message_multidesc</b>
 */
int mt_add_to_buffer(mt_desc_t* desc, message_t* message){

  byte digest[DIGEST_LEN];
  mt_desc2digest(desc, &digest);

  // create new status element if necessary
  int* status = digestmap_get(desc_status, (char*)digest);
  if(!status){
    status = tor_calloc(1, sizeof(int));
    digestmap_set(desc_status, (char*)digest, status);
  }
  else{
    // message should have gone through if status is available
    tor_assert(*status == 0);
    return MT_ERROR;
  }

  // create new buffer element if necessary
  smartlist_t* buffer = digestmap_get(desc_buffer, (char*)digest);
  if(!buffer){
    buffer = smartlist_new();
    digestmap_set(desc_buffer, (char*)digest, buffer);
  }

  // add message to buffer
  smartlist_add(desc_buffer, message);
  return MT_SUCCESS;
}

/**
 * Attempt to invoke an <b>mt_send_message</b> call. If the attempt
 * returns and ERROR, then queue the request and try again later.
 */
int mt_buffer_message(mt_desc_t *desc, mt_ntype_t type, byte* msg, int size){

  // attempt to send message; if it goes through then we're done
  if(mt_send_message(desc, type, msg, size) != MT_ERROR){
    return MT_SUCCESS;
  }

  // create message to buffer
  message_t* message = tor_malloc(sizeof(message_t));
  message->is_multidesc = 0;
  message->desc1 = *desc;
  message->type = type;
  message->size = size;
  message->msg = tor_malloc(size);
  memcpy(message->msg, msg, size);

  return mt_add_to_buffer(desc, message);
}

/**
 * Attempt to invoke an <b>mt_send_message_multidesci</b> call. If the
 * attempt returns and ERROR, then queue the request and try again
 * later.
 */
int mt_buffer_message_multidesc(mt_desc_t* desc1, mt_desc_t* desc2, mt_ntype_t type,
				byte* msg, int size){

  // attempt to send message; if it goes through then we're done
  if(mt_send_message_multidesc(desc1, desc2, type, msg, size) != MT_ERROR){
    return MT_SUCCESS;
  }

  // create message to buffer
  message_t* message = tor_malloc(sizeof(message_t));
  message->is_multidesc = 1;
  message->desc1 = *desc1;
  message->desc2 = *desc2;
  message->type = type;
  message->size = size;
  message->msg = tor_malloc(size);
  memcpy(message->msg, msg, size);

  return mt_add_to_buffer(desc1, message);
}
