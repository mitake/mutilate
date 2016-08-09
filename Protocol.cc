#include <netinet/tcp.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#include "Protocol.h"
#include "Connection.h"
#include "distributions.h"
#include "Generator.h"
#include "mutilate.h"
#include "binary_protocol.h"
#include "util.h"

#define unlikely(x) __builtin_expect((x),0)

/**
 * Send an ascii get request.
 */
int ProtocolAscii::get_request(const char* key) {
  int l;
  l = evbuffer_add_printf(
    bufferevent_get_output(bev), "get %s\r\n", key);
  if (read_state == IDLE) read_state = WAITING_FOR_GET;
  return l;
}

/**
 * Send an ascii set request.
 */
int ProtocolAscii::set_request(const char* key, const char* value, int len) {
  int l;
  l = evbuffer_add_printf(bufferevent_get_output(bev),
                          "set %s 0 0 %d\r\n", key, len);
  bufferevent_write(bev, value, len);
  bufferevent_write(bev, "\r\n", 2);
  l += len + 2;
  if (read_state == IDLE) read_state = WAITING_FOR_END;
  return l;
}

/**
 * Handle an ascii response.
 */
bool ProtocolAscii::handle_response(evbuffer *input, bool &done) {
  char *buf = NULL;
  int len;
  size_t n_read_out;

  switch (read_state) {

  case WAITING_FOR_GET:
  case WAITING_FOR_END:
    buf = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_CRLF);
    if (buf == NULL) return false;

    conn->stats.rx_bytes += n_read_out;

    if (!strncmp(buf, "END", 3)) {
      if (read_state == WAITING_FOR_GET) conn->stats.get_misses++;
      read_state = WAITING_FOR_GET;
      done = true;
    } else if (!strncmp(buf, "VALUE", 5)) {
      sscanf(buf, "VALUE %*s %*d %d", &len);

      // FIXME: check key name to see if it corresponds to the op at
      // the head of the op queue?  This will be necessary to
      // support "gets" where there may be misses.

      data_length = len;
      read_state = WAITING_FOR_GET_DATA;
      done = false;
    } else {
      // must be a value line..
      done = false;
    }
    free(buf);
    return true;

  case WAITING_FOR_GET_DATA:
    len = evbuffer_get_length(input);
    if (len >= data_length + 2) {
      evbuffer_drain(input, data_length + 2);
      read_state = WAITING_FOR_END;
      conn->stats.rx_bytes += data_length + 2;
      done = false;
      return true;
    }
    return false;

  default: printf("state: %d\n", read_state); DIE("Unimplemented!");
  }

  DIE("Shouldn't ever reach here...");
}

/**
 * Perform SASL authentication if requested (write).
 */
bool ProtocolBinary::setup_connection_w() {
  if (!opts.sasl) return true;

  string user = string(opts.username);
  string pass = string(opts.password);

  binary_header_t header = {0x80, CMD_SASL, 0, 0, 0, {0}, 0, 0, 0};
  header.key_len = htons(5);
  header.body_len = htonl(6 + user.length() + 1 + pass.length());

  bufferevent_write(bev, &header, 24);
  bufferevent_write(bev, "PLAIN\0", 6);
  bufferevent_write(bev, user.c_str(), user.length() + 1);
  bufferevent_write(bev, pass.c_str(), pass.length());

  return false;
}

/**
 * Perform SASL authentication if requested (read).
 */
bool ProtocolBinary::setup_connection_r(evbuffer* input) {
  if (!opts.sasl) return true;

  bool b;
  return handle_response(input, b);
}

/**
 * Send a binary get request.
 */
int ProtocolBinary::get_request(const char* key) {
  uint16_t keylen = strlen(key);

  // each line is 4-bytes
  binary_header_t h = { 0x80, CMD_GET, htons(keylen),
                        0x00, 0x00, {htons(0)},
                        htonl(keylen) };

  bufferevent_write(bev, &h, 24); // size does not include extras
  bufferevent_write(bev, key, keylen);
  return 24 + keylen;
}

/**
 * Send a binary set request.
 */
int ProtocolBinary::set_request(const char* key, const char* value, int len) {
  uint16_t keylen = strlen(key);

  // each line is 4-bytes
  binary_header_t h = { 0x80, CMD_SET, htons(keylen),
                        0x08, 0x00, {htons(0)},
                        htonl(keylen + 8 + len) };

  bufferevent_write(bev, &h, 32); // With extras
  bufferevent_write(bev, key, keylen);
  bufferevent_write(bev, value, len);
  return 24 + ntohl(h.body_len);
}

/**
 * Tries to consume a binary response (in its entirety) from an evbuffer.
 *
 * @param input evBuffer to read response from
 * @return  true if consumed, false if not enough data in buffer.
 */
bool ProtocolBinary::handle_response(evbuffer *input, bool &done) {
  // Read the first 24 bytes as a header
  int length = evbuffer_get_length(input);
  if (length < 24) return false;
  binary_header_t* h =
          reinterpret_cast<binary_header_t*>(evbuffer_pullup(input, 24));
  assert(h);

  // Not whole response
  int targetLen = 24 + ntohl(h->body_len);
  if (length < targetLen) return false;

  // If something other than success, count it as a miss
  if (h->opcode == CMD_GET && h->status) {
      conn->stats.get_misses++;
  }

  if (unlikely(h->opcode == CMD_SASL)) {
    if (h->status == RESP_OK) {
      V("SASL authentication succeeded");
    } else {
      DIE("SASL authentication failed");
    }
  }

  evbuffer_drain(input, targetLen);
  conn->stats.rx_bytes += targetLen;
  done = true;
  return true;
}

// masstree protocol implementation
#include "json.hh"
#include "msgpack.hh"
#include <assert.h>
#include <string.h>

#define MASSTREE_MAXKEYLEN 255	// FIXME

static outbuf* new_outbuf(int buflen) {
  outbuf* buf = static_cast<outbuf *>(malloc(sizeof(*buf)));
  assert(buf);
  memset(buf, 0, sizeof(*buf));
  buf->capacity = buflen;
  buf->buf = (char*) malloc(buf->capacity); 
  assert(buf->buf);
  return buf;
}

const bool ProtocolMasstree::receive(int len) {
  inbuflen_ += len;
  inbufpos_ = const_cast<char *>(parser_.consume(inbufpos_, inbufpos_ + len, lcdf::String()));

  if (parser_.success() && parser_.result().is_a()) {
    if (inbufpos_ == inbuf_ + inbuflen_) {
      inbufpos_ = inbuf_;
      inbuflen_ = 0;
    }

    parser_.reset();

    return true;
  }

  return false;
}

ProtocolMasstree::ProtocolMasstree(options_t opts, Connection* conn, bufferevent* bev) : Protocol(opts, conn, bev) {
  lcdf::Json handshake;

  out_ = new_outbuf(64 * 1024);

  handshake.resize(3);
  handshake[0] = 0;
  handshake[1] = Cmd_Handshake;
  handshake[2] = lcdf::Json::make_object().set("core", -1)
    .set("maxkeylen", MASSTREE_MAXKEYLEN);

  inbuf_ = new char[inbufsz];
  inbufpos_ = inbuf_;

  // send handshake request
  msgpack::unparse(*out_, handshake);
  bufferevent_write(bev, out_->buf, out_->n);
  out_->n = 0;
}

bool ProtocolMasstree::setup_connection_r(evbuffer* input)
{
  int len = evbuffer_get_length(input);
  if (!len)
    DIE("handshake failed, input length is 0");

  char *buf = reinterpret_cast<char *>(evbuffer_pullup(input, len));
  memcpy(inbufpos_, buf, len);
  if (!receive(len))
    DIE("handshake failed, parse error");

  const lcdf::Json& rsp = parser_.result();

  if (!rsp.is_a() || rsp[1] != Cmd_Handshake + 1 || !rsp[2])
    DIE("handshake failed, invalid response");

  evbuffer_drain(input, len);
  conn->stats.rx_bytes += len;

  return true;
}

int ProtocolMasstree::get_request(const char* key) {
  lcdf::Json getReq;
  getReq.resize(3);
  getReq[0] = seq_get_++;
  getReq[1] = Cmd_Get;
  // getReq[2] = lcdf::String::make_stable(key);
  getReq[2] = lcdf::String::make_stable("k");

  msgpack::unparse(*out_, getReq);
  bufferevent_write(bev, out_->buf, out_->n);

  int ret = out_->n;
  out_->n = 0;
  return ret;
}

int ProtocolMasstree::set_request(const char* key, const char* value, int len) {
  lcdf::Json putReq;
  putReq.resize(4);
  putReq[0] = seq_set_++;
  putReq[1] = Cmd_Replace;
  putReq[2] = lcdf::String::make_stable("k");
  // putReq[3] = lcdf::String::make_stable("v");
  // putReq[2] = lcdf::String::make_stable(key);
  putReq[3] = lcdf::String::make_stable(value);
  

  msgpack::unparse(*out_, putReq);
  bufferevent_write(bev, out_->buf, out_->n);

  int ret = out_->n;
  out_->n = 0;
  return ret;
}

bool ProtocolMasstree::handle_response(evbuffer *input, bool &done) {
  int len = evbuffer_get_length(input);

  if (!len) {
    done = false;
    return false;
  }

  char *buf = reinterpret_cast<char *>(evbuffer_pullup(input, len));
  memcpy(inbufpos_, buf, len);
  evbuffer_drain(input, len);

  if (!receive(len)) {
    done = false;
    return false;
  }

  const lcdf::Json& rsp = parser_.result();

  conn->stats.rx_bytes += len;

  done = true;
  return true;
}
