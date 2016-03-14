// -*- c++-mode -*-
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <event2/bufferevent.h>

#include "ConnectionOptions.h"

using namespace std;

class Connection;

class Protocol {
public:
  Protocol(options_t _opts, Connection* _conn, bufferevent* _bev):
    opts(_opts), conn(_conn), bev(_bev) {};
  ~Protocol() {};

  virtual bool setup_connection_w() = 0;
  virtual bool setup_connection_r(evbuffer* input) = 0;
  virtual int  get_request(const char* key) = 0;
  virtual int  set_request(const char* key, const char* value, int len) = 0;
  virtual bool handle_response(evbuffer* input, bool &done) = 0;

protected:
  options_t    opts;
  Connection*  conn;
  bufferevent* bev;
};

class ProtocolAscii : public Protocol {
public:
  ProtocolAscii(options_t opts, Connection* conn, bufferevent* bev):
    Protocol(opts, conn, bev) {
    read_state = IDLE;
  };

  ~ProtocolAscii() {};

  virtual bool setup_connection_w() { return true; }
  virtual bool setup_connection_r(evbuffer* input) { return true; }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, bool &done);

private:
  enum read_fsm {
    IDLE,
    WAITING_FOR_GET,
    WAITING_FOR_GET_DATA,
    WAITING_FOR_END,
  };

  read_fsm read_state;
  int data_length;
};

class ProtocolBinary : public Protocol {
public:
  ProtocolBinary(options_t opts, Connection* conn, bufferevent* bev):
    Protocol(opts, conn, bev) {};
  ~ProtocolBinary() {};

  virtual bool setup_connection_w();
  virtual bool setup_connection_r(evbuffer* input);
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, bool &done);
};

/* masstree protocol */
#include <assert.h>
#include <stdlib.h>

struct outbuf {			// something like kvout
    char* buf;
    unsigned capacity; // allocated size of buf
    unsigned n;   // # of chars we've written to buf

    inline void append(char c);
    inline char* reserve(int n);
    inline void adjust_length(int delta);
    inline void set_end(char* end);
    inline void grow(unsigned want);
};

inline void outbuf::append(char c) {
  if (n == capacity)
      grow(0);
  buf[n] = c;
  ++n;
}

inline char* outbuf::reserve(int nchars) {
  if (n + nchars > capacity)
      grow(n + nchars);
  return buf + n;
}

inline void outbuf::adjust_length(int delta) {
  n += delta;
}

inline void outbuf::set_end(char* x) {
  n = x - buf;
}

inline void outbuf::grow(unsigned want) {
  if (want == 0)
      want = capacity + 1;
  while (want > capacity)
      capacity *= 2;
  buf = (char*) realloc(buf, capacity);
  assert(buf);
}

#include "msgpack.hh"

class ProtocolMasstree : public Protocol {
  enum {
    Cmd_None = 0,
    Cmd_Get = 2,
    Cmd_Scan = 4,
    Cmd_Put = 6,
    Cmd_Replace = 8,
    Cmd_Remove = 10,
    Cmd_Checkpoint = 12,
    Cmd_Handshake = 14,
    Cmd_Max
  };

  enum result_t {
    NotFound = -2,
    Retry,
    OutOfDate,
    Inserted,
    Updated,
    Found,
    ScanDone
  };

  int seq_get_, seq_set_;

  outbuf *out_;

  enum { inbufsz = 64 * 1024, inbufrefill = 56 * 1024 };
  char *inbuf_;
  int inbufpos_;
  int inbuflen_;
  msgpack::streaming_parser parser_;

  const bool receive(int);

public:
  ProtocolMasstree(options_t opts, Connection* conn, bufferevent* bev);
  ~ProtocolMasstree() {};

  virtual bool setup_connection_r(evbuffer* input);
  virtual bool setup_connection_w() {
    // need to let read_state be CONN_SETUP
    return false;
  }
  virtual int  get_request(const char* key);
  virtual int  set_request(const char* key, const char* value, int len);
  virtual bool handle_response(evbuffer* input, bool &done);
};

#endif
