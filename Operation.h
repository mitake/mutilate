// -*- c++-mode -*-
#ifndef OPERATION_H
#define OPERATION_H

#include <string>

using namespace std;

class Operation {
public:
  double start_time, end_time;

  enum type_enum {
    GET, SET, SASL
  };

  type_enum type;

  string key;
  // string value;

  double time() const { return (end_time - start_time) * 1000000; }

  bool operator<(const Operation& rhs) const {
    return start_time < rhs.start_time;
  }
};


#endif // OPERATION_H
