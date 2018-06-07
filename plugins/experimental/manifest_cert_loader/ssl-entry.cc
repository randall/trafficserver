#include "ssl-entry.h"

SSLEntry::SSLEntry() : ctx(nullptr)
{
  this->mutex = TSMutexCreate();
}
