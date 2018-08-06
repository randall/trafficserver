#include "exp_conditions.h"

bool
ConditionProto::eval(const Resources &res)
{
  std::string s;

  append_value(s, res);
  TSDebug(PLUGIN_NAME, "Evaluating %%<proto>");

  return static_cast<const MatcherType *>(_matcher)->test(s);
}

void
ConditionProto::append_value(std::string &s, const Resources &res)
{
  std::string resolved_variable = "";
  TSMBuffer bufp;
  TSMLoc url_loc;

  // Protocol of the incoming request
  if (TSHttpTxnPristineUrlGet(res.txnp, &bufp, &url_loc) == TS_SUCCESS) {
    int len;
    const char *tmp = TSUrlSchemeGet(bufp, url_loc, &len);
    if ((tmp != nullptr) && (len > 0)) {
      resolved_variable.assign(tmp, len);
    }
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, url_loc);

    s.append(resolved_variable);
    TSDebug(PLUGIN_NAME, "Appending %%<proto>(%s) to evaluation value -> %s", resolved_variable.c_str(), s.c_str());
  }
}
