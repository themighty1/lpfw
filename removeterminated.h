#ifndef REMOVETERMINATED_H
#define REMOVETERMINATED_H

#include "ruleslist.h"
#include "rulesfile.h"

class RemoveTerminated
{
friend class RemoveTerminatedFriend;

public:
  RemoveTerminated(RulesList*);
  void loop();
private:
  void iteration();
  RulesList* rulesList;
  int refresh_interval = 1;
};

#endif // REMOVETERMINATED_H
