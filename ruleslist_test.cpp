#include "gtest/gtest.h"
#include "ruleslist.h"

//class RulesListTest: ::testing::Test{};

TEST(RulesList, testAllMethods){
  rule rule1;
  rule1.path = "/rule1/path";
  rule1.perms = ALLOW_ALWAYS;
  rule1.sha = "rule1sha";
  rule1.is_fixed_ctmark = true;
  rule1.ctmark_out = 7777;
  rule1.ctmark_in = 17777;
  rule rule2;
  rule2.path = "/rule2/path";
  rule2.perms = DENY_ALWAYS;
  rule2.sha = "rule2sha";
  rule2.is_fixed_ctmark = false;
  vector<rule> newrules = {rule1, rule2};
  RulesList rules(newrules);

  rules.add("/rule3/path", "2222", ALLOW_ONCE, true, "", 3333, 0, true);
  ADD_FAILURE();

}

