#include "gtest/gtest.h"
#include "rulesfile.h"

TEST(RulesFile, savingAndLoading)
{
  RulesFile testRulesFile("/tmp/blah");
  rule newrule1;
  newrule1.path = "/someweirdpath/ыыыы";
  newrule1.pid = "12345";
  newrule1.perms = ALLOW_ALWAYS;
  newrule1.sha = "deadbeef";
  newrule1.is_fixed_ctmark = false;
  newrule1.is_permanent = true;
  newrule1.ctmark_in = 21000;
  newrule1.ctmark_out = 11000;
  rule newrule2;
  newrule2.path = "/usr/bin/two";
  newrule2.pid = "5678";
  newrule2.perms = ALLOW_ONCE;
  newrule2.sha = "beefbeef";
  rule newrule3;
  newrule3.path = "/usr/bin/three";
  newrule3.pid = "9764";
  newrule3.perms = DENY_ALWAYS;
  newrule3.sha = "ffffffff";
  newrule3.is_fixed_ctmark = true;
  newrule3.is_permanent = true;
  newrule3.ctmark_in = 11000;
  newrule3.ctmark_out = 1000;
  //same path as rule 1, should be filtered out
  rule newrule4;
  newrule4.path = "/someweirdpath/ыыыы";
  newrule4.pid = "22345";
  newrule4.perms = ALLOW_ALWAYS;
  newrule4.sha = "deadbeef";
  newrule4.is_fixed_ctmark = false;
  newrule4.ctmark_in = 21001;
  newrule4.ctmark_out = 11001;

  vector<rule> newrules;
  newrules.push_back(newrule1);
  newrules.push_back(newrule2);
  newrules.push_back(newrule3);
  testRulesFile.save(newrules);
  vector<rule> loadedRules = testRulesFile.read();
  ASSERT_EQ(loadedRules.size(), 2);

  bool rule1Found = false;
  bool rule3Found = false;
  for (int i=0; i < loadedRules.size(); i++){
    rule matchedRule;
    if (!rule1Found && (loadedRules[i].path == newrule1.path)){
      rule1Found = true;
      matchedRule = newrule1;
      ASSERT_EQ(loadedRules[i].is_permanent, true);
      ASSERT_EQ(loadedRules[i].is_fixed_ctmark, false);
      ASSERT_EQ(loadedRules[i].ctmark_in, 0);
      ASSERT_EQ(loadedRules[i].ctmark_out, 0);
    }
    else if (!rule3Found && (loadedRules[i].path == newrule3.path)){
      rule3Found = true;
      matchedRule = newrule3;
      ASSERT_EQ(loadedRules[i].is_permanent, true);
      ASSERT_EQ(loadedRules[i].is_fixed_ctmark, true);
      ASSERT_EQ(loadedRules[i].ctmark_in, 11000);
      ASSERT_EQ(loadedRules[i].ctmark_out, 1000);
    }
    else{
      ADD_FAILURE();
    }

    ASSERT_EQ(loadedRules[i].path == matchedRule.path, true);
    ASSERT_EQ("0", loadedRules[i].pid);
    ASSERT_EQ(matchedRule.perms, loadedRules[i].perms);
    ASSERT_EQ(matchedRule.sha, loadedRules[i].sha);
  }
  ASSERT_EQ(rule1Found && rule3Found, true);
}

