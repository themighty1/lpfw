#ifndef RULESFILE_H
#define RULESFILE_H

#include <string>
#include <vector>
#include "common/includes.h" //for struct rule

using namespace std;

class RulesFile
{
  string rulesFilePath;
public:
  RulesFile();
  RulesFile(string);
  vector<rule> read();
  bool save(vector<rule> rulesToSave);
  vector<rule> sanitizeBeforeSave(vector<rule> rulesToSave);
private:
  string rulesfile_header = "\n"
  "# Leopard Flower personal firewall rules list\n"
  "# lines startng with # are comments and will be ignored\n"
  "# blank line is used to separate individual rules\n"
  "# (Each parameter must have one or more spaces after the = sign and terminate with a newline)\n"
  "\n"
  "# Mandatory parameters (strictly in this order):\n"
  "# full_path= followed by the full path to the executable\n"
  "# permission= followed by either ALLOW_ALWAYS or DENY_ALWAYS\n"
  "# sha256_hexdigest= followed by sha256 UPPERCASE hexdigest with any leading zeroes\n"
  "# Optional parameters:\n"
  "# conntrack_mark= followed by an integer\n"
  "# (conntrack_mark can be manually assigned by the user in this file. This will enable the user\n"
  "# to create more complex netfilter rules for the application, e.g. rate-limiting, IP/port blocking etc\n"
  "# conntrack_mark set here will be used for outgoing connections\n"
  "# for incoming connections conntrack_mark+10000 will be used)\n"
  "\n"
  "# Make sure there is a blank line at the end of this file\n"
  "\n"
  "# Example rules list:\n"
  "# full_path=        /usr/bin/app1\n"
  "# permission=       ALLOW_ALWAYS\n"
  "# sha256_hexdigest= 3719407990275C319C882786125B1F148CC163FA3BF4C7712092034BBA06CE4D\n"
  "# conntrack_mark=   45678\n"
  "\n"
  "# full_path=        /home/myusername/app2\n"
  "# permission=       ALLOW_ALWAYS\n"
  "# sha256_hexdigest= 9AF0F74366D0B3D1415AB6DF5D7E2429BF5CB5AC901B5ECFCC3DD51DA4B83D75\n"
  "\n";
};

#endif // RULESFILE_H
