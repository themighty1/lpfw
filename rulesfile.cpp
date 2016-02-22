#include "rulesfile.h"
#include <fstream>

//empty constructor so we can init a global var
RulesFile::RulesFile(){}

//the actual constructor
RulesFile::RulesFile(string path)
{
  this->rulesFilePath = path;
}

vector<rule> RulesFile::read(){
  ifstream inputFile(this->rulesFilePath);
  string line;
  int pos;
  bool is_full_path_found = false;
  bool is_permission_found = false;
  bool is_sha256_hexdigest_found = false;
  bool is_conntrack_mark_found = false;
  string full_path = "";
  string permission = "";
  string sha256_hexdigest = "";
  int conntrack_mark = 0;
  vector<rule> rules;

  while (getline(inputFile, line))
  {
    if (line[0] == '#') continue;
    if (line == ""){
      if (is_full_path_found && is_permission_found && is_sha256_hexdigest_found){
        //the end of the rule parameters
        rule newrule;
        newrule.path = full_path;
        newrule.perms = permission;
        newrule.sha = sha256_hexdigest;
        newrule.pid = "0";
        newrule.is_active = false;
        newrule.stime = 0;
        newrule.first_instance = true;
        newrule.ctmark_out = 0;
        newrule.ctmark_in = 0;
        if (is_conntrack_mark_found){
          newrule.ctmark_out = conntrack_mark;
          newrule.ctmark_in = conntrack_mark+CTMARK_DELTA;
          newrule.is_fixed_ctmark = true;
        }
        rules.push_back(newrule);
        is_full_path_found = false;
        is_permission_found = false;
        is_sha256_hexdigest_found = false;
        is_conntrack_mark_found = false;
        full_path = "";
        permission = "";
        sha256_hexdigest = "";
        conntrack_mark = 0;
      }
      continue;
    }
    if ((pos = line.find(" ")) == string::npos) {
       throw("error");
       //return; //TODO should throw?
    }
    //mandatory parameters
    if (!is_full_path_found){
      if (line.substr(0,11) != "full_path= ") {
        throw("error");
        //return; //TODO should throw?
      }
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      full_path = line;
      is_full_path_found = true;
      continue;
    }
    if (!is_permission_found){
      if (line.substr(0,12) != "permission= ") {
        throw("error");
        //return; //TODO should throw?
      }
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      permission = line;
      is_permission_found = true;
      continue;
    }
    if (!is_sha256_hexdigest_found){
      if (line.substr(0,18) != "sha256_hexdigest= ") {
        throw("error");
        //return; //TODO should throw?
      }
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      sha256_hexdigest = line;
      is_sha256_hexdigest_found = true;
      continue;
    }
    if (!is_conntrack_mark_found){
      if (line.substr(0,16) != "conntrack_mark= ") {
        throw("error");
        //return; //TODO should throw?
      }
      //trim leading spaces
      line = line.substr(pos, string::npos);
      line = line.substr( line.find_first_not_of(" "), string::npos);
      conntrack_mark = std::stoi(line);
      is_conntrack_mark_found = true;
      continue;
    }
  }
  inputFile.close();
  return rules;
}


bool RulesFile::save(vector<rule> unsanitizedRules){
  vector<rule>rulesToSave = sanitizeBeforeSave(unsanitizedRules);

  string string_to_write = this->rulesfile_header;
  for(int i = 0; i < rulesToSave.size(); i++){
    string_to_write += "full_path=        " + rulesToSave[i].path + "\n";
    string_to_write += "permission=       " + rulesToSave[i].perms + "\n";
    string_to_write += "sha256_hexdigest= " + rulesToSave[i].sha + "\n";
    if (rulesToSave[i].is_fixed_ctmark){
      string_to_write += "conntrack_mark=   " + to_string(rulesToSave[i].ctmark_out) + "\n";
    }
    string_to_write += "\n";
  }
  ofstream f(this->rulesFilePath);
  f << string_to_write;
  f.close();
}


//iterate over rulescopy removing all rules which are not *ALWAYS
//or which are duplicates of other *ALWAYS rules with the same path
//this will leave us with rulescopy with unique *ALWAYS rules
vector<rule> RulesFile::sanitizeBeforeSave(vector<rule> rulescopy){
  for(int i = 0; i < rulescopy.size(); i++){
    if (rulescopy[i].perms == ALLOW_ALWAYS || rulescopy[i].perms == DENY_ALWAYS) continue;
    //else
    rulescopy.erase(rulescopy.begin()+i);
    --i; //indexes shrunk by one, we need to revisit the same index on next iteration
  }
  //iterate again removing duplicate
  int j;
  for(int k = 0; k < rulescopy.size(); k++){
    for(j = k+1; j < rulescopy.size(); j++){
      if (rulescopy[j].path != rulescopy[k].path) continue;
      //else
      rulescopy.erase(rulescopy.begin()+j);
      --j;
    }
  }
  return rulescopy;
}
