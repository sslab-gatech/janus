#include <list>
#include <string>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <unistd.h>
#include <err.h>

using namespace std;
using namespace boost::algorithm;

bool is_target(char *dir, char *argv[], int argc) {
  for (int i = 0; i < argc - 1; i ++) {
    if (!strcmp(argv[i], "-o") && strstr(argv[i+1], dir) 
      // || (strstr(argv[i+1], "fs/jbd2") && !strcmp(dir, "fs/ext4"))
    )
      return true;
  }
  return false;
}

void run(list<string> &params) {
  char **args = (char **)malloc(sizeof(char *) * (params.size() + 1));
  if (!args)
    err(1, "failed to allocate memory");

  int i = 0;
  for(auto &arg : params) {
    args[i] = strdup(arg.c_str());
    i ++;
  }
  args[i] = NULL;
  execvp(args[0], args);
}

void drop(list<string> &params, string key) {
  auto pos = find(params.begin(), params.end(), key);
  if (pos == params.end())
    return;
  params.erase(pos);
}

string get_output(string cmd) {
	char buf[1024];
	FILE *fp = popen(cmd.c_str(), "r");
  if (!fp)
    err(1, "failed to run: %s", cmd.c_str());

  string ret;
	if (fgets(buf, sizeof(buf), fp) != NULL) {
    ret = buf;
	}
	pclose(fp);

  trim_right(ret);
  return ret;
}

void adjust_clang_flags(list<string> &params) {
  // from Makefile
  params.push_back("-Qunused-arguments");
  params.push_back("-Wno-unknown-warning-option");
  params.push_back("-Wno-unused-variable");
  params.push_back("-Wno-format-invalid-specifier");
  params.push_back("-Wno-gnu");
  params.push_back("-Wno-tautological-compare");
  params.push_back("-mno-global-merge");

  params.push_back("-Wno-initializer-overrides");
  params.push_back("-Wno-unused-value");
  params.push_back("-Wno-format");
  params.push_back("-Wno-sign-compare");
  params.push_back("-Wno-format-zero-length");
  params.push_back("-Wno-uninitialized");
  
  drop(params, "-Wno-unused-but-set-variable");
  drop(params, "-fno-delete-null-pointer-checks");
  drop(params, "-DCC_HAVE_ASM_GOTO");
  drop(params, "-fconserve-stack");
  drop(params, "-fno-var-tracking-assignments");
  drop(params, "-femit-struct-debug-baseonly");

  params.push_back("-Xclang");
  params.push_back("-load");
  params.push_back("-Xclang");
  params.push_back("../core/afl-image/afl-llvm-pass.so");
  
  params.push_back("-isystem");
  params.push_back(get_output(*params.begin() + " -print-file-name=include"));

}

int main(int argc, char* argv[]) {
  if (argc < 2)
    err(1, "[usage] %s [dir]", argv[0]);

  list<string> params;

  bool clang = is_target(argv[1], argv, argc);
  if (clang) {
    params.push_back("clang");
  } else {
    params.push_back("gcc");
  }

  for (int i = 2; i < argc; i ++) {
    if (clang && !strcmp(argv[i], "-isystem")) {
      i ++;
      continue;
    }
    params.push_back(argv[i]);
  }

  if (clang)
    adjust_clang_flags(params);

  if (clang) {
    fstream fout;
    fout.open("ff-gcc.log", fstream::out | std::fstream::app);
    if (!fout)
      err(1, "failed to open a log");
    
    for (auto &i: params) {
      if (i.find(argv[1]) != string::npos)
        fout << "> " << i << endl;
    }
    
#ifdef DEBUG    
    for (auto &i: params) {
      fout << " " << i << endl;
    }
#endif
    
    fout.close();
  }

  run(params);

  return 0;

}
