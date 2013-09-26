#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

typedef std::vector<std::string> Args;

std::string execute(const std::string& cmd, Args args, const std::string& data) {
    pid_t pid = 0;
    int pipein[2], pipeout[2], pipeerr[2];

    pipe(&pipein[0]);
    pipe(&pipeout[0]);
    pipe(&pipeerr[0]);

    std::vector<const char *> argsraw;
    argsraw.push_back(cmd.c_str());
    for (int i = 0; i< args.size(); ++i) {
        argsraw.push_back(args[i].c_str());
    }
    argsraw.push_back(NULL);

    pid = fork();
    if (pid == 0)
    {
        // Child
        close(pipein[1]);
        dup2(pipein[0], STDIN_FILENO);

        close(pipeout[0]);
        dup2(pipeout[1], STDOUT_FILENO);

        close(pipeerr[0]);
        dup2(pipeerr[1], STDERR_FILENO);

        exit(execvp(cmd.c_str(), (char**)(&argsraw[0])));
    }
    else {
        close(pipein[0]);
        close(pipeout[1]);
        close(pipeerr[1]);
    }

    char buf[4096];
    write(pipein[1], data.c_str(), data.size());
    close(pipein[1]);

    std::string result;

    int readed = 0;
    while(readed = read(pipeout[0], buf, sizeof(buf)), readed > 0) {
        result.append(buf, readed);
    }

    return result; 
}

std::string digest(const std::string& keypath, const std::string& data) {

    Args args;
    args.push_back("dgst");
    args.push_back("-engine");
    args.push_back("gost");
    args.push_back("-sign");
    args.push_back(keypath);

    std::string dgst = execute("openssl", args, data);
    std::string result = execute("base64", Args(), dgst);

    return result;
}

int main(int argc, char *argv[])
{
    std::stringstream input;           
    input << std::cin.rdbuf();
    Args args; args.push_back("-");
    digest("/home/jerry/devel/examples/keys/seckey.pem", input.str());
    
    return 0;
}

extern "C" {
    const char* dgst(const char* keypath, const char* data) {
        return digest(keypath, data).c_str();
    }
}


