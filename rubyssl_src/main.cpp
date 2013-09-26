
#include <sys/wait.h>

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

typedef std::vector<std::string> Args;

std::string execute(const std::string& cmd, Args args, const std::string& data) {
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

    pid_t pid = fork();
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

    std::string result_out;
    std::string result_err;

    int readed = 0;
    while(readed = read(pipeout[0], buf, sizeof(buf)), readed > 0) {
        result_out.append(buf, readed);
    }
    close(pipeout[0]);
    
    while(readed = read(pipeerr[0], buf, sizeof(buf)), readed > 0) {
        result_err.append(buf, readed);
    }
    close(pipeerr[0]);
    
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        kill(pid, SIGTERM);
        sleep(3);
        if (waitpid(pid, &status, WNOHANG) != pid) {
            kill(pid, SIGKILL);
        }
    }
    
    if (WIFEXITED(status) && !WEXITSTATUS(status)) {
        return result_out; 
    }
    else {
        throw std::runtime_error(result_err.c_str());
    }
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

#define HANDLE_ERRORS(expr) \
    try {\
        (expr);\
        return 0;\
    }\
    catch(const std::exception& e) {\
        strncpy(error, e.what(), esize);\
        return -1;\
    }\
    catch (...) {\
        strncpy(error, "Unknown error", esize);\
        return -1;\
    }    

extern "C" {
    
    int dgst(const char* keypath, const char* data, char* result, int rsize, char* error, int esize) {
        HANDLE_ERRORS({
            const std::string res = digest(keypath, data);
            strncpy(result, res.c_str(), rsize);
        })
    }
}


