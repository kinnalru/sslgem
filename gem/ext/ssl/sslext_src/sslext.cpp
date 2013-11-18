﻿#include <sys/wait.h>

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <zconf.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>

typedef std::vector<char> Bytes;
typedef std::vector<std::string> Args;
typedef int (Main) (int argc, char **argv);

Bytes execute(const std::string& cmd, Args args, const Bytes& data, Main main = NULL) {
    int pipein[2], pipeout[2], pipeerr[2];

    pipe(&pipein[0]);
    pipe(&pipeout[0]);
    pipe(&pipeerr[0]);

    std::vector<char*> argsraw;
    argsraw.push_back(const_cast<char*>(cmd.c_str()));
    for (int i = 0; i< args.size(); ++i) {
        argsraw.push_back(const_cast<char*>(args[i].c_str()));
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

        if (main) {
            exit(main(argsraw.size() - 1, argsraw.data()));
        }
        else {
            exit(execvp(cmd.c_str(), argsraw.data()));
        }
    }
    else {
        close(pipein[0]);
        close(pipeout[1]);
        close(pipeerr[1]);
    }

    char buf[4096];
    write(pipein[1], data.data(), data.size());
    close(pipein[1]);

    Bytes result_out;
    Bytes result_err;

    int readed = 0;
    while(readed = read(pipeout[0], buf, sizeof(buf)), readed > 0) {
        result_out.insert(result_out.end(), buf, buf + readed);
    }
    close(pipeout[0]);
    
    while(readed = read(pipeerr[0], buf, sizeof(buf)), readed > 0) {
        result_err.insert(result_err.end(), buf, buf + readed);
    }
    result_err.push_back(0);
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
        throw std::runtime_error(result_err.data());
    }
}

extern "C" {
    int main(int argc, char **argv);
}

Bytes digest(const Bytes& data) {

    Args args;
    args.push_back("dgst");
    args.push_back("-engine");
    args.push_back("gost");
    args.push_back("-md_gost94");
    args.push_back("-binary");

    return execute("openssl", args, data, main);
}

Bytes sign_impl(const std::string& privatekeypath, const Bytes& data) {

    Args args;
    args.push_back("dgst");
    args.push_back("-engine");
    args.push_back("gost");
    args.push_back("-sign");
    args.push_back(privatekeypath);

    return execute("openssl", args, data, main);
}

void smime_verify(const std::string& signaturepath, const std::string& filename) {

    Args args;
    args.push_back("smime");
    args.push_back("-verify");
    args.push_back("-engine");
    args.push_back("gost");
    args.push_back("-noverify");
    args.push_back("-inform");
    args.push_back("DER");
    args.push_back("-in");
    args.push_back(signaturepath);
    args.push_back("-content");
    args.push_back(filename);
    

    execute("openssl", args, Bytes(), main);
}

Bytes smime_sign(const std::string& privatekeypath, const std::string& certificatefile, const std::string& filename) {

    Args args;
    args.push_back("smime");
    args.push_back("-sign");
    args.push_back("-engine");
    args.push_back("gost");
    args.push_back("-gost89");
    args.push_back("-inkey");
    args.push_back(privatekeypath);
    args.push_back("-signer");
    args.push_back(certificatefile);    
    args.push_back("-in");
    args.push_back(filename);
    args.push_back("-outform");        
    args.push_back("DER");
    args.push_back("-binary");
    
    return execute("openssl", args, Bytes(), main);
}

// int main(int argc, char *argv[])
// {
//     return dgst_main(argc,argv);
// } 

#include "ruby.h"

#define HANDLE_EXCEPTIONS(expr) \
    try {\
        (expr);\
    }\
    catch(const std::exception& e) {\
        rb_raise(rb_eStandardError, e.what(), NULL);\
    }\
    catch (...) {\
        rb_raise(rb_eStandardError, "SslExt: unknown exception");\
    }\
    return Qnil;

extern "C" {

    VALUE dgst(VALUE self, VALUE rdata) {
        HANDLE_EXCEPTIONS({
            const Bytes data(RSTRING_PTR(rdata), RSTRING_END(rdata));
            const Bytes res = digest(data);
            return rb_str_new2(res.data());
        })
    }
    
    VALUE sign(VALUE self, VALUE rkey, VALUE rdata) {
        HANDLE_EXCEPTIONS({
            const std::string privatekeypath(RSTRING_PTR(rkey), RSTRING_END(rkey));          
            const Bytes data(RSTRING_PTR(rdata), RSTRING_END(rdata));
            std::cerr << "sign key: " << privatekeypath << " sign data:" << &data[0] << std::endl;
            const Bytes res = sign_impl(privatekeypath, data);
            return rb_str_new2(res.data());
        })
    }    
    
    VALUE verify_file(VALUE self, VALUE rsign, VALUE rpath) {
        HANDLE_EXCEPTIONS({
            const std::string signaturepath(RSTRING_PTR(rsign), RSTRING_END(rsign));
            const std::string filename(RSTRING_PTR(rpath), RSTRING_END(rpath));
            std::cerr << "verify signature: " << signaturepath << " filename:" << filename << std::endl;
            smime_verify(signaturepath, filename);
        })
    }

    VALUE sign_file(VALUE self, VALUE rkey, VALUE rcert, VALUE rpath) {
        HANDLE_EXCEPTIONS({
            const std::string privatekeypath(RSTRING_PTR(rkey), RSTRING_END(rkey));
            const std::string certificatefile(RSTRING_PTR(rcert), RSTRING_END(rcert));
            const std::string filename(RSTRING_PTR(rpath), RSTRING_END(rpath));
            std::cerr << "sign file  key: " << privatekeypath << " cert:" << certificatefile << " file: " << filename << std::endl;
            const Bytes res = smime_sign(privatekeypath, certificatefile, filename);
            return rb_str_new2(res.data());
        })
    }

    // The initialization method for this module
    void Init_sslext() {
        static VALUE sslExt = rb_define_module("SslExt");
        rb_define_method(sslExt, "dgst", (VALUE(*)(...))dgst, 1);
        rb_define_method(sslExt, "sign", (VALUE(*)(...))sign, 2);
        rb_define_method(sslExt, "verify_file", (VALUE(*)(...))verify_file, 2);
        rb_define_method(sslExt, "sign_file", (VALUE(*)(...))sign_file, 3);
    }


}
