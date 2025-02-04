/*
** Copyright 2021, Corellium, LLC
** Copyright 2010, Adam Shanks (@ChainsDD)
** Copyright 2008, Zinx Verituse (@zinxv)
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <pwd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/types.h>
#include <netinet/in.h> 

#include "su.h"
#include "utils.h"

extern int is_daemon;
extern int daemon_from_uid;
extern int daemon_from_pid;

unsigned get_shell_uid() {
  struct passwd* ppwd = getpwnam("shell");
  if (NULL == ppwd) {
    return 2000;
  }

  return ppwd->pw_uid;
}

unsigned get_system_uid() {
  struct passwd* ppwd = getpwnam("system");
  if (NULL == ppwd) {
    return 1000;
  }

  return ppwd->pw_uid;
}

unsigned get_radio_uid() {
  struct passwd* ppwd = getpwnam("radio");
  if (NULL == ppwd) {
    return 1001;
  }

  return ppwd->pw_uid;
}

int fork_zero_fucks() {
    int pid = fork();
    if (pid) {
        int status;
        waitpid(pid, &status, 0);
        return pid;
    }
    else {
        if ((pid = fork()))
            exit(0);
        return 0;
    }
}

static int from_init(struct su_initiator *from) {
    char path[PATH_MAX], exe[PATH_MAX];
    char args[4096], *argv0, *argv_rest;
    int fd;
    ssize_t len;
    int i;
    int err;

    from->uid = getuid();
    from->pid = getppid();

    if (is_daemon) {
        from->uid = daemon_from_uid;
        from->pid = daemon_from_pid;
    }

    /* Get the command line */
    snprintf(path, sizeof(path), "/proc/%u/cmdline", from->pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        PLOGE("Opening command line");
        return -1;
    }
    len = read(fd, args, sizeof(args));
    err = errno;
    close(fd);
    if (len < 0 || len == sizeof(args)) {
        PLOGEV("Reading command line", err);
        return -1;
    }

    argv0 = args;
    argv_rest = NULL;
    for (i = 0; i < len; i++) {
        if (args[i] == '\0') {
            if (!argv_rest) {
                argv_rest = &args[i+1];
            } else {
                args[i] = ' ';
            }
        }
    }
    args[len] = '\0';

    if (argv_rest) {
        strncpy(from->args, argv_rest, sizeof(from->args));
        from->args[sizeof(from->args)-1] = '\0';
    } else {
        from->args[0] = '\0';
    }

    /* If this isn't app_process, use the real path instead of argv[0] */
    snprintf(path, sizeof(path), "/proc/%u/exe", from->pid);
    len = readlink(path, exe, sizeof(exe));
    if (len < 0) {
        PLOGE("Getting exe path");
        return -1;
    }
    exe[len] = '\0';
    if (strcmp(exe, "/system/bin/app_process")) {
        argv0 = exe;
    }

    strncpy(from->bin, argv0, sizeof(from->bin));
    from->bin[sizeof(from->bin)-1] = '\0';

    struct passwd *pw;
    pw = getpwuid(from->uid);
    if (pw && pw->pw_name) {
        strncpy(from->name, pw->pw_name, sizeof(from->name));
    }

    return 0;
}

static void user_init(struct su_context *ctx) {
    if (ctx->from.uid > 99999) {
        ctx->user.android_user_id = ctx->from.uid / 100000;
    }
}

static void populate_environment(const struct su_context *ctx) {
    struct passwd *pw;

    if (ctx->to.keepenv)
        return;

    pw = getpwuid(ctx->to.uid);
    if (pw) {
        setenv("HOME", pw->pw_dir, 1);
        if (ctx->to.shell)
            setenv("SHELL", ctx->to.shell, 1);
        else
            setenv("SHELL", DEFAULT_SHELL, 1);
        if (ctx->to.login || ctx->to.uid) {
            setenv("USER", pw->pw_name, 1);
            setenv("LOGNAME", pw->pw_name, 1);
        }
    }
}

void set_identity(unsigned int uid) {
    if (setresgid(uid, uid, uid)) {
        PLOGE("setresgid (%u)", uid);
        exit(EXIT_FAILURE);
    }
    if (setresuid(uid, uid, uid)) {
        PLOGE("setresuid (%u)", uid);
        exit(EXIT_FAILURE);
    }
}

static void usage(int status) {
    FILE *stream = (status == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(stream,
    "Usage: su [options] [--] [-] [LOGIN] [--] [args...]\n\n"
    "Options:\n"
    "  --daemon                      start the su daemon agent\n"
    "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
    "  -h, --help                    display this help message and exit\n"
    "  -, -l, --login                pretend the shell to be a login shell\n"
    "  -m, -p,\n"
    "  --preserve-environment        do not change environment variables\n"
    "  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n");
    exit(status);
}

static __attribute__ ((noreturn)) void fail(struct su_context *ctx) {
    char *cmd = get_command(&ctx->to);

    LOGW("request failed (%u->%u %s)", ctx->from.uid, ctx->to.uid, cmd);
    fprintf(stderr, "%s\n", strerror(EACCES));
    exit(EXIT_FAILURE);
}

static __attribute__ ((noreturn)) void allow(struct su_context *ctx) {
    char *arg0;
    int argc, err;

    umask(ctx->umask);

    char *binary;
    argc = ctx->to.optind;
    if (ctx->to.command) {
        binary = ctx->to.shell;
        ctx->to.argv[--argc] = ctx->to.command;
        ctx->to.argv[--argc] = "-c";
    }
    else if (ctx->to.shell) {
        binary = ctx->to.shell;
    }
    else {
        if (ctx->to.argv[argc]) {
            binary = ctx->to.argv[argc++];
        }
        else {
            binary = DEFAULT_SHELL;
        }
    }

    arg0 = strrchr (binary, '/');
    arg0 = (arg0) ? arg0 + 1 : binary;
    if (ctx->to.login) {
        int s = strlen(arg0) + 2;
        char *p = malloc(s);

        if (!p)
            exit(EXIT_FAILURE);

        *p = '-';
        strcpy(p + 1, arg0);
        arg0 = p;
    }

    populate_environment(ctx);
    if (ctx->to.uid)
        set_identity(ctx->to.uid);

    #define PARG(arg)                                    \
        (argc + (arg) < ctx->to.argc) ? " " : "",                    \
        (argc + (arg) < ctx->to.argc) ? ctx->to.argv[argc + (arg)] : ""

    LOGD("%u %s executing %u %s using binary %s : %s%s%s%s%s%s%s%s%s%s%s%s%s%s",
            ctx->from.uid, ctx->from.bin,
            ctx->to.uid, get_command(&ctx->to), binary,
            arg0, PARG(0), PARG(1), PARG(2), PARG(3), PARG(4), PARG(5),
            (ctx->to.optind + 6 < ctx->to.argc) ? " ..." : "");

    ctx->to.argv[--argc] = arg0;
    execvp(binary, ctx->to.argv + argc);
    PLOGE("exec");
    fprintf(stderr, "Cannot execute %s: %s\n", binary, strerror(errno));
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    return su_main(argc, argv, 1);
}

int su_main(int argc, char *argv[], int need_client) {
    // start up in daemon mode if prompted
    if (argc == 2 && strcmp(argv[1], "--daemon") == 0) {
        return run_daemon();
    }

    int ppid = getppid();

    struct su_context ctx = {
        .from = {
            .pid = -1,
            .uid = 0,
            .bin = "",
            .args = "",
            .name = "",
        },
        .to = {
            .uid = AID_ROOT,
            .login = 0,
            .keepenv = 0,
            .shell = NULL,
            .command = NULL,
            .argv = argv,
            .argc = argc,
            .optind = 0,
            .name = "",
        },
        .user = {
            .android_user_id = 0,
        },
    };

    int c;

    struct option long_opts[] = {
        { "command",            required_argument,    NULL, 'c' },
        { "help",            no_argument,        NULL, 'h' },
        { "login",            no_argument,        NULL, 'l' },
        { "preserve-environment",    no_argument,        NULL, 'p' },
        { "shell",            required_argument,    NULL, 's' },
        { "version",                no_argument,        NULL, 'v' },
        { "context",                required_argument,  NULL, 'z' },
        { NULL, 0, NULL, 0 },
    };

    while ((c = getopt_long(argc, argv, "+c:hlmps:Vvz:", long_opts, NULL)) != -1) {
        switch(c) {
        case 'c':
            ctx.to.shell = DEFAULT_SHELL;
            ctx.to.command = optarg;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'l':
            ctx.to.login = 1;
            break;
        case 'm':
        case 'p':
            ctx.to.keepenv = 1;
            break;
        case 's':
            ctx.to.shell = optarg;
            break;
        case 'V':
            printf("%d\n", 0);
            exit(EXIT_SUCCESS);
        case 'v':
            printf("%s\n", "0:0");
            exit(EXIT_SUCCESS);
        case 'z':
            break;
        default:
            /* Bionic getopt_long doesn't terminate its error output by newline */
            fprintf(stderr, "\n");
            usage(2);
        }
    }

    if (need_client) {
        return connect_daemon(argc, argv, ppid);
    }

    if (optind < argc && !strcmp(argv[optind], "-")) {
        ctx.to.login = 1;
        optind++;
    }
    /* username or uid */
    if (optind < argc && strcmp(argv[optind], "--")) {
        struct passwd *pw;
        pw = getpwnam(argv[optind]);
        if (!pw) {
            char *endptr;

            /* It seems we shouldn't do this at all */
            errno = 0;
            ctx.to.uid = strtoul(argv[optind], &endptr, 10);
            if (errno || *endptr) {
                LOGE("Unknown id: %s\n", argv[optind]);
                fprintf(stderr, "Unknown id: %s\n", argv[optind]);
                exit(EXIT_FAILURE);
            }
        } else {
            ctx.to.uid = pw->pw_uid;
            if (pw->pw_name)
                strncpy(ctx.to.name, pw->pw_name, sizeof(ctx.to.name));
        }
        optind++;
    }
    if (optind < argc && !strcmp(argv[optind], "--")) {
        optind++;
    }
    ctx.to.optind = optind;

    if (from_init(&ctx.from) < 0) {
        fail(&ctx);
    }

    user_init(&ctx);

    // Allow everything
    allow(&ctx);

}
