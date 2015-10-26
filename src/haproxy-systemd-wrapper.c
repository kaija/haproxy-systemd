/*
 * Wrapper to make haproxy systemd-compliant.
 *
 * Copyright 2013 Marc-Antoine Perennou <Marc-Antoine@Perennou.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#define PROCPS_BUFSIZE 1024


#define REEXEC_FLAG "HAPROXY_SYSTEMD_REEXEC"
#define SD_DEBUG "<7>"
#define SD_NOTICE "<5>"

static volatile sig_atomic_t caught_signal;
static int read_pids_from_proc(char ***pid_strv);

static char *pid_file = "/run/haproxy.pid";
static int wrapper_argc;
static char **wrapper_argv;
static pid_t self_pid;
/* returns the path to the haproxy binary into <buffer>, whose size indicated
 * in <buffer_size> must be at least 1 byte long.
 */
static void locate_haproxy(char *buffer, size_t buffer_size)
{
	char *end = NULL;
	int len;

	len = readlink("/proc/self/exe", buffer, buffer_size - 1);
	if (len == -1)
		goto fail;

	buffer[len] = 0;
	end = strrchr(buffer, '/');
	if (end == NULL)
		goto fail;

	if (strcmp(end + strlen(end) - 16, "-systemd-wrapper") == 0) {
		end[strlen(end) - 16] = '\0';
		return;
	}

	end[1] = '\0';
	strncpy(end + 1, "haproxy", buffer + buffer_size - (end + 1));
	buffer[buffer_size - 1] = '\0';
	return;
 fail:
	strncpy(buffer, "/usr/sbin/haproxy", buffer_size);
	buffer[buffer_size - 1] = '\0';
	return;
}

static void spawn_haproxy(char **pid_strv, int nb_pid)
{
	char haproxy_bin[512];
	pid_t pid;
	int main_argc;
	char **main_argv;
	int i = 0;
	char **pid_strv2 = NULL;
	int proc_kill = 0;

	main_argc = wrapper_argc - 1;
	main_argv = wrapper_argv + 1;
	pid = fork();
	if (!pid) {
		/* 3 for "haproxy -Ds -sf" */
		char **argv = calloc(4 + main_argc + nb_pid + 1, sizeof(char *));
		int argno = 0;
		locate_haproxy(haproxy_bin, 512);
		argv[argno++] = haproxy_bin;
		for (i = 0; i < main_argc; ++i)
			argv[argno++] = main_argv[i];
		//argv[argno++] = "-Ds";
		argv[argno++] = "-d";//for
		if (nb_pid > 0) {
			argv[argno++] = "-sf";
			for (i = 0; i < nb_pid; ++i)
				argv[argno++] = pid_strv[i];
		}else{
			fprintf(stderr, SD_NOTICE "find all haproxy pid\n");
			nb_pid = read_pids_from_proc(&pid_strv2);
			if(nb_pid > 0) {
				proc_kill = 1;
				argv[argno++] = "-sf";
				for (i = 0; i < nb_pid; ++i) {
					argv[argno++] = pid_strv2[i];
				}
			}
		}
		argv[argno] = NULL;

		fprintf(stderr, SD_DEBUG "haproxy-systemd-wrapper: executing ");
		for (i = 0; argv[i]; ++i)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");

		execv(argv[0], argv);
		if(proc_kill == 1) {
			for (i = 0; i < nb_pid; ++i) {
				free(pid_strv2[i]);
			}
			free(pid_strv2);
		}
		exit(0);
	}
}

static int read_to_buf(const char *filename, void *buf)
{
        int fd;
        /* open_read_close() would do two reads, checking for EOF.
         * When you have 10000 /proc/$NUM/stat to read, it isn't desirable */
        ssize_t ret = -1;
        fd = open(filename, O_RDONLY);
        if (fd >= 0) {
                ret = read(fd, buf, PROCPS_BUFSIZE-1);
                close(fd);
        }
        ((char *)buf)[ret > 0 ? ret : 0] = '\0';
        return ret;
}

static int read_pids_from_proc(char ***pid_strv)
{
	unsigned int pid = 0;
	unsigned int ppid = 0;
	int read = 0, allocated = 8;
	char name[32];
	DIR *dir;
	struct dirent * ptr;
	char proc_buf[PROCPS_BUFSIZE];
	char proc_stat_path[32];
	char pid_str[10];
	dir = opendir("/proc");
	*pid_strv = malloc(allocated * sizeof(char *));
	while((ptr = readdir(dir)) != NULL)
	{
		if (ptr->d_type == DT_DIR) {
			pid = atoi(ptr->d_name);
			if(pid > 1) {
				sprintf(proc_stat_path, "/proc/%d/stat", atoi(ptr->d_name));
				read_to_buf(proc_stat_path, proc_buf);
				sscanf(proc_buf, "%d %s %*c %d %*d", &pid, name, &ppid);
				//printf ("pid: %d name: %s ppid: %d\n", pid, name, ppid);
				if(strncmp(name, "(haproxy)", 9) == 0 && self_pid == ppid) {
					sprintf(pid_str, "%u", pid);
					if (read == allocated) {
						allocated *= 2;
						*pid_strv = realloc(*pid_strv, allocated * sizeof(char *));
					}
					(*pid_strv)[read++] = strdup(pid_str);
				}
			}
		}
	}
	closedir(dir);
	return read;
}

static int read_pids(char ***pid_strv)
{
	FILE *f = fopen(pid_file, "r");
	int read = 0, allocated = 8;
	char pid_str[10];

	if (!f)
		return 0;

	*pid_strv = malloc(allocated * sizeof(char *));
	while (1 == fscanf(f, "%s\n", pid_str)) {
		if (read == allocated) {
			allocated *= 2;
			*pid_strv = realloc(*pid_strv, allocated * sizeof(char *));
		}
		(*pid_strv)[read++] = strdup(pid_str);
	}

	fclose(f);

	return read;
}

static void signal_handler(int signum)
{
	caught_signal = signum;
}

static void do_restart(void)
{
	setenv(REEXEC_FLAG, "1", 1);
	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: re-executing\n");

	execv(wrapper_argv[0], wrapper_argv);
}

static void do_shutdown(void)
{
	int i, pid;
	char **pid_strv = NULL;
	int nb_pid = read_pids(&pid_strv);
	for (i = 0; i < nb_pid; ++i) {
		pid = atoi(pid_strv[i]);
		if (pid > 0) {
			fprintf(stderr, SD_DEBUG "haproxy-systemd-wrapper: SIGINT -> %d\n", pid);
			kill(pid, SIGINT);
			free(pid_strv[i]);
		}
	}
	free(pid_strv);
	nb_pid = read_pids_from_proc(&pid_strv);
	if(nb_pid > 0) {
		for (i = 0; i < nb_pid; ++i) {
			if ((pid= atoi(pid_strv[i])) > 0) {
				fprintf(stderr, SD_DEBUG "haproxy-systemd-wrapper: proc kill SIGINT -> %d\n", pid);
				kill(pid, SIGINT);
				free(pid_strv[i]);
			}
		}
		free(pid_strv);
	}
}

static void init(int argc, char **argv)
{
	while (argc > 1) {
		if ((*argv)[0] == '-' && (*argv)[1] == 'p') {
			pid_file = *(argv + 1);
		}
		--argc; ++argv;
	}
}

int main(int argc, char **argv)
{
	int status;
	struct sigaction sa;

	self_pid = getpid();

	wrapper_argc = argc;
	wrapper_argv = argv;

	--argc; ++argv;
	init(argc, argv);

	//unlink pid file beofre start
	unlink(pid_file);

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = &signal_handler;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (getenv(REEXEC_FLAG) != NULL) {
		/* We are being re-executed: restart HAProxy gracefully */
		int i;
		char **pid_strv = NULL;
		int nb_pid = read_pids(&pid_strv);

		unsetenv(REEXEC_FLAG);
		spawn_haproxy(pid_strv, nb_pid);

		for (i = 0; i < nb_pid; ++i)
			free(pid_strv[i]);
		free(pid_strv);
	}
	else {
		/* Start a fresh copy of HAProxy */
		spawn_haproxy(NULL, 0);
	}
	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: pid %d\n", getpid());

	status = -1;
	while (-1 != wait(&status) || errno == EINTR) {
		if (caught_signal == SIGUSR2 || caught_signal == SIGHUP) {
			caught_signal = 0;
			do_restart();
		}
		else if (caught_signal == SIGINT || caught_signal == SIGTERM) {
			caught_signal = 0;
			do_shutdown();
		}
		else if (caught_signal == SIGUSR1) {
			fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: catch SIGUSR1\n");
			caught_signal = 0;
			do_shutdown();
			return 0;
		}
	}

	fprintf(stderr, SD_NOTICE "haproxy-systemd-wrapper: exit, haproxy RC=%d\n",
			status);
	return status;
}
