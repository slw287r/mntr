#define _GNU_SOURCE
#ifndef __linux__
#error "Only supports Linux platform!"
#endif
#include <stdio.h>
#include <stdlib.h> 
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <proc/readproc.h>

#include "thpool.h"
#include "kvec.h"
typedef kvec_t(pid_t) kv_t;

extern char *__progname;
#define basename(str) (strrchr(str, '/') ? strrchr(str, '/') + 1 : str)

typedef struct
{
    int utime_ticks;
    int cutime_ticks;
    int stime_ticks;
    int cstime_ticks;
    int vsize; // virtual memory size in bytes
    int rss; //Resident  Set  Size in bytes
} pstat_t;

typedef struct
{
	pid_t pid;
	double rss, shr, cpu;
} usg_t;

/*
 * read /proc data into the passed variables
 * returns 0 on success, -1 on error
*/
void get_shr(const pid_t pid, long unsigned *shr)
{
	char *statm;
	asprintf(&statm, "/proc/%d/statm", pid);
	FILE *fpstat = fopen(statm, "r");
	free(statm);
	if (!fpstat) return;
	if (fscanf(fpstat, "%*d %*d %ld %*[^\1]", shr) == EOF)
	{
		fclose(fpstat);
		return;
	}
	*shr *= getpagesize();
	fclose(fpstat);
}

/*
 * read /proc data into the passed struct pstat
 * returns 0 on success, -1 on error
*/
int get_usg(const pid_t pid, pstat_t* result)
{
	//convert pid to string
	char pid_s[20];
	snprintf(pid_s, sizeof(pid_s), "%d", pid);
	char stat_filepath[30] = "/proc/";
	strncat(stat_filepath, pid_s,
			sizeof(stat_filepath) - strlen(stat_filepath) -1);
	strncat(stat_filepath, "/stat",
			sizeof(stat_filepath) - strlen(stat_filepath) -1);
	FILE *fpstat = fopen(stat_filepath, "r");
	if (!fpstat)
		return -1;
	//read values from /proc/pid/stat
	bzero(result, sizeof(pstat_t));
	if (fscanf(fpstat, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu"
			"%lu %ld %ld %*d %*d %*d %*d %*u %lu %ld",
			&result->utime_ticks, &result->stime_ticks,
			&result->cutime_ticks, &result->cstime_ticks,
			&result->vsize, &result->rss) == EOF)
		return -1;
	fclose(fpstat);
	result->rss *= getpagesize();
	return 0;
}

/*
* calculates the elapsed CPU usage between 2 measuring points in ticks
*/
void get_cpu(const pstat_t *cur_usage, const pstat_t *last_usage,
		int *ucpu_usage, int *scpu_usage)
{
	*ucpu_usage = (cur_usage->utime_ticks + cur_usage->cutime_ticks) -
			(last_usage->utime_ticks + last_usage->cutime_ticks);
	*scpu_usage = (cur_usage->stime_ticks + cur_usage->cstime_ticks) -
			(last_usage->stime_ticks + last_usage->cstime_ticks);
}

int chk_pid(pid_t pid)
{
	int ok = 1;
	struct stat st;
	char a[NAME_MAX];
	snprintf(a, sizeof(a), "/proc/%d", pid);
	if (stat(a, &st) == -1 && errno == ENOENT)
		ok = 0;
	return ok;
}

int ncpid(const pid_t ppid)
{
	int n = 0;
	static proc_t pinfo;
	memset(&pinfo, 0, sizeof(pinfo));
	PROCTAB *proc = openproc(PROC_FILLSTAT);
	if (!proc) return n;
	while (readproc(proc, &pinfo))
		n += pinfo.ppid == ppid;
	closeproc(proc);
	return n;
}

void get_cpid(const pid_t ppid, pid_t *pid)
{
	static proc_t pinfo;
	memset(&pinfo, 0, sizeof(pinfo));
	PROCTAB *proc = openproc(PROC_FILLSTAT);
	if (!proc) return;
	while (readproc(proc, &pinfo))
		if (pinfo.ppid == ppid)
			*pid = pinfo.tgid;
	closeproc(proc);
}

void pids_of_ppid(const pid_t ppid, kv_t *kv)
{
	static proc_t pinfo;
	int i, j = kv_size(*kv), k;
	memset(&pinfo, 0, sizeof(pinfo));
	PROCTAB *proc = openproc(PROC_FILLSTAT);
	if (!proc) return;
	while (readproc(proc, &pinfo))
		if (pinfo.ppid == ppid)
			kv_push(pid_t, *kv, pinfo.tgid);
	closeproc(proc);
	k = kv_size(*kv);
	for (i = j; i < k; ++i)
		pids_of_ppid(kv_A(*kv, i), kv);
}

int pgrep(const char *proc)
{
	int _pid = 0;
	const char* directory = "/proc";
	char task_name[PATH_MAX];
	DIR *dir = opendir(directory);
	if (dir)
	{
		struct dirent *de = 0;
		while ((de = readdir(dir)) != 0)
		{
			if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
				continue;
			int pid = -1;
			int res = sscanf(de->d_name, "%d", &pid);
			if (res == 1)
			{
				// we have a valid pid
				// open the cmdline file to determine what's the name of the process running
				char cmdline_file[PATH_MAX] = {0};
				sprintf(cmdline_file, "%s/%d/cmdline", directory, pid);
				FILE *fp = fopen(cmdline_file, "r");
				if (!fp)
					return _pid;
				if (fgets(task_name, PATH_MAX - 1, fp))
				{
					if (!strcmp(basename(task_name), basename(proc)))
					{
						_pid = pid;
						break;
					}
				}
				fclose(fp);
			}
		}
		closedir(dir);
	}
	return _pid;
}

int pid_to_name(const pid_t pid, char cmd[NAME_MAX])
{
	int i = 0;
	char *cmdline;
	asprintf(&cmdline, "/proc/%lu/cmdline", pid);
	FILE *fp = fopen(cmdline, "r");
	if (!fp)
	{
		cmd[0] = '\0';
		return -1;
	}
	do
	{
		cmd[i] = fgetc(fp);
		if(feof(fp) || cmd[i] == '\0' || i + 1 == NAME_MAX)
			break;
		++i;
	} while(1);
	cmd[i] = '\0';
	fclose(fp);
}

unsigned nprocs()
{
	unsigned np = 1;
#ifdef __linux__
	np = get_nprocs();
#else
	np = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	return np;
}

void calc_usg(void *_usg)
{
	usg_t *usg = (usg_t *)_usg;
	int pid = usg->pid;
	if (!chk_pid(pid))
		return;
	long unsigned shr = 0;
	int up = 0, idle = 0;
	pstat_t last, current;
	get_shr(pid, &shr);
	int rl = get_usg(pid, &last);
	sleep(1);
	int rc = get_usg(pid, &current);
	get_cpu(&current, &last, &up, &idle);
	usg->rss = last.rss / pow(1024.0, 3);
	usg->shr = shr / pow(1024.0, 3);
	usg->cpu = !(rl + rc) ? up + idle : 0;
}

void calc_usg_daemon(const pid_t ppid)
{
	int i, j;
	kv_t kv;
	kv_init(kv);
	char cmd[NAME_MAX], *cmds = 0;
	pid_to_name(ppid, cmd);
	asprintf(&cmds, "%s", basename(cmd));
	pids_of_ppid(ppid, &kv);
	int n = kv_size(kv);
	/*
	putchar('>');
	for (i = 0; i < n; ++i)
		printf("%d ", kv_A(kv, i));
	putchar('\n');
	*/
	usg_t *usg = calloc(n + 1, sizeof(usg_t));
	usg[0].pid = ppid;
	for (i = 0; i < n; ++i)
		usg[i + 1].pid = kv_A(kv, i);
	i = j = 0;
	threadpool thpool = thpool_init(n + 1);
	thpool_add_work(thpool, calc_usg, (void *)(uintptr_t)(usg));
	for (i = 0; i < n; ++i)
	{
		pid_t pid = kv_A(kv, i);
		if (!chk_pid(pid))
			continue;
		pid_to_name(pid, cmd);
		if (strcmp("sh",cmd) && strcmp("bash",cmd) &&
				!strstr(cmd, "systemd") && !strstr(cmds, cmd))
			asprintf(&cmds, "%s>%s", cmds, basename(cmd));
		thpool_add_work(thpool, calc_usg, (void *)(uintptr_t)(usg + i + 1));
	}
	thpool_wait(thpool);
	thpool_destroy(thpool);
	double rss = usg[0].rss, shr = usg[0].shr, cpu = usg[0].cpu;
	for (i = 0; i < n; ++i)
	{
		rss += usg[i + 1].rss;
		shr = fmax(shr, usg[i + 1].shr);
		cpu += usg[i + 1].cpu;
	}
	free(usg);
	kv_destroy(kv);
	char buf[32];
	time_t _now = time(0);
	strftime(buf, sizeof(buf), "%x %X", localtime(&_now));
	if (strlen(cmds))
		printf("%s\t%f\t%f\t%.3f\t%s\n", buf, fmax(0, rss), shr, cpu > nprocs() * 100 ? 100 : cpu, cmds);
	fflush(stdout);
	free(cmds);
}

int ndigit(const char *str)
{
	int i = 0, n = 0;
	while (str[i])
		n += (bool)isdigit(str[i++]);
	return n;
}

void usage()
{
	puts("\e[4mMonitor MEM & CPU of process by name, pid or cmds\e[0m");
	puts("Examples:");
	printf("  \e[1;31m%s\e[0;0m \e[35m<cmd>\e[0m\n", __progname);
	printf("  \e[1;31m%s\e[0;0m \e[35m<pid>\e[0m\n", __progname);
	printf("  \e[1;31m%s\e[0;0m \e[35m<cmd> <args> ...\e[0m\n", __progname);
}

int main(int argc, char *argv[])
{
	int i;
	pid_t pid = 0, self = getpid();
	char *pidir = 0, str[PATH_MAX];
	if (argc == 1)
	{
		usage();
		exit(1);
	}
	else if (argc == 2)
	{
		if (!strcmp(basename(argv[0]), basename(argv[1])))
			return 0;
		if (strlen(argv[1]) == ndigit(argv[1]))
			pid = atoi(argv[1]);
		else
			pid = pgrep(argv[1]);
		if (pid)
		{
			puts("#TIMESTAMP\tRSS\tSHR\tCPU\tCOMMAND");
			while (1)
			{
				if ((kill(pid, 0) == -1 && errno == ESRCH))
					break;
				calc_usg_daemon(pid);
				sleep(2);
			}
		}
	}
	else
	{
		char **args = malloc(sizeof(char *) * argc);
		for (i = 0; i < argc - 1; ++i)
			args[i] = argv[i + 1];
		args[argc - 1] = NULL;
		pid_t fpid = fork();
		if (fpid == 0)
		{
			if (execvp(argv[1], args) < 0)
			{
				perror("Error running command");
				exit(-1);
			}
			free(args);
		}
		else if (fpid > 1)
		{
			int status;
			pid = getpid();
			get_cpid(pid, &pid);
			if (pid)
			{
				puts("#TIMESTAMP\tRSS\tSHR\tCPU\tCOMMAND");
				while (1)
				{
					if ((kill(pid, 0) == -1 && errno == ESRCH))
						break;
					waitpid(pid, &status, WNOHANG|WUNTRACED);
					if (!WIFEXITED(status))
						break;
					else
					{
						calc_usg_daemon(pid);
						sleep(2);
					}
				}
			}
		}
		else
		{
			printf("Error: Fork process failed");
			exit(-1);
		}
	}
}
