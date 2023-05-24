#define _GNU_SOURCE
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
#ifdef __linux__
#include <sys/sysinfo.h>
#include <proc/readproc.h>
#endif
#include <cairo/cairo.h>
#include <cairo/cairo-svg.h>

#include "thpool.h"
#include "kvec.h"
#define ARR "\e[2m\xE2\x97\x82\e[0m"
#define INF "\e[1;34m\xE2\x84\xb9\e[0;0m"

#define VERSION "0.2.3"
extern char *__progname;
typedef kvec_t(pid_t) kv_t;
#define GB(x) ((size_t) (x) << 30)
#define basename(str) (strrchr(str, '/') ? strrchr(str, '/') + 1 : str)
#define PP fprintf(stderr, "%s\t%d\t<%s>\n", __FILE__, __LINE__, __func__);
#define PPT do \
{ \
    char buf[80]; \
    time_t now = time(0); \
    strftime(buf, sizeof(buf), "\e[34m%D %X\e[0m", localtime(&now)); \
    fprintf(stderr, "%s %s %s\t%d\t<%s>\n", INF, buf, __FILE__, __LINE__, __func__); \
} while (0);


#define CHUNK 0xFFFF
// plot dimensions
#define MARGIN 55
#define DIM_X 605
#define DIM_Y 165
#define WIDTH (DIM_X + MARGIN)
#define HEIGHT (DIM_Y + MARGIN)

typedef struct
{
    int utime_ticks;
    int cutime_ticks;
    int stime_ticks;
    int cstime_ticks;
    int vsize; // virtual memory size in bytes
} pstat_t;

typedef struct
{
	pid_t pid;
	bool use_shm;
	long shm;
	double rss, shr, cpu;
} usg_t;

typedef struct
{
	long unsigned rss, shr;
} mem_t;

typedef struct
{
	unsigned long ts;
	double rss, shr, cpu;
	char cmd[PATH_MAX];
} mn_t;

void ttoa(time_t t);
time_t atot(const char *a);
void stoa(const int sec, char **a);
bool use_shm(const pid_t pid);
bool ends_with(const char *str, const char *sfx);

int pgrep(const char *proc);
int chk_pid(pid_t pid);
int ncpid(const pid_t ppid);
void get_cpid(const pid_t ppid, pid_t *pid);
void pids_of_ppid(const pid_t ppid, kv_t *kv);
void pid_to_name(const pid_t pid, char cmd[PATH_MAX]);

unsigned nprocs();
void calc_usg(void *_usg);
void calc_usgd(const pid_t ppid, mn_t **mns, int *m, int *n, const double shm, FILE *fp);

long size_of(const char *fn);
char *get_now(void);
void get_mem(const pid_t pid, mem_t *mem);
void get_cpu(const pstat_t *cur_usage, const pstat_t *last_usage, int *ucpu_usage, int *scpu_usage);
int get_usg(const pid_t pid, pstat_t* result);
int ndigit(const char *str);

void ldlg(const char *fn, mn_t **mns, int *m, int *n);
void draw_rrect(cairo_t *cr);
void draw_box(cairo_t *cr, double x, double y, double width, double height);
void draw_arrow(cairo_t *cr, double start_x, double start_y, double end_x, double end_y);
void draw_xlab(cairo_t *cr, const char *xlab);
void draw_ylab(cairo_t *cr, const char *ylab);
void draw_y2lab(cairo_t *cr, const char *ylab);
void draw_yticks(cairo_t *cr, const double ymax);
void draw_y2ticks(cairo_t *cr, const double ymax);
void draw_cpu(cairo_t *cr, mn_t **mns, const int n);
void draw_rss(cairo_t *cr, mn_t **mns, const int n);
void draw_shr(cairo_t *cr, mn_t **mns, const int n);
void do_drawing(cairo_t *cr, mn_t **mns, const int n, const char *st);

void usage();

int main(int argc, char *argv[])
{
	char *st = get_now();
	int i, m = CHUNK, n = 0;
	mn_t **mns = calloc(m, sizeof(mn_t *));
	pid_t pid = 0, self = getpid();
	char *pidir = 0, str[PATH_MAX];
	setenv("FONTCONFIG_PATH", "/etc/fonts", 1);
	if (argc == 1)
	{
		usage();
		free(mns);
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
			char *log;
			asprintf(&log, "%d.log", pid);
			FILE *fp = fopen(log, "w");
			if (!fp)
			{
				perror("Error opening log file");
				exit(1);
			}
			long shm = size_of("/dev/shm");
			fputs("#TIMESTAMP\tRSS\tSHR\tCPU\tCOMMAND\n", fp);
			while (1)
			{
				if ((kill(pid, 0) == -1 && errno == ESRCH))
					break;
				calc_usgd(pid, mns, &m, &n, shm, fp);
				sleep(2);
			}
			fclose(fp);
			free(log);
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
				char *log;
				asprintf(&log, "%d.log", pid);
				FILE *fp = fopen(log, "w");
				if (!fp)
				{
					perror("Error opening log file");
					exit(1);
				}
				long shm = size_of("/dev/shm");
				fputs("#TIMESTAMP\tRSS\tSHR\tCPU\tCOMMAND\n", fp);
				while (1)
				{
					if ((kill(pid, 0) == -1 && errno == ESRCH))
						break;
					waitpid(pid, &status, WNOHANG|WUNTRACED);
					if (!WIFEXITED(status))
						break;
					else
					{
						calc_usgd(pid, mns, &m, &n, shm, fp);
						sleep(2);
					}
				}
				fclose(fp);
				free(log);
			}
		}
		else
		{
			printf("Error: Fork process failed");
			exit(-1);
		}
	}
	if (n)
	{
		if (n < m)
			mns = realloc(mns, n * sizeof(mn_t *));
		char *svg;
		asprintf(&svg, "%d.svg", pid);
		cairo_surface_t *sf = cairo_svg_surface_create(svg, WIDTH, HEIGHT);
		cairo_t *cr = cairo_create(sf);
		cairo_set_antialias(cr, CAIRO_ANTIALIAS_BEST);
		// draw lines
		do_drawing(cr, mns, n, st);
		// clean canvas
		cairo_surface_destroy(sf);
		cairo_destroy(cr);
		for (i = 0; i < n; ++i)
			free(mns[i]);
		free(svg);
	}
	free(mns);
	free(st);
	return 0;
}

char *get_now(void)
{
	char buf[80];
	time_t now = time(0);
	strftime(buf,sizeof(buf),"%D %X" ,localtime(&now));
	return strdup(buf);
}

/*
 * read /proc data into the passed variables
 * returns 0 on success, -1 on error
*/
void get_mem(const pid_t pid, mem_t *mem)
{
	char *statm;
	asprintf(&statm, "/proc/%d/statm", pid);
	FILE *fpstat = fopen(statm, "r");
	free(statm);
	if (!fpstat) return;
	if (fscanf(fpstat, "%*d %ld %ld %*[^\1]", &mem->rss, &mem->shr) == EOF)
	{
		fclose(fpstat);
		return;
	}
	mem->rss *= getpagesize();
	mem->shr *= getpagesize();
	mem->rss -= mem->shr;
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
			"%lu %ld %ld %*d %*d %*d %*d %*u %lu %*d",
			&result->utime_ticks, &result->stime_ticks,
			&result->cutime_ticks, &result->cstime_ticks,
			&result->vsize) == EOF)
		return -1;
	fclose(fpstat);
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

bool use_shm(const pid_t pid)
{
	bool shm = false;
	char cmdline[PATH_MAX] = {0};
	sprintf(cmdline, "/proc/%d/cmdline", pid);
	if (!access(cmdline, R_OK))
	{
		FILE *fp = fopen(cmdline, "r");
		int i;
		size_t sz = 0;
		char *line = NULL;
		if (fp && (i = getline(&line, &sz, fp)) >= 1)
		{
			line[--i] = '\0';
			for (--i; i >= 0; --i)
				if (line[i] == '\0')
					line[i] = ' ';
			shm = (bool)strstr(line, "/dev/shm");
			free(line);
			fclose(fp);
		}
	}
	return shm;
}

long size_of(const char *dirname)
{
	struct stat st;
	DIR *dir = opendir(dirname);
	if (dir == 0)
		return 0;
	struct dirent *dit;
	long size = 0;
	long total_size = 0;
	char path[PATH_MAX];
	while ((dit = readdir(dir)) != NULL)
	{
		if (!strcmp(dit->d_name, ".") || !strcmp(dit->d_name, ".."))
			continue;
		sprintf(path, "%s/%s", dirname, dit->d_name);
		if (lstat(path, &st) != 0)
			continue;
		size = st.st_size;
        if (S_ISDIR(st.st_mode))
		{
			long dir_size = size_of(path) + size;
			total_size += dir_size;
		}
		else
			total_size += size;
	}
	return total_size;
}

bool ends_with(const char *str, const char *sfx)
{
	bool ret = false;
	int str_len = strlen(str);
	int sfx_len = strlen(sfx);
	if ((str_len >= sfx_len) && (0 == strcasecmp(str + (str_len-sfx_len), sfx)))
		ret = true;
	return ret;
}

void pid_to_name(const pid_t pid, char cmd[PATH_MAX])
{
	char cmdline[PATH_MAX] = {0};
	sprintf(cmdline, "/proc/%d/cmdline", pid);
	if (!access(cmdline, R_OK))
	{
		FILE *fp = fopen(cmdline, "r");
		int i, j;
		size_t sz = 0;
		char *line = NULL;
		if (fp && (j = getline(&line, &sz, fp)) >= 1)
		{
			char *p = line;
			while (ends_with(p, "python") ||
					ends_with(p, "python2") ||
					ends_with(p, "python3") ||
					ends_with(p, "perl") ||
					ends_with(p, "java") ||
					ends_with(p, "Rscript") ||
					*p == '-')
				p += strlen(p) + 1;
			strcpy(cmd, basename(p));
			free(line);
			fclose(fp);
		}
		else
			cmd[0] = '\0';
	}
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
	pid_t pid = usg->pid;
	if (!chk_pid(pid))
		return;
	int up = 0, idle = 0;
	pstat_t last, current;
	mem_t mem = {0, 0};
	get_mem(pid, &mem);
	int rl = get_usg(pid, &last);
	sleep(1);
	int rc = get_usg(pid, &current);
	get_cpu(&current, &last, &up, &idle);
	usg->rss = mem.rss / pow(1024.0, 3);
	usg->shr = mem.shr / pow(1024.0, 3) + (usg->use_shm ? fmax(0, (size_of("/dev/shm") - usg->shm) / pow(1024.0, 3)) : 0);
	usg->cpu = !(rl + rc) ? up + idle : 0;
}

void calc_usgd(const pid_t ppid, mn_t **mns, int *m, int *n, const double shm, FILE *fp)
{
	int i, j;
	kv_t kv;
	kv_init(kv);
	char cmd[PATH_MAX], *cmds = NULL, *cmds_ascii = NULL;
	pid_to_name(ppid, cmd);
	asprintf(&cmds, "%s", cmd);
	asprintf(&cmds_ascii, "%s", cmd);
	pids_of_ppid(ppid, &kv);
	int kn = kv_size(kv);
	usg_t *usg = calloc(kn + 1, sizeof(usg_t));
	usg[0].pid = ppid;
	usg[0].shm = shm;
	usg[0].use_shm = use_shm(ppid);
	for (i = 0; i < kn; ++i)
	{
		pid_t pid = kv_A(kv, i);
		usg[i + 1].pid = pid;
		usg[i + 1].shm = shm;
		usg[i + 1].use_shm = use_shm(pid);
	}
	i = j = 0;
	threadpool thpool = thpool_init(kn + 1);
	thpool_add_work(thpool, calc_usg, (void *)(uintptr_t)(usg));
	for (i = 0; i < kn; ++i)
	{
		pid_t pid = kv_A(kv, i);
		if (!chk_pid(pid))
			continue;
		pid_to_name(pid, cmd);
		if (strcmp("sh", cmd) && strcmp("bash", cmd) && strcmp("xargs", cmd) &&
				!strstr(cmd, "systemd") && !strstr(cmds, cmd))
		{
			asprintf(&cmds, "%s%s%s", cmds, ARR, cmd);
			asprintf(&cmds_ascii, "%s;%s", cmds_ascii, cmd);
		}
		thpool_add_work(thpool, calc_usg, (void *)(uintptr_t)(usg + i + 1));
	}
	thpool_wait(thpool);
	thpool_destroy(thpool);
	double rss = usg[0].rss, shr = usg[0].shr, cpu = usg[0].cpu;
	for (i = 0; i < kn; ++i)
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
	{
		fprintf(fp, "%s\t%f\t%f\t%.3f\t%s\n", buf, fmax(0, rss), shr, cpu > nprocs() * 100 ? 100 : cpu, cmds);
		mn_t *mn = calloc(1, sizeof(mn_t));
		mn->ts = atot(buf);
		mn->rss = fmax(0, rss);
		mn->shr = shr;
		mn->cpu = cpu > nprocs() * 100 ? 100 : cpu;
		char *p = NULL, *q = strdup(cmds_ascii);
		if ((p = strchr(q, ';')))
		{
			if ((p = strchr(p + 1, ';')))
				*p = '\0';
			strcpy(mn->cmd, strchr(q, ';') + 1);
		}
		else
			strcpy(mn->cmd, q);
		free(q);
		mns[*n] = mn;
		if (*n + 1 == *m)
		{
			*m <<= 1;
			mns = realloc(mns, *m * sizeof(mn_t *));
		}
		(*n)++;
	}
	free(cmds);
	free(cmds_ascii);
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

// convert timestamp string to hms
void ttoa(time_t t)
{
	char a[9];
	struct tm *s = localtime(&t);
	strftime(a, sizeof(a), "%H:%M:%S", s);
	puts(a);
}

// convert timestamp string to time in seconds since 1900
time_t atot(const char *a)
{
	struct tm tm;
	strptime(a, "%m/%d/%y %H:%M:%S %Y", &tm);
	tm.tm_isdst = -1;
	time_t t = mktime(&tm);
	return t;
}

// convert seconds to time hms string
void stoa(const int sec, char **a)
{
	int h, m, s;
	h = (sec/3600); 
	m = (sec -(3600*h))/60;
	s = (sec -(3600*h)-(m*60));
	asprintf(a, "%02d:%02d:%02d", h, m, s);
}

// load mntr log
/*
#TIMESTAMP	RSS	SHR	CPU	COMMAND
03/25/22 22:05:32	0.000050	0.000000	0.000	mntr
03/25/22 22:05:35	0.607754	0.001118	3141.000	gptk[2m◂[0mtrimadap
...
03/25/22 22:25:36	0.117447	0.001102	775.000	gptk[2m◂[0mcross[2m◂[0mminimap2[2m◂[0msamtools
*/
void ldlg(const char *fn, mn_t **mns, int *m, int *n)
{
	size_t sz = 0;
	int i = 0;
	char *line = NULL, *data = NULL, timestamp[18];
	FILE *fp = fopen(fn, "r");
	if (!fp)
	{
		perror("Error reading input!\n");
		exit(EXIT_FAILURE);
	}
	if (getline(&line, &sz, fp) < 0) // skip header
	{
		perror("Error reading input!\n");
		exit(EXIT_FAILURE);
	}
	while (getline(&line, &sz, fp) >= 0)
	{
		mn_t *mn = calloc(1, sizeof(mn_t));
		*(line + strlen(line) - 1) = '\0';
		strncpy(timestamp, line, 17);
		timestamp[17] = '\0';
		sscanf(line + 18, "%lf %lf %lf %s", &mn->rss, &mn->shr, &mn->cpu, mn->cmd);
		mn->ts = atot(timestamp);
		mns[*n] = mn;
		if (*n + 1 == *m)
		{
			*m <<= 1;
			mns = realloc(mns, *m * sizeof(mn_t *));
		}
		(*n)++;
	}
	free(line);
	fclose(fp);
	if (*n && *n < *m)
		mns = realloc(mns, *n * sizeof(mn_t *));
}

void draw_box(cairo_t *cr, double x, double y, double width, double height)
{
	cairo_save(cr);
	double w1 = 1.0, w2 = 1.0;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2) / 2.0);
	cairo_set_source_rgb(cr, 0.6, 0.6, 0.6);
	cairo_rectangle(cr, x, y, width, height);
	cairo_stroke(cr);
	cairo_restore(cr);
}

void draw_rect(cairo_t *cr, double x, double y, double width, double height)
{
	cairo_save(cr);
	cairo_new_sub_path (cr);
	cairo_rectangle(cr, x, y, width, height);
	cairo_set_source_rgba (cr, .96, .96, .96, 0.86);
	cairo_fill(cr);
	cairo_restore(cr);
}

void draw_rrect(cairo_t *cr)
{
	// a custom shape that could be wrapped in a function
	double x         = 0,        // parameters like cairo_rectangle
	       y         = 0,
	       width         = WIDTH,
	       height        = HEIGHT,
	       aspect        = 1.0,     // aspect ratio
	       corner_radius = height / 60.0;   // and corner curvature radius
	double radius = corner_radius / aspect;
	double degrees = M_PI / 180.0;
	cairo_new_sub_path (cr);
	cairo_arc (cr, x + width - radius, y + radius, radius, -90 * degrees, 0 * degrees);
	cairo_arc (cr, x + width - radius, y + height - radius, radius, 0 * degrees, 90 * degrees);
	cairo_arc (cr, x + radius, y + height - radius, radius, 90 * degrees, 180 * degrees);
	cairo_arc (cr, x + radius, y + radius, radius, 180 * degrees, 270 * degrees);
	cairo_close_path (cr);
	cairo_set_source_rgba (cr, .96, .96, .96, .5);
	cairo_fill(cr);
}

void draw_arrow(
		cairo_t *cr,
		double start_x,
		double start_y,
		double end_x,
		double end_y)
{
	double angle = atan2(end_y - start_y, end_x - start_x) + M_PI;
	double arrow_degrees_ = M_PI / 15;
	double arrow_length_ = 10;
	double x1 = end_x + arrow_length_ * cos(angle - arrow_degrees_);
	double y1 = end_y + arrow_length_ * sin(angle - arrow_degrees_);
	double x2 = end_x + arrow_length_ * cos(angle + arrow_degrees_);
	double y2 = end_y + arrow_length_ * sin(angle + arrow_degrees_);
	double w1 = 1.0, w2 = 1.0;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2) / 2.0);
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, start_x, start_y);
	cairo_line_to(cr, (x1 + x2) / 2, (y1 + y2) / 2);
	cairo_stroke(cr);
	cairo_set_line_width(cr, fmin(w1, w2) / 2);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_MITER);
	cairo_move_to(cr, x1, y1);
	cairo_line_to(cr, x2, y2);
	cairo_line_to(cr, end_x, end_y);
	cairo_line_to(cr, x1, y1);
	cairo_close_path(cr);
	cairo_fill(cr);
}

void draw_xlab(cairo_t *cr, const char *xlab)
{
	double x, y;
	cairo_text_extents_t ext;
	cairo_set_font_size(cr, 10.0);
	cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
	cairo_text_extents(cr, xlab, &ext);
	x = DIM_X / 2.0 - (ext.width / 2.0 + ext.x_bearing);
	y = DIM_Y + MARGIN / 4.0 - (ext.height / 2 + ext.y_bearing);
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, xlab);
}

void draw_ylab(cairo_t *cr, const char *ylab)
{
	cairo_save(cr);
	cairo_text_extents_t ext;
	cairo_set_source_rgb(cr, 87 / 255.0, 122 / 255.0, 166 / 255.0);
	cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
	//cairo_translate(cr, MARGIN / 1.25, HEIGHT / 2.0); // translate origin to the center
	cairo_translate(cr, MARGIN / 2.0, HEIGHT / 2.0); // translate origin to the center
	cairo_rotate(cr, 3 * M_PI / 2.0);
	cairo_text_extents(cr, ylab, &ext);
	//cairo_move_to(cr, MARGIN / 5, -MARGIN);
	cairo_move_to(cr, MARGIN / 5.0, -MARGIN / 1.5);
	cairo_show_text(cr, ylab);
	cairo_restore(cr);
}

void draw_y2lab(cairo_t *cr, const char *ylab)
{
	cairo_save(cr);
	cairo_text_extents_t ext;
	cairo_set_source_rgb(cr, 166 / 255.0, 122 / 255.0, 87 / 255.0);
	cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
	cairo_translate(cr, MARGIN / 2, HEIGHT / 2.0); // translate origin to the center
	cairo_rotate(cr, M_PI / 2.0); // was 270
	cairo_text_extents(cr, ylab, &ext);
	//cairo_move_to(cr, MARGIN / 2.5 + WIDTH, -MARGIN * 1.25);
	cairo_move_to(cr, -MARGIN, MARGIN * 1.25 - WIDTH);
	cairo_show_text(cr, ylab);
	cairo_restore(cr);
}

void draw_cpu(cairo_t *cr, mn_t **mns, const int n)
{
	int i;
	double w1 = 1.0, w2 = 1.0, x = 0, y = 0, x1, y1;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2));
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
	cairo_set_source_rgb(cr, 87 / 255.0, 122 / 255.0, 166 / 255.0);
	cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
	// get max cpu usage
	double cpu_max = 100;
	for (i = 0; i < n; ++i)
		cpu_max = fmax(cpu_max, mns[i]->cpu);
	if (cpu_max)
	{
		// draw cpu history
		unsigned long offset = mns[0]->ts;
		for (i = 0; i < n; ++i)
		{
			x1 = (double)(mns[i]->ts - offset) / (mns[n - 1]->ts - offset);
			y1 = (double)mns[i]->cpu / cpu_max;
			cairo_move_to(cr, x, 1 - y);
			cairo_line_to(cr, x1, 1 - y1);
			x = x1;
			y = y1;
		}
		cairo_save(cr);
		cairo_scale(cr, 1.0, (double)DIM_X / DIM_Y);
		cairo_stroke(cr);
		cairo_restore(cr);
	}
}

void draw_rss(cairo_t *cr, mn_t **mns, const int n)
{
	int i;
	double w1 = 1.0, w2 = 1.0, x = 0, y = 0, x1, y1;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2));
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
	cairo_set_source_rgb(cr, 166 / 255.0, 122 / 255.0, 87 / 255.0);
	cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
	// get max cpu usage
	double mem_max = 0;
	for (i = 0; i < n; ++i)
		mem_max = fmax(mem_max, fmax(mns[i]->rss, mns[i]->shr));
	// draw cpu history
	unsigned long offset = mns[0]->ts;
	for (i = 0; i < n; ++i)
	{
		x1 = (double)(mns[i]->ts - offset) / (mns[n - 1]->ts - offset);
		y1 = (double)mns[i]->rss / mem_max;
		cairo_move_to(cr, x, 1 - y);
		cairo_line_to(cr, x1, 1 - y1);
		x = x1;
		y = y1;
	}
	cairo_save(cr);
	cairo_scale(cr, 1.0, (double)DIM_X / DIM_Y);
	cairo_stroke(cr);
	cairo_restore(cr);
}

void draw_shr(cairo_t *cr, mn_t **mns, const int n)
{
	int i;
	double w1 = 1.0, w2 = 1.0, x = 0, y = 0, x1, y1;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2));
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
	cairo_set_source_rgb(cr, 218 / 255.0, 165 / 255.0, 32 / 255.0);
	cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
	// get max cpu usage
	double mem_max = 0;
	for (i = 0; i < n; ++i)
		mem_max = fmax(mem_max, fmax(mns[i]->rss, mns[i]->shr));
	// draw cpu history
	unsigned long offset = mns[0]->ts;
	for (i = 0; i < n; ++i)
	{
		x1 = (double)(mns[i]->ts - offset) / (mns[n - 1]->ts - offset);
		y1 = (double)mns[i]->shr / mem_max;
		cairo_move_to(cr, x, 1 - y);
		cairo_line_to(cr, x1, 1 - y1);
		x = x1;
		y = y1;
	}
	cairo_save(cr);
	cairo_scale(cr, 1.0, (double)DIM_X / DIM_Y);
	cairo_stroke(cr);
	cairo_restore(cr);
}

void draw_steps(cairo_t *cr, mn_t **mns, const int n)
{
	int i;
	double w1 = 1.0, w2 = 1.0, x0 = 0, x, y;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2) / 1.25);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
	cairo_set_source_rgb(cr, 87 / 255.0, 122 / 255.0, 166 / 255.0);
	cairo_set_antialias(cr, CAIRO_ANTIALIAS_NONE);
	// draw 1st mark mntr ignored
	char *cmd1 = mns[0]->cmd;
	unsigned long offset = mns[0]->ts;
	cairo_text_extents_t ext;
	int block = 1;
	cairo_set_source_rgb(cr, 166 / 255.0, 122 / 255.0, 87 / 255.0);
	for (i = 1; i < n; ++i)
	{
		if (strcmp(mns[i]->cmd, mns[i - 1]->cmd)) // new command encountered
		{
			// process the previous command
			cairo_text_extents(cr, mns[i - 1]->cmd, &ext);
			x = DIM_X * (double)(mns[i - 1]->ts - offset) / (mns[n - 1]->ts - offset);
			//y = - (ext.height / 2 + ext.y_bearing); // topright
			y = - ext.height - ext.y_bearing; // topright
			block += (x - x0 > 0.1);
			if (block && block % 2)
				draw_rect(cr, x0, 0, x - x0, DIM_Y);
			if (x - x0 > 0.05)
			{
				cairo_move_to(cr, (x + x0) / 2.0, y);
				cairo_save(cr);
				cairo_translate(cr, MARGIN / 2.0, HEIGHT / 2.0); // translate origin to the center
				cairo_rotate(cr, -M_PI / 6.0);
				cairo_set_font_size(cr, 8.0);
				cairo_select_font_face(cr, "Mono", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
				cairo_show_text(cr, mns[i - 1]->cmd);
				cairo_restore(cr);
			}
			x0 = DIM_X * (double)(mns[i]->ts - offset) / (mns[n - 1]->ts - offset);
		}
	}
	// the last one
	block += (x - x0 > 0.1);
	if (block && block % 2)
		draw_rect(cr, x0, 0, x - x0, DIM_Y);
	cairo_text_extents(cr, mns[n - 1]->cmd, &ext);
	x = DIM_X * (double)(mns[n - 1]->ts - offset) / (mns[n - 1]->ts - offset);
	y = - ext.height - ext.y_bearing; // topright
	if (x - x0 > 0.01)
	{
		cairo_move_to(cr, (x + x0) / 2.0, y);
		cairo_save(cr);
		cairo_translate(cr, MARGIN / 2.0, HEIGHT / 2.0); // translate origin to the center
		cairo_rotate(cr, -M_PI / 6.0);
		cairo_set_font_size(cr, 8.0);
		cairo_select_font_face(cr, "Mono", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
		cairo_show_text(cr, mns[n - 1]->cmd);
		cairo_restore(cr);
	}
}

void draw_yticks(cairo_t *cr, const double ymax)
{
	int i, j;
	double x, y;
	double w1 = 1.0, w2 = 1.0;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2));
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);
	cairo_text_extents_t ext;
	char buf[sizeof(uint64_t) * 8 + 1];
	double h = ceil(log10(ymax));
	cairo_text_extents(cr, "m", &ext);
	double x_offset = ext.width;
	for (i = 0; i <= h; ++i)
	{
		sprintf(buf, "%d", (int)pow(10, h - i));
		cairo_select_font_face(cr, "Open Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
		cairo_text_extents(cr, buf, &ext);
		x = -ext.width - x_offset / 2.5;
		y = 1 - (double)i / (h + 1);
		cairo_move_to(cr, x, DIM_Y - y * DIM_Y + ext.height / 2);
		cairo_show_text(cr, buf);
		// major ticks
		cairo_move_to(cr, 0, DIM_Y - y * DIM_Y);
		cairo_line_to(cr, x_offset * .75, DIM_Y - y * DIM_Y);
		// minor ticks
		for (j = 2; j <= 9 && i < h; ++j)
		{
			y = (log10((11 - j) * pow(10, i)) + 1)  / (h + 1);
			cairo_move_to(cr, 0, DIM_Y - y * DIM_Y);
			cairo_line_to(cr, x_offset * .375, DIM_Y - y * DIM_Y);
		}
	}
	cairo_stroke(cr);
}

void draw_y2ticks(cairo_t *cr, const double ymax)
{
	int i, j;
	double x, y;
	double w1 = 1.0, w2 = 1.0;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2));
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);
	cairo_text_extents_t ext;
	char buf[sizeof(uint64_t) * 8 + 1];
	double h = ceil(log10(ymax));
	cairo_text_extents(cr, "m", &ext);
	double x_offset = ext.width;
	for (i = 0; i <= h; ++i)
	{
		sprintf(buf, "%d", (int)pow(10, h - i));
		cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
		cairo_text_extents(cr, buf, &ext);
		x = -ext.width - x_offset / 2.5;
		y = 1 - (double)i / (h + 1);
		cairo_move_to(cr, x, DIM_Y - y * DIM_Y + ext.height / 2);
		cairo_show_text(cr, buf);
		// major ticks
		cairo_move_to(cr, 0, DIM_Y - y * DIM_Y);
		cairo_line_to(cr, x_offset * .75, DIM_Y - y * DIM_Y);
		// minor ticks
		for (j = 2; j <= 9 && i < h; ++j)
		{
			y = (log10((11 - j) * pow(10, i)) + 1)  / (h + 1);
			cairo_move_to(cr, 0, DIM_Y - y * DIM_Y);
			cairo_line_to(cr, x_offset * .375, DIM_Y - y * DIM_Y);
		}
	}
	cairo_stroke(cr);
}

void do_drawing(cairo_t *cr, mn_t **mns, const int n, const char *st)
{
	cairo_set_source_rgb (cr, 0, 0, 0);
	cairo_translate(cr, MARGIN / 2, MARGIN / 2.0);
	// axis labels
	double x, y;
	cairo_text_extents_t ext;
	//cairo_set_source_rgb(cr, 0.25, 0.25, 0.25);
	char xlab[] = "Timeline";
	char ylab[] = "CPU (%)";
	// title
	/*
	cairo_set_font_size(cr, 10.0);
	cairo_select_font_face(cr, "serif", CAIRO_FONT_SLANT_ITALIC, CAIRO_FONT_WEIGHT_NORMAL);
	cairo_text_extents(cr, "Title text italic", &ext);
	x = DIM_X / 2.0 - (ext.width / 2.0 + ext.x_bearing);
	y = ext.height / 2 + ext.y_bearing;
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, "Title text italic");
	*/
	// zlab
	/*
	char zlab[NAME_MAX];
	sprintf(zlab, "%s", op->ann);
	//cairo_set_font_size(cr, 10.0);
	cairo_select_font_face(cr, "Open Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	cairo_text_extents(cr, zlab, &ext);
	x = DIM_X - (ext.width + ext.x_bearing);
	y = ext.height / 2 + ext.y_bearing;
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, zlab);
	*/
	// xlab
	draw_xlab(cr, xlab);
	// ylab
	draw_ylab(cr, ylab);
	// get max cpu and mem
	int i;
	double cpu_max = 100, mem_max = 0;
	for (i = 0; i < n; ++i)
	{
		cpu_max = fmax(cpu_max, mns[i]->cpu);
		mem_max = fmax(mem_max, fmax(mns[i]->rss, mns[i]->shr));
	}
	char y2lab[NAME_MAX] = {'\0'};
	snprintf(y2lab, NAME_MAX, "Mem (%c)", mem_max <= 1 ? 'M' : 'G');
	draw_y2lab(cr, y2lab);
	draw_steps(cr, mns, n);
	draw_box(cr, 0, 0, DIM_X, DIM_Y);
	// draw cpu
	cairo_save(cr);
	cairo_scale(cr, DIM_X, DIM_Y);
	draw_cpu(cr, mns, n);
	draw_rss(cr, mns, n);
	draw_shr(cr, mns, n);
	cairo_restore(cr);
	// axis
	//draw_arrow(cr, 0, DIM_Y*1.005, DIM_X, DIM_Y*1.005); // xaxis
	double w1 = 1.0, w2 = 1.0;
	cairo_device_to_user_distance(cr, &w1, &w2);
	cairo_set_line_width(cr, fmin(w1, w2) / 1.25);
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_SQUARE);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, 0, 0);
	cairo_line_to(cr, 0, DIM_Y); // yaxis
	// yticks
	//draw_yticks(cr, cpu_max);
	// y2ticks
	//draw_y2ticks(cr, mem_max);
	char *a;
	stoa(mns[n - 1]->ts - mns[0]->ts, &a);
	asprintf(&a, "Runtime: %s", a);
	cairo_set_font_size(cr, 8.0);
	cairo_select_font_face(cr, "Sans", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
	cairo_text_extents(cr, a, &ext);
	x = DIM_X - ext.width - ext.x_bearing;
	y = DIM_Y + ext.height * 3 + ext.y_bearing; // bottom right
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	// start time
	asprintf(&a, "Start: %s", st);
	cairo_text_extents(cr, a, &ext);
	x = ext.x_bearing;
	y = DIM_Y + ext.height * 3 + ext.y_bearing; // bottom left
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	// legend
	// max cpu usage
	asprintf(&a, "%.*f", cpu_max < 1 ? 2 : 0, cpu_max);
	cairo_text_extents(cr, a, &ext);
	cairo_set_font_size(cr, 8.0);
	cairo_set_source_rgb(cr, 87 / 255.0, 122 / 255.0, 166 / 255.0);
	x = -ext.x_bearing * 4 - ext.width;
	y = ext.height;
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	// max memory
	if (mem_max < 1)
	{
		double mem_max_m = mem_max * 1000;
		if (mem_max_m < 1)
			asprintf(&a, "<1M");
		else
			asprintf(&a, "%.0fM", mem_max_m);
	}
	else
		asprintf(&a, "%.0fG", mem_max);
	cairo_text_extents(cr, a, &ext);
	cairo_set_source_rgb(cr, 166 / 255.0, 122 / 255.0, 87 / 255.0);
	//x = DIM_X - ext.width + ext.x_bearing;
	x = DIM_X + ext.x_bearing;
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	// draw legend
	asprintf(&a, "—CPU");
	cairo_text_extents(cr, a, &ext);
	x = DIM_X - ext.width * 1.25;
	y = ext.height - ext.y_bearing * 1.5;
	cairo_set_source_rgb(cr, 87 / 255.0, 122 / 255.0, 166 / 255.0);
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	
	asprintf(&a, "—RSS");
	x = DIM_X - ext.width * 1.25;
	y = ext.height - ext.y_bearing * 3.0;
	cairo_set_source_rgb(cr, 166 / 255.0, 122 / 255.0, 87 / 255.0);
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);

	asprintf(&a, "—SHR");
	x = DIM_X - ext.width * 1.25;
	y = ext.height - ext.y_bearing * 4.5;
	cairo_set_source_rgb(cr, 218 / 255.0, 165 / 255.0, 32 / 255.0);
	cairo_move_to(cr, x, y);
	cairo_show_text(cr, a);
	free(a);
}
