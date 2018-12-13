/* 
 * KASH - A tiny shell based on the CMU Shell Lab's tsh
 * 
 * <Kat Cannon-MacMartin -- guthrie@marlboro.edu>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */

/* Status codes for sigmsg */
#define SUS 1   /* SIGCHLD: WIFSTOPPED */
#define KILL 2  /* SIGCHLD: WIFSIGNALLED */
#define RES 3   /* Sent SIGCONT (from do_bgfg) */
#define FIN 4   /* SIGCHLD: WIFEXITED */

#define MAXMESSAGE 12 /* Max message length for sigmsg death type */

/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "~ ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 1;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */

/* My new global variables */
struct sigmsg{              /* object for holding signal-related messaged */
  int method;               /* type of signal (number 1-4 corresponding to macro set at beginning) */
  int jid;                  /* job id of the job that sent/recieved the signal */
  int signum;               /* specifices id of the signal that terminated a job (only in case of termination) */
  char message[MAXMESSAGE]; /* text expression of method variable */
  char cmdline[MAXLINE];    /* command that initialized the job */
};
struct sigmsg inbox[MAXJOBS]; /* the shell's inbox, holds sigmsgs to be read before each new loop */

int ctrcflag = 0;           /* flags to signal (with some execptions) when the user presses ^C or ^Z */
int ctrzflag = 0;           /* these flags are read and reset each time mail is read. */

/* End my new globals */

struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */

/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);

/* Not implemented because of tcsetpgrp use in waitfg */
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* these functions were added by me to create a 'mail' system which avoids printing from a signal handler */
void deletemsg(struct sigmsg *msg);
void openinbox(struct sigmsg *inbox);
int addmsg(struct sigmsg *inbox, int method, int jid, int signum, char *cmdline);
int readmail(struct sigmsg *inbox);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv); 
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);

void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);

/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':             /* print help message */
            usage();
	    break;
        case 'v':             /* emit additional diagnostic info */
            verbose = 1;
	    break;
        case 'p':             /* don't print a prompt */
            emit_prompt = 0;  /* handy for automatic testing */
	    break;
	default:
            usage();
	}
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler); 

    /* Initialize the job list */
    initjobs(jobs);
    /* open up the inbox (similar to initjobs) */
    openinbox(inbox);

    /* Execute the shell's read/eval loop */
    while (1) {

      /* Check inbox for sigmsgs. If they are present, prints them before prompt */
      readmail(inbox);
      
	/* Read command line */
	if (emit_prompt) {
	    printf("%s", prompt);
	    fflush(stdout);
	}
	if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
	    app_error("fgets error");
	if (feof(stdin)) { /* End of file (ctrl-d) */
	    fflush(stdout);
	    exit(0);
	}

	/* Evaluate the command line */
	eval(cmdline);
	fflush(stdout);
	fflush(stdout);
    } 

    exit(0); /* control never reaches here */
}
  
/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline){

  char *argv[MAXARGS];
  int state = UNDEF;
  pid_t pid;
  sigset_t mask;
  
  if(parseline(cmdline, argv)){    /* Leverages return value of parseline to save the state of the job */
    state = BG;
  }
  else{
    state = FG;
  }

  if (!argv[0]){                   /* I'm not sure what caused this issue, but part of the way */
    return;                        /* through my testing, my shell began segfaulting every time */
  }                                /* I entered a blank line. This fixed it. */
  
  if (verbose){
    printf("State: %i\n", state);
  }
    
  if (!builtin_cmd(argv)){

    sigemptyset(&mask);            /* Setting the all-important SIGCHLD mask before forking */
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    
    if ((pid = fork()) < 0){
      unix_error("Fork error!");
    }
    else if (pid == 0){
      sigprocmask(SIG_UNBLOCK, &mask, NULL);  /* Mask must still be lifted inside fork */
      setpgid(0, 0);                          /* Ensure that fork has unique gpid */
      if (execvp(argv[0], argv) == -1){
	unix_error("Error");
	return;
      }
      else{
	exit(0);
      }
    }
    else{
      addjob(jobs, pid, state, cmdline);
      if (state == BG){
	printf("[%d] %d\n", pid2jid(pid), pid);
      }
      sigprocmask(SIG_UNBLOCK, &mask, NULL);  /* Ensure that job list is safe from sigchld until */
      sigemptyset(&mask);                     /* after the addjob function */

      if (state == FG){
	waitfg(pid);                          /* Waiting allows process to use the terminal */
      }
    }
  }

  return;
  
}
    
/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv) 
{
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
	buf++;

    /* Build the argv list */
    argc = 0;
    if (*buf == '\'') {
	buf++;
	delim = strchr(buf, '\'');
    }
    else {
	delim = strchr(buf, ' ');
    }

    while (delim) {
	argv[argc++] = buf;
	*delim = '\0';
	buf = delim + 1;
	while (*buf && (*buf == ' ')) /* ignore spaces */
	       buf++;

	if (*buf == '\'') {
	    buf++;
	    delim = strchr(buf, '\'');
	}
	else {
	    delim = strchr(buf, ' ');
	}
    }
    argv[argc] = NULL;
    
    if (argc == 0)  /* ignore blank line */
	return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc-1] == '&')) != 0) {
	argv[--argc] = NULL;
    }
    return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_cmd(char **argv){

  char *quitstr = "quit";     /* I'm sure there's a better way to do this but... it works */
  char *exitstr = "exit";
  char *jobsstr = "jobs";
  char *bgstr = "bg";
  char *fgstr = "fg";
  
  if (!strcmp(argv[0], quitstr) || !strcmp(argv[0], exitstr)){    /* Quit the shell */
    exit(0);
  }
  else if (!strcmp(argv[0], jobsstr)){                            /* Lists jobs */
    listjobs(jobs);
    return 1;
  }

  else if (!strcmp(argv[0], bgstr) || !strcmp(argv[0], fgstr)){   /* bg or fg a job */
    do_bgfg(argv);
    return 1;
  }
  
  return 0; /* Not a builtin */
}

/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv){
  
  struct job_t *selected;
  char *arg;
  int jid;
  int pid;
  int topjob;

  arg = argv[1];

  /* This section finds the pid of whatever job the function will be acting on, regardless of 
     wether it is executing bg or fg */

  if (arg == NULL){                          /* Unlike the example shell, my shell implements fg in */
    if ((topjob = maxjid(jobs)) != 0){       /* the same way normal UNIX shells do. When called w/o */
                                             /* an argument, it will foreground the most recently */
      selected = getjobjid(jobs, topjob);    /* initialized job. */

      pid = selected->pid;
    }
    else{
      printf("No background or stopped jobs available\n");
      return;
    }
  }
  
  else if (arg[0] == '%'){                   
    
    selected = getjobjid(jobs, (jid = atoi(&arg[1])));
    
    if (selected == NULL){
      printf("Error: No such job [%d]\n", jid);
      return;
    }

    pid = selected->pid;

  }

  else if (isdigit(arg[0])){
    pid = atoi(arg);
    selected = getjobpid(jobs, pid);
    if (selected == NULL){
      printf("Error: PID %d is not valid or does not belong to this tsh instance\n", pid);
      return;
    }
  }

  else{
    printf("%s: Argument must be valid pid or jid\n", argv[0]);
    return;
  }

  kill(-pid, SIGCONT); /* Send continue signal to pgrp (does nothing if target is a running bg job) */

  if (!strcmp("fg", argv[0])){
      selected->state = FG;
      waitfg(pid);
  }

  else if (!strcmp("bg", argv[0])){
    selected->state = BG;
    addmsg(inbox, RES, pid2jid(pid), 0, getjobpid(jobs, pid)->cmdline); /* add resume message to inbox */
  }
    
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid){
  sigset_t mask;
  
  if (fgpid(jobs) == 0){
    return;
  }

  tcsetpgrp(STDIN_FILENO, pid);                  /* Gives control of terminal to fg process */
  sigaddset(&mask, SIGTTOU);                     /* Shell will not be able seize control of terminal */
  sigprocmask(SIG_BLOCK, &mask, NULL);           /* unless SIGTTOU is blocked. */

  while (pid == fgpid(jobs)){                    /* Wait until job is deleted by the signal handler */
  }

  tcsetpgrp(STDIN_FILENO, getpgid(getpid()));    /* Seize control of the terminal again */
  sigprocmask(SIG_UNBLOCK, &mask, NULL);         /* Unblock SIGTTOU */
  
  return;
}

/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig) 
{
  int status;
  int errno_save = errno;     /* save original errno for later */
  pid_t rm_pid;

  while ((rm_pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0){            /* The while loop and WNOHANG ensure that the handler reaps */
                                                                             /* as many children as possible, while not waiting for any unfinished */
    if (WIFSTOPPED(status)){         /* if process was suspended */          /* processes. The WUNTRACED argument allows for determination of the status. */
      if (getjobpid(jobs, rm_pid)->state == FG){                             
	ctrzflag = 1;
      }
      getjobpid(jobs, rm_pid)->state = ST;
      addmsg(inbox, SUS, pid2jid(rm_pid), 0, getjobpid(jobs, rm_pid)->cmdline);
    }
    
    else if (WIFEXITED(status)){    /* if process exited by itself */
      if (!(getjobpid(jobs, rm_pid)->state == FG)){
	addmsg(inbox, FIN, pid2jid(rm_pid), 0, getjobpid(jobs, rm_pid)->cmdline);
      }
      deletejob(jobs, rm_pid);
    }
    
    else if (WIFSIGNALED(status)){  /* if process was terminated by external signal */
      if (!(getjobpid(jobs, rm_pid)->state == FG)){
	addmsg(inbox, KILL, pid2jid(rm_pid), WTERMSIG(status), getjobpid(jobs, rm_pid)->cmdline);
      }
      else{
	ctrcflag = 1;
      }	  
      deletejob(jobs, rm_pid);
    }
  }

  errno = errno_save;
  return;
}

/***********  These two handlers were uneeded because of the use of tcsetpgrp in the waitfg function ***********/

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig){
  return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig){
  return;
}

/*********************
 * End signal handlers
 *********************/

/******************
 * Messaging system
 ******************/

/* deletemsg - clear msg in inbox */

void deletemsg(struct sigmsg *msg){
  msg->method = 0;
  msg->jid = 0;
  msg->signum = 0;
  msg->message[0] = '\0';
  msg->cmdline[0] = '\0';
}

/* openinbox - Initialize the sigmsg list */
void openinbox(struct sigmsg *inbox){
  int cnt;

  for (cnt = 0; cnt < MAXJOBS; cnt++){  /* Ensure all messages are blank at init */
    deletemsg(&inbox[cnt]);
  }
}

/* printsigmsg - Print a sigmsg to STDOUT */
void printmsg(struct sigmsg *msg){
  if (msg->method == KILL){
    printf("[%d]   Terminated by signal %d   %s", msg->jid, msg->signum, msg->cmdline);
  }
  else{
    printf("[%d]   %s                        %s", msg->jid, msg->message, msg->cmdline);
  }
}

/* addmsg - Add a sigmsg to the inbox */
int addmsg(struct sigmsg *inbox, int method, int jid, int signum, char *cmdline){
  int cnt;
  char *sus = "Suspended\0";                    /* Notice that I'm once again using this questionable */
  char *termed = "Terminated\0";                /* system for string variable organization. I really need */
  char *res = "Resumed\0";                      /* to figure out a better option... */
  char *fin = "Done\0";
  
  for (cnt = 0; cnt < MAXJOBS; cnt++){
    if (inbox[cnt].jid == 0){
      inbox[cnt].method = method;
      inbox[cnt].jid = jid;
      inbox[cnt].signum = signum;               /* Function uses a switch based on the method attribute to assign */
      switch (method){                          /* the correct message string. */
        case SUS:
	  strcpy(inbox[cnt].message, sus);
	  break;
        case KILL:
	  strcpy(inbox[cnt].message, termed);
	  break;
        case RES:
 	  strcpy(inbox[cnt].message, res);
	  break;
        case FIN:
	  strcpy(inbox[cnt].message, fin);
	  break;
      }
	
      strcpy(inbox[cnt].cmdline, cmdline);
      return 1;
    }
  }
  return 0;
}

/* readmail - Called at the beggining of each read/eval loop in the shell's main routine. 
 * Checks for any messages in inbox and prints those that are available, deleting each 
 * message as it is printed. Also checks for and responds to ctr flags before resetting them.
 */
int readmail(struct sigmsg *inbox){
  sigset_t mask;
  int cnt = 0;

  sigemptyset(&mask);                    /* Because the sigchld handler modifies the inbox, SIGCHLD */
  sigaddset(&mask, SIGCHLD);             /* must be blocked while messages are being printed. */
  sigprocmask(SIG_BLOCK, &mask, NULL);

  if (ctrzflag | ctrcflag){              /* Were ^C or ^Z pressed? Print newline so it doesn't look weird!!! */
    printf("\n");
  }

  ctrcflag = 0;
  ctrzflag = 0;
  
  while (inbox[cnt].jid != 0){           /* Loop to print and delete all available messages. */
    printmsg(&inbox[cnt]);
    deletemsg(&inbox[cnt]);
    cnt++;
  }

  sigprocmask(SIG_UNBLOCK, &mask, NULL); /* Unblock SIGCHLD */
  sigemptyset(&mask);
  return 0;
}

/**********************
 * End messaging system
 **********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].jid > max)
	    max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
    int i;
    
    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].pid == 0) {
	    jobs[i].pid = pid;
	    jobs[i].state = state;
	    jobs[i].jid = nextjid++;
	    if (nextjid > MAXJOBS)
		nextjid = 1;
	    strcpy(jobs[i].cmdline, cmdline);
  	    if(verbose){
	        printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
	}
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
    int i;

    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].pid == pid) {
	    clearjob(&jobs[i]);
	    nextjid = maxjid(jobs)+1;
	    return 1;
	}
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].state == FG)
	    return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
	return NULL;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].pid == pid)
	    return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
    int i;

    if (jid < 1)
	return NULL;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].jid == jid)
	    return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
    int i;

    if (pid < 1)
	return 0;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
    int i;
    
    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].pid != 0) {
	    printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
	    switch (jobs[i].state) {
		case BG: 
		    printf("Running ");
		    break;
		case FG: 
		    printf("Foreground ");
		    break;
		case ST: 
		    printf("Stopped ");
		    break;
	    default:
		    printf("listjobs: Internal error: job[%d].state=%d ", 
			   i, jobs[i].state);
	    }
	    printf("%s", jobs[i].cmdline);
	}
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) 
{
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
	unix_error("Signal error:");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) 
{
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}



