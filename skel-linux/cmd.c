/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * TODO Name, Group
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int status;

	if (dir != NULL) {
		
		if (dir->next_word != NULL) {
			return RETURN_CODE_TOO_MANY_ARGUMENTS;
		}

		status = chdir(dir->string);

	}

	return status;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO execute exit/quit */
	return SHELL_EXIT; /* TODO replace with actual exit code */
}

static int command_redirect(simple_command_t *s)
{
	char *fileNameOut = NULL, *fileNameIn = NULL, *fileNameErr = NULL;
	int flag = s->io_flags;
	int fd_redirect_out, fd_redirect_in, fd_redirect_err;
	int redirect = 0;
	int out_err_redirect = 0;
	int is_cd_command = 0;

	int old_fd_out = dup(STDOUT_FILENO);
	int old_fd_in = dup(STDIN_FILENO);
	int old_fd_err = dup(STDERR_FILENO);

	if (strcmp(s->verb->string, CD_COMMAND) == 0)
		is_cd_command = 1;

	if (s->out != NULL) {		
		fileNameOut = get_word(s->out);
		redirect = 1;
	}

	if (s->in != NULL) {
		fileNameIn = get_word(s->in);
		redirect = 1;
	}

	if (s->err != NULL) {
		fileNameErr = get_word(s->err);
		redirect = 1;
	}

	if (
		fileNameOut != NULL
		&& fileNameErr != NULL
		&& strcmp(fileNameOut, fileNameErr) == 0
	)
		out_err_redirect = 1;	/** In case of &> redirect */

	if (redirect != 0) {
			
		if (fileNameIn != NULL) {
			fd_redirect_in = open(fileNameIn, O_RDONLY, 0644);
			if (fd_redirect_in < 0)
				return RETURN_CODE_OPEN_FILE_ERROR;

			int ret;
			
			if (!is_cd_command)
				ret = dup2(fd_redirect_in, STDIN_FILENO);
			else
				ret = dup2(fd_redirect_in, old_fd_in);

			if (ret < 0)
				return RETURN_CODE_DUP2_ERROR;
			
			close(fd_redirect_in);
		}

		if (fileNameOut != NULL) {
 			if (flag == IO_REGULAR)
			 	if(!out_err_redirect)
					fd_redirect_out = open(fileNameOut, O_CREAT | O_RDWR | O_TRUNC, 0644);
				else
					fd_redirect_out = open(fileNameOut, O_CREAT | O_RDWR | O_APPEND);
			else if (flag == IO_OUT_APPEND)
				fd_redirect_out = open(fileNameOut, O_CREAT | O_WRONLY | O_APPEND);
			if (fd_redirect_out < 0)
				return RETURN_CODE_OPEN_FILE_ERROR;
			
			int ret;
			
			if (!is_cd_command)
				ret  = dup2(fd_redirect_out, STDOUT_FILENO);
			else
				ret = dup2(fd_redirect_out, old_fd_out);

			if (ret < 0)
				return RETURN_CODE_DUP2_ERROR;
			
			close(fd_redirect_out);
		}
		
		if (fileNameErr != NULL) {
 			if (flag == IO_REGULAR)
			 	if(!out_err_redirect)
					fd_redirect_err = open(fileNameErr, O_CREAT | O_RDWR | O_TRUNC, 0644);
				else
					fd_redirect_err = open(fileNameErr, O_CREAT | O_RDWR | O_TRUNC);
			else if (flag == IO_ERR_APPEND)
				fd_redirect_err = open(fileNameErr, O_CREAT | O_WRONLY | O_APPEND);
			if (fd_redirect_err < 0)
				return RETURN_CODE_OPEN_FILE_ERROR;

			int ret;

			if (!is_cd_command) 
				ret = dup2(fd_redirect_err, STDERR_FILENO);
			else
				ret = dup2(fd_redirect_err, old_fd_err);

			if (ret < 0)
				return RETURN_CODE_DUP2_ERROR;
			
			close(fd_redirect_err);

		}

	}
	
	return RETURN_CODE_SUCCESS;
}
/**
 * Returns status if variable was set
 * Returns -1 if variable was not set
 */ 
static int set_environment_variable(word_t* verb)
{
	const char *variable, *operator;
	char *value = (char*)calloc(1, sizeof(char));
	int status;

	variable = verb->string;
	if (verb->next_part != NULL) {
		operator = verb->next_part->string;
		if(strcmp(operator, "=") == 0) {
			word_t* v = verb->next_part->next_part;
			while(v != NULL) {
				value = (char*)realloc(value, (strlen(value) + strlen(v->string) + 1)*  sizeof(char));
				if (value) {
					if (v->expand)
						strcat(value, getenv(v->string));
					else
						strcat(value, v->string);
					v = v->next_part;
				} else {
					DIE(value == NULL, "Failed to reallocate memory");
				}
				
			}

			status = setenv(variable, value, 1);
			free(value);					
			return status;
		}
	}

	return -1;
}

/**
 * Execute simple command without creating a child process.
 * It should be called only by forked processes because
 * the execv call will replace the image of the process with
 * the image of the executable to run.
 */ 
static int execute_simple_command(simple_command_t *s, int level, command_t *father)
{

	int arguments_number = 0;
	char** command_arguments = get_argv(s, &arguments_number);
	
	int return_code, variable_set = 0, code;

	if(strcmp(s->verb->string, EXIT_COMMAND) == 0) {
		return shell_exit();
	}
	else if(strcmp(s->verb->string, QUIT_COMMAND) == 0) {
		return shell_exit();
	}
	else if(strcmp(s->verb->string, CD_COMMAND) == 0) {
			int return_code = command_redirect(s);

			if(return_code != 0)
				return return_code;

			return shell_cd(s->params);
	}

	variable_set = set_environment_variable(s->verb);
	
	if (variable_set != -1)
		return variable_set; 

	return_code = command_redirect(s);

	if(return_code != 0)
		return return_code;
		
	code = execvp(s->verb->string, command_arguments);
	
	exit(WEXITSTATUS(code));

	return code;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO sanity checks */
	int arguments_number = 0;
	char** command_arguments = get_argv(s, &arguments_number);
	
	pid_t pid, wait_ret;
	int status = 0, return_code, variable_set = 0, code;

	if(strcmp(s->verb->string, EXIT_COMMAND) == 0) {
		return shell_exit();
	}
	else if(strcmp(s->verb->string, QUIT_COMMAND) == 0) {
		return shell_exit();
	}
	else if(strcmp(s->verb->string, CD_COMMAND) == 0) {
			int return_code = command_redirect(s);

			if(return_code != 0)
				return return_code;

			return shell_cd(s->params);
	}

	variable_set = set_environment_variable(s->verb);
	
	if (variable_set != -1)
		return variable_set; 

	pid = fork();
	
	switch (pid) {
	
		case -1:
			return RETURN_CODE_FORK_ERROR;

		case 0:
			
			return_code = command_redirect(s);

			if(return_code != 0)
				return return_code;
				
			code = execvp(s->verb->string, command_arguments);
			exit(WEXITSTATUS(code));
			
			break;
		default:
			wait_ret = waitpid(pid, &status, 0);		
			
			// if (WIFEXITED(status))
            //     return WEXITSTATUS(status);
                
			break;				
	}
 
 	return status;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int status1, status2, return_code;
	pid_t pid1, pid2, wait_ret1, wait_ret2;
	int parse_return1, parse_return2;

	pid1 = fork();
	
	switch(pid1) {
		
		case -1:
			return false;
		
		case 0:
			parse_return1 = parse_command(cmd1, ++level, father, 1);
			exit(WEXITSTATUS(parse_return1));
				
			break;

		default:
			pid2 = fork();
			switch(pid2) {

				case -1:
					return EXIT_FAILURE;

				case 0:					
					parse_return2 = parse_command(cmd2, ++level, father, 1);
					exit(WEXITSTATUS(parse_return2));			
					break;

				default:
	
					wait_ret2 = waitpid(pid2, &status2, 0);
					if (wait_ret2 < 0)
						return EXIT_FAILURE;

					break;
			}

			wait_ret1 = waitpid(pid1, &status1, 0);
			if (wait_ret1 < 0)
				return EXIT_FAILURE;
				
			break;
	}

	return status2; /* TODO replace with actual exit status */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO redirect the output of cmd1 to the input of cmd2 */

	int pipefd[2], status1, status2, return_code;
	pid_t pid1, pid2, wait_ret1, wait_ret2;
	int parse_return1, parse_return2;

	return_code = pipe(pipefd);
	if (return_code == -1)
		return EXIT_FAILURE;

	pid1 = fork();
	
	switch(pid1) {
		
		case -1:
			return false;
		
		case 0:
            dup2(pipefd[1], 1);
            close(pipefd[0]);
            close(pipefd[1]);		
			parse_return1 = parse_command(cmd1, ++level, father, 1);
			exit(WEXITSTATUS(parse_return1));
				
			break;

		default:
			pid2 = fork();
			switch(pid2) {

				case -1:
					return EXIT_FAILURE;

				case 0:					
					dup2(pipefd[0], 0);
					close(pipefd[1]);
					close(pipefd[0]);
					parse_return2 = parse_command(cmd2, ++level, father, 1);
					exit(WEXITSTATUS(parse_return2));
				
					break;

				default:
					
					close(pipefd[0]);
        			close(pipefd[1]);

					wait_ret2 = waitpid(pid2, &status2, 0);
					if (wait_ret2 < 0)
						return EXIT_FAILURE;

					break;
			}

			wait_ret1 = waitpid(pid1, &status1, 0);
			if (wait_ret1 < 0)
				return EXIT_FAILURE;
				
			break;
	}

	
	close(pipefd[0]);
	close(pipefd[1]);
	return status2; /* TODO replace with actual exit status */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father, int fotk_process)
{	
	int code1, code2;

	if (fotk_process == 1 && c->op == OP_NONE) {
		return execute_simple_command(c->scmd, ++level, father);
	}

	/* TODO sanity checks */
	if (c->op == OP_NONE) {
		/* TODO execute a simple command */
		return parse_simple(c->scmd, ++level, father); /* TODO replace with actual exit code of command */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:

		if (c->cmd1 != NULL)
			parse_command(c->cmd1, ++level, father, 0);
		if (c->cmd2 != NULL)
			return parse_command(c->cmd2, ++level, father, 0);
			
		break;

	case OP_PARALLEL:
		if (c->cmd1 != NULL && c->cmd2 != NULL)
			return do_in_parallel(c->cmd1, c->cmd2, ++level, father);
		break;

	case OP_CONDITIONAL_NZERO:	/* OR */
		
		if (c->cmd1 != NULL)
			code1 = parse_command(c->cmd1, ++level, father, 0);

		if (c->cmd2 != NULL && code1 != 0)
			return parse_command(c->cmd2, ++level, father, 0);
		
		return code1;
		
	case OP_CONDITIONAL_ZERO: /* AND */
		
		if (c->cmd1 != NULL)
			code1 = parse_command(c->cmd1, ++level, father, 0);
			
		if (c->cmd2 != NULL && code1 == 0)
			return parse_command(c->cmd2, ++level, father, 0);
		
		return code1;
		
	case OP_PIPE:
		if (c->cmd1 != NULL && c->cmd2 != NULL)
			return do_on_pipe(c->cmd1, c->cmd2, ++level, father);

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO replace with actual exit code of command */
}
