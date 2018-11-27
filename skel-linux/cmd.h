/**
 * Operating Sytems 2013-2017 - Assignment 2
 */

#ifndef _CMD_H
#define _CMD_H

#include "parser.h"

#define SHELL_EXIT -100
#define EXIT_COMMAND "exit"
#define QUIT_COMMAND "quit"
#define CD_COMMAND "cd"
#define EXCEPTION_TOO_MANY_ARGUMENTS "Too many arguments given"
#define RETURN_CODE_TOO_MANY_ARGUMENTS -101
#define EXCEPTION_FORK "Fork error"
#define RETURN_CODE_FORK_ERROR -102
#define EXCEPTION_CHILD_WAIT "Wait error"
#define RETURN_CODE_CHILD_WAIT -103
#define EXCEPTION_EXEC "Cannot execute command"
#define RETURN_CODE_EXEC_ERROR -104
#define EXCEPTION_OPEN_FILE "Cannot open file"
#define RETURN_CODE_OPEN_FILE_ERROR -105
#define RETURN_CODE_SUCCESS 0
#define EXCEPTION_DUP2_ERROR "Cannot duplicate error"
#define RETURN_CODE_DUP2_ERROR -106

/**
 * Parse and execute a command.
 */
int parse_command(command_t *cmd, int level, command_t *father, int flag);

#endif /* _CMD_H */
