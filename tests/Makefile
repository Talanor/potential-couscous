NAME	=	test1
SRC	=	$(NAME).c
OBJ	=	$(SRC:.c=.o)
CC	=	gcc
RM	=	rm -f
CFLAGS	=	-W -Wall -Wextra -pedantic -O0
LDFLAGS	=	

all:	$(NAME)

$(NAME):	$(OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

%.o:	%.c
	$(CC) -c $^ $(CFLAGS) -o $@

clean:
	$(RM) $(OBJ)

fclean:	clean
	$(RM) $(NAME)

re:	fclean all
