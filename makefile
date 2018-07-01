CC := gcc
LD := gcc
RM := rm -f
#copy from http://stackoverflow.com/questions/18136918/how-to-get-current-relative-directory-of-your-makefile
#thank you for spending your time answer other people question
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

OUTPUT:=output
$(shell mkdir -p $(OUTPUT))

PRJ :=  $(notdir $(current_dir))
SRCS += main.c
INC +=.


LIBDIR+=


LIB=$(patsubst %,-L%,$(LIBDIR))



OBJS+=$(patsubst %.c,%.o,$(SRCS))
OBJECTS = $(addprefix $(OUTPUT)/, $(OBJS))

all: INIT_DIR $(PRJ)
INIT_DIR:
		$(shell mkdir -p ${OBJDIR} 2>/dev/null)
$(OUTPUT)/%.o:%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(PRJ): $(OBJECTS)
	mkdir -p $(@D)
	$(LD) $(CFLAGS) -o $(OUTPUT)/$@ $^ $(LDFLAGS)

VPATH +=:.

# CFLAGS+=-MD -MP
CFLAGS+=$(patsubst %,-I%,$(INC))
CFLAGS+= -std=gnu99 -Wextra -Wall -Werror
LDFLAGS :=
# -include $(OBJECTS:.o=.d)

clean:
	$(RM) $(OUTPUT)/$(PRJ)
	$(RM) $(OUTPUT)/*.o $(OUTPUT)/$(PRJ)

.PHONY: all clean
