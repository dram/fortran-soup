PROGRAM = tests/run-tests
MODULES_DIR = modules
OBJECT_FILES = sources/soup.o sources/soup_aux.o
OBJECT_FILES += tests/strings.o tests/cstrings.o tests/main.o
CONSTANTS_FILE = sources/constants.f90
CONSTANTS_GENERATOR = sources/constants

.PHONY: build clean run setup

build: setup ${PROGRAM}

run: build
	@${PROGRAM}

sources/soup.o: sources/soup.f90 ${CONSTANTS_FILE}

${CONSTANTS_FILE}: ${CONSTANTS_GENERATOR}
	$^ >$@

${CONSTANTS_GENERATOR}: sources/constants.c
	${CC} -Wall $(shell pkg-config --cflags libsoup-2.4) -o $@ $^

%.o: %.f90
	${CC} -Wall -J ${MODULES_DIR} -o $@ -c $<

${PROGRAM}: ${OBJECT_FILES}
	${CC} -o $@ $^ -lgfortran $(shell pkg-config --libs libsoup-2.4)

setup: ${MODULES_DIR}

${MODULES_DIR}:
	mkdir -p $@

clean:
	rm -rf ${PROGRAM} ${OBJECT_FILES} ${MODULES_DIR}
	rm -rf ${CONSTANTS_GENERATOR} ${CONSTANTS_FILE}
