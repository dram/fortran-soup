PROGRAM = tests/run-tests
MODULES_DIR = modules
OBJECT_FILES = sources/soup.o sources/soup_aux.o
OBJECT_FILES += tests/strings.o tests/cstrings.o tests/main.o

.PHONY: build clean run setup

build: setup ${PROGRAM}

run: build
	@${PROGRAM}

sources/soup.f90: tools/api-translator.py
	$< soup /usr/local/share/gir-1.0/Soup-2.4.gir >$@

%.o: %.f90
	${CC} -Wall -J ${MODULES_DIR} -o $@ -c $<

${PROGRAM}: ${OBJECT_FILES}
	${CC} -o $@ $^ -lgfortran $(shell pkg-config --libs libsoup-2.4)

setup: ${MODULES_DIR}

${MODULES_DIR}:
	mkdir -p $@

clean:
	rm -rf ${PROGRAM} ${OBJECT_FILES} ${MODULES_DIR}
