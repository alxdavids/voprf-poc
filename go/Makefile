TEST_FLAGS=./... -cover -count=1
BENCH_FLAGS=$(TEST_FLAGS) -bench=.
COMPILED=voprf-go
BUILD_FLAGS=-o $(COMPILED)

# defaults
GROUP=P384
H2C=SSWU-RO
ifeq ($(GROUP),curve448)
H2C=ELL2-RO
endif
SUFFIX=$(GROUP)-HKDF-SHA512-$(H2C)
MAX_EVALS=10
N=3

# check verifiability
PREFIX=VOPRF
ifndef VERIFIABLE
ifndef TEST
PREFIX=OPRF
endif
endif
CIPHERSUITE=$(PREFIX)-$(SUFFIX)

# args
CIPHERSUITE_ARG=--ciph=$(CIPHERSUITE)
MAX_EVALS_ARG=--max_evals=$(MAX_EVALS)
N_ARG=--n=$(N)
PK_ARG=--pk=$(PUBLIC_KEY)
CLIENT_MODE=--mode=client
SERVER_MODE=--mode=server

CLIENT_ARGS=$(CLIENT_MODE) $(N_ARG) $(CIPHERSUITE_ARG)
SERVER_ARGS=$(SERVER_MODE) $(MAX_EVALS_ARG) $(CIPHERSUITE_ARG)

ifdef VERIFIABLE
CLIENT_ARGS+=$(PK_ARG)
endif

ifdef TEST
TEST_ARG=--test=$(TEST)
CLIENT_ARGS=$(CLIENT_MODE) $(CIPHERSUITE_ARG) $(TEST_ARG)
SERVER_ARGS=$(SERVER_MODE) $(CIPHERSUITE_ARG) $(TEST_ARG)
endif

.PHONY: build
build:
	go build $(BUILD_FLAGS)

.PHONY: test
test:
	go test $(TEST_FLAGS)

.PHONY: bench
bench:
	go test $(BENCH_FLAGS)

.PHONY: docs
docs:
	./docs.sh

.PHONY: server
server: build
	./$(COMPILED) $(SERVER_ARGS)

.PHONY: client
client: build
	./$(COMPILED) $(CLIENT_ARGS)
