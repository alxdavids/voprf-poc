TEST_FLAGS=./... -cover -count=1
BENCH_FLAGS=$(TEST_FLAGS) -bench=.
RUN_COMMAND=run main.go

VERIFIABLE=false
CURVE=P384
SUFFIX=$(CURVE)-HKDF-SHA512-SSWU-RO

CIPHERSUITE=OPRF-$(SUFFIX)

# client args
OPRF_CLIENT_ARGS=--mode=client --n=3 --ciph=$(CIPHERSUITE)
CLIENT_ARGS=$(OPRF_CLIENT_ARGS)

# VOPRF args
ifeq ($(VERIFIABLE),true)
CIPHERSUITE=VOPRF-$(SUFFIX)
CLIENT_ARGS+=--pk=$(PUBLIC_KEY)
endif

# server args
MAX_EVALS=10
SERVER_ARGS=--mode=server --max_evals=$(MAX_EVALS) --ciph=$(CIPHERSUITE)

CLIENT_TEST_VECTOR_ARGS=$(CLIENT_ARGS) -test_vectors

.PHONY: server
server:
	go $(RUN_COMMAND) $(SERVER_ARGS)

.PHONY: client
client:
	go $(RUN_COMMAND) $(CLIENT_ARGS)

.PHONY: test-vectors
test-vectors:
	go $(RUN_COMMAND) $(CLIENT_TEST_VECTOR_ARGS)

.PHONY: test
test:
	go test $(TEST_FLAGS)

.PHONY: bench
bench:
	go test $(BENCH_FLAGS)