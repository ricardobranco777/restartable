FROM	docker.io/library/golang AS builder

WORKDIR	/go/src/restartable
COPY	. .

RUN	make

FROM	scratch
COPY	--from=builder /go/src/restartable/restartable /usr/local/bin/restartable

ENTRYPOINT ["/usr/local/bin/restartable"]
