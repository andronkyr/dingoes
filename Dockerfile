FROM ubuntu:20.04
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y python3-pip 
COPY ./requirements.txt .
RUN pip3 install -r requirements.txt

COPY . . 

CMD ["/bin/python3","dingoes.py", "-h" ]