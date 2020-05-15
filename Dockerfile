FROM ubuntu:latest
MAINTAINER David Manouchehri

RUN useradd -m patchkit
WORKDIR /home/patchkit
ENV HOME /home/patchkit

RUN apt-get -y update && \
	DEBIAN_FRONTEND=noninteractive apt-get -y install git python-pip build-essential git cmake python-dev libglib2.0-dev && \
	su - patchkit -c "git clone https://github.com/lunixbochs/patchkit.git" && \
	su - patchkit -c "cd /home/patchkit/patchkit && HEADLESS=1 ./deps.sh" && \
	cd /home/patchkit/patchkit && \
	HEADLESS=1 build=/home/patchkit/patchkit/build ./install.sh && \
	rm -rf /home/patchkit/patchkit/build

USER patchkit
ENV PATH /home/patchkit/patchkit:$PATH

CMD ["/bin/bash"]
