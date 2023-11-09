FROM ubuntu:20.04

# install 32-bit support
RUN dpkg --add-architecture i386

ENV TZ=Asia/Taipei

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y tzdata

# general dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y git build-essential python3 python3-pip python3-dev htop vim sudo

# install virtualenvwrapper
#RUN pip install virtualenvwrapper

# angr dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y openjdk-8-jdk zlib1g:i386 libtinfo5:i386 libstdc++6:i386 libgcc1:i386 libc6:i386 libssl-dev nasm binutils-multiarch qtdeclarative5-dev libpixman-1-dev libglib2.0-dev debian-archive-keyring debootstrap libtool libreadline-dev cmake libffi-dev libxslt1-dev libxml2-dev
RUN pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9

# setup user `ioctlance` with a home directory
RUN useradd -ms /bin/bash ioctlance
USER ioctlance

#ENV VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
#RUN /bin/bash -c "source /usr/local/bin/virtualenvwrapper.sh && \
#    mkvirtualenv ioctlance && \
#    pip install angr==9.2.18 ipython==8.5.0 ipdb==0.13.9"

COPY ./analysis /home/ioctlance/analysis/
COPY ./evaluation /home/ioctlance/evaluation/
COPY ./dataset /home/ioctlance/dataset/
USER root

#RUN echo 'export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3' >> /home/ioctlance/.bashrc
#RUN echo 'export WORKON_HOME=$HOME/.virtualenvs' >> /home/ioctlance/.bashrc
#RUN echo 'source /usr/local/bin/virtualenvwrapper.sh && workon ioctlance' >> /home/ioctlance/.bashrc

WORKDIR /home/ioctlance/
CMD ["/bin/bash"]
