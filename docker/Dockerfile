FROM ubuntu:20.04
ENV TZ=America/Los_Angeles
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    bzip2 \
    default-jdk \
    git-core \
    gzip \
    liblzma-dev \
    liblzo2-dev \
    liblzo2-dev \
    ocaml-nox gawk \
    lzop \
    p7zip-full \
    python3 \
    python3-lzo \
    python3-pip \
    squashfs-tools \
    srecord \
    tar \
    unzip \
    perl \
    rsync \
    fakeroot \
    ccache ecj fastjar \
    gettext git java-propose-classpath libelf-dev libncurses5-dev \
    libncursesw5-dev libssl-dev python python2.7-dev \
    python3-setuptools python3-dev rsync subversion \
    gcc-multilib \
    pkg-config \
    wget \
    sudo \
    cpio \
    bc \
    vim \
    tmux \
    zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# add non-root user required for buildroot
ENV HOME "/home/builder"
RUN useradd -m builder &&\
    echo 'builder ALL=NOPASSWD: ALL' > /etc/sudoers.d/builder
USER builder

# a place to mount the src code for the module
RUN mkdir -p $HOME/src

# download buildroot
WORKDIR $HOME
RUN wget -c https://buildroot.org/downloads/buildroot-2022.08.tar.gz -O - | tar -xz

# this is where images produced by buildroot will be copied for export to the host
# allow to mount an external ext tree here
VOLUME [ "/home/builder/src" ]

# change to the ext-tree
WORKDIR $HOME/src
ENTRYPOINT [ "/bin/bash" ]
