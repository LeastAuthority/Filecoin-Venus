FROM fedora:34

RUN sudo yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm; sudo yum install -y git gcc bzr jq pkgconfig clang llvm mesa-libGL-devel opencl-headers ocl-icd ocl-icd-devel hwloc-devel

# TODO: install and use asdf.
# Install golang
ADD https://golang.org/dl/go1.16.3.linux-amd64.tar.gz /root/go.tgz
RUN tar -C /usr/local -xzf /root/go.tgz
RUN mkdir /root/go
ENV GOPATH=/root/go
ENV PATH=/usr/local/go/bin:$GOPATH/bin:$PATH

# Install go-fuzz
RUN GO111MODULE=off go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
#WORKDIR /tmp/fuzzing

# Venus make deps
#RUN git init
#COPY ./venus ./venus
#WORKDIR /tmp/fuzzing/venus
#RUN make deps

# NB: for use with docker-compose
COPY ./venus/fleece/docker/go-fuzz.sh /go-fuzz.sh
RUN chmod 755 /go-fuzz.sh

CMD bash
