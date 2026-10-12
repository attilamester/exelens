FROM docker.io/attilamester/radare2:6.0.4-slim

WORKDIR /usr/exelens

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends graphviz libgraphviz-dev pkg-config build-essential python3-dev wget unzip && \
    apt-get clean all && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*


COPY ./requirements.txt .

RUN python3 -m pip install -r requirements.txt

COPY ./src/exelens ./exelens

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "-m", "exelens"]
CMD ["--input", "/usr/exelens/workdir/input.file"]
