FROM alpine:3.10

ENV VAULT_VERSION=v3.2.3
ENV KUBECTL_VERSION=v1.18.2
ENV VELERO_VERSION=v1.4.2
ENV YTT_VERSION=v0.27.1
ENV VAULT_VERSION=1.4.3
ENV VAULT_PACKAGE=vault_"$VAULT_VERSION"_linux_amd64.zip

WORKDIR /velero

RUN apk --no-cache update \
    && apk upgrade \
    && apk --no-cache add curl wget unzip jq \
    && curl -LO https://storage.googleapis.com/kubernetes-release/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl \ 
    && chmod +x /velero/kubectl \
    && mv /velero/kubectl /usr/local/bin/ \
    && curl -LO https://releases.hashicorp.com/vault/$VAULT_VERSION/$VAULT_PACKAGE \
    && unzip /velero/$VAULT_PACKAGE \
    && mv /velero/vault /usr/local/bin/vault \
    && curl -L https://github.com/k14s/ytt/releases/download/$YTT_VERSION/ytt-linux-amd64 -o /usr/local/bin/ytt \
    && chmod +x /usr/local/bin/ytt \
    && curl -LO https://github.com/heptio/velero/releases/download/$VELERO_VERSION/velero-$VELERO_VERSION-linux-amd64.tar.gz \ 
    && tar -xvzf velero-$VELERO_VERSION-linux-amd64.tar.gz \
    && chmod +x velero-$VELERO_VERSION-linux-amd64/velero \
    && mv velero-$VELERO_VERSION-linux-amd64/velero /usr/local/bin/velero \
    && chown root:root /usr/local/bin/velero \
    && rm -rf velero-$VELERO_VERSION-linux-amd64 \
    && rm velero-$VELERO_VERSION-linux-amd64.tar.gz

ADD . .

RUN chmod +x bootstrap.sh