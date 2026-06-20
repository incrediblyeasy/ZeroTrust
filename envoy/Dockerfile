FROM envoyproxy/envoy:v1.31-latest

COPY envoy.yaml /etc/envoy/envoy.yaml

COPY certs/ /etc/envoy/certs/

USER root
RUN mkdir -p /var/log/envoy && chown -R envoy:envoy /var/log/envoy /etc/envoy/certs
USER envoy

EXPOSE 8080 9901

ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "-l", "info"]
