FROM busybox:1.36.1-musl AS busybox

FROM openpolicyagent/opa:latest

COPY --from=busybox /bin/busybox /bin/busybox

COPY policies /policies

ENTRYPOINT ["/opa"]
CMD ["run", \
     "--server", \
     "--addr=0.0.0.0:8181", \
     "--log-level=info", \
     "--set=decision_logs.console=true", \
     "/policies"]
