FROM busybox:1.36.1-musl AS busybox

# Pinned for reproducible builds — never track a floating :latest for the PDP.
FROM openpolicyagent/opa:0.66.0

COPY --from=busybox /bin/busybox /bin/busybox

COPY policies /policies

ENTRYPOINT ["/opa"]
# --authorization=basic enforces the system.authz policy on every API request,
# so the management API (policy/data writes) is locked down to the gateway's
# decision query and health probe only.
CMD ["run", \
     "--server", \
     "--addr=0.0.0.0:8181", \
     "--log-level=info", \
     "--authorization=basic", \
     "--set=decision_logs.console=true", \
     "/policies"]
