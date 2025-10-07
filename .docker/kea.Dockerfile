FROM jonasal/kea-dhcp4:3.1.2-alpine

COPY --from=jonasal/kea-hooks:3.1.2-alpine /hooks /usr/lib/kea/hooks

RUN ldconfig /usr/local/lib/kea/hooks