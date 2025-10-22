FROM jonasal/kea-dhcp4:3.1.2-alpine AS runtime

COPY --from=jonasal/kea-hooks:3.1.2-alpine /hooks /usr/lib/kea/hooks

RUN touch /kea/config/kea-dhcp4.conf

COPY ./kea-dhcp4.conf /kea/config/kea-dhcp4.conf

RUN chmod 750 /kea/config/kea-dhcp4.conf

RUN ldconfig /usr/local/lib/kea/hooks