FROM gradle:jdk11
EXPOSE 8180/tcp
COPY --chown=gradle:gradle . /cpcds-auth-server/
COPY --chown=gradle:gradle . database.mv.db
WORKDIR /cpcds-auth-server/
RUN gradle installBootDist
CMD ["gradle", "bootRun"]