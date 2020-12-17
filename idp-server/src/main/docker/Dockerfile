# used by spotify's maven plugin
FROM adoptopenjdk/maven-openjdk11:latest AS build-env
RUN mkdir /app
COPY idp-server*.jar /app
COPY cacerts /opt/java/openjdk/lib/security/
RUN ls -l /app
# docker plugin creates additional jar file for whatever reasons, wont need it so skip it on image
RUN rm -f /app/idp-server*-docker-info.jar
# get only remaining jar and link it without version number as /app/idp-server.jar
RUN cd app && export JAR=`ls *.jar  | grep -v docker | head -1` && ln -s $JAR ./idp-server.jar
RUN ls -al /app
WORKDIR /app
EXPOSE 8080
CMD ["java", "-jar", "/app/idp-server.jar"]
