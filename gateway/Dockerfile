FROM eclipse-temurin:21-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY target/gateway.jar app.jar

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "app.jar"]