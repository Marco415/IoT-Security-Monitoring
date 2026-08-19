FROM eclipse-temurin:21-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY target/event-service.jar app.jar

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]