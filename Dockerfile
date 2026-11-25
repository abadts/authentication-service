FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace
COPY . .
RUN ./gradlew --no-daemon clean bootJar

FROM eclipse-temurin:17-jre
WORKDIR /app
RUN mkdir -p /app/data && chown 10001:10001 /app/data
COPY --from=build /workspace/build/libs/authentication-service-1.0.0.jar application.jar
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/application.jar"]
