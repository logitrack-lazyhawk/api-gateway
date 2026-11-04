# ==============================================================================
# Etapa 1: Builder (Compilación con Maven y JDK 25)
# ==============================================================================
FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /app

# Copiar descriptor de dependencias para aprovechar la caché de capas de Docker
COPY pom.xml ./
RUN mvn dependency:go-offline -B

# Copiar código fuente y compilar el microservicio
COPY src ./src
RUN mvn clean package -DskipTests

# ==============================================================================
# Etapa 2: Runner (Ejecución ligera con JRE 25)
# ==============================================================================
FROM eclipse-temurin:25-jre-noble AS runner
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Crear usuario y grupo no privilegiado por seguridad
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

# Copiar el JAR generado desde la etapa de compilación
COPY --from=builder /app/target/api-gateway-*.jar app.jar

# Asignar permisos y cambiar a usuario no root
RUN chown -R appuser:appgroup /app
USER appuser

# Exponer el puerto del API Gateway
EXPOSE 8066

# Parámetros optimizados para JVM en contenedores
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

# Entrypoint limpio
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
