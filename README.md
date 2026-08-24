# IoT Security Monitoring

## Microservices application with graph database integration.


This project is an IoT security monitoring system, using microservices and an API gateway. The system architecture is as follows:

\-Client application
\-Eureka service registry
\-API gateway
\-Device service
\-Event service
\-Authentication service
\-PostgreSQL
\-Elasticsearch
\-Logstash
\-Kibana


The device service allows user to add, update, or delete devices. The event service allows users to add, update, or delete security events for devices. The authentication service handles user authentication using JWT tokens. Each service has its own PostgreSQL database, implementing the database per service microservices pattern. Logging and monitoring services are provided by Logstash, Elasticsearch, and Kibana. The web client app provides a UI for HTTP requests, which are directed to the API. The system is containerised and deployed in Docker, while the web client is hosted on a live server in VS Code.


Technologies used include:

\-JDK 21
\-PostgreSQL
\-Spring Boot
\-Docker Compose
\-JWT Authentication
\-Logstash
\-Elasticsearch
\-Kibana
