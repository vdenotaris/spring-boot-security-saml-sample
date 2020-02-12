############################################################################
#                                                                          #
# Copyright 2020 Vincenzo De Notaris                                       #
#                                                                          #
# Licensed under the Apache License, Version 2.0 (the "License");          #
# you may not use this file except in compliance with the License.         #
# You may obtain a copy of the License at                                  #
#                                                                          #
#     http://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                          #
# Unless required by applicable law or agreed to in writing, software      #
# distributed under the License is distributed on an "AS IS" BASIS,        #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. #
# See the License for the specific language governing permissions and      #
# limitations under the License.                                           #
#                                                                          #
############################################################################

# Use Maven to pack a standalone executable fat-JAR file
FROM maven:3.6.0-jdk-8-alpine AS build

# Upgrade Alpine packages and install OpenSSL
RUN apk update && \
    apk upgrade && \
    apk add --no-cache openssl nss-dev nss

# Copy the source code
COPY src /usr/src/app/src  
COPY pom.xml /usr/src/app

# Setup working directory
WORKDIR /usr/src/app

# Retrieve a fresh SSO Circle's certificate and store it within the application keystore
RUN chmod +x /usr/src/app/src/main/resources/saml/update-certifcate.sh
RUN cd /usr/src/app/src/main/resources/saml/ && sh ./update-certifcate.sh

# Speed up Maven JVM a bit
ENV MAVEN_OPTS="-XX:+TieredCompilation -XX:TieredStopAtLevel=1"

# Compile the code, run unit tests and pack the fat-JAR file
RUN mvn -T 1C -f /usr/src/app/pom.xml clean package

############################################################################

# Base Alpine Linux based image with OpenJDK JRE only
FROM openjdk:8-jdk-alpine

# Project maintainer
LABEL maintainer="dev@vdenotaris.com"

# Add a volume pointing to /tmp
VOLUME /tmp

# Create a group and user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# All future commands should run as the appuser user	
USER appuser

# Setup working directory
WORKDIR /home/appuser

# Get the packed fat-JAR
COPY --from=build /usr/src/app/target/spring-boot-security-saml*.jar /home/appuser/app/springsamlsp.jar 

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Setup application entry point
ENTRYPOINT ["java","-jar","/home/appuser/app/springsamlsp.jar"]  

############################################################################
