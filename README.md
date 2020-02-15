[SBS3] Spring Boot Sample SAML 2.0 Service Provider
====================

[![Build Status](https://travis-ci.org/vdenotaris/spring-boot-security-saml-sample.svg?branch=master)](https://travis-ci.org/vdenotaris/spring-boot-security-saml-sample)
[![DOI](https://zenodo.org/badge/22013861.svg)](https://zenodo.org/badge/latestdoi/22013861)
![GitHub release](https://img.shields.io/github/release/vdenotaris/spring-boot-security-saml-sample.svg)
[![GitHub forks](https://img.shields.io/github/forks/vdenotaris/spring-boot-security-saml-sample.svg)](https://github.com/vdenotaris/spring-boot-security-saml-sample/network)
[![GitHub stars](https://img.shields.io/github/stars/vdenotaris/spring-boot-security-saml-sample.svg)](https://github.com/vdenotaris/spring-boot-security-saml-sample/stargazers)
[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/vdenotaris/spring-boot-security-saml-sample/master/LICENSE)
![Beerpay](https://img.shields.io/beerpay/vdenotaris/spring-boot-security-saml-sample.svg)

---------

<img src="https://i.ibb.co/CKbFBzH/logo-small.png" align="right" />

## Project description

This project represents a sample implementation of a **SAML 2.0 Service Provider**, completely built on **Spring Framework**. In particular, it shows how to develop a web solution devised for Federated Authentication, by integrating **Spring Boot** and **Spring Security SAML**. The configuration has been completely defined using *Java annotations* (no XML).

**SSOCircle** ([ssocircle.com](http://www.ssocircle.com/en/portfolio/publicidp/)) is used as public Identity Provider for test purpose.

- **Author:** Vincenzo De Notaris ([dev@vdenotaris.com](mailto:dev@vdenotaris.com))
- **Website:** [www.vdenotaris.com](http://www.vdenotaris.com)
- **Version:**  ` 2.3.1.RELEASE`
- **Last update**: February 15th, 2020

Thanks to *Vladimír Schäfer* ([github.com/vschafer](https://github.com/vschafer)) for supporting my work.

### References

#### Spring Boot

> Spring Boot makes it easy to create Spring-powered, production-grade applications and services with absolute minimum fuss.  It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need.
> - **Ref.:** [http://projects.spring.io/spring-boot/](http://projects.spring.io/spring-boot/)

#### Spring Security SAML Extension

> Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.
> - **Ref.:** [http://projects.spring.io/spring-security-saml/](http://projects.spring.io/spring-security-saml/)

---------

## Walkthrough

### Run as Docker container

To make it even easier, it is possible to run the project "as-is" also as Docker container. A valid account on [SSOCircle](https://www.ssocircle.com/en/) is needed to perform the authentication process.

**Run as container building a Docker image**

Run a pre-built fat-jar:

```
docker run -it --rm -p 8080:8080 -t vdenotaris/spring-saml-sp:latest
```

or compile the code and run the application with Maven:

```
docker run -it --rm -p 8080:8080 -t vdenotaris/spring-saml-sp:2.3.1-mvn-jdk-8
```

*Note: the related Docker image is publicly available on [Docker Hub](https://hub.docker.com/r/vdenotaris/spring-saml-sp/).*


The Service Provider is deployed as web application. Enter [http://localhost:8080/](http://localhost:8080/) in a browser to see the application running.

If you’re using Docker natively on Linux, Docker for Mac, or Docker for Windows, then the web app should now be listening on port 8080 on your Docker daemon host. Point your web browser to http://localhost:8080 to find the starting page. If this doesn’t resolve, you can also try [http://127.0.0.1:8080/](http://127.0.0.1:8080/).

If you’re using Docker Machine on a Mac or Windows, use `docker-machine ip MACHINE_VM` to get the IP address of your Docker host. Then, open *http://MACHINE_VM_IP:8080* in a browser. However, please note that the Service Provider is statically registered with localhost as endpoint on SSOCircle. Thus you need to reconfigure the application.

------

### Unit tests

I would like to say thank you to *Alexey Syrtsev* ([github.com/airleks](https://github.com/airleks)) for his contribution on unit tests.

| Metric | Result |
| ------------- | -----:|
| Coverage % | 99% |
| Lines Covered | 196 |
| Total Lines | 199 |

------

### Additional notes

1. The certificate on [https://idp.ssocircle.com/](https://idp.ssocircle.com/) seems to change on a fairly regular basis. This results in the following exception. 

`javax.net.ssl.SSLPeerUnverifiedException: SSL peer failed hostname validation for name: null`

To update the SSOCircle certificates within the keystore, just run: 

	cd src/main/resources/saml/ && sh ./update-certifcate.sh 

2. Sometimes SSO Circle could display you an error during the authenticaton process. In this case, please update your federation metadata directly on [https://idp.ssocircle.com](https://idp.ssocircle.com):

	> Manage Metadata > Service Provider Metadata
	
	Remove the current record and add a new one, using your FQDN and providing a new copy of your metadata: your can retrieve them at [http://localhost:8080/saml/metadata](http://localhost:8080/saml/metadata).

3. When the project version corresponds with the Spring Boot parent version, Maven may give you a warning as follows:

	> Version is duplicate of parent version.

	Actually there is nothing wrong with the used configuration, thus you can just ignore that message.

---------

### License

    Copyright 2020 Vincenzo De Notaris

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

## Support on Beerpay
Hey dude! Help me out for a couple of :beers:!

[![Beerpay](https://beerpay.io/vdenotaris/spring-boot-security-saml-sample/badge.svg?style=beer-square)](https://beerpay.io/vdenotaris/spring-boot-security-saml-sample)  [![Beerpay](https://beerpay.io/vdenotaris/spring-boot-security-saml-sample/make-wish.svg?style=flat-square)](https://beerpay.io/vdenotaris/spring-boot-security-saml-sample?focus=wish)

