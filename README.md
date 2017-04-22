

## References

#### Spring Boot

Spring Boot makes it easy to create Spring-powered, production-grade applications and services with absolute minimum fuss. It takes an opinionated view of the Spring platform so that new and existing users can quickly get to the bits they need.

- **Website:** [http://projects.spring.io/spring-boot/](http://projects.spring.io/spring-boot/)

#### Spring Security SAML Extension

Spring SAML Extension allows seamless inclusion of SAML 2.0 Service Provider capabilities in Spring applications. All products supporting SAML 2.0 in Identity Provider mode (e.g. ADFS 2.0, Shibboleth, OpenAM/OpenSSO, Ping Federate, Okta) can be used to connect with Spring SAML Extension.

- **Website:** [http://projects.spring.io/spring-security-saml/](http://projects.spring.io/spring-security-saml/)

---------

## Project description

Currently Spring Security SAML module doesn't provide a starter for Spring Boot. Moreover, its configuration is XML-based as of this writing. The aim of this project is to explain how to develop a **Service Provider (SP)** which uses **Spring Boot** (`1.4.0.RELEASE`) and **Spring Security SAML Extension** (`1.0.2.RELEASE`), by defining an annotation-based configuration (**Java Configuration**). **Thymeleaf** is also used as template engine.

**SSOCircle** ([ssocircle.com](http://www.ssocircle.com/en/portfolio/publicidp/)) is used as public Identity Provider for test purpose.

- **Author:** Vincenzo De Notaris ([dev@vdenotaris.com](mailto:dev@vdenotaris.com))
- **Website:** [vdenotaris.com](http://www.vdenotaris.com)
- **Version:**  ` 1.4.0.RELEASE `
- **Date**: 2016-09-09

Thanks to *Vladimír Schäfer* ([github.com/vschafer](https://github.com/vschafer)) for supporting my work.

#### Unit tests

I would like to say thank you to *Alexey Syrtsev* ([github.com/airleks](https://github.com/airleks)) for his contribution on unit tests.

| Metric | Result |
| ------------- | -----:|
| Coverage % | 99% |
| Lines Covered | 196 |
| Total Lines | 199 |

#### Useful notes

1. The certificate on [https://idp.ssocircle.com/](https://idp.ssocircle.com/) seems to change on a fairly regular basis. This results in the following exception. 

	
	    Caused by: javax.net.ssl.SSLPeerUnverifiedException: SSL peer failed hostname validation for name: null
	        at org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory.verifyHostname(TLSProtocolSocketFactory.java:233) ~[openws-1.5.1.jar:?]
	        at org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory.createSocket(TLSProtocolSocketFactory.java:186) ~[openws-1.5.1.jar:?]
	        at org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory.createSocket(TLSProtocolSocketFactory.java:97) ~[spring-security-saml2-core-1.0.2.RELEASE.jar:1.0.2.RELEASE]
	        at org.apache.commons.httpclient.HttpConnection.open(HttpConnection.java:707) ~[commons-httpclient-3.1.jar:?]
	        at org.apache.commons.httpclient.MultiThreadedHttpConnectionManager$HttpConnectionAdapter.open(MultiThreadedHttpConnectionManager.java:1361) ~[commons-httpclient-3.1.jar:?]
	        at org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(HttpMethodDirector.java:387) ~[commons-httpclient-3.1.jar:?]
	        at org.apache.commons.httpclient.HttpMethodDirector.executeMethod(HttpMethodDirector.java:171) ~[commons-httpclient-3.1.jar:?]
	        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:397) ~[commons-httpclient-3.1.jar:?]
	        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:323) ~[commons-httpclient-3.1.jar:?]
	        at org.opensaml.saml2.metadata.provider.HTTPMetadataProvider.fetchMetadata(HTTPMetadataProvider.java:250) ~[opensaml-2.6.1.jar:?]
	        at org.opensaml.saml2.metadata.provider.AbstractReloadingMetadataProvider.refresh(AbstractReloadingMetadataProvider.java:255) ~[opensaml-2.6.1.jar:?]
	        ... 47 more

    To update the certificates in the keystore run the following commands: 

		cd src/main/resources/saml/  
		./update-certifcate.sh 

2. Sometimes SSO Circle could display you an error during the authenticaton process. In this case, please update your federation metadata directly on [https://idp.ssocircle.com](https://idp.ssocircle.com):

	> Manage Metadata > Service Provider Metadata
	
	Remove the current record and add a new one, using your FQDN and providing a new copy of your metadata: your can retrieve them at [http://localhost:8080/saml/metadata](http://localhost:8080/saml/metadata).

3. When the project version corresponds with the Spring Boot parent version, Maven may give you a warning as follows:

	> Version is duplicate of parent version.

	Actually there is nothing wrong with the used configuration, thus you can just ignore that message.

### License

    Copyright 2017 Vincenzo De Notaris

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	    http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
